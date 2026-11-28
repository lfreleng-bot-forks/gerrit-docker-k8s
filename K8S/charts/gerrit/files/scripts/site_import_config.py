# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Compare an archive's gerrit.config with the chart's render.

The chart's render replaces the archive's gerrit.config, so the
migration report names each key the import loses or changes, with its
values where they are safe to print, and the keys only the render
sets. ``site_import_report.py`` adds the lines to the report.
"""

from __future__ import annotations

import json
import re
import string
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from site_import_common import SiteImportError, run_bytes

GIT_CONFIG = ["git", "-c", "safe.directory=*", "config"]
# The keys of the sections that decide who signs in, and as whom:
# unqualified [auth] and [saml], as git names them, lower case. Each
# such key only the render sets keeps a line of its own
SIGN_IN_KEYS = re.compile(r"(auth|saml)\.[^.]+")
# Keys the chart sets from the container's layout, which differ on
# every import, as git names them; a name ending in '.' stands for its
# whole section
UNCOMPARED = (
    # The git store's path in the container
    "gerrit.basepath",
    # The site's identity, which check_identity compares and refuses
    "gerrit.serverid",
    # The address and port the container serves HTTP on
    "httpd.listenurl",
    # The address and port the container serves SSH on
    "sshd.listenaddress",
    # The container's Java, heap, user and war, from the chart's values
    "container.",
    # The persistent cache's path in the container
    "cache.directory",
    # The index the chart builds; a reindex replaces the archive's
    "index.type",
    # The chart mounts its own keystore, and check_keystore compares it
    "saml.keystorepath",
)
# A file path cannot be compared with a URL, or with a path on another
# host, so this key is compared only between two URLs
METADATA_PATH = "saml.metadatapath"
METADATA_URL = re.compile(r"https?://", re.IGNORECASE)
# Key names whose values the report never prints, in lower case:
# "key" covers "privatekey", and "pass" a name such as smtpPass
SECRET_SUFFIXES = ("password", "pass", "secret", "key", "token", "seed")
# A value's runs of text between whitespace; a URL reference runs to
# the end of its run: a URL may hold an apostrophe, and a stray quote or
# angle bracket must not end it before a credential
TOKEN = re.compile(r"\S+")
SCHEME_CHARS = frozenset(string.ascii_letters + string.digits + "+.-")
SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:(?=//)")
WHITESPACE = re.compile(r"\s")
# A URL's path is shown in full, so it must not hold another URL whose
# user-info would show with it: a nested authority, user-info, a scheme
# or any of them percent-encoded
NESTED = re.compile(r"//|[@:%]")
HIDDEN = "(not shown)"
# Controls json.dumps leaves as they are once ensure_ascii is off, which
# a terminal may still obey: DEL and the C1 set, whose CSI starts an
# escape sequence as ESC [ does
RAW_CONTROLS = re.compile(r"[\x7f-\x9f]")


def config_settings(path: Path) -> dict[str, list[str | None]]:
    """Every key of a git config file, subsections included.

    Each name, whose section and key git reports in lower case and whose
    subsection it reports as written, maps to the list of its values in
    file order; a key written without '=' has the value None.
    A quoted subsection may hold a carriage return, which text mode
    would read as the newline that ends a name, so the output is split
    as bytes and only then decoded. Bytes that are not UTF-8 are
    replaced, so a value cannot fail the import that only reports on it.
    """
    if not path.is_file():
        raise SiteImportError(f"cannot read {path}")
    result = run_bytes(
        [*GIT_CONFIG, "-f", str(path), "-z", "--list"], capture_output=True
    )
    if result.returncode:
        raise SiteImportError(f"cannot parse {path}")
    found: dict[str, list[str | None]] = {}
    for entry in filter(None, result.stdout.split(b"\0")):
        name, newline, value = entry.partition(b"\n")
        text = value.decode(errors="replace") if newline else None
        found.setdefault(name.decode(errors="replace"), []).append(text)
    return found


def url_start(token: str) -> int:
    """Where a URL reference starts in a run of text, or -1.

    An absolute or scheme-relative reference starts at its scheme or its
    '//'; a relative one with a query or a fragment starts the run. Its
    user-info, query and fragment may carry a credential. Each step is a
    single pass, so a long value costs linear time.
    """
    slashes = token.find("//")
    delimiters = [i for i in (token.find("?"), token.find("#")) if i >= 0]
    if delimiters and (slashes < 0 or min(delimiters) < slashes):
        return 0
    if slashes < 1 or token[slashes - 1] != ":":
        return slashes
    colon = first = slashes - 1
    while first and token[first - 1] in SCHEME_CHARS:
        first -= 1
    letters = (i for i in range(first, colon) if token[i] in string.ascii_letters)
    return next(letters, slashes)


def url_spans(value: str) -> list[tuple[int, int]]:
    """The start and end of each URL reference in a value."""
    spans = []
    for token in TOKEN.finditer(value):
        start = url_start(token.group(0))
        if start >= 0:
            spans.append((token.start() + start, token.end()))
    return spans


def hide_url(url: str) -> str:
    """A URL reference with its user-info, query and fragment hidden.

    The query is hidden whole: a bare token may hold '=', as Base64
    padding does, so no part of a field is safe to show. Call it only
    on a URL unsafe_url clears, which urlsplit can read.
    """
    parts = urlsplit(url)
    _, at, host = parts.netloc.rpartition("@")
    netloc = f"{HIDDEN}@{host}" if at else host
    query = HIDDEN if parts.query else ""
    fragment = HIDDEN if parts.fragment else ""
    return urlunsplit((parts.scheme, netloc, parts.path, query, fragment))


def unsafe_url(url: str) -> bool:
    """Whether hiding a URL reference's parts may still show a credential.

    Its path is shown in full, so it must not hold another URL. An '@'
    in its query or fragment may close user-info whose password held the
    '?' or '#', which ended the authority early and would show the user
    and password as the host. A URL urlsplit cannot read may hide an '@'
    the report needs to see, so it is unsafe too.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return True
    return bool(NESTED.search(parts.path)) or "@" in parts.query + parts.fragment


def outside_credential(text: str) -> bool:
    """Whether a value as the report prints it may hold a credential.

    ``text`` is the value with each URL in it hidden and its scheme left
    out. A ':' before an '@' may be a user and password, whose password
    may hold whitespace, or a '//' that starts a URL the matcher splits
    from the user and password before it; a '%' may encode a URL with
    its user-info.
    """
    return "%" in text or -1 < text.find(":") < text.rfind("@")


def without_scheme(url: str) -> str:
    """A hidden URL reference without the scheme and ':' it starts with."""
    scheme = SCHEME.match(url)
    return url[scheme.end() :] if scheme else url


def shown_value(value: str | None) -> str:
    """One value as the report prints it.

    A URL ends at whitespace, so text after a space may still be its
    query, as in a quoted ``?label=Sign in&token=...``: a value holding
    both a URL and any whitespace is hidden whole. So is a value holding
    a URL that unsafe_url names, or one that outside_credential names
    once its URLs are hidden.
    """
    if value is None:
        return "(no value)"
    spans = url_spans(value)
    found = [value[a:b] for a, b in spans]
    starts, ends = [a for a, _ in spans], [b for _, b in spans]
    bounds = zip([0, *ends], [*starts, len(value)], strict=True)
    gaps = [value[a:b] for a, b in bounds]
    if (found and WHITESPACE.search(value)) or any(unsafe_url(u) for u in found):
        return "(value not shown)"
    hidden = [hide_url(url) for url in found]
    pieces = list(zip(hidden, gaps[1:], strict=True))
    checked = gaps[0] + "".join(without_scheme(h) + g for h, g in pieces)
    if outside_credential(checked):
        return "(value not shown)"
    text = gaps[0] + "".join(h + g for h, g in pieces)
    quoted = json.dumps(text, ensure_ascii=False)
    return RAW_CONTROLS.sub(lambda c: f"\\u{ord(c.group()):04x}", quoted)


def shown(values: list[str | None]) -> str:
    quoted = [shown_value(v) for v in values]
    return quoted[0] if len(quoted) == 1 else f"[{', '.join(quoted)}]"


def shown_name(name: str) -> str:
    """A key's full name as the report prints it.

    git keeps a subsection's name as written, so it may be a URL with
    its credentials, as an [http] or [url] section's can be: the
    subsection is shown as shown_value shows a value, without its
    quotes and with its control characters still escaped, or hidden
    whole when that hides it. The section and the key are names git
    checks, and are shown as they are.
    """
    section, _, rest = name.partition(".")
    subsection, dot, key = rest.rpartition(".")
    if not dot:
        return name
    text = shown_value(subsection)
    subsection = text[1:-1] if text.startswith('"') else HIDDEN
    return f"{section}.{subsection}.{key}"


def secret(name: str) -> bool:
    """Whether a key's name marks its value as one never to print.

    git cannot put a '.' in a key's own name, so the key is what follows
    the last; a subsection's case is its own, so the test ignores case.
    """
    return name.rpartition(".")[2].lower().endswith(SECRET_SUFFIXES)


def config_line(name: str, archive: list[str | None], render: list[str | None]) -> str:
    """One report line for a key the archive and the render set differently.

    An empty list stands for a key the file does not set.
    """
    theirs, ours = "the archive", "the chart's render"
    shown_as = shown_name(name)
    if secret(name):
        if not render:
            where = f"in {theirs} and not in {ours}"
        elif not archive:
            where = f"in {ours} and not in {theirs}"
        else:
            where = f"in {theirs} and in {ours}, to different values"
        if not SIGN_IN_KEYS.fullmatch(name):
            return (
                f"gerrit.config sets {shown_as} {where}; the value is not shown, as "
                "the key's name marks a secret"
            )
        return (
            f"gerrit.config sets {shown_as} {where}; the value is not shown, and the "
            "chart takes it from a Secret"
        )
    if not render:
        return f"gerrit.config sets {shown_as} to {shown(archive)} in {theirs} and not in {ours}"
    if not archive:
        return f"gerrit.config sets {shown_as} to {shown(render)} in {ours} and not in {theirs}"
    have, want = shown(archive), shown(render)
    if have == want:
        return (
            f"gerrit.config sets {shown_as} to {have} in {theirs} and in "
            f"{ours}, with values that differ in a part of a URL not shown"
        )
    return f"gerrit.config sets {shown_as} to {have} in {theirs} and {want} in {ours}"


def urls(values: list[str | None]) -> bool:
    return bool(values) and all(v is not None and METADATA_URL.match(v) for v in values)


def compared(name: str, have: list[str | None], want: list[str | None]) -> bool:
    """Whether the report compares a key the two files set differently."""
    if any(
        name == key or (key.endswith(".") and name.startswith(key))
        for key in UNCOMPARED
    ):
        return False
    if name == METADATA_PATH:
        return urls(have) and urls(want)
    return True


def config_report(imported: Path, rendered: Path) -> list[str]:
    """Name each gerrit.config key the render changes from the archive's.

    The chart's render replaces the archive's gerrit.config, so a key
    left out of the values, or given another value, is lost on import:
    one line names each key the archive sets and the render does not, or
    sets differently, and so does each [auth] and [saml] key only the
    render sets. The other keys only the render sets come from the
    chart's values and defaults, and one line names them, without their
    values. Names compare as git reports them, and print as shown_name
    shows them. Runtime overrides apply later and are not compared.
    """
    archive, render = config_settings(imported), config_settings(rendered)
    lines, added = [], []
    for name in sorted(set(archive) | set(render)):
        have, want = archive.get(name, []), render.get(name, [])
        if have == want or not compared(name, have, want):
            continue
        if have or SIGN_IN_KEYS.fullmatch(name):
            lines.append(config_line(name, have, want))
        else:
            added.append(shown_name(name))
    if added:
        lines.append(
            "gerrit.config sets these keys in the chart's render and not in "
            f"the archive, from the chart's values and defaults: {', '.join(added)}"
        )
    return lines
