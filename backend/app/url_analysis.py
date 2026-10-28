"""Safe, offline URL checks.

IMPORTANT: nothing in this module ever opens, fetches or resolves a URL. We only
parse the text of the link, so analysing a malicious link cannot harm the server
(no SSRF) and no link is "visited" on the user's behalf.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .brands import BRANDS

# Two-label public suffixes, so "careers.example.co.in" -> "example.co.in".
SECOND_LEVEL = {
    "co.in", "org.in", "net.in", "gov.in", "nic.in", "ac.in", "edu.in", "res.in",
    "firm.in", "gen.in", "ind.in", "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au",
    "net.au", "org.au", "co.nz", "co.za", "com.np", "com.pk", "com.bd", "com.sg",
    "com.br", "co.jp",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly",
    "shorturl.at", "tiny.cc", "rebrand.ly", "buff.ly", "bl.ink", "s.id", "v.gd",
}

# TLDs that are cheap and heavily abused. This is a risk signal, not proof.
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "live", "site", "online", "icu", "buzz", "rest", "cfd",
    "sbs", "work", "support", "link", "monster", "vip", "loan", "zip", "mov", "gq",
    "cf", "tk", "ml", "ga",
}

FREE_HOSTING = {
    "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com", "github.io",
    "netlify.app", "vercel.app", "pages.dev", "web.app", "firebaseapp.com",
    "glitch.me", "herokuapp.com", "godaddysites.com",
}

STRUCTURE_CODES = {
    "ip_host", "userinfo", "punycode", "shortener", "suspicious_tld",
    "free_hosting", "many_subdomains", "spoofed_spelling",
}

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _normalize(token: str) -> str:
    return token.lower().translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registrable_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return last_two


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Decimal (http://3232235777) and hex (http://0xC0A80001) forms.
    return host.isdigit() or bool(re.fullmatch(r"0x[0-9a-f]+", host))


def _brand_issues(host: str, reg: str) -> list:
    labels = host.split(".")
    tokens = set()
    for label in labels[:-1] or labels:
        for tok in label.split("-"):
            if tok:
                tokens.add(tok)

    issues = []  # (kind, detail)
    for key, info in BRANDS.items():
        if reg in info["domains"]:
            continue
        display = info["display"]
        for tok in sorted(tokens):
            norm = _normalize(tok)
            if tok == key:
                issues.append(("exact", f"'{display}' appears in the domain, but {reg} is not a known {display} domain."))
                break
            if norm == key:
                issues.append(("homoglyph", f"'{tok}' imitates '{display}' using look-alike characters."))
                break
            if len(key) >= 5 and _levenshtein(norm, key) == 1:
                issues.append(("typo", f"'{tok}' is one character away from '{display}'."))
                break
            if len(key) >= 5 and key in norm:
                issues.append(("embedded", f"'{display}' is embedded in '{tok}', but {reg} is not a known {display} domain."))
                break
    return issues


def analyze_url(raw: str) -> dict:
    """Return structural red flags for one URL. Pure string analysis, no network."""
    raw = raw.strip()
    scheme_given = bool(re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I))
    try:
        parts = urlsplit(raw if scheme_given else "//" + raw)
        host = (parts.hostname or "").lower()
        try:
            port = parts.port
        except ValueError:
            port = None
    except ValueError:
        return {"url": raw, "valid": False, "flags": []}

    if not host:
        return {"url": raw, "valid": False, "flags": []}

    scheme = parts.scheme.lower() if scheme_given else None
    reg = host if _is_ip(host) else registrable_domain(host)
    flags: list = []

    def add(code: str, severity: str, detail: str) -> None:
        flags.append({"code": code, "severity": severity, "detail": detail})

    if scheme == "http":
        add("http", "medium", "Uses HTTP, so the connection is not encrypted.")

    if _is_ip(host):
        add("ip_host", "high", "Uses a raw IP address instead of a domain name. Legitimate organisations almost never do this.")

    if "@" in parts.netloc:
        add("userinfo", "high",
            "Contains an '@' before the host. Browsers ignore everything before it, so the "
            "real destination is different from what it appears to be.")

    if "xn--" in host or any(ord(ch) > 127 for ch in host):
        add("punycode", "high", "Uses non-standard characters that can imitate a trusted site (an IDN homograph trick).")

    if reg in SHORTENERS:
        add("shortener", "medium", "A link shortener hides the real destination until you click.")

    tld = host.rsplit(".", 1)[-1]
    if not _is_ip(host) and tld in SUSPICIOUS_TLDS:
        add("suspicious_tld", "medium", f".{tld} domains are cheap and frequently used in scams. This is a risk signal, not proof.")

    if any(host == d or host.endswith("." + d) for d in FREE_HOSTING):
        add("free_hosting", "medium", "Hosted on a free site-builder, where anyone can publish a page that looks official.")

    if not _is_ip(host) and len(host.split(".")) > 4:
        add("many_subdomains", "medium", "Has an unusually long chain of subdomains, often used to bury the real domain.")

    if host.count("-") >= 2:
        add("many_hyphens", "low", "Contains several hyphens, common in made-up look-alike domains.")

    if port not in (None, 80, 443):
        add("odd_port", "low", f"Uses an unusual port ({port}).")

    if not _is_ip(host):
        spoofed = False
        for kind, detail in _brand_issues(host, reg):
            add("brand_lookalike", "high", detail)
            spoofed = spoofed or kind in ("homoglyph", "typo")
        if spoofed:
            # Swapped characters or typos are a deliberate spoofing trick, not just a brand mention.
            add("spoofed_spelling", "high",
                "The domain spells a trusted name with swapped or altered characters, a deliberate spoofing trick.")

    return {
        "url": raw,
        "valid": True,
        "host": host,
        "registrable_domain": reg,
        "scheme": scheme,
        "flags": flags,
    }


# --------------------------------------------------------------------------
# Finding URLs inside free text
# --------------------------------------------------------------------------
_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'`]+", re.I)

_BARE_TLDS = sorted(
    SUSPICIOUS_TLDS | {"com", "in", "org", "net", "co", "io", "app", "info", "me", "ly", "gl", "gle"},
    key=len, reverse=True,
)
_BARE_RE = re.compile(
    r"(?<![@\w./-])(?:[a-z0-9-]+\.)+(?:" + "|".join(_BARE_TLDS) + r")(?:/[^\s<>\"'`]*)?(?![\w@-])",
    re.I,
)

_TRAILING = ".,;:!?)]}>'\""


def find_urls(text: str) -> list:
    """Return [(url, start, end)] for URLs and bare domains in `text`."""
    found: list = []

    def overlaps(s: int, e: int) -> bool:
        return any(s < fe and e > fs for _, fs, fe in found)

    for regex in (_URL_RE, _BARE_RE):
        for m in regex.finditer(text):
            start, end = m.start(), m.end()
            while end > start and text[end - 1] in _TRAILING:
                end -= 1
            if end > start and not overlaps(start, end):
                found.append((text[start:end], start, end))
    return sorted(found, key=lambda t: t[1])
