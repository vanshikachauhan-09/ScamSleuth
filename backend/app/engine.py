"""ScamSleuth detection engine.

Combines text rules, offline URL checks and an organisation-claim check into an
explainable, capped *heuristic* risk score. It is deliberately not a probability
of fraud: the weights are illustrative and unvalidated.
"""

from __future__ import annotations

import re

from .brands import BRANDS, EXTRA_CLAIMS
from .rules import TEXT_RULES, URL_POINTS
from .url_analysis import STRUCTURE_CODES, analyze_url, find_urls

MAX_URLS = 10
MAX_EVIDENCE = 5

DISCLAIMER = (
    "ScamSleuth highlights warning signs using simple, transparent rules. A low score does not "
    "prove a message is safe, and a high score does not prove it is a scam. The score is a "
    "heuristic risk indicator, not a probability."
)

VERIFICATION_CHECKLIST = [
    "Find the organisation's official website yourself (search for it, don't use the link you were sent).",
    "Look for the same offer on the official careers or notices page.",
    "Contact the organisation using a phone number or email from its official site.",
    "Check the sender's email domain or phone number against the official one.",
    "Ask someone you trust (friend, teacher, family) before paying or sharing any details.",
]

NEXT_STEPS = {
    "upfront_payment": "Do not pay anything until you have confirmed the opportunity through the organisation's official website or contact details.",
    "credential_request": "Never share an OTP, password, PIN or CVV with anyone. No genuine company or bank will ask for them.",
    "sensitive_docs": "Hold back identity documents (Aadhaar, PAN, passport, selfies) until you have verified the sender. Share them only through an official portal.",
    "urgency": "Pause. Real opportunities do not disappear in minutes, so take the time to verify.",
    "threat_pressure": "If it mentions your bank, SIM or KYC, contact them using the number on your card or their official website, not the one in the message.",
    "too_good": "Ask yourself whether you actually applied or entered. If not, be very sceptical of the 'selection' or 'prize'.",
    "off_platform": "Be wary of moving the conversation to WhatsApp or Telegram. Ask for communication through official email or the company portal.",
    "secrecy": "Talk to someone you trust. Scammers ask for secrecy so nobody can warn you.",
    "lookalike_domain": "Do not open this link. The domain imitates a known organisation. Type the official address yourself.",
    "suspicious_url": "Do not open the link until you have verified where it leads. Do not enter any information on it.",
    "insecure_http": "Avoid entering personal details on pages that do not use HTTPS.",
    "unverified_claim": "The message claims to come from a known organisation but links nowhere official. Check the organisation's real website independently.",
}

_STEP_ORDER = [
    "credential_request", "upfront_payment", "lookalike_domain", "suspicious_url",
    "sensitive_docs", "threat_pressure", "urgency", "off_platform", "secrecy",
    "too_good", "unverified_claim", "insecure_http",
]

REPORT_GUIDANCE = {
    "title": "If you have already paid or shared details (India)",
    "items": [
        "Call the national cybercrime helpline 1930 as soon as possible if money has been lost.",
        "File a complaint on the National Cybercrime Reporting Portal: cybercrime.gov.in.",
        "Contact your bank or payment app immediately to try to block or flag the transaction.",
        "Keep screenshots, links, phone numbers and payment receipts as evidence.",
    ],
    "note": "Check the official sites for the latest contact details.",
}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
_NEGATION = re.compile(
    r"\b(?:do\s+not|don'?t|dont|never|should\s+not|shouldn'?t|won'?t|will\s+not|not)\b", re.I
)


def _is_negated(text: str, start: int) -> bool:
    """True if the match sits in a warning sentence like 'Never share your OTP'."""
    prefix = text[:start]
    sentence_start = max(prefix.rfind(c) for c in ".!?\n") + 1
    return bool(_NEGATION.search(prefix[sentence_start:]))


def _utf16_index(text: str, idx: int) -> int:
    """JavaScript strings are UTF-16, so convert Python code-point offsets."""
    return len(text[:idx].encode("utf-16-le")) // 2


def _snippet(text: str, start: int, end: int) -> str:
    s = " ".join(text[start:end].split())
    return s if len(s) <= 100 else s[:97] + "..."


def _merge_spans(spans: list) -> list:
    """spans: [(start, end, rule_id)] -> merged, non-overlapping [(start, end, {ids})]."""
    merged: list = []
    for start, end, rid in sorted(spans):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
            merged[-1][2].add(rid)
        else:
            merged.append([start, end, {rid}])
    return merged


def risk_level(score: int) -> tuple:
    if score >= 75:
        return "critical", "Critical risk"
    if score >= 45:
        return "high", "High risk"
    if score >= 20:
        return "moderate", "Moderate risk"
    return "low", "Low risk"


SUMMARIES = {
    "low": "We did not find strong warning signs. That does not prove it is safe, so still verify if money, documents or logins are involved.",
    "moderate": "Some warning signs were found. Verify through an official channel before you act.",
    "high": "Several warning signs match common scam patterns. Do not pay, click or share details until you have verified it independently.",
    "critical": "This matches many common scam patterns. Treat it as dangerous until you can verify it through an official channel.",
}


# --------------------------------------------------------------------------
# main entry point
# --------------------------------------------------------------------------
def analyze(text: str = "", url: str = "") -> dict:
    text = text or ""
    url = (url or "").strip()

    findings: list = []
    spans: list = []          # (start, end, rule_id) in Python code points
    titles: dict = {}

    # ---- 1. text rules ---------------------------------------------------
    for rule in TEXT_RULES:
        hits: list = []
        for pattern in rule.patterns:
            for m in pattern.finditer(text):
                if rule.negatable and _is_negated(text, m.start()):
                    continue
                hits.append((m.start(), m.end()))
        if not hits:
            continue
        titles[rule.id] = rule.title
        for s, e in hits:
            spans.append((s, e, rule.id))
        evidence = []
        for s, e, _ in _merge_spans([(s, e, rule.id) for s, e in hits])[:MAX_EVIDENCE]:
            evidence.append(_snippet(text, s, e))
        findings.append({
            "id": rule.id, "title": rule.title, "points": rule.points,
            "category": "content", "evidence_type": "found_in_text",
            "why": rule.why, "evidence": evidence,
        })

    # ---- 2. URLs (from the text and the separate URL field) --------------
    candidates: list = list(find_urls(text))
    seen = {c[0].lower() for c in candidates}
    if url and url.lower() not in seen:
        candidates.append((url, None, None))

    url_reports: list = []
    for raw, start, end in candidates[:MAX_URLS]:
        report = analyze_url(raw)
        report["in_text"] = start is not None
        url_reports.append((report, start, end))

    notes: list = []
    invalid = [r["url"] for r, _, _ in url_reports if not r["valid"]]
    if invalid:
        notes.append("Some links could not be parsed: " + ", ".join(invalid[:3]))
    if len(candidates) > MAX_URLS:
        notes.append(f"Only the first {MAX_URLS} links were analysed.")

    def collect(codes: set, structure: bool = False) -> tuple:
        evidence, hit_spans = [], []
        for report, start, end in url_reports:
            if not report["valid"]:
                continue
            matching = [f for f in report["flags"] if (f["code"] in STRUCTURE_CODES if structure else f["code"] in codes)]
            if not matching:
                continue
            evidence.append(f"{report['url']}: " + " ".join(f["detail"] for f in matching[:2]))
            if start is not None:
                hit_spans.append((start, end))
        return evidence, hit_spans

    for fid, title, why, codes, structure in (
        ("lookalike_domain", "Link imitates a known organisation",
         "The domain contains or imitates the name of a real organisation but is not one of its "
         "known domains. Fake sites use this to look trustworthy.", {"brand_lookalike"}, False),
        ("suspicious_url", "Suspicious link structure",
         "The link has structural features common in scam links, such as raw IP addresses, "
         "shorteners, look-alike characters or frequently abused domain endings. We did not "
         "open the link; this is based on its text only.", set(), True),
        ("insecure_http", "Link is not encrypted (HTTP)",
         "Pages served over plain HTTP can be read or altered in transit. Legitimate sign-in and "
         "payment pages use HTTPS.", {"http"}, False),
    ):
        evidence, hit_spans = collect(codes, structure)
        if not evidence:
            continue
        titles[fid] = title
        for s, e in hit_spans:
            spans.append((s, e, fid))
        findings.append({
            "id": fid, "title": title, "points": URL_POINTS[fid],
            "category": "url", "evidence_type": "found_in_link",
            "why": why, "evidence": evidence[:MAX_EVIDENCE],
        })

    # ---- 3. unverified organisation claim (an assumption, not proof) -----
    other_points = sum(f["points"] for f in findings)
    if text.strip() and other_points > 0:
        linked_domains = {r["registrable_domain"] for r, _, _ in url_reports if r["valid"]}
        unverified: list = []
        for info in BRANDS.values():
            pattern = r"\b(?:" + "|".join(re.escape(a) for a in info["aliases"]) + r")\b"
            if re.search(pattern, text, re.I) and not (linked_domains & info["domains"]):
                unverified.append(info["display"])
        for name, domains in EXTRA_CLAIMS.items():
            if re.search(re.escape(name), text, re.I) and not (linked_domains & domains):
                unverified.append(name)
        if unverified:
            titles["unverified_claim"] = "Unverified sender or company claim"
            findings.append({
                "id": "unverified_claim", "title": "Unverified sender or company claim",
                "points": URL_POINTS["unverified_claim"], "category": "sender",
                "evidence_type": "needs_verification",
                "why": (
                    "The message names a well-known organisation but contains no link to one of "
                    "its official domains. We cannot verify who really sent it. Treat this as "
                    "something to check, not as proof."
                ),
                "evidence": [f"Mentions {n} without linking to an official {n} site." for n in unverified[:MAX_EVIDENCE]],
            })

    # ---- 4. score --------------------------------------------------------
    findings.sort(key=lambda f: -f["points"])
    raw_total = sum(f["points"] for f in findings)
    score = min(100, raw_total)
    level, level_label = risk_level(score)

    # ---- 5. highlights (UTF-16 offsets for the browser) ------------------
    highlights = []
    for start, end, ids in _merge_spans(spans):
        ordered = sorted(ids, key=lambda i: -next(f["points"] for f in findings if f["id"] == i))
        highlights.append({
            "start": _utf16_index(text, start),
            "end": _utf16_index(text, end),
            "text": text[start:end],
            "rule_ids": ordered,
            "labels": [titles[i] for i in ordered],
        })

    # ---- 6. advice -------------------------------------------------------
    fired = {f["id"] for f in findings}
    next_steps = [NEXT_STEPS[i] for i in _STEP_ORDER if i in fired]
    if not next_steps:
        next_steps = ["No known warning signs were found, but verify independently before paying or sharing personal details."]

    show_report = level in ("high", "critical") or bool(fired & {"upfront_payment", "credential_request"})

    return {
        "score": score,
        "raw_points": raw_total,
        "score_note": "Heuristic risk score built from illustrative weights and capped at 100. It is not a probability of fraud.",
        "level": level,
        "level_label": level_label,
        "summary": SUMMARIES[level],
        "findings": findings,
        "highlights": highlights,
        "urls": [r for r, _, _ in url_reports],
        "next_steps": next_steps,
        "verification_checklist": VERIFICATION_CHECKLIST,
        "report_guidance": REPORT_GUIDANCE if show_report else None,
        "notes": notes,
        "disclaimer": DISCLAIMER,
    }
