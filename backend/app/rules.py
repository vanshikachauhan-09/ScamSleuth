"""Text detection rules for ScamSleuth.

Every rule has:
  * `points`  - illustrative weight. These are tunable heuristics, NOT validated
                fraud probabilities.
  * `why`     - plain-language explanation shown to the user.
  * `patterns`- compiled regexes. The exact matched text is returned so the UI can
                highlight the phrase that triggered the warning.
  * `negatable` - if True, a match inside a warning sentence such as
                "Never share your OTP" is ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_F = re.IGNORECASE | re.UNICODE


def _c(*patterns: str) -> tuple:
    return tuple(re.compile(p, _F) for p in patterns)


AMOUNT = r"(?:₹|rs\.?|inr|rupees?)\s?\d[\d,]*(?:\.\d+)?|\d[\d,]*\s?(?:₹|rs\.?|inr|rupees?)"

_SECRETS = (
    r"(?:otp|one[- ]time\s+password|passwords?|passcode|pin|cvv|upi\s*pin|mpin|"
    r"card\s+(?:number|details)|bank\s+(?:account\s+)?details|login\s+(?:details|credentials)|"
    r"credentials|net\s*banking)"
)

_DOCS = (
    r"(?:aadhaar|aadhar|pan\s+card|pan\s+number|passport|marksheets?|bank\s+passbook|"
    r"passbook|cancell?ed\s+cheque|selfie|id\s+proof|photo\s+id|driving\s+licen[cs]e)"
)


@dataclass(frozen=True)
class TextRule:
    id: str
    title: str
    points: int
    why: str
    patterns: tuple
    negatable: bool = False


TEXT_RULES: tuple = (
    TextRule(
        id="upfront_payment",
        title="Upfront payment demand",
        points=25,
        why=(
            "Genuine employers, colleges and scholarship bodies rarely ask you to pay "
            "a fee just to be selected, confirmed or to receive a reward. Asking for "
            "money first is the most common pattern in fake internships and jobs."
        ),
        patterns=_c(
            r"\b(?:registration|processing|security|refundable|admission|application|verification|"
            r"training|kit|joining|onboarding|interview|confirmation|enrol+ment|certificate|courier|"
            r"laptop)\s+(?:fee|fees|charges?|deposit|amount|payment)\b",
            rf"(?:{AMOUNT})[^.\n]{{0,25}}\b(?:to\s+(?:confirm|secure|book|reserve|activate|unlock|release|"
            rf"get|receive)|as\s+(?:a\s+|an\s+|the\s+)?(?:\w+\s+){{0,2}}?(?:fee|fees|deposit|charges?))\b",
            r"\b(?:pay|send|deposit|transfer)\b[^.\n]{0,40}\bto\s+(?:confirm|secure|book|reserve|"
            r"activate|unlock|release)\s+(?:your|the)\b",
            r"रजिस्ट्रेशन\s*फ[ीि]स",
            r"फ[ीि]स\s*जमा",
        ),
    ),
    TextRule(
        id="credential_request",
        title="Request for OTP, password or banking details",
        points=30,
        why=(
            "No genuine bank, company or government office will ask you to share an OTP, "
            "password, PIN or CVV. Anyone who asks for these is trying to take over your "
            "account or move your money."
        ),
        patterns=_c(
            rf"\b(?:share|send|enter|provide|tell|submit|give|confirm|verify|update|reply\s+with|"
            rf"forward|type)\b[^.\n]{{0,40}}?\b{_SECRETS}\b",
            rf"\b{_SECRETS}\b[^.\n]{{0,20}}\b(?:required|needed|to\s+(?:verify|confirm|activate|proceed))\b",
            r"ओटीपी\s*(?:शेयर|बताएं|बताइए|भेजें|भेजिए)",
        ),
        negatable=True,
    ),
    TextRule(
        id="sensitive_docs",
        title="Request for identity documents",
        points=15,
        why=(
            "Fake recruiters collect Aadhaar, PAN, passport or selfies for identity theft or "
            "loan fraud. Real employers ask for documents only after a verified process, "
            "through an official portal."
        ),
        patterns=_c(
            rf"\b(?:send|share|upload|submit|provide|email|whatsapp|forward)\b[^.\n]{{0,40}}?\b{_DOCS}\b",
        ),
        negatable=True,
    ),
    TextRule(
        id="urgency",
        title="Artificial urgency or pressure",
        points=15,
        why=(
            "Scammers rush you so you act before checking. Real opportunities leave time "
            "for you to verify them."
        ),
        patterns=_c(
            r"\b(?:act|apply|register|pay|reply|respond|confirm|verify|claim)\s+(?:now|today|immediately|asap)\b",
            r"\b(?:limited\s+(?:seats?|slots?|vacanc(?:y|ies)|time|period)|last\s+(?:chance|date|day)|"
            r"hurry|urgent(?:ly)?|immediately|right\s+away|expires?\s+(?:today|soon|in)|"
            r"only\s+\d+\s+(?:seats?|slots?|left)|within\s+\d+\s*(?:hours?|hrs?|minutes?|mins?))\b",
            r"तुरंत",
            r"जल्दी\s*करें",
            r"आज\s*ही",
            r"सीमित\s*सीटें",
        ),
    ),
    TextRule(
        id="threat_pressure",
        title="Threats or fear-based language",
        points=15,
        why=(
            "Messages that threaten to block your account, expire your KYC or involve the "
            "police are designed to scare you into reacting without thinking."
        ),
        patterns=_c(
            r"\b(?:account|sim|number|card|wallet|upi|kyc)\b[^.\n]{0,25}\b(?:will\s+be\s+|has\s+been\s+|"
            r"is\s+|got\s+)?(?:blocked|suspended|closed|deactivated|terminated|frozen|expire[sd]?)\b",
            r"\b(?:legal\s+action|arrest(?:ed)?|police\s+(?:case|complaint)|fir|court\s+notice|"
            r"case\s+(?:will\s+be\s+)?filed)\b",
            r"\bkyc\b[^.\n]{0,30}\b(?:pending|expired?|update|incomplete|mandatory)\b",
        ),
    ),
    TextRule(
        id="too_good",
        title="Too-good-to-be-true promise",
        points=10,
        why=(
            "Prizes you never entered for, jobs with no interview, or huge pay for easy work "
            "are classic bait. Note that genuine offers can also say 'selected', so check "
            "whether you actually applied."
        ),
        patterns=_c(
            r"\b(?:lottery|jackpot|lucky\s+draw|prize\s+money)\b",
            r"\bno\s+(?:interview|experience|qualification|skills?)\s+(?:is\s+)?(?:required|needed|necessary)\b",
            r"\b(?:guaranteed|100%\s+(?:guaranteed\s+)?)(?:job|placement|selection|returns?|profit)\b",
            rf"\bearn\b[^.\n]{{0,20}}(?:{AMOUNT})[^.\n]{{0,10}}\b(?:per|a|/)\s*(?:day|hour|week|task)\b",
            r"\bwork\s+from\s+home\b[^.\n]{0,40}\b(?:earn|income|salary)\b",
            r"\bselected\b[^.\n]{0,40}\bwithout\b[^.\n]{0,15}\b(?:interview|applying)\b",
            r"\bcongratulations\b[^.\n]{0,60}\b(?:selected|shortlisted|won|chosen)\b",
        ),
    ),
    TextRule(
        id="off_platform",
        title="Pushes you to WhatsApp or Telegram",
        points=10,
        why=(
            "Scammers move conversations to private chat apps where there is no company "
            "record and they are harder to report. Official hiring uses official email or portals."
        ),
        patterns=_c(
            r"\b(?:contact|message|text|chat|dm|join|add|reach|connect)\b[^.\n]{0,30}\b(?:whatsapp|telegram|signal)\b",
            r"\b(?:whatsapp|telegram)\s+(?:us|me|now|number|no\.?)\b",
            r"\b(?:on|via|through|at)\s+(?:whatsapp|telegram)\b",
            r"\bwa\.me/\S+",
            r"\bt\.me/\S+",
            r"\bchat\.whatsapp\.com/\S+",
        ),
    ),
    TextRule(
        id="secrecy",
        title="Asks you to keep it secret",
        points=10,
        why=(
            "Scammers ask for secrecy so nobody can warn you. A real opportunity is fine "
            "to discuss with family, friends or a teacher."
        ),
        patterns=_c(
            # "share this/it ... anyone" is deliberately excluded: it is the standard wording of
            # genuine bank warnings ("Never share this OTP with anyone").
            r"\b(?:do\s+not|don'?t|dont|never)\s+(?:tell|inform)\b[^.\n]{0,20}"
            r"\b(?:anyone|anybody|family|parents|friends|others)\b",
            r"\bkeep\s+(?:this|it)\b[^.\n]{0,10}\b(?:secret|confidential|private)\b",
            r"\bconfidential\s+offer\b",
        ),
    ),
)

# Weights for findings produced by the URL / sender logic in engine.py.
URL_POINTS = {
    "lookalike_domain": 25,
    "suspicious_url": 20,
    "unverified_claim": 10,
    "insecure_http": 5,
}
