import re
from pathlib import Path


# ==========================================
# EMAIL CLASS
# ==========================================

class Email:
    def __init__(self):
        self.sender = ""
        self.subject = ""
        self.body = ""
        self.urls = []

    def set_sender(self, sender):
        self.sender = sender

    def set_subject(self, subject):
        self.subject = subject

    def append_body(self, line):
        self.body += line + "\n"

    def add_url(self, url):
        self.urls.append(url)


# ==========================================
# REPORT CLASS
# ==========================================

class Report:
    def __init__(self):
        self.score = 100

        # Sender analysis
        self.business_email = False
        self.free_provider = False
        self.brand_impersonation = False

        # URL analysis
        self.has_http = False
        self.has_https = False
        self.has_ip = False
        self.short_url = False
        self.suspicious_tld = False

        # Content analysis
        self.urgency = False
        self.prize = False
        self.credential = False
        self.promotion = False
        self.threat = False
        self.financial_request = False
        self.secrecy = False

        self.reasons = []

    def deduct_score(self, marks):
        self.score = max(0, self.score - marks)


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def to_lower(text):
    return text.lower()


def contains(text, key):
    return key.lower() in text.lower()


def load_data(filename):
    """Load non-empty lines from a text file."""
    try:
        with open(filename, "r", encoding="utf-8") as file:
            return [
                line.strip().lower()
                for line in file
                if line.strip()
            ]
    except FileNotFoundError:
        print(f"Warning: {filename} not found.")
        return []


def load_keywords(filename):
    return load_data(filename)


def get_domain(sender):
    if "@" in sender:
        return sender.rsplit("@", 1)[1].strip().lower()

    return ""


# ==========================================
# EXTRACT EMAIL INFORMATION
# ==========================================

def extract_urls(mail):
    # Find URLs beginning with HTTP or HTTPS.
    url_pattern = r"""https?://[^\s"'<>]+"""

    # Find URLs inside HTML anchor tags.
    href_pattern = r"""<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']"""

    urls = set()

    for url in re.findall(url_pattern, mail.body, re.IGNORECASE):
        urls.add(url.rstrip(".,;!?)"))

    for url in re.findall(href_pattern, mail.body, re.IGNORECASE):
        urls.add(url)

    mail.urls = sorted(urls)


# ==========================================
# SENDER ANALYSIS
# ==========================================

def analyze_sender(mail, report):
    sender = mail.sender.strip().lower()
    domain = get_domain(sender)

    business_domains = load_data("business_domains.txt")
    free_providers = load_data("free_email.txt")
    brands = load_data("brand_names.txt")

    if domain in business_domains:
        report.business_email = True

    if domain in free_providers:
        report.free_provider = True

    for brand in brands:
        if brand in sender and not report.business_email:
            report.brand_impersonation = True
            report.deduct_score(25)
            report.reasons.append("Possible brand impersonation.")
            break


# ==========================================
# URL ANALYSIS
# ==========================================

def analyze_urls(mail, report):
    shorteners = load_data("shortener.txt")
    bad_tlds = load_data("suspicious_tld.txt")

    ip_pattern = re.compile(
        r"^https?://(\d{1,3}\.){3}\d{1,3}([/:]|$)",
        re.IGNORECASE
    )

    # Avoid deducting points repeatedly for the same category.
    http_penalty = False
    ip_penalty = False
    short_penalty = False
    tld_penalty = False

    for url in mail.urls:
        lower_url = url.lower()

        # HTTP
        if lower_url.startswith("http://"):
            report.has_http = True

            if not http_penalty:
                report.deduct_score(7)
                report.reasons.append(
                    "Uses HTTP instead of HTTPS."
                )
                http_penalty = True

        # HTTPS
        if lower_url.startswith("https://"):
            report.has_https = True

        # IP address instead of a domain name
        if ip_pattern.search(lower_url):
            report.has_ip = True

            if not ip_penalty:
                report.deduct_score(20)
                report.reasons.append(
                    "Uses an IP address instead of a domain name."
                )
                ip_penalty = True

        # URL shorteners
        for site in shorteners:
            if site in lower_url:
                report.short_url = True

                if not short_penalty:
                    report.deduct_score(8)
                    report.reasons.append(
                        "Uses a URL shortening service."
                    )
                    short_penalty = True

                break

        # Suspicious top-level domains
        for tld in bad_tlds:
            if tld in lower_url:
                report.suspicious_tld = True

                if not tld_penalty:
                    report.deduct_score(10)
                    report.reasons.append(
                        "Uses a suspicious top-level domain."
                    )
                    tld_penalty = True

                break

    if len(mail.urls) > 3:
        report.deduct_score(5)
        report.reasons.append(
            "Email contains an unusually large number of links."
        )


# ==========================================
# CONTENT ANALYSIS
# ==========================================

def analyze_content(mail, report):
    text = to_lower(mail.subject + " " + mail.body)

    urgency_words = load_keywords("urgency.txt")
    prize_words = load_keywords("prize.txt")
    credential_words = load_keywords("credential.txt")
    promotion_words = load_keywords("promotion.txt")

    # URGENCY
    for word in urgency_words:
        if contains(text, word):
            report.urgency = True
            report.deduct_score(10)
            report.reasons.append(
                "Urgency language detected."
            )
            break

    # PRIZE OR REWARD
    for word in prize_words:
        if contains(text, word):
            report.prize = True
            report.deduct_score(10)
            report.reasons.append(
                "Prize or reward language detected."
            )
            break

    # CREDENTIAL REQUEST
    for word in credential_words:
        if contains(text, word):
            report.credential = True
            report.deduct_score(20)
            report.reasons.append(
                "Request for credentials or authentication "
                "information detected."
            )
            break

    # PROMOTION
    for word in promotion_words:
        if contains(text, word):
            report.promotion = True
            # Promotion alone is not suspicious.
            break

    # THREATS
    threats = [
        "account suspended",
        "account blocked",
        "account terminated",
        "legal action",
        "permanently suspended",
        "failure to respond",
        "will be suspended",
        "will be blocked",
        "will be terminated",
        "police",
        "lawsuit"
    ]

    for word in threats:
        if contains(text, word):
            report.threat = True
            report.deduct_score(12)
            report.reasons.append(
                "Threatening or fear-based language detected."
            )
            break

    # FINANCIAL REQUESTS
    financial_words = [
        "bank account",
        "bank details",
        "credit card",
        "debit card",
        "card number",
        "account number",
        "payment details",
        "transfer money",
        "make payment",
        "financial information"
    ]

    for word in financial_words:
        if contains(text, word):
            report.financial_request = True
            report.deduct_score(15)
            report.reasons.append(
                "Request for financial information or payment detected."
            )
            break

    # SECRECY OR CONFIDENTIALITY
    secrecy_words = [
        "do not share",
        "don't share",
        "keep this secret",
        "keep this confidential",
        "do not tell anyone",
        "don't tell anyone"
    ]

    for word in secrecy_words:
        if contains(text, word):
            report.secrecy = True
            report.deduct_score(3)
            report.reasons.append(
                "Secrecy or confidentiality language detected."
            )
            break


# ==========================================
# RISK LEVEL
# ==========================================

def get_risk_level(score):
    if score >= 90:
        return "VERY SAFE"
    elif score >= 70:
        return "PROBABLY SAFE"
    elif score >= 50:
        return "SUSPICIOUS"
    elif score >= 30:
        return "HIGH RISK"
    else:
        return "LIKELY PHISHING"


def print_status(title, status):
    print(f"{title:<25}{'YES' if status else 'NO'}")


# ==========================================
# PRINT REPORT
# ==========================================

def print_report(mail, report):
    print("\n=========================================")
    print("           MAILGUARD REPORT")
    print("=========================================")

    print(f"\nSender  : {mail.sender}")
    print(f"Subject : {mail.subject}")

    print("\n----------- Sender Analysis -----------")
    print_status("Business Domain", report.business_email)
    print_status("Free Email", report.free_provider)
    print_status("Brand Impersonation", report.brand_impersonation)

    print("\n----------- URL Analysis -----------")
    print(f"URLs Found : {len(mail.urls)}")

    for url in mail.urls:
        print(f"- {url}")

    print()
    print_status("HTTP Used", report.has_http)
    print_status("HTTPS Used", report.has_https)
    print_status("IP Address URL", report.has_ip)
    print_status("Shortened URL", report.short_url)
    print_status("Suspicious TLD", report.suspicious_tld)

    print("\n----------- Content Analysis -----------")
    print_status("Urgency", report.urgency)
    print_status("Prize / Reward", report.prize)
    print_status("Credential Request", report.credential)
    print_status("Promotion", report.promotion)
    print_status("Threat", report.threat)
    print_status("Financial Request", report.financial_request)
    print_status("Secrecy", report.secrecy)

    print("\n=========================================")
    print(f"Trust Score : {report.score}/100")
    print(f"Risk Level  : {get_risk_level(report.score)}")

    print("\nReasons")

    if not report.reasons:
        print("No suspicious indicators detected.")
    else:
        for reason in report.reasons:
            print(f"- {reason}")

    print("\nRecommendation")

    if report.score >= 90:
        print("Looks safe.")
    elif report.score >= 70:
        print("Probably safe, but verify before clicking links.")
    elif report.score >= 50:
        print("Exercise caution before interacting.")
    else:
        print("Do NOT click links or download attachments.")
        print("Verify the sender through an official website.")

    print("\n=========================================")


# ==========================================
# MAIN PROGRAM
# ==========================================

def main():
    print("=========================================")
    print("              MAILGUARD")
    print("      Email Phishing Detection System")
    print("=========================================\n")

    print("Welcome to MailGuard!\n")
    print("MailGuard analyzes:")
    print("* Sender Information")
    print("* URLs and Links")
    print("* Email Content")
    print("* Phishing Keywords")
    print("* Trust Score and Risk Level")

    print("\n=========================================")
    print("Press 1 to Analyze an Email: ", end="")

    try:
        choice = input().strip()
    except EOFError:
        return

    if choice != "1":
        print("\nInvalid Choice!")
        return

    mail = Email()
    report = Report()

    print("\nPaste the complete email below.")
    print("Type END on a new line when finished.\n")

    while True:
        try:
            line = input()
        except EOFError:
            break

        if line == "END":
            break

        if line.startswith("From:"):
            mail.set_sender(line[5:].strip())

        elif line.startswith("Subject:"):
            mail.set_subject(line[8:].strip())

        else:
            mail.append_body(line)

    extract_urls(mail)
    analyze_sender(mail, report)
    analyze_urls(mail, report)
    analyze_content(mail, report)

    print_report(mail, report)


if __name__ == "__main__":
    main()
    