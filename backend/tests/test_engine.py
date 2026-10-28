import pytest
from fastapi.testclient import TestClient

from app.engine import analyze
from app.main import app
from app.samples import SAMPLES
from app.url_analysis import analyze_url, find_urls, registrable_domain

client = TestClient(app)


def ids(result):
    return {f["id"] for f in result["findings"]}


# ---------------------------------------------------------------- text rules
def test_fake_internship_example_from_the_brief():
    r = analyze(
        "Congratulations! You have been selected for a Google internship. Pay ₹499 as a "
        "registration fee today to confirm your position. Limited seats available. "
        "Click here to register: http://google-careers-register.xyz/apply"
    )
    assert {"upfront_payment", "urgency", "suspicious_url"} <= ids(r)
    assert r["level"] in ("high", "critical")
    assert 0 <= r["score"] <= 100


def test_otp_and_kyc_scam():
    r = analyze("Your KYC is pending and your account will be blocked. Share the OTP immediately to verify.")
    assert {"credential_request", "threat_pressure", "urgency"} <= ids(r)


def test_warning_sentence_is_not_flagged_as_credential_request():
    r = analyze("Your OTP is 482913. Never share this OTP with anyone, including bank staff.")
    assert "credential_request" not in ids(r)
    # Regression: the standard bank warning must not trip the secrecy rule either.
    assert r["findings"] == []
    assert r["score"] == 0


def test_negation_does_not_leak_across_sentences():
    r = analyze("Don't ignore this message. Please share your OTP to verify.")
    assert "credential_request" in ids(r)


def test_hindi_phrases():
    r = analyze("तुरंत रजिस्ट्रेशन फीस जमा करें")
    assert {"urgency", "upfront_payment"} <= ids(r)


def test_secrecy_and_off_platform_and_documents():
    r = analyze("Message us on WhatsApp. Send your Aadhaar and selfie. Do not tell anyone about this.")
    assert {"off_platform", "sensitive_docs", "secrecy"} <= ids(r)


def test_plain_text_is_low_risk():
    r = analyze("The mid-semester timetable has been published on the student portal.")
    assert r["score"] == 0 and r["level"] == "low"
    assert r["findings"] == []


# ------------------------------------------------------------------- scoring
def test_score_is_capped_at_100():
    r = analyze(
        "Congratulations you have been selected! Pay registration fee today. Share your OTP now, "
        "account will be blocked, legal action. WhatsApp us. Send Aadhaar. Do not tell anyone. "
        "Visit http://192.168.1.1/pay and http://g00gle-login.xyz",
    )
    assert r["raw_points"] > 100
    assert r["score"] == 100
    assert r["level"] == "critical"


def test_each_warning_sign_counts_once():
    once = analyze("Pay the registration fee.")
    twice = analyze("Pay the registration fee. Also a joining fee and a processing fee.")
    assert once["score"] == twice["score"]


# ----------------------------------------------------------------------- URLs
def codes(url):
    return {f["code"] for f in analyze_url(url)["flags"]}


def test_ip_address_url():
    assert "ip_host" in codes("http://192.168.4.7/login")


def test_decimal_ip_url():
    assert "ip_host" in codes("http://3232235777/login")


def test_userinfo_trick():
    assert "userinfo" in codes("https://google.com@evil.xyz/login")


def test_punycode():
    assert "punycode" in codes("https://xn--pypal-4ve.com")


def test_shortener_matches_domain_not_substring():
    assert "shortener" in codes("https://bit.ly/abc")
    # Regression: "t.co" must not match inside microsoft.com
    assert "shortener" not in codes("https://www.microsoft.com/billing")


def test_homoglyph_lookalike():
    assert "brand_lookalike" in codes("https://paypa1-secure-login.com/verify")
    assert "brand_lookalike" in codes("https://g00gle.com")


def test_typosquat_one_character_away():
    assert "brand_lookalike" in codes("https://gogle.com")


def test_spoofed_spelling_counts_as_structural_flag():
    assert "spoofed_spelling" in codes("https://paypa1-secure-login.com/verify")
    # A brand merely embedded in an unrelated domain is a lookalike, but not a spelling trick.
    assert "spoofed_spelling" not in codes("https://google-careers.com")
    r = analyze("", "https://paypa1-secure-login.com/verify")
    assert {"lookalike_domain", "suspicious_url"} <= ids(r)
    assert r["level"] == "high"


def test_brand_in_subdomain_of_other_domain():
    assert "brand_lookalike" in codes("https://google.com.account-check.xyz")


def test_official_domains_are_not_flagged():
    for u in ("https://careers.google.com/jobs", "https://www.amazon.in", "https://aws.amazonaws.com",
              "https://www.hdfcbank.com"):
        assert "brand_lookalike" not in codes(u), u


def test_no_scheme_is_not_flagged_as_http():
    assert "http" not in codes("example.com/page")
    assert "http" in codes("http://example.com/page")


def test_registrable_domain():
    assert registrable_domain("careers.example.co.in") == "example.co.in"
    assert registrable_domain("a.b.example.com") == "example.com"


def test_find_urls_and_trailing_punctuation():
    found = find_urls("See https://example.com/x, or bit.ly/abc. Mail a@b.com too.")
    urls = [u for u, _, _ in found]
    assert "https://example.com/x" in urls
    assert "bit.ly/abc" in urls
    assert not any("a@b.com" in u for u in urls)


def test_urls_are_never_fetched(monkeypatch):
    import socket

    def boom(*a, **k):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)
    analyze("Visit http://evil-paypa1.xyz/login", "http://192.168.0.1/admin")


# ------------------------------------------------------------- explainability
def test_highlights_use_utf16_offsets():
    text = "😀😀 Pay the registration fee now."
    r = analyze(text)
    assert r["highlights"]
    utf16 = text.encode("utf-16-le")
    for h in r["highlights"]:
        assert utf16[h["start"] * 2 : h["end"] * 2].decode("utf-16-le") == h["text"]


def test_highlights_do_not_overlap():
    r = analyze(SAMPLES[0]["text"])
    last = 0
    for h in r["highlights"]:
        assert h["start"] >= last
        last = h["end"]


def test_unverified_claim_is_marked_as_needs_verification():
    r = analyze("Selected for a Google internship. Pay registration fee today.")
    claim = next(f for f in r["findings"] if f["id"] == "unverified_claim")
    assert claim["evidence_type"] == "needs_verification"


def test_unverified_claim_not_raised_for_plain_mention():
    assert "unverified_claim" not in ids(analyze("I use Google Maps to get to college."))


def test_official_link_verifies_the_claim():
    r = analyze("Google internship: pay registration fee at https://careers.google.com/jobs")
    assert "unverified_claim" not in ids(r)


# ------------------------------------------------------------------ samples
@pytest.mark.parametrize("sample", SAMPLES, ids=[s["id"] for s in SAMPLES])
def test_sample_library_behaves(sample):
    r = analyze(sample["text"], sample["url"])
    if sample["kind"] == "scam":
        assert r["score"] >= 45, (sample["id"], r["score"])
    else:
        assert r["score"] < 20, (sample["id"], r["score"], ids(r))


# ----------------------------------------------------------------------- API
def test_api_analyze_ok():
    res = client.post("/api/analyze", json={"text": SAMPLES[0]["text"]})
    assert res.status_code == 200
    body = res.json()
    assert body["level"] in ("high", "critical")
    assert body["disclaimer"] and body["verification_checklist"]


def test_api_requires_input():
    assert client.post("/api/analyze", json={"text": "  ", "url": ""}).status_code == 422
    assert client.post("/api/analyze", json={}).status_code == 422


def test_api_rejects_oversized_input():
    assert client.post("/api/analyze", json={"text": "a" * 5001}).status_code == 422


def test_api_samples_and_health():
    assert client.get("/api/health").json() == {"status": "ok"}
    assert len(client.get("/api/samples").json()) == len(SAMPLES)
