"""Organisations that scammers commonly impersonate, and the domains they really own.

The key is the single lowercase token we look for inside domain names.
`aliases` are the names we look for inside message text.
"""

BRANDS = {
    "google": {
        "display": "Google",
        "aliases": ["google"],
        "domains": {"google.com", "google.co.in", "withgoogle.com", "googleapis.com",
                    "googleusercontent.com", "gstatic.com"},
    },
    "microsoft": {
        "display": "Microsoft",
        "aliases": ["microsoft"],
        "domains": {"microsoft.com", "microsoftonline.com", "office.com", "live.com"},
    },
    "amazon": {
        "display": "Amazon",
        "aliases": ["amazon"],
        "domains": {"amazon.com", "amazon.in", "amazon.jobs", "amazonaws.com", "aboutamazon.com"},
    },
    "flipkart": {
        "display": "Flipkart",
        "aliases": ["flipkart"],
        "domains": {"flipkart.com"},
    },
    "paytm": {
        "display": "Paytm",
        "aliases": ["paytm"],
        "domains": {"paytm.com"},
    },
    "phonepe": {
        "display": "PhonePe",
        "aliases": ["phonepe"],
        "domains": {"phonepe.com"},
    },
    "paypal": {
        "display": "PayPal",
        "aliases": ["paypal"],
        "domains": {"paypal.com"},
    },
    "tcs": {
        "display": "TCS",
        "aliases": ["tcs", "tata consultancy services"],
        "domains": {"tcs.com"},
    },
    "infosys": {
        "display": "Infosys",
        "aliases": ["infosys"],
        "domains": {"infosys.com"},
    },
    "wipro": {
        "display": "Wipro",
        "aliases": ["wipro"],
        "domains": {"wipro.com"},
    },
    "accenture": {
        "display": "Accenture",
        "aliases": ["accenture"],
        "domains": {"accenture.com"},
    },
    "cognizant": {
        "display": "Cognizant",
        "aliases": ["cognizant"],
        "domains": {"cognizant.com"},
    },
    "sbi": {
        "display": "SBI",
        "aliases": ["sbi", "state bank of india"],
        "domains": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com"},
    },
    "hdfc": {
        "display": "HDFC",
        "aliases": ["hdfc"],
        "domains": {"hdfcbank.com", "hdfc.com"},
    },
    "icici": {
        "display": "ICICI",
        "aliases": ["icici"],
        "domains": {"icicibank.com"},
    },
    "airtel": {
        "display": "Airtel",
        "aliases": ["airtel"],
        "domains": {"airtel.in", "airtel.com"},
    },
    "naukri": {
        "display": "Naukri",
        "aliases": ["naukri"],
        "domains": {"naukri.com"},
    },
    "linkedin": {
        "display": "LinkedIn",
        "aliases": ["linkedin"],
        "domains": {"linkedin.com", "lnkd.in"},
    },
    "internshala": {
        "display": "Internshala",
        "aliases": ["internshala"],
        "domains": {"internshala.com"},
    },
    "aicte": {
        "display": "AICTE",
        "aliases": ["aicte"],
        "domains": {"aicte-india.org"},
    },
    "ugc": {
        "display": "UGC",
        "aliases": ["ugc"],
        "domains": {"ugc.gov.in", "ugc.ac.in"},
    },
}

# Phrases that name an organisation but have no single-token domain form.
EXTRA_CLAIMS = {
    "National Scholarship Portal": {"scholarships.gov.in"},
}
