"""Demo library: realistic scam-style and legitimate messages for testing and the live demo."""

SAMPLES = [
    {
        "id": "fake-internship",
        "kind": "scam",
        "label": "Fake internship fee",
        "text": (
            "Congratulations! You have been selected for a Google internship. Pay ₹499 as a "
            "registration fee today to confirm your position. Limited seats available. "
            "Click here to register: http://google-careers-register.xyz/apply"
        ),
        "url": "",
    },
    {
        "id": "kyc-otp",
        "kind": "scam",
        "label": "Bank KYC + OTP",
        "text": (
            "Dear customer, your SBI account will be blocked within 24 hours as your KYC is pending. "
            "Update immediately at http://sbi-kyc-update.top/login and share the OTP you receive "
            "to verify your identity."
        ),
        "url": "",
    },
    {
        "id": "whatsapp-task",
        "kind": "scam",
        "label": "WhatsApp task job",
        "text": (
            "Work from home and earn ₹3000 per day. No interview required! Just complete simple tasks. "
            "Message us on WhatsApp now, only 10 slots left. Send your Aadhaar and a selfie to get started. "
            "Do not tell anyone about this offer."
        ),
        "url": "",
    },
    {
        "id": "scholarship-fee",
        "kind": "scam",
        "label": "Scholarship processing fee",
        "text": (
            "Your National Scholarship Portal application is approved. Transfer ₹1,200 as a processing "
            "fee to release your scholarship amount. Reply within 2 hours or your application will be cancelled."
        ),
        "url": "https://bit.ly/3scholar-claim",
    },
    {
        "id": "lookalike-link",
        "kind": "scam",
        "label": "Look-alike link only",
        "text": "",
        "url": "https://paypa1-secure-login.com/verify",
    },
    {
        "id": "legit-bank-otp",
        "kind": "legit",
        "label": "Real bank OTP notice",
        "text": (
            "Your OTP for the transaction of Rs 1,250 at a merchant is 482913. It is valid for 5 minutes. "
            "Never share this OTP with anyone, including bank staff. Visit https://www.hdfcbank.com for help."
        ),
        "url": "",
    },
    {
        "id": "legit-application",
        "kind": "legit",
        "label": "Genuine application receipt",
        "text": (
            "Hi, thank you for applying to the Software Engineering Intern role at Google. We have received "
            "your application and our recruiting team will review it. You can track the status at "
            "https://careers.google.com/jobs. We will never ask you for payment during the hiring process."
        ),
        "url": "",
    },
    {
        "id": "legit-college",
        "kind": "legit",
        "label": "College notice",
        "text": (
            "The mid-semester timetable has been published on the college notice board and the student portal. "
            "Please check your batch schedule and contact the exam cell if you see any clash."
        ),
        "url": "",
    },
]
