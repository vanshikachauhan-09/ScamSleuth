# ScamSleuth

Paste a suspicious message, job offer, scholarship notice or link. ScamSleuth doesn't just say
"safe" or "dangerous". It shows **which exact phrases and link features raised a flag, why they
matter, and what to do next.**

> ScamSleuth identifies suspicious indicators. It cannot guarantee that a message is a scam, or
> that a message with no warnings is safe. The score is a heuristic, not a probability of fraud.

## Run it

You need Python 3.9+ and Node 18+.

**1. Backend (FastAPI)**

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**2. Frontend (React + Vite)** in a second terminal

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173
```

Vite proxies `/api` to the backend, so there is nothing else to configure.

**Single-server deploy (handy for the demo):**

```bash
cd frontend && npm install && npm run build   # creates frontend/dist
cd ../backend && uvicorn app.main:app --port 8000
```

When `frontend/dist` exists, FastAPI serves the website and the API from one URL.
Set `CORS_ORIGINS` (comma separated) if the frontend is hosted on another origin.

**Tests:** `cd backend && python -m pytest`

## How it works

1. The user submits a message and/or a link.
2. **Text rules** (`backend/app/rules.py`) look for warning signs and record the exact matched phrase.
3. **URL checks** (`backend/app/url_analysis.py`) inspect the link *text only*. No link is ever
   opened or resolved.
4. **Scoring** (`backend/app/engine.py`) adds each warning sign **once**, caps the total at 100 and
   maps it to a level.
5. The UI shows the score, highlighted phrases, an explanation per warning, next steps, a
   verification checklist and reporting guidance.

### Warning signs and weights

These are illustrative weights you can tune, not validated fraud probabilities.

| Warning sign | Points | Source |
|---|---|---|
| Request for OTP / password / banking details | +30 | text |
| Upfront payment demand | +25 | text |
| Link imitates a known organisation | +25 | link |
| Suspicious link structure (IP host, shortener, spoofed spelling, risky TLD, `@` trick, punycode, free hosting, long subdomain chain) | +20 | link |
| Urgency or pressure | +15 | text |
| Threats / fear (blocked account, KYC, legal action) | +15 | text |
| Request for identity documents | +15 | text |
| Too-good-to-be-true promise | +10 | text |
| Pushes you to WhatsApp / Telegram | +10 | text |
| Asks you to keep it secret | +10 | text |
| Unverified sender or company claim | +10 | **assumption** |
| Link is HTTP, not HTTPS | +5 | link |

Levels: **0-19** Low, **20-44** Moderate, **45-74** High, **75-100** Critical.

### Evidence vs. assumption

Every finding is labelled. *Found in the message / link* points at something visible in what was
submitted. *Needs verification* (the unverified company claim) is something ScamSleuth cannot
confirm and the user must check.

### Design decisions worth mentioning to judges

- **Explainable, not a black box.** Every point in the score maps to a visible finding.
- **Safe URL handling.** No fetching, so there is no SSRF risk and no link is visited for the user.
- **Warning sentences are not flagged.** "Never share your OTP" is genuine advice, so negated
  sentences are ignored for credential and document requests.
- **Domain matching, not substring matching.** `t.co` is matched as a domain, so it doesn't flag
  `microsoft.com`.
- **Privacy.** Text is analysed in memory; nothing is stored or logged.
- **Hindi + English** phrases for the most common patterns.

## API

`POST /api/analyze` with `{ "text": "...", "url": "..." }` (at least one; text max 5000 chars).
`GET /api/samples` returns demo scam and legitimate messages. `GET /api/health` for a liveness check.

## Project layout

```
backend/
  app/
    main.py          FastAPI app and routes
    engine.py        scoring, evidence, highlights, next steps
    rules.py         text rules and weights  <- tune these
    url_analysis.py  offline URL checks
    brands.py        organisations and their real domains
    samples.py       demo scam / legit messages
  tests/             pytest suite
frontend/
  src/               React app (App, api, components, styles)
```

## Known limitations

- Rule-based: new scam wording will be missed until you add a rule. A natural next step is an
  optional AI "explain in simple words" layer on top of the rule findings.
- The brand list is small. Add organisations and their real domains in `brands.py`.
- The India reporting guidance (helpline 1930, cybercrime.gov.in) should be re-checked against the
  official sites before a public launch.
