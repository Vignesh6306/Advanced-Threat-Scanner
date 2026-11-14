# 🛡️ Advanced Threat Scanner (Cyber Intel)

A Streamlit web app that checks links for phishing signs **before you click**. It explains every
verdict, so you can see *why* a link scored the way it did.

## Features

| Module | What it does |
|---|---|
| **Scanner** | Scores one URL (0-100), shows a gauge, a check-by-check explanation and a colour-coded URL breakdown |
| **Batch Scanner** | Scan up to 200 links from pasted text or a CSV / TXT file; 4-level risk summary and CSV export |
| **Global Analytics** | Risk distribution, score histogram, scans over time, most triggered checks, riskiest domains |
| **Detection Evaluation** | Measures accuracy, precision, recall, F1 and a confusion matrix on labelled URLs (built-in sanity set or your own CSV) |
| **Scan History** | Search, filter by risk and score, inspect any record, delete one or all |
| **Security Reports** | CSV, JSON, HTML and Markdown reports with summary, risk distribution, per-URL reasons and methodology |
| **Education** | Real-style scam examples, a 10-question quiz with saved scores and a progress dashboard |
| **Settings** | Sensitivity (Lenient / Balanced / Strict), allowlist, blocklist / threat-feed import, storage status |

## How detection works

Every URL starts at 100 points and loses points for each rule it triggers:

- Missing HTTPS, IP address instead of a domain, the `user@host` trick, URL shorteners
- Brand impersonation and typosquatting (`paypa1`, `g00gle`), brand + login words
- Look-alike alphabets (homograph / punycode), suspicious TLDs, free-hosting subdomains
- Open-redirect parameters, risky file extensions, excessive subdomains, odd ports
- Your own blocklist

Scores: **80-100 Low**, **55-79 Medium**, **30-54 High**, **0-29 Critical**.

> HTTPS only means the connection is encrypted. It does **not** mean a site is trustworthy,
> so `https://paypal-secure-login.example.com` is still flagged.

## Honest limitations

- The scanner reads the **text of the URL only**. It never visits the site, so it cannot see page
  content, domain age or live reputation data.
- Rule-based detection produces false positives and false negatives. Use it as a first-line screen.
- The built-in benchmark is small and hand-written. Upload a labelled dataset on the
  **Detection Evaluation** page for a meaningful figure.

## Security design

- URLs are analysed as text and **never fetched** (no SSRF, no redirect following)
- Input limits: 2048 characters per URL, 200 URLs per batch, 5000 imported domains
- All user text is HTML-escaped; CSV exports neutralise spreadsheet formulas
- Reports show defanged links (`hxxp://example[.]com`)
- Database credentials come from secrets, never from the code

## Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Streamlit Community Cloud

1. Push this repository to GitHub.
2. In Streamlit Cloud choose **New app**, pick this repo, main file `app.py`.
3. Every push to `main` redeploys the app automatically.

## Permanent history (optional PostgreSQL)

By default history is saved in a local SQLite file, which can reset when Streamlit Cloud restarts the app.
For permanent storage create a free PostgreSQL database (for example on Supabase) and add this in
**App settings > Secrets**:

```toml
DATABASE_URL = "postgresql://USER:PASSWORD@HOST:5432/postgres?sslmode=require"
```

Tables are created automatically. **Never commit this value to GitHub.**

## Project structure

```
app.py             # the whole application
requirements.txt   # dependencies
.gitignore         # keeps secrets and local databases out of Git
```

## Roadmap

- Live reputation lookups (e.g. Google Safe Browsing) through a server-side API key
- Domain-age checks
- A trained ML model, evaluated on a public labelled dataset, to complement the rules
