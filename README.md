# THREATZERO Bharat
**Detect Early. Stay Safe. Stay Protected.**

AI-assisted, explainable digital-fraud *indicator* analysis for Indian users: fake jobs, internships, betting, investment, UPI/payment fraud, phishing, scholarship scams and impersonation. English and Telugu-English mixed text supported.

> The score is an **indicative risk index (0-100)**, not a probability of fraud. It shows suspicious signals, never verified facts. A low score is **not** a guarantee of safety.

## Features
| Page | What it does |
|---|---|
| Overview | Live KPIs, charts, recent activity (all from SQLite), quick-scan buttons, demo-data loader |
| Message scanner | 17 weighted rule groups (urgency, fees, OTP/PIN, fake-job, Telegram tasks, money doubling, impersonation...), category, score, evidence, why-it-matters, actions, PDF |
| Website scanner | **Offline** URL analysis (HTTP, IP host, shorteners, hyphens, length, TLD, keywords, `@` tricks, punycode, brand lookalikes, APK links). Never visits the URL; DNS/WHOIS/reputation shown as *not verified* |
| Screenshot scanner | PNG/JPG upload, OpenCV preprocessing, OCR (EasyOCR -> Tesseract -> manual paste fallback), editable text, same engine |
| Fraud intelligence | Date/type/level/category filters, Plotly charts, top indicators, history, CSV export |
| Incident assistance | Structured incident summary + PDF, 1930 helpline and cybercrime.gov.in guidance. Does **not** file complaints |

## Setup
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
# OCR: install the Tesseract binary (Ubuntu: sudo apt install tesseract-ocr tesseract-ocr-tel | macOS: brew install tesseract
#      | Windows: https://github.com/UB-Mannheim/tesseract/wiki). Optional better OCR: pip install easyocr
streamlit run app.py
```
Without any OCR engine the screenshot page still works - paste the visible text manually.

## Tests and evaluation
```bash
python -m pytest -q                 # unit + storage + PDF + UI-independent checks
python -m scamshield.evaluate       # metrics on data/sample_cases.csv -> reports/evaluation.md
```
**Read this before quoting numbers:** `data/sample_cases.csv` has 63 *synthetic, author-written* cases (47 fraud across 10 categories incl. 6 Telugu-English, 16 legitimate incl. 2 deliberate hard negatives). The rules and the cases were written by the same author, so near-perfect scores are a **regression check, not real-world accuracy**. One hard negative (a genuine college "registration fee" notice) is a known false positive. Real performance on unseen scams will be lower; validate on real, labelled data before any production claim.
scikit-learn is not used: with 63 samples a trained model would be less trustworthy than transparent rules.

## How scoring works
Each rule belongs to a *group*; only the highest-point rule per group counts (no double counting). Three or more groups add +6, five or more +10. Cap 100. Levels: 0-24 Low, 25-49 Moderate, 50-74 High, 75-100 Critical.

## Privacy and safety
- Only a redacted excerpt (long digit runs and emails masked) is stored in `data/scamshield.db` (git-ignored).
- URLs are parsed, never fetched. Optional reputation lookup (Google Safe Browsing) is off unless `GOOGLE_SAFE_BROWSING_KEY` is set; that path needs internet and a key and is not covered by the offline tests.
- The app warns users never to enter OTPs, PINs, CVVs or passwords.

## Deployment
- **Streamlit Community Cloud:** push to GitHub, create app with `app.py`; `packages.txt` installs Tesseract (incl. Telugu) and `requirements.txt` the Python deps.
- **Local demo:** `streamlit run app.py`, then on Overview click **Load demo scans** to populate dashboards (rows are tagged `source=demo`, dates spread over 14 days, removable via *Remove demo scans*).

## Suggested 3-minute demo
1. Overview -> Load demo scans (dashboards fill from the real engine).
2. Message scanner -> pick a Telugu-English sample -> Analyse -> show evidence + PDF.
3. Website scanner -> "Payment app lookalike" -> note the *not verified* status box.
4. Screenshot scanner -> upload a chat screenshot -> edit OCR text -> Analyse.
5. Fraud intelligence -> apply filters. 6. Incident assistance -> generate PDF.

## Known limitations
Regex rules can be evaded by rewording or images with unusual fonts; Telugu coverage is a small keyword set (transliterated + a few script words); brand/official-domain lists are small and local; legitimate messages that mention fees/OTP can trigger warnings.
