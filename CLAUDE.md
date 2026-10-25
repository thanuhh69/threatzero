# CLAUDE.md - ScamShield Bharat

Streamlit app + rule-based fraud-indicator engine. Python 3.10+.

## Commands
- Run: `streamlit run app.py`
- Tests: `python -m pytest -q`
- Evaluate on synthetic data: `python -m scamshield.evaluate` (writes reports/evaluation.{md,json})

## Architecture
- `scamshield/message_detector.py` - weighted regex rules (`R` list). Each rule: id, group, points, why, patterns, optional `exclude`.
- `scamshield/url_detector.py` - offline URL analysis. MUST NEVER make network requests.
- `scamshield/risk_engine.py` - group-deduped scoring (max per group + corroboration bonus, cap 100). Levels 0-24/25-49/50-74/75-100.
- `scamshield/category_classifier.py` - keyword + indicator-boost category scoring.
- `scamshield/detector.py` - orchestration, explanations, recommendations.
- `scamshield/storage.py` - SQLite; stores redacted excerpts only. `scamshield/reporting.py` - ReportLab PDFs.
- `scamshield/ocr_engine.py` - EasyOCR -> Tesseract -> manual fallback. `scamshield/reputation.py` - optional Safe Browsing.
- `app.py` - UI via `st.navigation`; `SCAMSHIELD_TEST_PAGE` env var is a test-only hook for AppTest.

## Rules of the project
- The score is an indicative risk index, not a probability. Never claim content is verified safe/fraudulent.
- Never ask for OTP/PIN/CVV/passwords. Never auto-submit complaints. Never fetch user-supplied URLs.
- Adding a rule: add to `R`, add a test, add a boost in `category_classifier.BOOST`, rerun evaluation.
- Materially editing rules against `data/sample_cases.csv` makes its metrics less meaningful - add NEW cases instead.
