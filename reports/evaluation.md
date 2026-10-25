# Evaluation (synthetic data)

> synthetic, author-written (not real-world data). Cases: 63. Flag threshold: score >= 25.
> Rules and dataset were written by the same author, so this is a regression check, not real-world accuracy.

| TP | FP | FN | TN | Precision | Recall | F1 | FP rate |
|---|---|---|---|---|---|---|---|
| 47 | 1 | 0 | 15 | 0.979 | 1.0 | 0.989 | 0.062 |

Category accuracy on fraud cases: **1.0**

| Category | n | Flagged | Category correct | Category accuracy |
|---|---|---|---|---|
| Betting and gaming fraud | 5 | 5 | 5 | 1.0 |
| Impersonation fraud | 5 | 5 | 5 | 1.0 |
| Internship fraud | 4 | 4 | 4 | 1.0 |
| Investment fraud | 5 | 5 | 5 | 1.0 |
| Part-time job fraud | 5 | 5 | 5 | 1.0 |
| Phishing | 5 | 5 | 5 | 1.0 |
| Recruitment fraud | 4 | 4 | 4 | 1.0 |
| Scholarship and education fraud | 4 | 4 | 4 | 1.0 |
| UPI and payment fraud | 5 | 5 | 5 | 1.0 |
| Work-from-home fraud | 5 | 5 | 5 | 1.0 |

## False positives
- #62 (score 28): Please pay the registration fee of Rs 500 for the semester exam at the college accounts office counter before Friday.

## False negatives

## Category mismatches