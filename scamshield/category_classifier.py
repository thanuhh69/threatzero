"""Keyword/pattern category scoring. Returns the most likely category - a heuristic, not a probability."""
import re

CATS = ["Betting and gaming fraud", "Internship fraud", "Scholarship and education fraud", "Investment fraud",
        "Impersonation fraud", "UPI and payment fraud", "Phishing", "Part-time job fraud", "Work-from-home fraud",
        "Recruitment fraud", "General suspicious activity"]  # order = tie-break priority
NONE = "No clear fraud pattern detected"

KW = {
 "Betting and gaming fraud": (r"\b(bet|betting|ipl|cricket|satta|matka|casino|teen patti|rummy|aviator|dream11|fantasy|jackpot|fixed match|gaming)\b", 4),
 "Internship fraud": (r"\b(internship|intern|stipend|trainee)\b", 4),
 "Scholarship and education fraud": (r"\b(scholarship|admission|university|college|coaching|neet|jee|fee waiver|grant|education)\b", 4),
 "Investment fraud": (r"\b(invest\w*|returns?|crypto|bitcoin|forex|trading|stock|ipo|mutual fund|portfolio|signals?|scheme|double)\b", 3),
 "Impersonation fraud": (r"\b(rbi|police|cbi|customs|trai|income tax|officer|arrest|digital arrest|courier|calling from|customer care|warrant)\b", 4),
 "UPI and payment fraud": (r"\b(upi|gpay|phonepe|paytm|qr|collect request|refund|cashback|wrongly|payment|transfer)\b", 3),
 "Phishing": (r"\b(click|link|verify|login|kyc|password|netbanking|credentials|sign in|blocked|suspended)\b", 2),
 "Part-time job fraud": (r"\b(part[- ]?time|tasks?|like|subscribe|rating|review|commission|telegram|youtube|prepaid)\b", 3),
 "Work-from-home fraud": (r"\b(work from home|wfh|home[- ]based|online (job|work)|typing|copy[- ]?paste|data entry|form filling|work at home)\b", 4),
 "Recruitment fraud": (r"\b(offer letter|vacancy|recruit\w*|hiring|interview|hr|joining|placement|selected|job|jobs|udyogam)\b", 2),
}
BOOST = {  # indicator id -> {category: weight}
 "guaranteed_betting": {"Betting and gaming fraud": 8}, "money_doubling": {"Investment fraud": 8},
 "telegram_task": {"Part-time job fraud": 6}, "job_lure": {"Recruitment fraud": 2, "Work-from-home fraud": 1},
 "payment_request": {"UPI and payment fraud": 5}, "otp_pin_request": {"UPI and payment fraud": 2, "Phishing": 2},
 "password_request": {"Phishing": 4}, "suspicious_link": {"Phishing": 3}, "click_link": {"Phishing": 1},
 "impersonation": {"Impersonation fraud": 5}, "secrecy": {"Impersonation fraud": 2},
 "prize_lure": {"Scholarship and education fraud": 2}, "remote_access": {"Impersonation fraud": 2, "Phishing": 2},
 "url_lookalike": {"Phishing": 6}, "url_keywords": {"Phishing": 3}, "url_userinfo": {"Phishing": 5},
 "url_ip": {"Phishing": 4}, "url_idn": {"Phishing": 5}, "url_apk": {"Phishing": 4}, "url_redirect": {"Phishing": 3},
}


def classify(text: str, indicator_ids, score: int):
    scores = {c: 0.0 for c in CATS}
    for c, (pat, w) in KW.items():
        n = len(set(m.group(0).lower() for m in re.finditer(pat, text or "", re.I)))
        scores[c] += min(n, 3) * w
    for i in indicator_ids:
        for c, w in BOOST.get(i, {}).items():
            scores[c] += w
    top = max(CATS[:-1], key=lambda c: (scores[c], -CATS.index(c)))
    if score < 25:
        return NONE, scores
    if scores[top] < 4:
        return "General suspicious activity", scores
    return top, scores
