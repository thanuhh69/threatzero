"""Orchestrates detection -> scoring -> category -> explanation -> recommendations."""
from datetime import datetime

from . import message_detector, category_classifier as cc
from .risk_engine import LIMITATIONS, level_for, score_indicators
from .url_detector import analyze_url_indicators
from .utils import collapse

GENERIC = ["Do not click links, install apps, or reply until you have verified the sender through an official channel.",
           "Contact the organisation using the phone number or website printed on its official site or your card/passbook.",
           "Never share OTPs, UPI PINs, CVVs, passwords or card details with anyone."]
BY_CAT = {
 "Work-from-home fraud": ["Do not pay any fee to get a work-from-home job; genuine employers do not charge candidates.",
                          "Search the company on its official website/LinkedIn and check the recruiter's company email domain."],
 "Part-time job fraud": ["Stop any 'task' scheme that asks you to deposit money to unlock higher earnings or withdraw profit.",
                         "Do not move conversations to Telegram/WhatsApp groups run by unknown recruiters."],
 "Recruitment fraud": ["Verify the vacancy on the company's official careers page; real offers follow a proper interview.",
                       "Never pay registration, training or security deposits for a job."],
 "Internship fraud": ["Check the organisation's official website and ask your college placement cell before paying anything.",
                      "Be cautious of paid 'certificate' or 'guaranteed placement' internships."],
 "Betting and gaming fraud": ["Betting outcomes cannot be guaranteed; do not deposit money with tipsters or unknown apps.",
                              "Online betting/gambling is restricted in India - avoid unlicensed platforms."],
 "Investment fraud": ["Check that the adviser or platform is registered with SEBI (sebi.gov.in) before investing.",
                      "Be wary of guaranteed or doubled returns, VIP signal groups and pressure to deposit quickly."],
 "UPI and payment fraud": ["You never need to enter a UPI PIN or scan a QR code to RECEIVE money.",
                           "Decline unexpected 'collect' requests; if you paid already, call your bank and 1930 immediately."],
 "Phishing": ["Open your bank or service app/site by typing the official address yourself, not via the received link.",
              "If you entered credentials, change the password immediately and contact your bank."],
 "Scholarship and education fraud": ["Check scholarships only on official portals (e.g. scholarships.gov.in) or your institution.",
                                     "Genuine scholarships do not require a processing fee."],
 "Impersonation fraud": ["Police, CBI, customs or RBI do not demand money or conduct 'digital arrests' over calls/video.",
                         "Disconnect the call, speak to a family member, and report to 1930 / cybercrime.gov.in."],
 "General suspicious activity": ["Pause and verify. If anything feels pressured or too good to be true, treat it as risky."],
}
BY_IND = {
 "otp_pin_request": "Never share an OTP, PIN or CVV - not even with someone claiming to be from your bank.",
 "upfront_fee": "Do not pay any upfront fee or deposit to receive a job, prize, loan or scholarship.",
 "remote_access": "Do not install remote-access apps or APK files; uninstall them if already installed and call your bank.",
 "suspicious_link": "Do not open the link. Paste it into the Website Scanner instead (it is analysed offline, never visited).",
 "sensitive_data": "Do not send Aadhaar, PAN, bank or selfie documents to unverified parties.",
}
AFTER = "If you already paid or shared details: call your bank, dial 1930 and report at https://cybercrime.gov.in/ as soon as possible."


def _recs(category, inds, score):
    recs = []
    for i in inds:
        if i["id"] in BY_IND and i["awarded"] > 0:
            recs.append(BY_IND[i["id"]])
    recs += BY_CAT.get(category, [])
    recs += GENERIC
    if score >= 25:
        recs.append(AFTER)
    else:
        recs = ["No known warning pattern was found, but that does not guarantee safety. Verify unexpected requests "
                "through official channels."] + GENERIC[:2]
    seen, out = set(), []
    for r in recs:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out[:8]


def _explain(input_type, score, level, category, inds, extra=""):
    active = [i for i in inds if i["awarded"] > 0 and i["id"] != "corroboration"]
    if not active:
        return (f"No known warning patterns were detected in this {input_type.lower()}. This is not proof that it is safe - "
                "scammers adapt their wording. Verify unexpected requests independently." + extra)
    top = ", ".join(i["name"].lower() for i in active[:3])
    cat = "" if category in (cc.NONE,) else f" The pattern most resembles: {category.lower()} (a heuristic match, not a verdict)."
    return (f"This {input_type.lower()} shows {len(active)} independent warning group(s); the strongest were: {top}. "
            f"Indicative risk index {score}/100 ({level}).{cat}{extra} Indicators show suspicious signals, not verified facts.")


def _finalize(text_for_cat, input_type, inds, extra="", urls=None, info=None):
    score, ind_dicts = score_indicators(inds)
    level = level_for(score)
    category, cat_scores = cc.classify(text_for_cat, [i["id"] for i in ind_dicts if i["awarded"] > 0], score)
    return {
        "input_type": input_type, "category": category, "score": score, "level": level,
        "indicators": ind_dicts, "explanation": _explain(input_type, score, level, category, ind_dicts, extra),
        "recommendations": _recs(category, ind_dicts, score), "limitations": LIMITATIONS,
        "urls": urls or [], "url_info": info, "created_at": datetime.now().isoformat(timespec="seconds"),
        "category_scores": {k: v for k, v in sorted(cat_scores.items(), key=lambda kv: -kv[1]) if v > 0},
    }


def analyze_text(text: str, input_type: str = "Message") -> dict:
    if not text or not text.strip():
        raise ValueError("Please provide some text to analyse.")
    inds, urls = message_detector.detect(text)
    return _finalize(collapse(text), input_type, inds, urls=urls)


def analyze_url(url: str) -> dict:
    if not url or not url.strip():
        raise ValueError("Please enter a URL.")
    info, inds = analyze_url_indicators(url.strip())
    extra = " No network request was made: DNS, ownership and reputation were NOT verified."
    from .url_detector import OFFICIAL
    if info.get("valid") and info.get("registered_domain") in OFFICIAL:
        extra += " The domain matches a well-known official domain in our local list (not a live verification)."
    text = (info.get("hostname", "") or url).replace(".", " ").replace("-", " ")
    a = _finalize(text, "Website URL", inds, extra=extra, urls=[url.strip()], info=info)
    return a
