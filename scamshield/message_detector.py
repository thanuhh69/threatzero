"""Weighted, transparent rule set for suspicious messages (English + Telugu-English/Telugu script)."""
import re

from .risk_engine import Indicator
from .url_detector import analyze_url_indicators
from .utils import collapse, extract_urls, snippet

F = re.I | re.S
VERBS = (r"share|send|tell|give|forward|provide|enter|read out|confirm|reply with|submit|"
         r"cheppandi|pampandi|ivvandi|cheppu|pampu")
NEG = re.compile(r"\b(do not|don'?t|dont|never|not to|no one|nobody|avoid)\b[^.]{0,25}"
                 r"\b(share|disclose|give|tell|send|reveal|provide)\b", re.I)
SECRETS = (r"otp|one[- ]time password|upi pin|atm pin|debit card pin|card pin|m-?pin|pin number|secret pin|"
           r"cvv|cvc|verification code|security code")

R = [
 dict(id="urgency", name="Urgency / pressure tactics", group="urgency", points=8,
      why="Scammers rush victims so they act before thinking or verifying.",
      pats=[r"\b(urgent(ly)?|immediately|right now|act now|hurry|last chance|final (notice|warning)|"
            r"limited (slots?|seats?|time|vacanc\w+)|only \d+ (slots?|seats?|vacanc\w+|spots?) (left|remaining)|"
            r"expires? (today|soon|in)|within \d+ ?(hours?|hrs?|minutes?|mins?)|today only|don'?t miss|"
            r"ventane|twaraga|tvaraga|ippude|ee roju matrame)\b", r"వెంటనే|త్వరగా"]),
 dict(id="guaranteed_income", name="Guaranteed / unrealistic income claim", group="income", points=18,
      why="Real employers do not guarantee high daily income for simple online work.",
      pats=[r"\b(guarante\w*|assured|fixed|sure)\s+(daily |weekly |monthly )?(income|salary|earning\w*|payout)\b",
            r"\bearn\b[^.]{0,40}\d[\d,]*\s*(/-)?\s*(per|a|every|each|/)\s*(day|daily|week|hour)\b",
            r"\b(daily|weekly)\s+(income|payment|payout)s?\s+(guarantee\w*|assured)\b",
            r"\bno (experience|skills?|qualification|investment)\s+(is |are )?(needed|required|necessary)\b[^.]{0,60}"
            r"\b(earn|income|salary|profit)\b",
            r"\b(dabbulu|dabbu)\b[^.]{0,30}\b(sampadinchandi|sampadinchavachu|guarantee|pakka)\b",
            r"\b(roju|rojuki|prathi roju)\s*(rs\.?|₹)?\s*\d[\d,]*\s*(rs|rupees|/-)?\s*(sampadinchandi|earn|income)\b",
            r"(డబ్బు|ఆదాయం)[^.]{0,20}(హామీ|గ్యారంటీ)"]),
 dict(id="guaranteed_betting", name="Guaranteed betting / gaming profit", group="betting", points=25,
      why="Outcomes of matches and games cannot be guaranteed; 'fixed match' claims are a classic lure.",
      pats=[r"\b(fixed|sure|100\s*%|guaranteed|confirmed|insider)\s+(match|win\w*|tips?|prediction\w*|profit\w*|jackpot|odds)\b",
            r"\b(ipl|cricket|satta|matka|teen patti|rummy|casino|betting|aviator|dream11|fantasy)\b[^.]{0,80}"
            r"\b(guarantee\w*|sure shot|fixed|100\s*%|double|risk[- ]free)\b",
            r"\b(guarantee\w*|sure shot|100\s*%)\b[^.]{0,80}\b(ipl|cricket|satta|matka|teen patti|rummy|casino|betting|aviator)\b",
            r"\b(match fixing|fixed match|jeetham guarantee)\b"]),
 dict(id="upfront_fee", name="Upfront fee / security deposit demanded", group="fee", points=28,
      why="Genuine employers, scholarships and prizes do not charge you money to receive them.",
      pats=[r"\b(registration|processing|joining|training|verification|security|refundable|activation|kit|document|"
            r"onboarding|clearance|insurance|gst|unlock|delivery|customs)\s+(fee|fees|charges?|deposit|amount)\b",
            r"\b(pay|deposit|send|transfer|submit)\b[^.]{0,40}(₹|rs\.?|inr)\s*\d[\d,]*[^.]{0,40}"
            r"\b(to (join|register|get|receive|claim|unlock|start|activate)|for (registration|joining|training|"
            r"verification|kit|processing|activation|delivery|clearance|the offer))\b",
            r"\b(fee|deposit|registration|security|amount)\b[^.]{0,20}\b(kattandi|pampandi|pay cheyandi|cheyandi|"
            r"cheyyandi|kattali|pampali)\b"]),
 dict(id="otp_pin_request", name="Request for OTP / PIN / CVV", group="credentials", points=30,
      why="No bank, company or government office will ever ask you to share an OTP, PIN or CVV.",
      exclude=NEG,
      pats=[rf"\b({VERBS})\b[^.\n]{{0,40}}\b({SECRETS})\b", rf"\b({SECRETS})\b[^.\n]{{0,30}}\b({VERBS})\b",
            r"(ఓటీపీ)\s*(చెప్పండి|పంపండి|షేర్)"]),
 dict(id="password_request", name="Request for password / login credentials", group="credentials", points=25,
      why="Legitimate services never ask for your password or net-banking credentials by message or call.",
      exclude=NEG,
      pats=[r"\b(share|send|tell|give|enter|provide|confirm|verify|update|pampandi|cheppandi)\b[^.]{0,30}"
            r"\b(password|passcode|login (id|details|credentials)|net ?banking (id|password|details)|credentials)\b"]),
 dict(id="payment_request", name="Suspicious payment / collect request", group="payment", points=18,
      why="Fraudsters push you to send money, scan QR codes or approve 'collect' requests to take money out.",
      pats=[r"\b(send|transfer|pay|deposit|pampandi)\b[^.]{0,30}\b(to|on)\b[^.]{0,20}\b(this|my|the below|given|following)\b"
            r"[^.]{0,20}\b(upi|account|number|qr|id|wallet|gpay|phonepe|paytm)\b",
            r"\bscan\b[^.]{0,20}\bqr\b[^.]{0,30}\b(receive|get|claim|refund|credit|cashback)\b",
            r"\b(accept|approve)\b[^.]{0,20}\b(collect |payment |money )?request\b",
            r"\b(wrongly|mistakenly|by mistake)\b[^.]{0,40}\b(sent|transferred|credited)\b[^.]{0,60}"
            r"\b(return|refund|send back|resend)\b",
            r"\b[\w.\-]{3,}@(ok(hdfcbank|icici|axis|sbi)|ybl|paytm|ibl|axl|apl)\b"]),
 dict(id="job_lure", name="Fake-job indicators (no interview / task-style work)", group="job", points=14,
      why="Offers without interviews, or paid 'tasks' like liking videos or copy-paste work, are common job scams.",
      pats=[r"\b(no interview|without (any )?interview|directly selected|hired without|selected without)\b",
            r"\b(typing|copy[- ]?paste|form filling|data entry|captcha|ad[- ]?posting|app (promotion|review)|"
            r"product (rating|review)s?|like (and|&) subscribe|youtube (likes?|subscribe\w*)|"
            r"google maps? (rating|review)s?)\b[^.]{0,40}\b(job|work|task|earn\w*|income)\b",
            r"\b(100\s*%|guaranteed)\s*(placement|job guarantee|job)\b|\bjob guarantee\b"]),
 dict(id="telegram_task", name="Telegram / task-and-commission scheme", group="task", points=20,
      why="Scams recruit through Telegram, pay small amounts for 'tasks', then demand larger deposits.",
      pats=[r"\btelegram\b[^.]{0,60}\b(task|tasks|channel|group|earn\w*|income|link|join|id)\b",
            r"\b(complete|finish|do)\b[^.]{0,15}\btasks?\b[^.]{0,60}\b(earn|commission|paid|reward|per task|income|profit)\b",
            r"\bper task\b|\bprepaid tasks?\b|\bmerchant tasks?\b|\bcommission\b[^.]{0,20}\btasks?\b"]),
 dict(id="money_doubling", name="Money-doubling / guaranteed investment returns", group="investment", points=28,
      why="Legitimate investments carry risk; promised doubling or fixed high returns are hallmarks of Ponzi/investment fraud.",
      pats=[r"\b(double|triple|2x|3x|5x|10x)\b[^.]{0,30}\b(money|investment|amount|income|capital|returns?)\b",
            r"\b(guaranteed|assured|fixed|daily|weekly)\s+returns?\b",
            r"\b\d{1,3}\s*%\s*(daily|per day|weekly|per week|monthly|per month)\b",
            r"\b(crypto|forex|stock|trading|bitcoin|ipo)\b[^.]{0,60}\b(guarantee\w*|assured|risk[- ]free|sure shot|100\s*%|"
            r"signals?|vip group|insider)\b",
            r"\b(dabbulu|money)\b[^.]{0,20}\b(double|rettimpu)\b", r"\brisk[- ]free (profit|returns?|investment)\b"]),
 dict(id="prize_lure", name="Prize / lottery / scholarship-claim lure", group="prize", points=22,
      why="Unsolicited prizes and 'approved' scholarships that need action from you are a common bait.",
      pats=[r"\b(you (have|'ve) won|lucky draw|lottery|kbc|jackpot winner|claim (your )?(prize|reward|gift|cashback|refund)|"
            r"congratulations[^.]{0,40}(won|winner|selected|prize|reward))\b",
            r"\b(scholarship|stipend|grant)\b[^.]{0,60}\b(fee|apply now|claim|click|link|limited|guarantee\w*|approved|"
            r"processing)\b"]),
 dict(id="impersonation", name="Impersonation / threat of account block or legal action", group="impersonation", points=18,
      why="Fraudsters pose as banks, police or agencies and threaten consequences to force compliance.",
      pats=[r"\b(your|ur)\s+(\w+\s+){0,2}(account|card|sim|number|aadhaar|pan|parcel|package|connection|electricity|kyc)\b[^.]{0,40}"
            r"\b(will be|has been|is|are)\s+(blocked|suspended|deactivated|frozen|disconnected|cancelled|seized|"
            r"expired|illegal)\b",
            r"\b(kyc|pan|aadhaar)\b[^.]{0,30}\b(update|verification|expire\w*|pending|suspend\w*)\b[^.]{0,40}"
            r"\b(click|link|call|share|immediately|today|urgent\w*)\b",
            r"\b(digital arrest|arrest warrant|case (has been )?registered|money laundering|illegal (parcel|items|goods)|"
            r"drugs? (found|in))\b",
            r"\b(i am|this is|calling from|we are calling|speaking from)\b[^.]{0,30}\b(rbi|sbi|hdfc|icici|bank|customs|"
            r"police|cbi|trai|income tax|amazon|paytm|customer care)\b"]),
 dict(id="sensitive_data", name="Request for sensitive personal data", group="pii", points=14,
      why="Identity and bank documents requested before any verified relationship enable identity theft.",
      exclude=NEG,
      pats=[r"\b(send|share|submit|provide|upload|give|whatsapp|forward|pampandi|ivvandi)\b[^.]{0,40}"
            r"\b(aadhaar|aadhar|pan (card|number)|bank (account|details|statement)|account number|passbook|selfie|"
            r"passport|cheque|debit card|credit card|card (number|details)|photo id|id proof|driving licen[cs]e)\b"]),
 dict(id="remote_access", name="Remote-access / APK installation request", group="remote", points=22,
      why="Remote-access tools and unknown APKs let criminals see your screen, read OTPs and empty accounts.",
      pats=[r"\b(anydesk|teamviewer|quick ?support|rustdesk|ammyy|screen ?share|remote (access|support|control))\b",
            r"\b(install|download)\b[^.]{0,30}\b(apk|app|application)\b[^.]{0,40}\b(link|from|click|below|verify|kyc|claim)\b",
            r"\.apk\b"]),
 dict(id="secrecy", name="Request to keep it secret", group="secrecy", points=14,
      why="Isolating the victim ('don't tell family/bank') is a core manipulation tactic.",
      pats=[r"\b(don'?t|do not|never)\b[^.]{0,20}\b(tell|inform)\b[^.]{0,20}\b(anyone|family|parents|bank|police)\b",
            r"\bkeep (this )?(confidential|secret)\b"]),
 dict(id="click_link", name="Prompt to click a link", group="link", points=6,
      why="Links in unsolicited messages are the main delivery route for phishing.",
      pats=[r"\b(click|tap|open|visit)\b[^.]{0,25}\b(link|below|here|url)\b", r"\blink click cheyandi\b"]),
 dict(id="informal_channel", name="Unprofessional contact channel", group="channel", points=6,
      why="Real recruiters use company email domains, not free mail or personal chat apps only.",
      pats=[r"\b(hr|career|recruit\w*|job|offer)\w*@(gmail|yahoo|outlook|hotmail)\.com\b",
            r"\b(whatsapp|telegram|dm|inbox)\b[^.]{0,25}\b(me|us|hr|now|only)\b[^.]{0,25}\b(for|to)\b[^.]{0,20}\b(job|work|join|apply|details)\b"]),
]
for r in R:
    r["c"] = [re.compile(p, F) for p in r["pats"]]


def _first_match(rule, t):
    for pat in rule["c"]:
        for m in pat.finditer(t):
            ctx = t[max(0, m.start() - 45): m.end()]
            if rule.get("exclude") and rule["exclude"].search(ctx):
                continue
            return m
    return None


def detect(text: str):
    """Returns (indicators, urls_found)."""
    t = collapse(text)
    inds = []
    for rule in R:
        m = _first_match(rule, t)
        if m:
            inds.append(Indicator(rule["id"], rule["name"], rule["group"], rule["points"],
                                  snippet(m.group(0)), rule["why"]))
    urls = extract_urls(t)
    worst = None
    for u in urls:
        info, uinds = analyze_url_indicators(u)
        # score of this url alone, group-deduped
        by = {}
        for i in uinds:
            by[i.group] = max(by.get(i.group, 0), i.points)
        s = sum(by.values())
        if s and (worst is None or s > worst[0]):
            worst = (s, u, uinds)
    if worst:
        s, u, uinds = worst
        top = ", ".join(i.name for i in sorted(uinds, key=lambda i: -i.points)[:3])
        inds.append(Indicator("suspicious_link", "Suspicious link structure", "link", min(22, max(7, round(s * 0.45))),
                              snippet(f"{u} → {top}", 140),
                              "The link shows structural warning signs (see Website Scanner for a full breakdown)."))
    return inds, urls
