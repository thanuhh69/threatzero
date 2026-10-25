import re
import unicodedata

TLDS = ("com|in|co|net|org|xyz|top|click|link|live|vip|online|site|info|me|ly|gl|to|cc|tk|ml|ga|cf|gq|icu|"
        "buzz|work|shop|store|app|apk|bet|win|club|fun|cloud|page")
URL_RE = re.compile(
    r"(?i)(?<![@\w.\-])((?:https?://|www\.)[^\s<>\"'()]+|(?:[a-z0-9\-]+\.)+(?:" + TLDS + r")\b(?:/[^\s<>\"'()]*)?)")


def collapse(text: str) -> str:
    """Unicode-normalise and collapse whitespace (keeps case; regexes use re.I)."""
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text or "")).strip()


def extract_urls(text: str) -> list:
    seen, out = set(), []
    for m in URL_RE.finditer(text or ""):
        u = m.group(1).rstrip(".,;:!?)")
        if u.lower() not in seen:
            seen.add(u.lower())
            out.append(u)
    return out


def snippet(s: str, limit: int = 110) -> str:
    s = collapse(s)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def redact(text: str, limit: int = 300) -> str:
    """Privacy: mask long digit runs (phones, card/Aadhaar numbers, OTPs) before storing."""
    t = collapse(text)
    t = re.sub(r"\d(?:[\s\-]?\d){5,}", "[number]", t)
    t = re.sub(r"[\w.\-]+@(?!ok|ybl|ibl|axl|paytm|upi|apl)[\w\-]+\.[\w.]+", "[email]", t)
    return t[:limit]
