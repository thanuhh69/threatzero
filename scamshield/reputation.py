"""Optional trusted reputation lookup (Google Safe Browsing v4). Disabled unless GOOGLE_SAFE_BROWSING_KEY is set.

The submitted URL is sent to Google's API as DATA only; it is never fetched by this app.
NOTE: this path needs a real API key and internet access and has not been exercised in the offline test suite.
"""
import json
import os
import urllib.request


def configured() -> bool:
    return bool(os.environ.get("GOOGLE_SAFE_BROWSING_KEY"))


def check(url: str, timeout: int = 6) -> dict:
    key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        return {"status": "not_configured"}
    body = {"client": {"clientId": "scamshield-bharat", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
    req = urllib.request.Request(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
                                 data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
        matches = data.get("matches", [])
        return {"status": "flagged" if matches else "no_match", "types": sorted({m["threatType"] for m in matches})}
    except Exception as e:  # network/API errors must never break the app
        return {"status": "error", "error": str(e)[:120]}
