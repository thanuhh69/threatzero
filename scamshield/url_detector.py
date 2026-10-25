"""Offline URL structure analysis. NEVER fetches the URL (no SSRF, no malicious page execution)."""
import ipaddress
import re
from urllib.parse import urlsplit, unquote

from .risk_engine import Indicator
from .utils import snippet

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly",
              "buff.ly", "tiny.cc", "rebrand.ly", "t.ly", "s.id", "v.gd", "bl.ink", "lnkd.in", "shrtco.de"}
MULTI_TLDS = {"co.in", "org.in", "gov.in", "nic.in", "ac.in", "net.in", "res.in", "co.uk", "com.au", "org.uk", "co.za"}
SUSPICIOUS_TLDS = {"xyz", "top", "tk", "click", "buzz", "work", "cf", "gq", "ml", "ga", "icu", "live", "vip", "bet",
                   "win", "club", "fun", "cyou", "rest", "monster", "loan", "zip", "mov"}
SUSPICIOUS_WORDS_LONG = ["login", "verify", "verification", "secure", "security", "update", "bonus", "claim",
                         "reward", "refund", "cashback", "lottery", "prize", "winner", "jackpot", "invest",
                         "betting", "income", "support", "official", "account", "banking", "wallet", "airdrop"]
SUSPICIOUS_WORDS_SHORT = {"kyc", "bet", "win", "free", "gift", "earn", "loan", "otp", "pay", "upi", "job", "jobs"}

BRAND_DOMAINS = {
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"}, "hdfc": {"hdfcbank.com", "hdfc.com"},
    "hdfcbank": {"hdfcbank.com"}, "icici": {"icicibank.com"}, "icicibank": {"icicibank.com"},
    "axisbank": {"axisbank.com"}, "kotak": {"kotak.com"}, "paytm": {"paytm.com"}, "phonepe": {"phonepe.com"},
    "gpay": {"pay.google.com", "google.com"}, "googlepay": {"pay.google.com", "google.com"},
    "amazon": {"amazon.in", "amazon.com", "amazonaws.com"}, "flipkart": {"flipkart.com"},
    "irctc": {"irctc.co.in"}, "uidai": {"uidai.gov.in"}, "aadhaar": {"uidai.gov.in"}, "npci": {"npci.org.in"},
    "rbi": {"rbi.org.in"}, "incometax": {"incometax.gov.in"}, "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "telegram": {"telegram.org", "t.me"}, "google": {"google.com", "googleapis.com", "gstatic.com",
                                                    "googleusercontent.com"},
    "naukri": {"naukri.com"}, "linkedin": {"linkedin.com"}, "myntra": {"myntra.com"},
}
OFFICIAL = set().union(*BRAND_DOMAINS.values()) | {"cybercrime.gov.in", "india.gov.in", "indeed.com", "swiggy.com",
                                                   "zomato.com", "microsoft.com", "github.com", "wikipedia.org"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t"})


def registered_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _I(id_, name, group, pts, ev, why):
    return Indicator(id_, name, group, pts, snippet(ev), why)


def parse_url(raw: str) -> dict:
    raw = (raw or "").strip()
    scheme_given = bool(re.match(r"(?i)^[a-z][a-z0-9+.\-]*://", raw))
    url = raw if scheme_given else "http://" + raw.lstrip("/")
    info = {"input": raw, "scheme_given": scheme_given, "valid": False}
    try:
        sp = urlsplit(url)
        host = (sp.hostname or "").lower().rstrip(".")
        port = sp.port
    except ValueError:
        return info
    if not host:
        return info
    info.update(valid=True, scheme=sp.scheme.lower() if scheme_given else "(not specified)", hostname=host,
                port=port, username=sp.username, path=sp.path, query=sp.query, length=len(raw))
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        if re.fullmatch(r"\d{8,10}|0x[0-9a-f]+", host):
            is_ip = True
    info["is_ip"] = is_ip
    info["registered_domain"] = host if is_ip else registered_domain(host)
    labels = host.split(".")
    info["tld"] = "" if is_ip else labels[-1]
    info["subdomain_count"] = 0 if is_ip else max(0, len(labels) - len(info["registered_domain"].split(".")))
    return info


def analyze_url_indicators(raw: str):
    """Returns (info, [Indicator])."""
    info = parse_url(raw)
    inds = []
    if not info["valid"]:
        inds.append(_I("url_malformed", "Malformed or unparseable URL", "malformed", 15, raw,
                       "Deceptive links are often malformed or crafted to confuse parsers."))
        return info, inds
    host, reg = info["hostname"], info["registered_domain"]
    is_ip = info["is_ip"]
    path_q = unquote(info["path"] + "?" + info["query"])

    if info["scheme_given"] and info["scheme"] == "http":
        inds.append(_I("url_http", "Unencrypted HTTP connection", "transport", 10, "http://",
                       "Legitimate login/payment pages use HTTPS. (HTTPS alone does not prove a site is safe.)"))
    if info["username"] is not None:
        inds.append(_I("url_userinfo", "Embedded credentials / deceptive '@' structure", "deceptive", 28,
                       f"'{info['username']}@' before host '{host}'",
                       "Text before '@' is ignored by browsers; attackers use it to disguise the real destination."))
    if is_ip:
        inds.append(_I("url_ip", "IP-address-based URL", "host_type", 28, host,
                       "Legitimate services rarely ask users to log in or pay on a raw IP address."))
    if reg in SHORTENERS:
        inds.append(_I("url_shortener", "URL shortener hides the destination", "shortener", 15, reg,
                       "Shorteners conceal where a link leads; fraud messages use them frequently."))
    if not is_ip:
        if len(host) > 30:
            inds.append(_I("url_long_host", "Unusually long hostname", "length", 8, f"{len(host)} characters: {host}",
                           "Long hostnames are used to bury lookalike words and push the real domain out of view."))
        if host.count("-") >= 2:
            inds.append(_I("url_hyphens", "Multiple hyphens in hostname", "hyphens", 10, host,
                           "Hyphen-chained names (e.g. brand-secure-login) are a common lookalike pattern."))
        if info["subdomain_count"] >= 3:
            inds.append(_I("url_subdomains", "Many subdomain levels", "subdomain", 8, host,
                           "Deep subdomains can make a malicious domain appear to contain a trusted name."))
        if info["tld"] in SUSPICIOUS_TLDS:
            inds.append(_I("url_tld", f"Domain ending '.{info['tld']}' is frequently abused", "tld", 10, host,
                           "Some low-cost top-level domains are disproportionately used in scams. Not proof by itself."))
        tokens = [t for t in re.split(r"[.\-]", host) if t]
        words = sorted({w for w in SUSPICIOUS_WORDS_LONG if any(w in t for t in tokens)} |
                       {t for t in tokens if t in SUSPICIOUS_WORDS_SHORT})
        if words:
            inds.append(_I("url_keywords", "Suspicious words in domain name", "keywords", 12, ", ".join(words),
                           "Words like login, verify, claim or bonus are used to create false trust or urgency."))
        if host.startswith("xn--") or ".xn--" in host or any(ord(c) > 127 for c in host):
            inds.append(_I("url_idn", "Internationalised (punycode/non-ASCII) domain", "lookalike", 22, host,
                           "Look-alike characters from other alphabets can imitate well-known brands."))
        norm = host.translate(LEET).replace("rn", "m").replace("vv", "w")
        ntokens = [t for t in re.split(r"[.\-]", norm) if t]
        label_norm = registered_domain(norm).split(".")[0]
        hit = None
        for brand, official in BRAND_DOMAINS.items():
            if reg in official or reg in OFFICIAL:
                continue
            for t in ntokens:
                if t == brand or (len(brand) >= 4 and (t.startswith(brand) or t.endswith(brand))):
                    hit = (brand, f"hostname contains '{brand}' but registered domain is '{reg}'", 25)
                    break
            if not hit and len(brand) >= 5 and label_norm != brand and _lev(label_norm, brand) <= 1:
                hit = (brand, f"'{reg}' is one character away from '{brand}'", 28)
            if hit:
                break
        if hit:
            inds.append(_I("url_lookalike", f"Possible lookalike of '{hit[0]}'", "lookalike", hit[2], hit[1],
                           "Attackers register near-copies of trusted brand names. Verify the official domain independently."))
    if info["port"] not in (None, 80, 443):
        inds.append(_I("url_port", "Non-standard port", "port", 6, f":{info['port']}",
                       "Unusual ports are uncommon on consumer-facing legitimate sites."))
    if re.search(r"\.apk\b", path_q, re.I):
        inds.append(_I("url_apk", "Link points to an APK (Android app file)", "download", 20, path_q[:60],
                       "Fraudsters push APK files that can steal SMS/OTP data or give remote control."))
    if re.search(r"(?i)[?&](url|redirect|redir|next|goto|link|dest)=https?", info["query"] or ""):
        inds.append(_I("url_redirect", "Embedded redirect to another URL", "deceptive", 10, info["query"][:60],
                       "Open redirects are used to hide the final destination behind a trusted-looking domain."))
    if len(info["input"]) > 120:
        inds.append(_I("url_long", "Very long URL", "length", 5, f"{len(info['input'])} characters",
                       "Long URLs can hide the true destination or carry tracking/phishing parameters."))
    if len(re.findall(r"%[0-9a-fA-F]{2}", info["input"])) >= 5:
        inds.append(_I("url_encoding", "Heavy percent-encoding", "encoding", 6, info["input"][:60],
                       "Heavy encoding can be used to obscure suspicious content."))
    return info, inds
