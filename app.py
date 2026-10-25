import hashlib
import html
import os
import random
from datetime import date, datetime, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from scamshield import storage, ocr_engine, reputation
from scamshield.detector import analyze_text, analyze_url
from scamshield.reporting import build_assessment_pdf, build_incident_pdf
from scamshield.risk_engine import LEVEL_COLORS

ROOT = os.path.dirname(os.path.abspath(__file__))
NAVY, ROYAL = "#0B1F4B", "#1D4ED8"
LEVELS = ["Low", "Moderate", "High", "Critical"]
st.set_page_config(page_title="ScamShield Bharat", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")
storage.init_db()

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&display=swap');
html, body, [class*="css"], .stApp, button, input, textarea { font-family: 'Manrope', 'Segoe UI', system-ui, sans-serif !important; }
.stApp { background: #FFFFFF; color: #0F172A; }
#MainMenu, footer, [data-testid="stToolbar"], [data-testid="stDecoration"] { visibility: hidden; height: 0; }
.block-container { padding-top: 2rem; padding-bottom: 3rem; max-width: 1180px; }
section[data-testid="stSidebar"] { background: #F5F7FB; border-right: 1px solid #E3E8F2; }
h1, h2, h3 { color: #0B1F4B; letter-spacing: -0.01em; }
h1 { font-weight: 800; font-size: 2rem !important; }
.ss-sub { color: #5B6B86; margin: -0.4rem 0 1.4rem; font-size: 1.02rem; max-width: 70ch; }
.ss-card { background:#fff; border:1px solid #E3E8F2; border-radius:14px; padding:18px 20px; box-shadow:0 1px 3px rgba(11,31,75,.05); }
.ss-card.soft { background:#F5F7FB; box-shadow:none; }
.ss-hero { background:#fff; border:1px solid #E3E8F2; border-left:6px solid #1D4ED8; border-radius:14px; padding:26px 28px; box-shadow:0 2px 8px rgba(11,31,75,.06); }
.ss-hero h2 { margin:0 0 6px; font-size:1.55rem; font-weight:800; }
.ss-hero p { margin:0; color:#43526E; max-width:75ch; line-height:1.6; }
.ss-kpi .l { color:#5B6B86; font-size:.85rem; font-weight:600; }
.ss-kpi .v { color:#0B1F4B; font-size:2rem; font-weight:800; line-height:1.15; margin-top:2px; }
.ss-kpi .v.sm { font-size:1.15rem; line-height:1.5; padding-top:.4rem; }
.ss-kpi .h { color:#7A889F; font-size:.78rem; margin-top:2px; }
.ss-badge { display:inline-block; padding:4px 14px; border-radius:999px; font-weight:800; font-size:.95rem; }
.ss-ind { border:1px solid #E3E8F2; border-left:4px solid #1D4ED8; border-radius:10px; padding:12px 14px; margin-bottom:10px; background:#fff; }
.ss-ind .t { font-weight:700; color:#0B1F4B; display:flex; justify-content:space-between; gap:12px; }
.ss-ind .pts { font-weight:800; color:#1D4ED8; white-space:nowrap; }
.ss-ind .pts.z { color:#7A889F; font-weight:600; }
.ss-ind code { background:#F1F4FA; color:#0B1F4B; padding:2px 7px; border-radius:6px; font-size:.84rem; white-space:normal; word-break:break-word; }
.ss-ind .w { color:#43526E; font-size:.9rem; margin-top:6px; }
.ss-note { background:#F5F7FB; border:1px solid #E3E8F2; border-radius:10px; padding:12px 14px; color:#43526E; font-size:.88rem; line-height:1.55; }
.ss-warn { background:#FFF7E6; border:1px solid #F3D9A4; border-radius:10px; padding:12px 14px; color:#7A4B00; font-size:.9rem; }
.ss-rec li { margin-bottom:6px; line-height:1.55; }
div.stButton > button, div.stDownloadButton > button, div[data-testid="stFormSubmitButton"] > button { border-radius:10px; font-weight:700; border:1px solid #D5DCEB; padding:.5rem 1rem; }
div.stButton > button[kind="primary"], div[data-testid="stFormSubmitButton"] > button[kind="primary"], div.stDownloadButton > button[kind="primary"] { background:#1D4ED8; border-color:#1D4ED8; color:#fff; }
div.stButton > button[kind="primary"]:hover { background:#0B1F4B; border-color:#0B1F4B; }
textarea, input { border-radius:10px !important; }
:focus-visible { outline:3px solid #93B4FF !important; outline-offset:2px; }
@media (prefers-reduced-motion: reduce) { * { transition:none !important; animation:none !important; } }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)
st.logo(os.path.join(ROOT, "assets", "logo.svg"), size="large")


# ---------- helpers ----------
def e(x):
    return html.escape(str(x if x is not None else ""))


def header(title, sub):
    st.markdown(f"# {e(title)}")
    st.markdown(f"<div class='ss-sub'>{e(sub)}</div>", unsafe_allow_html=True)


def kpi(label, value, hint="", small=False):
    st.markdown(f"<div class='ss-card ss-kpi'><div class='l'>{e(label)}</div><div class='v{' sm' if small else ''}'>{e(value)}</div>"
                f"<div class='h'>{e(hint)}</div></div>", unsafe_allow_html=True)


def fig_style(fig, h=300):
    fig.update_layout(height=h, margin=dict(l=10, r=10, t=30, b=10), paper_bgcolor="white", plot_bgcolor="white",
                      font=dict(family="Manrope, sans-serif", color="#0F172A"), title_font=dict(size=14, color=NAVY),
                      legend_title_text="")
    fig.update_xaxes(gridcolor="#EEF2F8", zeroline=False)
    fig.update_yaxes(gridcolor="#EEF2F8", zeroline=False)
    return fig


def gauge(score, level):
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score, number={"font": {"size": 46, "color": NAVY}, "suffix": "/100"},
        gauge={"axis": {"range": [0, 100], "tickvals": [0, 25, 50, 75, 100], "tickcolor": "#7A889F"},
               "bar": {"color": LEVEL_COLORS[level], "thickness": 0.3}, "bgcolor": "white", "borderwidth": 0,
               "steps": [{"range": [0, 25], "color": "#E7F4EC"}, {"range": [25, 50], "color": "#FBF1DC"},
                         {"range": [50, 75], "color": "#FCE6DA"}, {"range": [75, 100], "color": "#F9DADA"}]}))
    fig.update_layout(height=215, margin=dict(l=25, r=25, t=15, b=0), paper_bgcolor="white", font=dict(family="Manrope, sans-serif"))
    return fig


def render_assessment(a, key, excerpt=""):
    c1, c2 = st.columns([1, 1.5], gap="large")
    with c1:
        st.plotly_chart(gauge(a["score"], a["level"]), key=f"g_{key}", config={"displayModeBar": False})
    with c2:
        col = LEVEL_COLORS[a["level"]]
        st.markdown(f"<span class='ss-badge' style='background:{col}1A;color:{col};border:1px solid {col}55'>{a['level']} risk</span>"
                    f"<div style='margin-top:12px;color:#5B6B86;font-size:.85rem'>Most likely category</div>"
                    f"<div style='font-weight:800;color:{NAVY};font-size:1.2rem'>{e(a['category'])}</div>"
                    f"<p style='margin-top:10px;color:#43526E;line-height:1.6'>{e(a['explanation'])}</p>", unsafe_allow_html=True)
    st.markdown("### Why this score")
    st.caption("Each signal shows the evidence found, why it matters and the points awarded. Related signals are counted once.")
    if not a["indicators"]:
        st.markdown("<div class='ss-note'>No known warning patterns were detected. This does not mean the content is safe.</div>", unsafe_allow_html=True)
    for i in a["indicators"]:
        counted = i["awarded"] > 0
        border = LEVEL_COLORS["High"] if i["awarded"] >= 20 else "#B45309" if i["awarded"] >= 10 else ROYAL
        pts = f"+{i['awarded']} pts" if counted else f"0 pts (related signal, {i['points']} counted once)"
        st.markdown(f"<div class='ss-ind' style='border-left-color:{border if counted else '#C9D2E3'}'>"
                    f"<div class='t'><span>{e(i['name'])}</span><span class='pts{'' if counted else ' z'}'>{e(pts)}</span></div>"
                    f"<div style='margin-top:6px'>Evidence: <code>{e(i['evidence'])}</code></div>"
                    f"<div class='w'>{e(i['why'])}</div></div>", unsafe_allow_html=True)
    st.markdown("### What to do now")
    st.markdown("<ul class='ss-rec'>" + "".join(f"<li>{e(r)}</li>" for r in a["recommendations"]) + "</ul>", unsafe_allow_html=True)
    st.markdown(f"<div class='ss-note'><b>Limitations.</b> {e(a['limitations'])}</div>", unsafe_allow_html=True)
    st.write("")
    st.download_button("Download PDF assessment", build_assessment_pdf(a, excerpt), file_name=f"scamshield_assessment_{key}.pdf",
                       mime="application/pdf", icon=":material/download:", type="primary", key=f"dl_{key}")


def samples_df():
    return pd.read_csv(os.path.join(ROOT, "data", "sample_cases.csv"))


SAMPLE_URLS = {"Lookalike bank login (HTTP)": "http://hdfc-secure-login.top/verify/account",
               "Payment app lookalike": "http://paytrn-kyc-update.xyz/login",
               "IP-address login page": "http://192.168.10.5/bank/login.php",
               "Deceptive '@' structure": "https://www.google.com@free-bonus-claim.click/win",
               "Shortened link": "https://bit.ly/3AbCdEf",
               "Official bank website": "https://www.sbi.co.in/web/personal-banking"}


def load_demo():
    rnd = random.Random(7)
    df = samples_df()
    n = 0
    for _, r in df.iterrows():
        a = analyze_text(r["text"], rnd.choice(["WhatsApp message", "SMS", "Email", "Job offer"]))
        a["created_at"] = (datetime.now() - timedelta(days=rnd.randint(0, 13), hours=rnd.randint(0, 20))).isoformat(timespec="seconds")
        storage.save_scan(a, r["text"], source="demo")
        n += 1
    for u in SAMPLE_URLS.values():
        a = analyze_url(u)
        a["created_at"] = (datetime.now() - timedelta(days=rnd.randint(0, 13))).isoformat(timespec="seconds")
        storage.save_scan(a, u, source="demo")
        n += 1
    return n


def charts(stats, key):
    c1, c2 = st.columns(2, gap="medium")
    with c1:
        cats = {k: v for k, v in stats["categories"].items()}
        if cats:
            d = pd.DataFrame({"Category": list(cats), "Scans": list(cats.values())}).sort_values("Scans")
            f = px.bar(d, x="Scans", y="Category", orientation="h", title="Fraud category distribution", color_discrete_sequence=[ROYAL])
            st.plotly_chart(fig_style(f, 340), key=f"cat_{key}", config={"displayModeBar": False})
    with c2:
        lv = stats["levels"]
        if lv:
            d = pd.DataFrame({"Level": LEVELS, "Scans": [lv.get(x, 0) for x in LEVELS]})
            f = px.bar(d, x="Level", y="Scans", color="Level", color_discrete_map=LEVEL_COLORS, title="Risk-level distribution")
            f.update_layout(showlegend=False)
            st.plotly_chart(fig_style(f, 340), key=f"lvl_{key}", config={"displayModeBar": False})


def hist_df(rows):
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df["created_at"] = df["created_at"].str.replace("T", " ")
    df = df.rename(columns={"id": "ID", "created_at": "Time", "input_type": "Type", "category": "Category", "score": "Score",
                            "level": "Level", "input_excerpt": "Excerpt (redacted)", "source": "Source"})
    return df[["ID", "Time", "Type", "Category", "Score", "Level", "Source", "Excerpt (redacted)"]]


# ---------- pages ----------
def page_overview():
    st.markdown("<div class='ss-hero'><h2>Welcome to ScamShield Bharat</h2><p>Paste a suspicious message, check a link or upload a "
                "screenshot. ScamShield looks for known warning patterns used in job, betting, investment, payment and phishing scams, "
                "shows exactly what it found and why, and tells you what to do next. It gives an indicative risk index - never a guarantee "
                "that something is fraudulent or safe.</p></div>", unsafe_allow_html=True)
    st.write("")
    s = storage.dashboard_stats()
    k = st.columns(4, gap="medium")
    with k[0]: kpi("Total scans", s["total"], "all scanners")
    with k[1]: kpi("High-risk detections", s["high"], "score 50-74")
    with k[2]: kpi("Critical-risk detections", s["critical"], "score 75-100")
    with k[3]: kpi("Most frequent category", s["top_category"] or "No data yet", "among flagged scans", small=True)
    st.markdown("### Start a scan")
    q = st.columns(4, gap="medium")
    if q[0].button("Scan a message", icon=":material/chat:", width="stretch", type="primary"): st.switch_page(P_MSG)
    if q[1].button("Check a website", icon=":material/language:", width="stretch"): st.switch_page(P_URL)
    if q[2].button("Upload a screenshot", icon=":material/image:", width="stretch"): st.switch_page(P_IMG)
    if q[3].button("I lost money", icon=":material/support_agent:", width="stretch"): st.switch_page(P_INC)
    if s["total"] == 0:
        st.markdown("<div class='ss-note' style='margin-top:18px'><b>No scans yet.</b> Run your first scan above, or load the synthetic "
                    "demo scans (63 sample messages + 6 URLs run through the real engine) to preview the dashboards.</div>", unsafe_allow_html=True)
        if st.button("Load demo scans", icon=":material/science:"):
            st.success(f"Analysed and stored {load_demo()} demo scans (marked source = demo).")
            st.rerun()
        return
    charts(s, "ov")
    st.markdown("### Recent activity")
    st.dataframe(hist_df(storage.get_history(limit=8)), hide_index=True)
    if st.button("Remove demo scans", icon=":material/delete:"):
        st.toast(f"Removed {storage.clear_demo()} demo scans")
        st.rerun()


def page_message():
    header("AI message scanner", "Paste a WhatsApp/SMS/email message, job or investment offer. English and Telugu-English mixed text are supported.")
    df = samples_df()
    labels = [f"{r.category if r.is_fraud else 'Legitimate'}: {r.text[:60]}…" for r in df.itertuples()]
    c1, c2 = st.columns([4, 1], gap="small")
    pick = c1.selectbox("Demo sample (synthetic)", range(len(df)), format_func=lambda i: labels[i], key="msg_pick")
    c2.write(""); c2.write("")
    c2.button("Load sample", width="stretch", on_click=lambda: st.session_state.update(msg_text=df.text.iloc[st.session_state.msg_pick]))
    kind = st.selectbox("Message type", ["WhatsApp message", "SMS", "Email", "Job offer", "Investment / betting offer", "Payment request", "Other"], key="msg_kind")
    text = st.text_area("Message text", height=200, key="msg_text", placeholder="Paste the suspicious message here…")
    st.markdown("<div class='ss-warn'>Do not paste OTPs, PINs, CVVs or passwords. Phone and card numbers are masked before anything is saved.</div>", unsafe_allow_html=True)
    st.write("")
    if st.button("Analyse message", type="primary", icon=":material/security:"):
        try:
            a = analyze_text(text, kind)
            sid = storage.save_scan(a, text)
            st.session_state["msg_res"] = (a, sid, text)
        except ValueError as ex:
            st.error(str(ex))
    if "msg_res" in st.session_state:
        a, sid, t = st.session_state["msg_res"]
        st.divider()
        st.caption(f"Saved to scan history as #{sid}")
        render_assessment(a, f"msg{sid}", storage.get_scan(sid)["input_excerpt"])


def page_url():
    header("Website fraud scanner", "Checks the structure of a link. The page is never opened or fetched.")
    c1, c2 = st.columns([4, 1])
    c1.selectbox("Demo URL", list(SAMPLE_URLS), key="url_pick")
    c2.write(""); c2.write("")
    c2.button("Load sample", width="stretch", key="url_load", on_click=lambda: st.session_state.update(url_in=SAMPLE_URLS[st.session_state.url_pick]))
    url = st.text_input("URL to check", key="url_in", placeholder="https://example.com/login")
    if st.button("Analyse URL", type="primary", icon=":material/travel_explore:"):
        try:
            a = analyze_url(url)
            sid = storage.save_scan(a, url)
            rep = reputation.check(url) if reputation.configured() else {"status": "not_configured"}
            st.session_state["url_res"] = (a, sid, url, rep)
        except ValueError as ex:
            st.error(str(ex))
    if "url_res" in st.session_state:
        a, sid, u, rep = st.session_state["url_res"]
        info = a["url_info"] or {}
        st.divider()
        st.markdown("### Extracted URL information")
        if info.get("valid"):
            rows = [("Registered domain", info["registered_domain"]), ("Hostname", info["hostname"]), ("Scheme", info["scheme"]),
                    ("Path", info["path"] or "/"), ("Port", info["port"] or "default"), ("Top-level domain", info["tld"] or "n/a (IP)"),
                    ("Subdomain levels", info["subdomain_count"]), ("Length", f"{info['length']} characters")]
            st.dataframe(pd.DataFrame(rows, columns=["Field", "Value"]).astype(str), hide_index=True)
        rs = {"not_configured": "Not configured (no API key set) - not checked", "no_match": "No match in Google Safe Browsing (does not prove safety)",
              "flagged": "Flagged by Google Safe Browsing: " + ", ".join(rep.get("types", [])), "error": "Lookup failed: " + rep.get("error", "")}[rep["status"]]
        st.markdown(f"<div class='ss-note'><b>Verification status.</b> DNS resolution: not performed. Domain ownership (WHOIS): not performed. "
                    f"Site content: not visited. Reputation service: {e(rs)}. A clean result here only means no structural warning signs were found.</div>", unsafe_allow_html=True)
        st.write("")
        render_assessment(a, f"url{sid}", u)


def page_image():
    header("Screenshot fraud scanner", "Upload a screenshot of a chat, SMS or offer. Text is extracted on this machine and analysed like a message.")
    stt = ocr_engine.status()
    engine = "EasyOCR" if stt["easyocr"] else "Tesseract" if stt["tesseract"] else None
    if engine:
        st.caption(f"OCR engine available: {engine}. You can always correct the extracted text before analysing.")
    else:
        st.markdown("<div class='ss-warn'>No OCR engine is installed here. Upload still works - type or paste the text visible in the screenshot below.</div>", unsafe_allow_html=True)
    up = st.file_uploader("Screenshot (PNG, JPG, JPEG)", type=["png", "jpg", "jpeg"], key="img_up")
    if up is not None:
        data = up.getvalue()
        h = hashlib.sha1(data).hexdigest()
        c1, c2 = st.columns([1, 1.2], gap="large")
        c1.image(data, caption=up.name)
        if st.session_state.get("ocr_hash") != h:
            st.session_state["ocr_hash"] = h
            if engine:
                with st.spinner("Reading text from the screenshot…"):
                    txt, used, err = ocr_engine.extract_text(data)
                st.session_state["ocr_text"] = txt
                st.session_state["ocr_info"] = f"Extracted with {used}." if used else f"OCR failed ({err}). Paste the text manually."
            else:
                st.session_state["ocr_text"] = ""
                st.session_state["ocr_info"] = "Manual entry mode."
            st.session_state.pop("img_res", None)
        with c2:
            st.caption(st.session_state.get("ocr_info", ""))
            st.text_area("Text found in the screenshot (editable)", height=260, key="ocr_text")
            if st.button("Analyse extracted text", type="primary", icon=":material/security:"):
                try:
                    a = analyze_text(st.session_state["ocr_text"], "Screenshot (OCR text)")
                    sid = storage.save_scan(a, st.session_state["ocr_text"])
                    st.session_state["img_res"] = (a, sid)
                except ValueError:
                    st.error("No text to analyse. OCR found nothing - paste the visible text above.")
    if "img_res" in st.session_state and up is not None:
        a, sid = st.session_state["img_res"]
        st.divider()
        st.caption(f"Saved to scan history as #{sid}")
        render_assessment(a, f"img{sid}", storage.get_scan(sid)["input_excerpt"])


def page_intel():
    header("Fraud intelligence", "Patterns across everything scanned on this installation. All figures come from the local database.")
    all_rows = storage.get_history(limit=100000)
    if not all_rows:
        st.markdown("<div class='ss-note'>No data yet. Run a scan, or load demo scans from the Overview page.</div>", unsafe_allow_html=True)
        return
    f = st.columns(4, gap="small")
    d_min = min(r["created_at"][:10] for r in all_rows)
    rng = f[0].date_input("Date range", (date.fromisoformat(d_min), date.today()), key="f_rng")
    f_type = f[1].selectbox("Input type", ["All"] + sorted({r["input_type"] for r in all_rows}), key="f_type")
    f_lvl = f[2].selectbox("Risk level", ["All"] + LEVELS, key="f_lvl")
    f_cat = f[3].selectbox("Category", ["All"] + sorted({r["category"] for r in all_rows}), key="f_cat")
    start, end = (rng[0], rng[1]) if isinstance(rng, (tuple, list)) and len(rng) == 2 else (rng, rng) if not isinstance(rng, (tuple, list)) else (rng[0], date.today())
    flt = dict(start=start, end=end, input_type=f_type, level=f_lvl, category=f_cat)
    s = storage.dashboard_stats(**flt)
    k = st.columns(4, gap="medium")
    with k[0]: kpi("Scans in view", s["total"])
    with k[1]: kpi("Average risk index", s["avg_score"], "out of 100")
    with k[2]: kpi("High + Critical", s["high"] + s["critical"])
    with k[3]: kpi("Top flagged category", s["top_category"] or "n/a", small=True)
    if s["total"] == 0:
        st.info("No scans match these filters.")
        return
    charts(s, "in")
    rows = storage.get_history(limit=100000, **flt)
    c1, c2 = st.columns(2, gap="medium")
    with c1:
        ind = storage.indicator_counts(10, **flt)
        if ind:
            d = pd.DataFrame(ind).sort_values("n")
            fg = px.bar(d, x="n", y="name", orientation="h", title="Most common warning indicators", color_discrete_sequence=[NAVY], labels={"n": "Scans", "name": ""})
            st.plotly_chart(fig_style(fg, 340), key="ind_chart", config={"displayModeBar": False})
    with c2:
        d = pd.DataFrame(rows)
        d["day"] = d["created_at"].str[:10]
        t = d.groupby(["day", "level"]).size().reset_index(name="Scans")
        fg = px.bar(t, x="day", y="Scans", color="level", color_discrete_map=LEVEL_COLORS, title="Scans per day", labels={"day": ""},
                    category_orders={"level": LEVELS})
        st.plotly_chart(fig_style(fg, 340), key="time_chart", config={"displayModeBar": False})
    st.markdown("### Recent suspicious activity")
    sus = [r for r in rows if r["level"] in ("High", "Critical")][:8]
    st.dataframe(hist_df(sus), hide_index=True) if sus else st.caption("No high or critical scans in this view.")
    st.markdown("### Scan history")
    hd = hist_df(rows)
    st.dataframe(hd, hide_index=True)
    st.download_button("Export history (CSV)", hd.to_csv(index=False).encode(), "scamshield_history.csv", "text/csv", icon=":material/download:")


def page_incident():
    header("Incident assistance", "If you have been targeted or lost money, organise your details here and get a summary to take to your bank and the police.")
    st.markdown("<div class='ss-card' style='border-left:6px solid #B91C1C'><b>Act quickly if money was transferred.</b><br>"
                "Call <b>1930</b> (cyber financial fraud helpline) now, then report at "
                "<a href='https://cybercrime.gov.in/' target='_blank'>cybercrime.gov.in</a> (National Cyber Crime Reporting Portal). "
                "ScamShield Bharat does <b>not</b> submit complaints for you.</div>", unsafe_allow_html=True)
    st.write("")
    st.markdown("<div class='ss-warn'>Never enter OTPs, passwords, UPI PINs, CVVs or full card/bank credentials here.</div>", unsafe_allow_html=True)
    st.write("")
    with st.form("incident"):
        c1, c2, c3 = st.columns(3)
        cat = c1.selectbox("Incident category", ["Fake job / work-from-home", "Part-time task scam", "Fake internship", "Betting / gaming", "Investment fraud",
                                                 "UPI / payment fraud", "Phishing / fake website", "Scholarship / education", "Impersonation (police, bank, courier)", "Other"])
        when = c2.date_input("Incident date", date.today(), max_value=date.today())
        loss = c3.number_input("Approximate financial loss (INR)", min_value=0.0, step=500.0, format="%.2f")
        desc = st.text_area("What happened? (brief description)", height=130)
        urls = st.text_area("Relevant URLs (one per line)", height=70)
        notes = st.text_area("Evidence notes (screenshots kept, transaction IDs, phone numbers or UPI IDs involved)", height=90)
        go_ = st.form_submit_button("Create incident summary", type="primary", icon=":material/description:")
    if go_:
        if not desc.strip():
            st.error("Please add a brief description of what happened.")
        else:
            d = dict(category=cat, incident_date=when, loss_amount=loss, description=desc, urls=urls, evidence_notes=notes)
            st.session_state["inc"] = (storage.save_incident(d), d)
    if "inc" in st.session_state:
        iid, d = st.session_state["inc"]
        st.success(f"Summary created and saved locally as #{iid}. It has not been sent to any authority.")
        st.markdown(f"<div class='ss-card'><b>{e(d['category'])}</b> · {e(d['incident_date'])} · approx. loss INR {d['loss_amount']:,.2f}"
                    f"<p style='margin:.6rem 0 0;color:#43526E'>{e(d['description'])}</p></div>", unsafe_allow_html=True)
        st.write("")
        st.download_button("Download incident summary (PDF)", build_incident_pdf(d), f"incident_summary_{iid}.pdf", "application/pdf",
                           type="primary", icon=":material/download:")
        st.markdown("### Next steps")
        st.markdown("1. Call **1930** immediately if money moved.\n2. File a complaint at **https://cybercrime.gov.in/** and keep the acknowledgement number.\n"
                    "3. Tell your bank/UPI provider in writing and request a dispute reference.\n4. Keep all chats, screenshots, transaction IDs and URLs.\n"
                    "5. Change passwords of any account you may have exposed.")


P_OV = st.Page(page_overview, title="Overview", icon=":material/dashboard:", default=True, url_path="overview")
P_MSG = st.Page(page_message, title="Message scanner", icon=":material/chat:", url_path="message")
P_URL = st.Page(page_url, title="Website scanner", icon=":material/language:", url_path="website")
P_IMG = st.Page(page_image, title="Screenshot scanner", icon=":material/image:", url_path="screenshot")
P_INT = st.Page(page_intel, title="Fraud intelligence", icon=":material/monitoring:", url_path="intelligence")
P_INC = st.Page(page_incident, title="Incident assistance", icon=":material/support_agent:", url_path="incident")
nav = st.navigation([P_OV, P_MSG, P_URL, P_IMG, P_INT, P_INC])
with st.sidebar:
    st.markdown("<div style='color:#5B6B86;font-size:.8rem;line-height:1.5;margin-top:1rem'>Detect Early. Stay Safe. Stay Protected.<br>"
                "Helpline <b>1930</b> · <a href='https://cybercrime.gov.in/' target='_blank'>cybercrime.gov.in</a></div>", unsafe_allow_html=True)
_test_page = os.environ.get("SCAMSHIELD_TEST_PAGE")  # test hook used by AppTest only
if _test_page:
    globals()[_test_page]()
else:
    nav.run()
