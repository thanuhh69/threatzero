"""PDF generation with ReportLab (assessment reports and incident summaries)."""
import io
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, KeepTogether

from .risk_engine import LEVEL_COLORS, LIMITATIONS

NAVY, ROYAL, GREY, BORDER = colors.HexColor("#0B1F4B"), colors.HexColor("#1D4ED8"), colors.HexColor("#F5F7FB"), colors.HexColor("#DDE3EF")
_ss = getSampleStyleSheet()
BODY = ParagraphStyle("b", parent=_ss["BodyText"], fontName="Helvetica", fontSize=9.5, leading=13.5, alignment=TA_LEFT)
SMALL = ParagraphStyle("s", parent=BODY, fontSize=8, leading=11, textColor=colors.HexColor("#5B6B86"))
H2 = ParagraphStyle("h2", parent=BODY, fontName="Helvetica-Bold", fontSize=12, textColor=NAVY, spaceBefore=10, spaceAfter=4)
CELL = ParagraphStyle("c", parent=BODY, fontSize=8.5, leading=11)


def _p(t, st=BODY):
    return Paragraph(escape(str(t or "")), st)


def _header(story, title):
    brand = Table([[Paragraph('<font color="white"><b>SCAMSHIELD BHARAT</b></font>',
                              ParagraphStyle("x", parent=BODY, fontSize=15, leading=18)),
                    Paragraph('<font color="#BFD0F5">Detect Early. Stay Safe. Stay Protected.</font>',
                              ParagraphStyle("y", parent=BODY, fontSize=8.5, alignment=2))]],
                  colWidths=[95 * mm, 75 * mm])
    brand.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), NAVY), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                               ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                               ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
    story += [brand, Spacer(1, 8), Paragraph(f"<b>{escape(title)}</b>", ParagraphStyle("t", parent=BODY, fontSize=16, leading=20, textColor=NAVY))]


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#5B6B86"))
    canvas.drawString(20 * mm, 10 * mm, "ScamShield Bharat - indicative risk assessment, not a legal or forensic finding.")
    canvas.drawRightString(190 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _build(story):
    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=15 * mm,
                      bottomMargin=18 * mm, title="ScamShield Bharat Report").build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


def build_assessment_pdf(a: dict, input_excerpt: str = "") -> bytes:
    story = []
    _header(story, "Fraud Risk Assessment")
    story.append(Spacer(1, 6))
    lvl_color = colors.HexColor(LEVEL_COLORS.get(a["level"], "#1D4ED8"))
    summ = Table([[_p("Assessment date", SMALL), _p("Input type", SMALL), _p("Likely category", SMALL),
                   _p("Risk index", SMALL), _p("Risk level", SMALL)],
                  [_p(a.get("created_at", datetime.now().isoformat(timespec="seconds")).replace("T", " "), CELL),
                   _p(a["input_type"], CELL), _p(a["category"], CELL),
                   Paragraph(f"<b>{a['score']} / 100</b>", CELL),
                   Paragraph(f'<font color="{LEVEL_COLORS.get(a["level"])}"><b>{a["level"]}</b></font>', CELL)]],
                 colWidths=[33 * mm, 27 * mm, 50 * mm, 25 * mm, 25 * mm])
    summ.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), GREY), ("BOX", (0, 0), (-1, -1), .6, BORDER),
                              ("LINEBELOW", (0, 0), (-1, 0), .3, BORDER), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                              ("LINEBEFORE", (0, 0), (0, -1), 3, lvl_color)]))
    story += [summ, Paragraph("Explanation", H2), _p(a["explanation"])]
    if input_excerpt:
        story += [Paragraph("Analysed content (redacted excerpt)", H2), _p(input_excerpt, SMALL)]
    story.append(Paragraph("Detected warning indicators", H2))
    inds = a.get("indicators") or []
    if inds:
        rows = [[_p("Indicator", CELL), _p("Evidence found", CELL), _p("Why it matters", CELL), _p("Pts", CELL)]]
        for i in inds:
            rows.append([_p(i["name"], CELL), _p(i["evidence"], CELL), _p(i["why"], CELL),
                         _p(f"{i['awarded']}" + ("" if i["awarded"] == i["points"] else f" (of {i['points']}, counted once)"), CELL)])
        t = Table(rows, colWidths=[38 * mm, 42 * mm, 70 * mm, 20 * mm], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8EEFB")), ("GRID", (0, 0), (-1, -1), .4, BORDER),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]))
        story.append(t)
    else:
        story.append(_p("No known warning patterns detected. This does not guarantee safety."))
    story.append(Paragraph("Recommended safety actions", H2))
    for r in a.get("recommendations", []):
        story.append(Paragraph("&bull; " + escape(r), BODY))
    story += [Paragraph("Important limitations", H2), _p(a.get("limitations") or LIMITATIONS, SMALL),
              Spacer(1, 6), _p("If you have lost money: call 1930 (cyber financial fraud helpline) and report at "
                               "https://cybercrime.gov.in/ . ScamShield Bharat does not file complaints on your behalf.", SMALL)]
    return _build(story)


def build_incident_pdf(d: dict) -> bytes:
    story = []
    _header(story, "Incident Summary")
    story.append(Spacer(1, 6))
    rows = [("Prepared on", datetime.now().strftime("%Y-%m-%d %H:%M")), ("Incident category", d.get("category", "")),
            ("Incident date", str(d.get("incident_date", ""))),
            ("Approximate financial loss", f"INR {float(d.get('loss_amount') or 0):,.2f}")]
    t = Table([[_p(k, SMALL), _p(v, CELL)] for k, v in rows], colWidths=[50 * mm, 120 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), GREY), ("GRID", (0, 0), (-1, -1), .4, BORDER), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [t, Paragraph("Incident description", H2), _p(d.get("description") or "-"),
              Paragraph("Relevant URLs", H2), _p(d.get("urls") or "-"),
              Paragraph("Evidence notes", H2), _p(d.get("evidence_notes") or "-"),
              Paragraph("Suggested next steps", H2)]
    for s in ["Call 1930 (National cyber financial fraud helpline) immediately if money was transferred - early reporting improves the chance of a freeze.",
              "File a complaint at the National Cyber Crime Reporting Portal: https://cybercrime.gov.in/",
              "Inform your bank/UPI app in writing and ask for a transaction dispute reference number.",
              "Preserve evidence: screenshots, chat exports, transaction IDs, phone numbers, UPI IDs, URLs. Do not delete chats.",
              "Do not share OTPs, PINs, CVVs or passwords with anyone, including people who claim to help recover your money."]:
        story.append(Paragraph("&bull; " + escape(s), BODY))
    story += [Spacer(1, 8), _p("This summary was prepared by the user with the help of ScamShield Bharat to organise information. "
                               "It is not an official complaint and has not been submitted to any authority.", SMALL)]
    return _build(story)
