import os
from scamshield.detector import analyze_text
from scamshield.reporting import build_assessment_pdf, build_incident_pdf
from scamshield import storage


def test_assessment_pdf_valid():
    a = analyze_text("Pay Rs 999 registration fee to get your work from home job. Hurry!")
    pdf = build_assessment_pdf(a, "excerpt")
    assert pdf.startswith(b"%PDF") and len(pdf) > 2000


def test_incident_pdf_valid():
    pdf = build_incident_pdf({"category": "UPI fraud", "incident_date": "2026-10-01", "loss_amount": 5000,
                              "description": "Sent money to a fake job recruiter", "urls": "http://x.xyz", "evidence_notes": "chat"})
    assert pdf.startswith(b"%PDF")


def test_storage_roundtrip_and_redaction(tmp_path):
    db = str(tmp_path / "t.db")
    a = analyze_text("Share OTP now. Call me on 9876543210 about your KYC, account will be blocked")
    sid = storage.save_scan(a, "Call me on 9876543210 password hunter22", path=db)
    row = storage.get_scan(sid, path=db)
    assert "9876543210" not in row["input_excerpt"] and row["indicators"]
    st = storage.dashboard_stats(path=db)
    assert st["total"] == 1 and st["top_category"] == a["category"]
    assert storage.get_history(path=db, level=a["level"])[0]["id"] == sid
    assert storage.get_history(path=db, level="Low" if a["level"] != "Low" else "High") == []
    assert storage.indicator_counts(path=db)
    iid = storage.save_incident({"category": "Phishing", "incident_date": "2026-10-01", "loss_amount": 10, "description": "x"}, path=db)
    assert storage.get_incidents(path=db)[0]["id"] == iid
    storage.save_scan(a, "demo", source="demo", path=db)
    assert storage.clear_demo(path=db) == 1
