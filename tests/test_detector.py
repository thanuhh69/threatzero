import pytest
from scamshield.detector import analyze_text
from scamshield.risk_engine import level_for, score_indicators, Indicator
from scamshield.evaluate import evaluate

SCAM_WFH = "Work from home typing job, earn Rs 800 per day. Pay Rs 499 registration fee. Limited slots, hurry!"


def test_wfh_scam_flagged_with_explanations():
    a = analyze_text(SCAM_WFH)
    assert a["level"] in ("High", "Critical") and 0 <= a["score"] <= 100
    assert a["category"] == "Work-from-home fraud"
    for i in a["indicators"]:
        assert i["name"] and i["evidence"] and i["why"] and "awarded" in i
    assert a["recommendations"] and "indicative" in a["limitations"].lower()


def test_otp_request_detected_but_awareness_message_not():
    assert any(i["id"] == "otp_pin_request" for i in analyze_text("Please share your OTP to confirm")["indicators"])
    safe = analyze_text("Your OTP is 482913. Never share your OTP with anyone.")
    assert not any(i["id"] == "otp_pin_request" for i in safe["indicators"])


def test_legit_message_low_and_never_claims_safety():
    a = analyze_text("Interview scheduled Monday 10 AM at our office. Please bring your resume.")
    assert a["level"] == "Low"
    assert "not proof" in a["explanation"].lower() or "does not" in a["explanation"].lower()


def test_telugu_english_mixed():
    a = analyze_text("OTP cheppandi ventane, account block avtundi")
    assert any(i["id"] == "otp_pin_request" for i in a["indicators"])


def test_no_double_counting_and_cap():
    inds = [Indicator("a", "A", "g", 20, "x", "y"), Indicator("b", "B", "g", 10, "x", "y")]
    score, out = score_indicators(inds)
    assert score == 20 and sorted(i["awarded"] for i in out) == [0, 20]
    many = [Indicator(str(n), "n", f"g{n}", 40, "e", "w") for n in range(6)]
    assert score_indicators(many)[0] == 100


@pytest.mark.parametrize("s,lvl", [(0, "Low"), (24, "Low"), (25, "Moderate"), (49, "Moderate"), (50, "High"), (74, "High"), (75, "Critical"), (100, "Critical")])
def test_level_boundaries(s, lvl):
    assert level_for(s) == lvl


def test_empty_input_rejected():
    with pytest.raises(ValueError):
        analyze_text("   ")


def test_synthetic_evaluation_regression():
    o = evaluate()
    assert o["n"] >= 50 and o["recall"] >= 0.9 and o["precision"] >= 0.9
