import asyncio
import pytest
from fastapi import HTTPException
from backend.app.services.scanner.message_analyzer import message_analyzer
from backend.app.services.ai.gemini_explainer import gemini_explainer
from backend.app.schemas.message import MessageScanResponse, MessageScanRequest
from backend.app.api.v1.endpoints.message import analyze_message


def test_case_1_normal_suspicious_message():
    """Case 1: Normal suspicious message with urgency, authority, and malicious link."""
    msg = "URGENT from Chase Bank: A transaction of $842.19 was made from your account. If this was not you, verify at http://chase-auth-service.com/login"
    res = message_analyzer.analyze(msg)
    assert res.verdict == "LIKELY_SCAM"
    assert res.risk_score >= 60
    assert len(res.consumer_advice) > 0
    assert len(res.detected_tactics) >= 2
    assert "Artificial Urgency" in res.manipulation_tactics
    assert any("Bank" in t for t in res.manipulation_tactics)
    assert len(res.extracted_links) == 1
    assert "http://chase-auth-service.com/login" in res.extracted_links
    assert len(res.extracted_amounts) >= 1


def test_case_2_normal_harmless_message():
    """Case 2: Normal harmless message without any scam indicators."""
    msg = "Hey Sarah, are we still meeting for lunch tomorrow at 12:30 PM? Let me know!"
    res = message_analyzer.analyze(msg)
    assert res.verdict == "LOOKS_SAFE"
    assert res.risk_score < 30
    assert isinstance(res.detected_tactics, list)
    assert len(res.detected_tactics) == 0
    assert isinstance(res.manipulation_tactics, list)
    assert len(res.manipulation_tactics) == 0
    assert isinstance(res.extracted_links, list)
    assert len(res.extracted_links) == 0
    assert isinstance(res.consumer_advice, list)
    assert len(res.consumer_advice) > 0


def test_case_3_message_containing_multiple_urls():
    """Case 3: Message containing multiple URLs."""
    msg = "Please review your document here: https://secure-docs.example.org/doc1 and confirm backup at http://verify-portal.net/auth"
    res = message_analyzer.analyze(msg)
    assert len(res.extracted_links) == 2
    assert "https://secure-docs.example.org/doc1" in res.extracted_links
    assert "http://verify-portal.net/auth" in res.extracted_links
    assert isinstance(res.detected_tactics, list)
    assert isinstance(res.manipulation_tactics, list)


def test_case_4_message_containing_no_urls():
    """Case 4: Message containing no URLs (e.g. phone/utility scam)."""
    msg = "URGENT: Your power bill is past due. Call 1-800-555-0199 immediately to prevent disconnection."
    res = message_analyzer.analyze(msg)
    assert len(res.extracted_links) == 0
    assert isinstance(res.extracted_links, list)
    assert len(res.extracted_phones) >= 1
    assert any(t.tactic == "Artificial Urgency" for t in res.detected_tactics)
    assert "Artificial Urgency" in res.manipulation_tactics
    assert res.risk_score >= 30


def test_case_5_empty_message_validation():
    """Case 5: Empty message raises HTTP 400 Bad Request."""
    loop = asyncio.new_event_loop()
    try:
        req_empty = MessageScanRequest(message_text="")
        with pytest.raises(HTTPException) as exc_info:
            loop.run_until_complete(analyze_message(req_empty))
        assert exc_info.value.status_code == 400
        assert "empty" in exc_info.value.detail.lower()

        req_spaces = MessageScanRequest(message_text="   \n\t  ")
        with pytest.raises(HTTPException) as exc_info2:
            loop.run_until_complete(analyze_message(req_spaces))
        assert exc_info2.value.status_code == 400
    finally:
        loop.close()


def test_case_6_pydantic_schema_resilience_to_incomplete_data():
    """Case 6: Backend response schema provides robust defaults if fields are omitted."""
    # Test instantiating response with absolute bare minimum
    minimal_resp = MessageScanResponse()
    assert minimal_resp.verdict == "LOOKS_SAFE"
    assert minimal_resp.consumer_headline == "Message Safety Assessment"
    assert minimal_resp.consumer_advice == []
    assert minimal_resp.detected_tactics == []
    assert minimal_resp.manipulation_tactics == []
    assert minimal_resp.extracted_links == []
    assert minimal_resp.extracted_phones == []
    assert minimal_resp.extracted_amounts == []
    assert minimal_resp.risk_score == 0
    assert minimal_resp.confidence_score == 80.0
    assert minimal_resp.ai_explanation is None


def test_case_7_gemini_api_unavailable_fallback():
    """Case 7: Gemini API unavailable falls back cleanly to deterministic explanation."""
    loop = asyncio.new_event_loop()
    try:
        # Explainer with no API key uses deterministic heuristic fallback
        exp = loop.run_until_complete(
            gemini_explainer.explain_message_verdict(
                message_text="URGENT: Verify your account immediately",
                verdict="LIKELY_SCAM",
                risk_score=75,
                scam_category="Banking & Financial Fraud",
                detected_tactics=["Artificial Urgency", "Impersonating Bank"],
                extracted_links=["http://phish.example.com"],
            )
        )
        assert isinstance(exp, dict)
        assert "headline" in exp and exp["headline"]
        assert "summary" in exp and exp["summary"]
        assert "what_to_do" in exp and isinstance(exp["what_to_do"], list)
        assert len(exp["what_to_do"]) > 0
        assert "AstraNexus Deterministic Safety Rules" in exp["source"]
    finally:
        loop.close()


def test_endpoint_end_to_end_analyze():
    """End-to-end integration test of analyze_message endpoint."""
    loop = asyncio.new_event_loop()
    try:
        req = MessageScanRequest(
            message_text="USPS Notice: Package delivery failed. Pay redelivery fee of $2.50 at http://usps-redelivery.xyz",
            channel_type="SMS",
        )
        res = loop.run_until_complete(analyze_message(req))
        assert res.verdict == "LIKELY_SCAM"
        assert res.risk_score >= 60
        assert len(res.consumer_advice) > 0
        assert len(res.manipulation_tactics) > 0
        assert len(res.extracted_links) == 1
        assert res.ai_explanation is not None
        assert isinstance(res.ai_explanation.get("what_to_do"), list)
    finally:
        loop.close()
