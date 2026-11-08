"""
Regression test suite for ThreatCorrelator report model handling.

Verifies safe handling of:
A. CommunityReportResponse with a non-empty description.
B. CommunityReportResponse with an empty description or None.
C. Dictionary-based community reports.
D. Missing optional fields.
E. Mixed lists containing both dictionaries and Pydantic objects.
F. Zero exceptions across find_similar_cases() in all edge cases.
"""

from datetime import datetime, timezone
import pytest
from backend.app.schemas.alerts import CommunityReportResponse
from backend.app.services.intelligence.threat_correlator import (
    threat_correlator,
    get_report_field,
)


def test_get_report_field_helper():
    """Verify get_report_field handles all types and missing values."""
    # 1. Pydantic model with value
    pydantic_rep = CommunityReportResponse(
        id="rep-101",
        target_indicator="https://secure-login.example.com",
        indicator_type="LINK",
        category="Banking Fraud",
        description="Fake login page for bank",
        status="VERIFIED_THREAT",
        created_at=datetime.now(timezone.utc),
        verdict="MALICIOUS",
    )
    assert get_report_field(pydantic_rep, "description") == "Fake login page for bank"
    assert get_report_field(pydantic_rep, "id") == "rep-101"

    # 2. Pydantic model with None description
    pydantic_none_desc = CommunityReportResponse(
        id="rep-102",
        target_indicator="https://update.example.com",
        indicator_type="LINK",
        category="Banking Fraud",
        description=None,
        status="INVESTIGATING",
        created_at=datetime.now(timezone.utc),
        verdict=None,
    )
    assert get_report_field(pydantic_none_desc, "description", default="") == ""
    assert get_report_field(pydantic_none_desc, "verdict", default="PENDING") == "PENDING"
    assert get_report_field(pydantic_none_desc, "non_existent", default="fallback") == "fallback"

    # 3. Dictionary
    dict_rep = {
        "id": "rep-103",
        "target_indicator": "+18005550199",
        "indicator_type": "PHONE",
        "category": "Job Offers",
        "description": "WhatsApp task scam",
        "status": "RECEIVED",
    }
    assert get_report_field(dict_rep, "description") == "WhatsApp task scam"
    assert get_report_field(dict_rep, "verdict", default="UNKNOWN") == "UNKNOWN"

    # 4. Dictionary with None
    dict_none = {"id": "rep-104", "description": None}
    assert get_report_field(dict_none, "description", default="default_desc") == "default_desc"

    # 5. None report
    assert get_report_field(None, "description", default="empty") == "empty"


def test_similar_cases_pydantic_with_description():
    """Test A: CommunityReportResponse with non-empty description."""
    report = CommunityReportResponse(
        id="rep-a",
        target_indicator="https://chase-security-login.xyz",
        indicator_type="LINK",
        category="Banking Fraud",
        description="Urgent debit card verification SMS link",
        status="VERIFIED_THREAT",
        created_at=datetime.now(timezone.utc),
        verdict="MALICIOUS",
    )
    result = threat_correlator.find_similar_cases(
        target_indicator="https://chase-security-login.xyz",
        category="Banking Fraud",
        message_text="Urgent debit card verification required",
        existing_reports=[report],
    )
    assert result is not None
    assert result.similar_reports_count >= 1
    assert result.similar_cases[0].report_id == "rep-a"


def test_similar_cases_pydantic_with_empty_or_none_description():
    """Test B: CommunityReportResponse with empty or None description (the production bug)."""
    # Test with None description
    report_none = CommunityReportResponse(
        id="rep-b1",
        target_indicator="https://amazon-wfh-tasks.net",
        indicator_type="LINK",
        category="Job Offers",
        description=None,
        status="INVESTIGATING",
        created_at=datetime.now(timezone.utc),
        verdict=None,
    )
    # Test with empty string description
    report_empty = CommunityReportResponse(
        id="rep-b2",
        target_indicator="+1 (415) 555-0100",
        indicator_type="PHONE",
        category="Job Offers",
        description="",
        status="RECEIVED",
        created_at=datetime.now(timezone.utc),
    )
    result = threat_correlator.find_similar_cases(
        target_indicator="https://amazon-wfh-tasks.net",
        category="Job Offers",
        message_text="Congratulations! You have been selected for an Amazon work-from-home job.",
        existing_reports=[report_none, report_empty],
    )
    assert result is not None
    assert result.similar_reports_count >= 1


def test_similar_cases_dictionary_reports():
    """Test C: Dictionary-based community reports."""
    dict_report_1 = {
        "id": "dict-c1",
        "target_indicator": "https://sbi-kyc-update-portal.com",
        "indicator_type": "LINK",
        "category": "Banking Fraud",
        "description": "SMS demanding immediate KYC update within 24 hours",
        "status": "VERIFIED_THREAT",
        "created_at": datetime.now(timezone.utc),
        "verdict": "MALICIOUS",
    }
    dict_report_2 = {
        "id": "dict-c2",
        "target_indicator": "https://sbi-kyc-update-portal.com/auth",
        "indicator_type": "LINK",
        "category": "Banking Fraud",
        "description": None,
        "status": "INVESTIGATING",
        "created_at": "2026-11-08T12:00:00Z",
    }
    result = threat_correlator.find_similar_cases(
        target_indicator="https://sbi-kyc-update-portal.com",
        category="Banking Fraud",
        message_text="URGENT: Your SBI bank account will be blocked within 24 hours.",
        existing_reports=[dict_report_1, dict_report_2],
    )
    assert result is not None
    assert result.similar_reports_count >= 1


def test_similar_cases_missing_optional_fields():
    """Test D: Reports missing optional fields entirely."""
    bare_dict = {
        "target_indicator": "https://fake-lottery-winner.com",
        # missing id, category, status, created_at, verdict, description
    }
    bare_pydantic = CommunityReportResponse(
        id="bare-p1",
        target_indicator="https://fake-lottery-winner.com",
        indicator_type="LINK",
        category="Lottery Scam",
        created_at=datetime.now(timezone.utc),
        status="RECEIVED",
        description=None,
        verdict=None,
    )
    result = threat_correlator.find_similar_cases(
        target_indicator="https://fake-lottery-winner.com",
        category="Lottery Scam",
        message_text="Claim your lottery prize now!",
        existing_reports=[bare_dict, bare_pydantic],
    )
    assert result is not None
    assert result.similar_reports_count >= 1


def test_similar_cases_mixed_list():
    """Test E: Mixed list containing both dictionaries and Pydantic objects."""
    mixed_reports = [
        CommunityReportResponse(
            id="mixed-p1",
            target_indicator="https://amazon-recruitment-fee.top",
            indicator_type="LINK",
            category="Fake Job Offer Scam",
            description=None,  # Key case that crashed Render
            status="VERIFIED_THREAT",
            created_at=datetime.now(timezone.utc),
            verdict="MALICIOUS",
        ),
        {
            "id": "mixed-d1",
            "target_indicator": "+91 98765 43210",
            "indicator_type": "PHONE",
            "category": "Fake Job Offer Scam",
            "description": "Demanded refundable ₹499 registration fee for Amazon tasks",
            "status": "INVESTIGATING",
            "created_at": "2026-11-08T15:30:00Z",
            "verdict": "SUSPICIOUS",
        },
        CommunityReportResponse(
            id="mixed-p2",
            target_indicator="https://amazon-hiring-portal.org",
            indicator_type="LINK",
            category="Fake Job Offer Scam",
            description="",
            status="RECEIVED",
            created_at=datetime.now(timezone.utc),
        ),
    ]
    result = threat_correlator.find_similar_cases(
        target_indicator="https://amazon-recruitment-fee.top",
        category="Fake Job Offer Scam",
        message_text="Earn ₹5,000 daily. Pay refundable fee of ₹499.",
        extracted_phones=["+91 98765 43210"],
        existing_reports=mixed_reports,
    )
    assert result is not None
    assert result.similar_reports_count >= 2
    assert result.suspected_campaign_name is not None
