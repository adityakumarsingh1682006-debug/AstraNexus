import asyncio
import pytest
from backend.app.api.v1.endpoints.message import analyze_message
from backend.app.api.v1.endpoints.alerts import get_scam_alerts
from backend.app.api.v1.endpoints.reports import submit_report, list_reports
from backend.app.schemas.message import MessageScanRequest
from backend.app.schemas.alerts import CommunityReportCreate


def test_alerts_endpoint():
    """Verify alerts endpoint returns verified scam campaigns."""
    loop = asyncio.new_event_loop()
    try:
        alerts = loop.run_until_complete(get_scam_alerts())
        assert len(alerts) >= 3
        assert any("USPS" in a.title or "Delivery" in a.title for a in alerts)
        assert any(a.category == "Banking Fraud" for a in alerts)
    finally:
        loop.close()


def test_message_endpoint():
    """Verify message analyzer endpoint processes scam payload."""
    loop = asyncio.new_event_loop()
    try:
        req = MessageScanRequest(
            message_text="URGENT: Your Netflix account payment failed. Update now at http://netflix-auth-update.xyz",
            channel_type="SMS"
        )
        res = loop.run_until_complete(analyze_message(req))
        assert res.verdict in ("LIKELY_SCAM", "SUSPICIOUS")
        assert len(res.consumer_advice) > 0
    finally:
        loop.close()


def test_reports_submission_and_listing():
    """Verify user can submit a community threat report and see it listed."""
    loop = asyncio.new_event_loop()
    try:
        req = CommunityReportCreate(
            target_indicator="https://scam-delivery-portal.xyz",
            indicator_type="LINK",
            category="Delivery Scam",
            description="Got this via text claiming to be DHL."
        )
        created = loop.run_until_complete(submit_report(req))
        assert created.target_indicator == "https://scam-delivery-portal.xyz"
        assert created.status == "RECEIVED"

        all_reports = loop.run_until_complete(list_reports())
        assert any(r.id == created.id for r in all_reports)
    finally:
        loop.close()
