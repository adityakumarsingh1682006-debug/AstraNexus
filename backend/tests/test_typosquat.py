import pytest
from backend.app.services.scanner.typosquat import typosquat_detector


def test_official_domain_recognized_safe():
    """Verify official legitimate domains are recognized and never marked as impersonation."""
    official_targets = [
        "https://www.google.com",
        "https://apple.com/iphone",
        "https://chase.com/personal",
        "https://www.paypal.com/signin",
    ]
    for url in official_targets:
        res = typosquat_detector.analyze(url)
        assert res.get("is_legit_brand_domain") is True, f"Expected {url} to be marked legitimate brand domain"
        assert res.get("is_impersonation") is False


def test_combosquatting_phishing_detected():
    """Verify trademark stitching (e.g. chase-auth-service.com) is detected."""
    phish_targets = [
        "https://chase-auth-service.com/login",
        "https://paypal-verify-account.info",
        "https://netflix-billing-update.top",
    ]
    for url in phish_targets:
        res = typosquat_detector.analyze(url)
        assert res.get("is_impersonation") is True, f"Expected {url} to be caught as impersonation"
        assert res.get("impersonated_brand") is not None
        assert "COMBOSQUATTING" in res.get("techniques", [])


def test_punycode_homograph_detected():
    """Verify internationalized punycode lookalikes are detected."""
    punycode_url = "https://xn--gogle-qqa.com"
    res = typosquat_detector.analyze(punycode_url)
    assert "PUNYCODE_HOMOGRAPH" in res.get("techniques", [])
