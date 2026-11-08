import asyncio
from backend.app.main import root
from backend.app.api.v1.endpoints.health import get_system_health


def test_root_endpoint():
    """Verify root endpoint returns system identity."""
    loop = asyncio.new_event_loop()
    try:
        res = loop.run_until_complete(root())
        assert res["platform"] == "AstraNexus"
        assert "version" in res
        assert "/api/v1/health" in res["health_url"]
    finally:
        loop.close()


def test_health_endpoint():
    """Verify health endpoint returns status of all subsystems."""
    loop = asyncio.new_event_loop()
    try:
        res = loop.run_until_complete(get_system_health())
        assert res.status == "healthy"
        assert "gateway_core" in res.services
        assert res.services["gateway_core"].status == "operational"
        assert "ssrf_guard" in res.services
        assert res.services["ssrf_guard"].status == "operational"
        assert "feeds_subsystem" in res.services
    finally:
        loop.close()


if __name__ == "__main__":
    test_root_endpoint()
    print("ROOT_TEST_PASSED")
    test_health_endpoint()
    print("HEALTH_TEST_PASSED")
