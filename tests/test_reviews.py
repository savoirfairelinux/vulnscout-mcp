import httpx
import pytest

from client import VulnScoutClient, VulnScoutError


def _patch_http(monkeypatch, handler) -> VulnScoutClient:
    """Route every httpx.Client the code creates through a MockTransport."""
    real_client = httpx.Client
    monkeypatch.setattr(
        httpx, "Client", lambda *a, **k: real_client(transport=httpx.MockTransport(handler))
    )
    return VulnScoutClient("http://vulnscout.test")


def test_list_custom_assessments_passes_params(monkeypatch):
    # Arrange
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(200, json=[{"id": "a1", "has_review": False}])

    client = _patch_http(monkeypatch, handler)

    # Act
    rows = client.list_custom_assessments({"variant_id": "v1", "limit": 10})

    # Assert
    assert rows[0]["id"] == "a1"
    assert "variant_id=v1" in seen["url"]
    assert "limit=10" in seen["url"]


def test_write_assessment_review_puts_payload(monkeypatch):
    # Arrange
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        return httpx.Response(200, json={"review": {"id": "r1", "status": "affected"}})

    client = _patch_http(monkeypatch, handler)

    # Act
    result = client.write_assessment_review("a1", {"status": "affected", "rationale": "r"})

    # Assert
    assert seen["method"] == "PUT"
    assert seen["path"] == "/api/assessments/a1/review"
    assert result["review"]["status"] == "affected"


def test_write_assessment_review_raises_on_409(monkeypatch):
    # Arrange
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(409, json={"error": "only custom assessments can be reviewed"})

    client = _patch_http(monkeypatch, handler)

    # Act / Assert
    with pytest.raises(VulnScoutError, match="custom"):
        client.write_assessment_review("a1", {"status": "affected", "rationale": "r"})


def test_get_assessment_review_returns_empty_on_404(monkeypatch):
    # Arrange
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "Review not found"})

    client = _patch_http(monkeypatch, handler)

    # Act / Assert
    assert client.get_assessment_review("a1") == {}
