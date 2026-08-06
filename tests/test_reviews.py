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


from tools.reviews import (
    _get_custom_assessment_impl,
    _list_custom_assessments_impl,
    _write_assessment_review_impl,
)


class FakeClient:
    def __init__(
        self,
        assessment=None,
        rows=None,
        review_result=None,
        projects=None,
        variants=None,
    ):
        self._assessment = assessment or {}
        self._rows = rows or []
        self._review_result = review_result or {"review": {"id": "r1", "status": "affected"}}
        self._projects = projects if projects is not None else [{"id": "p1", "name": "proj"}]
        self._variants = variants if variants is not None else [{"id": "v-resolved", "name": "v1"}]
        self.last_params = None
        self.last_payload = None
        self.list_projects_calls = 0
        self.list_variants_by_project_calls = 0

    def get_assessment(self, assessment_id):
        return dict(self._assessment, id=assessment_id)

    def get_assessment_review(self, assessment_id):
        return {}

    def list_custom_assessments(self, params):
        self.last_params = params
        return self._rows

    def write_assessment_review(self, assessment_id, payload):
        self.last_payload = payload
        return self._review_result

    def list_projects(self):
        self.list_projects_calls += 1
        return self._projects

    def list_variants_by_project(self, project_id):
        self.list_variants_by_project_calls += 1
        return self._variants


def test_get_custom_assessment_refuses_non_custom_origin():
    # Arrange
    client = FakeClient(assessment={"origin": "sbom", "status": "affected"})

    # Act
    out = _get_custom_assessment_impl(client, "a1")

    # Assert
    assert "not a custom assessment" in out.lower()


def test_get_custom_assessment_returns_fields():
    # Arrange
    client = FakeClient(
        assessment={
            "origin": "custom",
            "vuln_id": "CVE-2024-0001",
            "packages": ["openssl@3.0.8"],
            "status": "not_affected",
            "variant_id": "v1",
        }
    )

    # Act
    out = _get_custom_assessment_impl(client, "a1")

    # Assert
    assert "CVE-2024-0001" in out
    assert "not_affected" in out
    assert "v1" in out


def test_list_custom_assessments_sends_limit_and_order():
    # Arrange
    client = FakeClient(rows=[{"id": "a1", "vuln_id": "CVE-2024-0001", "status": "affected"}])

    # Act
    out = _list_custom_assessments_impl(client, variant_id="v1", limit=10)

    # Assert
    assert client.last_params["variant_id"] == "v1"
    assert client.last_params["limit"] == 10
    assert client.last_params["order"] == "timestamp_desc"
    assert "CVE-2024-0001" in out


def test_list_custom_assessments_reports_empty_result():
    client = FakeClient(rows=[])

    assert "no custom assessments" in _list_custom_assessments_impl(client).lower()


def test_write_assessment_review_requires_rationale():
    # Arrange
    client = FakeClient()

    # Act
    out = _write_assessment_review_impl(client, "a1", status="affected", rationale="  ")

    # Assert
    assert out.startswith("Error")
    assert client.last_payload is None


def test_write_assessment_review_omits_unset_fields():
    # Arrange
    client = FakeClient()

    # Act
    _write_assessment_review_impl(client, "a1", status="affected", rationale="in rootfs")

    # Assert
    assert client.last_payload == {"status": "affected", "rationale": "in rootfs"}


def test_list_custom_assessments_resolves_project_and_variant_name():
    # Arrange
    client = FakeClient(
        projects=[{"id": "p1", "name": "proj"}],
        variants=[{"id": "v-resolved", "name": "v1"}],
    )

    # Act
    out = _list_custom_assessments_impl(client, project_name="proj", variant_name="v1")

    # Assert
    assert client.last_params["variant_id"] == "v-resolved"
    assert client.last_params["project_id"] == "p1"
    # _list_custom_assessments_impl resolves the project id directly, then again
    # inside _find_variant_id_or_raise, so list_projects is called twice.
    assert client.list_projects_calls == 2
    assert client.list_variants_by_project_calls == 1
    assert "No custom assessments" in out


def test_list_custom_assessments_defaults_variant_name_to_default():
    # Arrange
    client = FakeClient(
        projects=[{"id": "p1", "name": "proj"}],
        variants=[{"id": "v-default", "name": "default"}],
    )

    # Act
    _list_custom_assessments_impl(client, project_name="proj")

    # Assert
    assert client.last_params["variant_id"] == "v-default"


def test_list_custom_assessments_skips_resolution_when_variant_id_given():
    # Arrange
    client = FakeClient()

    # Act
    _list_custom_assessments_impl(client, project_name="proj", variant_id="v-explicit")

    # Assert
    assert client.last_params["variant_id"] == "v-explicit"
    assert "project_id" not in client.last_params
    assert client.list_projects_calls == 0
    assert client.list_variants_by_project_calls == 0
