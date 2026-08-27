import httpx

from client import VulnScoutClient
from tools.assessment_groups import _get_assessment_group_impl, _split_reference


BASE_URL = "http://vulnscout.test"

GROUP = {
    "group_id": "g-1",
    "vuln_id": "CVE-2024-1234",
    "origin": "custom",
    "status": "not_affected",
    "justification": "vulnerable_code_not_present",
    "status_notes": "notes",
    "impact_statement": "none",
    "workaround": "",
    "responses": [],
    "timestamp": "2024-01-15T10:30:00Z",
    "assessment_ids": ["a-1", "a-2"],
    "targets": [
        {"assessment_id": "a-1", "variant_id": "v-1", "package": "openssl@1.0.0", "outdated": False},
        {"assessment_id": "a-2", "variant_id": "v-2", "package": "openssl@1.0.0", "outdated": True},
    ],
}


def _patch_http(monkeypatch, handler) -> VulnScoutClient:
    """Route every httpx.Client the code creates through a MockTransport."""
    real_client = httpx.Client
    monkeypatch.setattr(
        httpx, "Client", lambda *a, **k: real_client(transport=httpx.MockTransport(handler))
    )
    return VulnScoutClient(BASE_URL)


class TestSplitReference:
    def test_strips_group_prefix(self):
        assert _split_reference(" Group:g-1 ") == ("group", "g-1")

    def test_strips_assessment_prefix(self):
        assert _split_reference("assessment:a-1") == ("assessment", "a-1")

    def test_bare_uuid_has_no_kind(self):
        assert _split_reference("a-1") == (None, "a-1")


class TestGetAssessmentGroupImpl:
    def test_group_reference_lists_ids_and_targets(self, monkeypatch):
        # Arrange
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["path"] = request.url.path
            return httpx.Response(200, json=GROUP)

        client = _patch_http(monkeypatch, handler)

        # Act
        result = _get_assessment_group_impl(client, "group:g-1")

        # Assert
        assert seen["path"] == "/api/assessment-groups/g-1"
        assert "Assessment group g-1" in result
        assert "CVE-2024-1234" in result
        assert "2 assessment(s)" in result
        assert "assessment_ids: a-1, a-2" in result
        assert "assessment_id=a-2 variant_id=v-2 package=openssl@1.0.0 outdated=True" in result

    def test_bare_id_resolves_through_group_endpoint(self, monkeypatch):
        # Arrange
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            return httpx.Response(200, json=GROUP)

        client = _patch_http(monkeypatch, handler)

        # Act
        result = _get_assessment_group_impl(client, "g-1")

        # Assert
        assert calls == ["/api/assessment-groups/g-1"]
        assert "assessment_ids: a-1, a-2" in result

    def test_bare_id_falls_back_to_assessment_lookup(self, monkeypatch):
        # Arrange
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            if request.url.path == "/api/assessment-groups/a-1":
                return httpx.Response(404, json={"error": "Group not found"})
            if request.url.path == "/api/assessments/a-1":
                return httpx.Response(200, json={"id": "a-1", "group_id": "g-1"})
            return httpx.Response(200, json=GROUP)

        client = _patch_http(monkeypatch, handler)

        # Act
        result = _get_assessment_group_impl(client, "a-1")

        # Assert
        assert calls == [
            "/api/assessment-groups/a-1",
            "/api/assessments/a-1",
            "/api/assessment-groups/g-1",
        ]
        assert "Assessment group g-1" in result

    def test_ungrouped_assessment_renders_single_member(self, monkeypatch):
        # Arrange
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            return httpx.Response(200, json={
                "id": "a-9",
                "group_id": None,
                "vuln_id": "CVE-2024-9999",
                "origin": "custom",
                "status": "affected",
                "justification": "",
                "status_notes": "",
                "impact_statement": "",
                "workaround": "",
                "responses": [],
                "timestamp": "2024-02-01T00:00:00Z",
                "variant_id": "v-7",
                "packages": ["zlib@1.2.11"],
            })

        client = _patch_http(monkeypatch, handler)

        # Act
        result = _get_assessment_group_impl(client, "assessment:a-9")

        # Assert
        assert calls == ["/api/assessments/a-9"]
        assert "Assessment a-9 (not grouped)" in result
        assert "assessment_ids: a-9" in result
        assert "package=zlib@1.2.11" in result

    def test_unknown_group_returns_group_error(self, monkeypatch):
        # Arrange
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.startswith("/api/assessments/"):
                return httpx.Response(500, text="boom " * 200)
            return httpx.Response(404, json={"error": "Group not found"})

        client = _patch_http(monkeypatch, handler)

        # Act
        result = _get_assessment_group_impl(client, "unknown")

        # Assert
        assert result.startswith("Error: Group not found (lookup as an assessment also failed: ")
        assert len(result) < 300

    def test_explicit_group_reference_does_not_fall_back(self, monkeypatch):
        # Arrange
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            return httpx.Response(404, json={"error": "Group not found"})

        client = _patch_http(monkeypatch, handler)

        # Act
        result = _get_assessment_group_impl(client, "group:g-x")

        # Assert
        assert calls == ["/api/assessment-groups/g-x"]
        assert result == "Error: Group not found"

    def test_empty_reference_reports_error(self, monkeypatch):
        # Arrange
        client = _patch_http(monkeypatch, lambda request: httpx.Response(200, json=GROUP))

        # Act / Assert
        assert _get_assessment_group_impl(client, "  ") == (
            "Error: no group or assessment id provided"
        )

    def test_connection_failure_returns_error_string(self, monkeypatch):
        # Arrange
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom")

        client = _patch_http(monkeypatch, handler)

        # Act
        result = _get_assessment_group_impl(client, "group:g-1")

        # Assert
        assert result == f"Error: Could not connect to VulnScout at {BASE_URL}"


class TestClientGetAssessmentGroup:
    def test_returns_parsed_json(self, monkeypatch):
        # Arrange
        client = _patch_http(monkeypatch, lambda request: httpx.Response(200, json=GROUP))

        # Act
        group = client.get_assessment_group("g-1")

        # Assert
        assert group["assessment_ids"] == ["a-1", "a-2"]

    def test_raises_on_error_response(self, monkeypatch):
        # Arrange
        import pytest

        from client import VulnScoutError

        client = _patch_http(
            monkeypatch, lambda request: httpx.Response(400, json={"error": "Invalid group_id"})
        )

        # Act / Assert
        with pytest.raises(VulnScoutError, match="Invalid group_id"):
            client.get_assessment_group("nope")
