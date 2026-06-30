import json
import pytest
import respx
import httpx

# conftest.py adds mcp/ to sys.path so this import works
from client import VulnScoutClient, VulnScoutError


BASE_URL = "http://vulnscout.test"


@pytest.fixture
def client():
    return VulnScoutClient(BASE_URL)


class TestWriteAssessment:

    def test_success_returns_response_dict(self, client):
        with respx.mock:
            respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "status": "success",
                        "assessment": {
                            "id": "abc-123",
                            "status": "affected",
                            "packages": ["openssl@1.0.0"],
                        },
                    },
                )
            )
            result = client.write_assessment(
                "CVE-2024-1234",
                {"packages": ["openssl@1.0.0"], "status": "affected"},
            )
        assert result["status"] == "success"
        assert result["assessment"]["id"] == "abc-123"

    def test_sends_payload_as_json(self, client):
        with respx.mock:
            route = respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(
                    200,
                    json={"status": "success", "assessment": {"id": "x", "status": "affected", "packages": []}},
                )
            )
            client.write_assessment(
                "CVE-2024-1234",
                {"packages": ["lib@2.0"], "status": "affected"},
            )
        assert route.called
        body = json.loads(route.calls[0].request.content)
        assert body["status"] == "affected"
        assert body["packages"] == ["lib@2.0"]

    def test_api_400_raises_vuln_scout_error_with_message(self, client):
        with respx.mock:
            respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(400, json={"error": "Justification required"})
            )
            with pytest.raises(VulnScoutError, match="Justification required"):
                client.write_assessment(
                    "CVE-2024-1234",
                    {"packages": ["lib@1.0"], "status": "not_affected"},
                )

    def test_api_500_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(500, json={"error": "Internal server error"})
            )
            with pytest.raises(VulnScoutError, match="Internal server error"):
                client.write_assessment("CVE-2024-1234", {"packages": ["lib@1.0"], "status": "affected"})

    def test_connection_error_raises_vuln_scout_error(self, client):
        with respx.mock:
            respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            with pytest.raises(VulnScoutError, match="Could not connect to VulnScout at http://vulnscout.test"):
                client.write_assessment("CVE-2024-1234", {"packages": ["lib@1.0"], "status": "affected"})
