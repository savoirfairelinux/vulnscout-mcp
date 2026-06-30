import json
import pytest
import respx
import httpx

# conftest.py puts mcp/ in sys.path
from client import VulnScoutClient, VulnScoutError
from tools.assessments import _write_assessment_impl


BASE_URL = "http://vulnscout.test"


@pytest.fixture
def client():
    return VulnScoutClient(BASE_URL)


class TestWriteAssessmentImpl:

    def test_affected_status_returns_success_summary(self, client):
        with respx.mock:
            respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "status": "success",
                        "assessment": {
                            "id": "uuid-abc",
                            "status": "affected",
                            "packages": ["openssl@1.0.0"],
                        },
                    },
                )
            )
            result = _write_assessment_impl(
                client,
                vuln_id="CVE-2024-1234",
                packages=["openssl@1.0.0"],
                status="affected",
            )
        assert "uuid-abc" in result
        assert "affected" in result
        assert "openssl@1.0.0" in result

    def test_not_affected_with_justification_sends_justification(self, client):
        with respx.mock:
            route = respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-5678/assessments").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "status": "success",
                        "assessment": {
                            "id": "uuid-def",
                            "status": "not_affected",
                            "packages": ["curl@7.0"],
                        },
                    },
                )
            )
            result = _write_assessment_impl(
                client,
                vuln_id="CVE-2024-5678",
                packages=["curl@7.0"],
                status="not_affected",
                justification="vulnerable_code_not_present",
            )
        assert "uuid-def" in result
        body = json.loads(route.calls[0].request.content)
        assert body["justification"] == "vulnerable_code_not_present"

    def test_optional_fields_omitted_when_none(self, client):
        with respx.mock:
            route = respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(
                    200,
                    json={"status": "success", "assessment": {"id": "x", "status": "affected", "packages": []}},
                )
            )
            _write_assessment_impl(
                client,
                vuln_id="CVE-2024-1234",
                packages=["lib@1.0"],
                status="affected",
            )
        body = json.loads(route.calls[0].request.content)
        assert "justification" not in body
        assert "status_notes" not in body
        assert "impact_statement" not in body
        assert "workaround" not in body
        assert "responses" not in body
        assert "timestamp" not in body

    def test_api_error_returns_error_string(self, client):
        with respx.mock:
            respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                return_value=httpx.Response(400, json={"error": "Justification required"})
            )
            result = _write_assessment_impl(
                client,
                vuln_id="CVE-2024-1234",
                packages=["lib@1.0"],
                status="not_affected",
            )
        assert "Error" in result
        assert "Justification required" in result

    def test_connection_error_returns_error_string(self, client):
        with respx.mock:
            respx.post(f"{BASE_URL}/api/vulnerabilities/CVE-2024-1234/assessments").mock(
                side_effect=httpx.ConnectError("refused")
            )
            result = _write_assessment_impl(
                client,
                vuln_id="CVE-2024-1234",
                packages=["lib@1.0"],
                status="affected",
            )
        assert "Error" in result
        assert "Could not connect" in result
