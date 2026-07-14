from typing import Optional
from client import VulnScoutClient, VulnScoutError


def _write_assessment_impl(
    client: VulnScoutClient,
    vuln_id: str,
    packages: list,
    status: str,
    variant_id: str,
    justification: Optional[str] = None,
    status_notes: Optional[str] = None,
    impact_statement: Optional[str] = None,
    workaround: Optional[str] = None,
    responses: Optional[list] = None,
    timestamp: Optional[str] = None,
    ai_generated: bool = True,
) -> str:
    """Core logic for write_assessment — separated for testability."""
    payload: dict = {"packages": packages, "status": status, "variant_id": variant_id, "ai_generated": ai_generated}
    if justification is not None:
        payload["justification"] = justification
    if status_notes is not None:
        payload["status_notes"] = status_notes
    if impact_statement is not None:
        payload["impact_statement"] = impact_statement
    if workaround is not None:
        payload["workaround"] = workaround
    if responses is not None:
        payload["responses"] = responses
    if timestamp is not None:
        payload["timestamp"] = timestamp

    try:
        result = client.write_assessment(vuln_id, payload)
        if "assessment" not in result:
            return str(result)
        a = result.get("assessment", {})
        return (
            f"Assessment created: id={a.get('id')}, "
            f"status={a.get('status')}, "
            f"packages={a.get('packages')}"
        )
    except VulnScoutError as e:
        return f"Error: {e}"


def _has_ai_assessment_impl(
    client: VulnScoutClient,
    vuln_id: str,
    variant_id: str,
) -> str:
    """Core logic for has_ai_assessment — separated for testability."""
    try:
        assessments = client.list_assessments_by_vuln(vuln_id)
    except VulnScoutError as e:
        return f"Error: {e}"

    for a in assessments:
        if a.get("ai_generated") is True and a.get("variant_id") == variant_id:
            return (
                f"AI assessment found: id={a.get('id')}, "
                f"status={a.get('status')}, "
                f"packages={a.get('packages')}"
            )
    return f"No AI assessment found for {vuln_id} with variant {variant_id}"


def _update_ai_assessment_impl(
    client: VulnScoutClient,
    assessment_id: str,
    status: Optional[str] = None,
    status_notes: Optional[str] = None,
    justification: Optional[str] = None,
    impact_statement: Optional[str] = None,
    workaround: Optional[str] = None,
) -> str:
    """Core logic for update_ai_assessment — separated for testability."""
    try:
        existing = client.get_assessment(assessment_id)
    except VulnScoutError as e:
        return f"Error: {e}"

    if existing.get("ai_generated") is not True:
        return f"Assessment {assessment_id} is not an AI-generated assessment; refusing to modify it."

    payload: dict = {}
    if status is not None:
        payload["status"] = status
    if status_notes is not None:
        payload["status_notes"] = status_notes
    if justification is not None:
        payload["justification"] = justification
    if impact_statement is not None:
        payload["impact_statement"] = impact_statement
    if workaround is not None:
        payload["workaround"] = workaround

    if not payload:
        return "Error: no fields provided to update"

    try:
        result = client.update_assessment(assessment_id, payload)
    except VulnScoutError as e:
        return f"Error: {e}"

    if "assessment" not in result:
        return str(result)
    a = result.get("assessment", {})
    return (
        f"Assessment updated: id={a.get('id')}, "
        f"status={a.get('status')}, "
        f"packages={a.get('packages')}"
    )


def register_tools(server, client: VulnScoutClient) -> None:
    """Register all assessment tools on the given FastMCP server."""

    @server.tool()
    def write_assessment(
        vuln_id: str,
        packages: list,
        status: str,
        variant_id: str,
        justification: Optional[str] = None,
        status_notes: Optional[str] = None,
        impact_statement: Optional[str] = None,
        workaround: Optional[str] = None,
        responses: Optional[list] = None,
        timestamp: Optional[str] = None,
        ai_generated: bool = True,
    ) -> str:
        """Write a VEX assessment for a CVE on one or more packages in VulnScout.

        Returns a success summary when the API response includes an `assessment`
        object. If the response does not include `assessment`, the call is treated
        as failed and the raw response payload is returned instead. Client errors
        are returned as an `Error: ...` string.

        Args:
            vuln_id: CVE identifier, e.g. CVE-2024-1234
            packages: List of affected package strings in 'name@version' format, e.g. ['openssl@1.0.0']
            status: Assessment status. OpenVEX values: under_investigation, not_affected, affected, fixed.
                    CycloneDX VEX values: in_triage, false_positive, not_affected, exploitable,
                    resolved, resolved_with_pedigree.
            variant_id: Required UUID of the variant to scope this assessment to.
            justification: Required when status is 'not_affected'. OpenVEX values:
                    component_not_present, vulnerable_code_not_present,
                    vulnerable_code_not_in_execute_path,
                    vulnerable_code_cannot_be_controlled_by_adversary,
                    inline_mitigations_already_exist. CycloneDX VEX values: code_not_present,
                    code_not_reachable, requires_configuration, requires_dependency,
                    requires_environment, protected_by_compiler, protected_at_runtime,
                    protected_at_perimeter, protected_by_mitigating_control.
            status_notes: Free-text notes about the assessment.
            impact_statement: Free-text description of impact.
            workaround: Workaround description.
            responses: CycloneDX response tags. Valid values: can_not_fix, will_not_fix,
                    update, rollback, workaround_available.
            timestamp: ISO 8601 datetime string, e.g. 2024-01-15T10:30:00Z.
            ai_generated: Whether this assessment was generated by an AI agent. Defaults to True.
        """
        return _write_assessment_impl(
            client,
            vuln_id=vuln_id,
            packages=packages,
            status=status,
            variant_id=variant_id,
            justification=justification,
            status_notes=status_notes,
            impact_statement=impact_statement,
            workaround=workaround,
            responses=responses,
            timestamp=timestamp,
            ai_generated=ai_generated,
        )

    @server.tool()
    def get_assessment(assessment_id: str) -> str:
        """Retrieve a single VEX assessment by its ID from VulnScout.

        Args:
            assessment_id: UUID of the assessment to retrieve.
        """
        try:
            result = client.get_assessment(assessment_id)
            return str(result)
        except VulnScoutError as e:
            return f"Error: {e}"

    @server.tool()
    def list_assessments_by_vuln(vuln_id: str) -> str:
        """List all VEX assessments for a given CVE in VulnScout.

        Returns all assessment records across all packages associated with the
        vulnerability, including their timestamps. Use this before writing a
        new assessment to understand the current assessment state for a CVE.

        Args:
            vuln_id: CVE identifier, e.g. CVE-2024-1234
        """
        try:
            results = client.list_assessments_by_vuln(vuln_id)
            if not results:
                return f"No assessments found for {vuln_id}"
            lines = [f"Assessments for {vuln_id} ({len(results)} total):"]
            for a in results:
                lines.append(
                    f"  id={a.get('id')} status={a.get('status')} "
                    f"packages={a.get('packages')} justification={a.get('justification')} "
                    f"timestamp={a.get('timestamp')}"
                )
            return "\n".join(lines)
        except VulnScoutError as e:
            return f"Error: {e}"

    @server.tool()
    def has_ai_assessment(vuln_id: str, variant_id: str) -> str:
        """Check if a vulnerability already has an AI-generated assessment for a given variant.

        Queries all assessments for the CVE and returns details of the first
        AI-generated assessment scoped to the specified variant, or a clear
        "not found" message if none exists. Use this before writing a new AI
        assessment to avoid duplicates.

        Args:
            vuln_id: CVE identifier, e.g. CVE-2024-1234
            variant_id: UUID of the variant to check.
        """
        return _has_ai_assessment_impl(client, vuln_id=vuln_id, variant_id=variant_id)

    @server.tool()
    def update_ai_assessment(
        assessment_id: str,
        status: Optional[str] = None,
        status_notes: Optional[str] = None,
        justification: Optional[str] = None,
        impact_statement: Optional[str] = None,
        workaround: Optional[str] = None,
    ) -> str:
        """Modify an existing AI-generated VEX assessment in VulnScout.

        Only assessments with `ai_generated` set to True may be modified by
        this tool. The assessment is fetched first to verify this; if it is
        not AI-generated, the tool refuses to modify it and no update request
        is sent. All fields below are optional — only the ones supplied are
        included in the update, and at least one must be provided.

        Args:
            assessment_id: UUID of the assessment to modify.
            status: New assessment status. OpenVEX values: under_investigation,
                    not_affected, affected, fixed. CycloneDX VEX values: in_triage,
                    false_positive, not_affected, exploitable, resolved,
                    resolved_with_pedigree.
            status_notes: Free-text notes about the assessment.
            justification: Required by the server when status is 'not_affected'.
                    OpenVEX values: component_not_present, vulnerable_code_not_present,
                    vulnerable_code_not_in_execute_path,
                    vulnerable_code_cannot_be_controlled_by_adversary,
                    inline_mitigations_already_exist. CycloneDX VEX values: code_not_present,
                    code_not_reachable, requires_configuration, requires_dependency,
                    requires_environment, protected_by_compiler, protected_at_runtime,
                    protected_at_perimeter, protected_by_mitigating_control.
            impact_statement: Free-text description of impact.
            workaround: Workaround description.
        """
        return _update_ai_assessment_impl(
            client,
            assessment_id=assessment_id,
            status=status,
            status_notes=status_notes,
            justification=justification,
            impact_statement=impact_statement,
            workaround=workaround,
        )