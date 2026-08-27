from typing import Optional

from client import VulnScoutClient, VulnScoutError
from tools.context import _find_project_id_or_raise, _find_variant_id_or_raise


def _get_custom_assessment_impl(client: VulnScoutClient, assessment_id: str) -> str:
    """Core logic for get_custom_assessment — separated for testability."""
    try:
        assessment = client.get_assessment(assessment_id)
    except VulnScoutError as e:
        return f"Error: {e}"

    origin = assessment.get("origin")
    if origin != "custom":
        return (
            f"Assessment {assessment_id} is not a custom assessment "
            f"(origin={origin!r}); skip it — only custom assessments are reviewed."
        )

    try:
        review = client.get_assessment_review(assessment_id)
    except VulnScoutError as e:
        return f"Error: {e}"

    lines = [
        f"Custom assessment {assessment_id}:",
        f"  vuln_id={assessment.get('vuln_id')}",
        f"  packages={assessment.get('packages')}",
        f"  variant_id={assessment.get('variant_id')}",
        f"  status={assessment.get('status')}",
        f"  justification={assessment.get('justification')}",
        f"  status_notes={assessment.get('status_notes')}",
        f"  impact_statement={assessment.get('impact_statement')}",
        f"  workaround={assessment.get('workaround')}",
        f"  responses={assessment.get('responses')}",
        f"  timestamp={assessment.get('timestamp')}",
    ]
    existing = review.get("review") if review else None
    if existing:
        lines.append(
            f"  existing review: status={existing.get('status')} "
            f"verdict={existing.get('verdict')} is_stale={existing.get('is_stale')}"
        )
    else:
        lines.append("  existing review: none")
    return "\n".join(lines)


def _list_custom_assessments_impl(
    client: VulnScoutClient,
    project_name: Optional[str] = None,
    variant_name: Optional[str] = None,
    variant_id: Optional[str] = None,
    has_review: Optional[bool] = None,
    order: str = "timestamp_desc",
    limit: int = 50,
    offset: int = 0,
) -> str:
    """Core logic for list_custom_assessments — separated for testability."""
    params: dict = {"order": order, "limit": limit, "offset": offset}

    if variant_id:
        params["variant_id"] = variant_id
    elif project_name:
        try:
            project_id = _find_project_id_or_raise(client, project_name)
            resolved_variant = _find_variant_id_or_raise(
                client, project_name, variant_name or "default"
            )
        except VulnScoutError as e:
            return f"Error: {e}"
        params["project_id"] = project_id
        params["variant_id"] = resolved_variant

    if has_review is not None:
        params["has_review"] = "true" if has_review else "false"

    try:
        rows = client.list_custom_assessments(params)
    except VulnScoutError as e:
        return f"Error: {e}"

    if not rows:
        return "No custom assessments found for the given scope."

    lines = [f"Custom assessments ({len(rows)} returned):"]
    for a in rows:
        lines.append(
            f"  assessment_id={a.get('id')} vuln_id={a.get('vuln_id')} "
            f"packages={a.get('packages')} variant_id={a.get('variant_id')} "
            f"status={a.get('status')} justification={a.get('justification')} "
            f"status_notes={a.get('status_notes')} "
            f"impact_statement={a.get('impact_statement')} "
            f"workaround={a.get('workaround')} timestamp={a.get('timestamp')} "
            f"has_review={a.get('has_review')}"
        )
    return "\n".join(lines)


def _write_assessment_review_impl(
    client: VulnScoutClient,
    assessment_id: str,
    status: str,
    rationale: str,
    status_notes: Optional[str] = None,
    justification: Optional[str] = None,
    impact_statement: Optional[str] = None,
    workaround: Optional[str] = None,
    responses: Optional[list] = None,
) -> str:
    """Core logic for write_assessment_review — separated for testability."""
    if not rationale or not rationale.strip():
        return "Error: rationale is required — state why the review reaches its conclusion."

    payload: dict = {"status": status, "rationale": rationale.strip()}
    if status_notes is not None:
        payload["status_notes"] = status_notes
    if justification is not None:
        payload["justification"] = justification
    if impact_statement is not None:
        payload["impact_statement"] = impact_statement
    if workaround is not None:
        payload["workaround"] = workaround
    if responses is not None:
        payload["responses"] = responses

    try:
        result = client.write_assessment_review(assessment_id, payload)
    except VulnScoutError as e:
        return f"Error: {e}"

    review = result.get("review")
    if not review:
        return str(result)
    return (
        f"Review saved: id={review.get('id')}, "
        f"assessment_id={review.get('assessment_id')}, "
        f"status={review.get('status')}, verdict={review.get('verdict')}"
    )


def register_tools(server, client: VulnScoutClient) -> None:
    """Register all assessment-review tools on the given FastMCP server."""

    @server.tool()
    def get_custom_assessment(assessment_id: str) -> str:
        """Fetch one user/custom VEX assessment by ID, with any existing review.

        Use this when the caller names a specific assessment to review. Returns
        the assessment's VEX fields plus its variant_id, which you need for
        `get_merged_context`. Refuses assessments whose origin is not "custom" —
        only user-authored assessments are reviewed.

        Args:
            assessment_id: UUID of the assessment to fetch.
        """
        return _get_custom_assessment_impl(client, assessment_id)

    @server.tool()
    def list_custom_assessments(
        project_name: Optional[str] = None,
        variant_name: Optional[str] = None,
        variant_id: Optional[str] = None,
        has_review: Optional[bool] = None,
        order: str = "timestamp_desc",
        limit: int = 50,
        offset: int = 0,
    ) -> str:
        """List user/custom VEX assessments, optionally scoped to a project variant.

        Every returned assessment has origin "custom" — assessments from SBOM
        scans and pending AI suggestions are never included. With no arguments,
        returns custom assessments across all variants.

        Args:
            project_name: Project name to scope to. Resolved to a UUID internally.
            variant_name: Variant name within the project. Defaults to "default"
                    when project_name is given.
            variant_id: Variant UUID, if already known. Takes precedence over
                    project_name/variant_name.
            has_review: True returns only assessments that already have a review;
                    False returns only those without one. Omit for both.
            order: "timestamp_desc" (newest first, the default) or "timestamp_asc".
            limit: Maximum rows to return. Defaults to 50.
            offset: Rows to skip, for paging through a large scope.
        """
        return _list_custom_assessments_impl(
            client,
            project_name=project_name,
            variant_name=variant_name,
            variant_id=variant_id,
            has_review=has_review,
            order=order,
            limit=limit,
            offset=offset,
        )

    @server.tool()
    def write_assessment_review(
        assessment_id: str,
        status: str,
        rationale: str,
        status_notes: Optional[str] = None,
        justification: Optional[str] = None,
        impact_statement: Optional[str] = None,
        workaround: Optional[str] = None,
        responses: Optional[list] = None,
    ) -> str:
        """Save an AI review of a user/custom VEX assessment.

        A review carries the same VEX fields as an assessment — they are the
        values the reviewer independently derived, which a user may later accept
        to replace the original. It never modifies the assessment itself.

        At most one review exists per assessment: writing again overwrites the
        previous review. The server rejects any assessment whose origin is not
        "custom".

        Every VEX field you leave unset is stored empty and counts as a
        disagreement when the server computes the agrees/differs verdict —
        pass every field you derived, including ones that match the
        assessment, not just the ones that differ from it.

        Args:
            assessment_id: UUID of the assessment being reviewed.
            status: Independently derived status. OpenVEX values:
                    under_investigation, not_affected, affected, fixed.
            rationale: Required. Why the review reaches this conclusion — name
                    the evidence, and for a disagreement name each differing field.
            status_notes: Notes that would replace the assessment's status_notes.
                    Append "confidence level: <high|medium|low>" here.
            justification: Required when status is 'not_affected'. OpenVEX values:
                    component_not_present, vulnerable_code_not_present,
                    vulnerable_code_not_in_execute_path,
                    vulnerable_code_cannot_be_controlled_by_adversary,
                    inline_mitigations_already_exist.
            impact_statement: Impact description for a 'not_affected' review.
            workaround: Workaround description, when one exists.
            responses: CycloneDX response tags. Valid values: can_not_fix,
                    will_not_fix, update, rollback, workaround_available.
        """
        return _write_assessment_review_impl(
            client,
            assessment_id=assessment_id,
            status=status,
            rationale=rationale,
            status_notes=status_notes,
            justification=justification,
            impact_statement=impact_statement,
            workaround=workaround,
            responses=responses,
        )
