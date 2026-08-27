from client import VulnScoutClient, VulnScoutError


def _split_reference(reference: str) -> tuple[str | None, str]:
    """Split a pasted reference into its kind and its uuid.

    The Review page and the vulnerability modal copy `group:<uuid>` or
    `assessment:<uuid>`. A bare uuid carries no kind, so it is returned as
    (None, uuid) and the caller decides how to resolve it.
    """
    ref = (reference or "").strip()
    for prefix, kind in (("group:", "group"), ("assessment:", "assessment")):
        if ref.lower().startswith(prefix):
            return kind, ref[len(prefix):].strip()
    return None, ref


def _format_group(group: dict) -> str:
    """Render a group dict from GET /api/assessment-groups/<id>."""
    group_id = group.get("group_id")
    assessment_ids = group.get("assessment_ids") or []
    targets = group.get("targets") or []
    header = (
        f"Assessment group {group_id}" if group_id
        else f"Assessment {assessment_ids[0] if assessment_ids else '?'} (not grouped)"
    )
    lines = [
        f"{header} ({group.get('vuln_id')}, origin={group.get('origin')}, "
        f"{len(assessment_ids)} assessment(s)):",
        f"  status={group.get('status')} justification={group.get('justification')}",
        f"  status_notes={group.get('status_notes')}",
        f"  impact_statement={group.get('impact_statement')}",
        f"  workaround={group.get('workaround')}",
        f"  responses={group.get('responses')} timestamp={group.get('timestamp')}",
        f"  assessment_ids: {', '.join(assessment_ids) if assessment_ids else 'none'}",
        "  targets:",
    ]
    for t in targets:
        lines.append(
            f"    assessment_id={t.get('assessment_id')} "
            f"variant_id={t.get('variant_id')} package={t.get('package')} "
            f"outdated={t.get('outdated')}"
        )
    if not targets:
        lines.append("    none")
    return "\n".join(lines)


def _group_from_assessment(assessment: dict) -> dict:
    """Build a one-member group dict for an ungrouped assessment."""
    assessment_id = str(assessment.get("id"))
    return {
        "group_id": None,
        "vuln_id": assessment.get("vuln_id"),
        "origin": assessment.get("origin"),
        "status": assessment.get("status"),
        "justification": assessment.get("justification"),
        "status_notes": assessment.get("status_notes"),
        "impact_statement": assessment.get("impact_statement"),
        "workaround": assessment.get("workaround"),
        "responses": assessment.get("responses"),
        "timestamp": assessment.get("timestamp"),
        "assessment_ids": [assessment_id],
        "targets": [
            {
                "assessment_id": assessment_id,
                "variant_id": assessment.get("variant_id"),
                "package": package,
                "outdated": None,
            }
            for package in (assessment.get("packages") or [None])
        ],
    }


def _resolve_via_assessment(client: VulnScoutClient, assessment_id: str) -> str:
    """Render the group an assessment belongs to, or the assessment itself."""
    assessment = client.get_assessment(assessment_id)
    group_id = assessment.get("group_id")
    if group_id:
        return _format_group(client.get_assessment_group(str(group_id)))
    return _format_group(_group_from_assessment(assessment))


def _get_assessment_group_impl(client: VulnScoutClient, reference: str) -> str:
    """Core logic for get_assessment_group — separated for testability."""
    kind, identifier = _split_reference(reference)
    if not identifier:
        return "Error: no group or assessment id provided"

    if kind == "assessment":
        try:
            return _resolve_via_assessment(client, identifier)
        except VulnScoutError as e:
            return f"Error: {e}"

    try:
        return _format_group(client.get_assessment_group(identifier))
    except VulnScoutError as e:
        # ``except ... as`` unbinds the name when the block ends.
        group_error = str(e)
    if kind == "group":
        return f"Error: {group_error}"

    # A bare id is ambiguous: it may well be an assessment id. When that
    # lookup fails too, the group error is the more likely explanation, but
    # keep a trimmed assessment error so a server fault is not read as a
    # simple "not found".
    try:
        return _resolve_via_assessment(client, identifier)
    except VulnScoutError as e:
        detail = " ".join(str(e).split())[:200]
        return f"Error: {group_error} (lookup as an assessment also failed: {detail})"


def register_tools(server, client: VulnScoutClient) -> None:
    """Register all assessment-group tools on the given MCP server."""

    @server.tool()
    def get_assessment_group(reference: str) -> str:
        """Resolve an assessment group to the assessment IDs it covers.

        One VEX verdict in VulnScout can cover several (package, variant)
        pairs; those rows share a group id. The Review page and the
        vulnerability modal have copy buttons that yield a reference such as
        `group:<uuid>` or `assessment:<uuid>` — pass whatever the user pasted
        straight into this tool.

        Returns the group's shared VEX content, every assessment id in the
        group, and one target line per (assessment, package, variant). Other
        tools still work one assessment at a time: feed the listed ids to
        `get_custom_assessment` or `write_assessment_review` individually.

        An assessment that belongs to no group is returned in the same shape
        with `group_id` absent and a single target, so there is no separate
        case to handle.

        Args:
            reference: `group:<uuid>`, `assessment:<uuid>`, or a bare UUID of
                    either kind.
        """
        return _get_assessment_group_impl(client, reference)
