from typing import Optional
from client import VulnScoutClient, VulnScoutError


def _fmt_context(ctx: dict) -> str:
    return (
        f"variant_id={ctx.get('variant_id')}\n"
        f"deployment_environment={ctx.get('deployment_environment')}\n"
        f"platform={ctx.get('platform')}\n"
        f"objectives_profile={ctx.get('objectives_profile')}\n"
        f"notes={ctx.get('notes')}"
    )


def register_tools(server, client: VulnScoutClient) -> None:
    """Register all variant context tools on the given FastMCP server."""

    @server.tool()
    def get_variant_context(variant_id: str) -> str:
        """Get the context fields of a variant by its UUID.

        Returns deployment_environment, platform, objectives_profile, and notes
        for the specified variant.

        Args:
            variant_id: UUID of the variant.
        """
        try:
            ctx = client.get_variant_context(variant_id)
            return _fmt_context(ctx)
        except VulnScoutError as e:
            return f"Error: {e}"

    @server.tool()
    def update_variant_context(
        variant_id: str,
        deployment_environment: Optional[str] = None,
        platform: Optional[str] = None,
        objectives_profile: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> str:
        """Update the context fields of a variant by its UUID.

        Only fields provided (non-None) are updated; omitted fields are unchanged.
        Pass null explicitly in JSON to clear a field.
        platform and objectives_profile are capped at 100 characters each.

        Args:
            variant_id: UUID of the variant to update.
            deployment_environment: Free-text description of the deployment environment.
            platform: Target platform identifier (max 100 chars), e.g. 'linux/amd64'.
            objectives_profile: Security objectives profile name (max 100 chars).
            notes: Free-text notes about this variant.
        """
        fields: dict = {}
        if deployment_environment is not None:
            fields["deployment_environment"] = deployment_environment
        if platform is not None:
            fields["platform"] = platform
        if objectives_profile is not None:
            fields["objectives_profile"] = objectives_profile
        if notes is not None:
            fields["notes"] = notes
        if not fields:
            return "Error: at least one field must be provided."
        try:
            ctx = client.update_variant_context(variant_id, fields)
            return _fmt_context(ctx)
        except VulnScoutError as e:
            return f"Error: {e}"

    @server.tool()
    def get_variant_context_by_name(project_name: str, variant_name: str) -> str:
        """Get the context fields of a variant by project name and variant name.

        Useful when the variant UUID is not known. Both project_name and
        variant_name are required and must match exactly (case-sensitive).

        Args:
            project_name: Exact name of the project containing the variant.
            variant_name: Exact name of the variant within that project.
        """
        try:
            ctx = client.get_variant_context_by_name(project_name, variant_name)
            return _fmt_context(ctx)
        except VulnScoutError as e:
            return f"Error: {e}"
