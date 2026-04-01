from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import get_client
from ..errors import tool_error_handler

_ENDPOINT_SAFE_FIELDS = {
    "Id", "Name", "Type", "URL", "Status", "GroupId", "PublicURL",
    "Snapshots", "EdgeID", "TagIds", "UserTrusted", "Extensions",
}


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @tool_error_handler
    async def portainer_endpoints_list() -> str:
        """List all Portainer environments (endpoints)."""
        client = get_client()
        endpoints = await client.get("/api/endpoints")
        result = []
        for ep in endpoints:
            result.append({
                "id": ep["Id"],
                "name": ep["Name"],
                "type": ep.get("Type"),
                "url": ep.get("URL"),
                "status": ep.get("Status"),
                "group_id": ep.get("GroupId"),
            })
        return json.dumps(result, indent=2)

    @mcp.tool()
    @tool_error_handler
    async def portainer_endpoint_inspect(endpoint_id: int) -> str:
        """Get details of a specific Portainer environment (endpoint).

        Args:
            endpoint_id: The ID of the endpoint to inspect
        """
        client = get_client()
        ep = await client.get(f"/api/endpoints/{endpoint_id}")
        filtered = {k: v for k, v in ep.items() if k in _ENDPOINT_SAFE_FIELDS}
        return json.dumps(filtered, indent=2)
