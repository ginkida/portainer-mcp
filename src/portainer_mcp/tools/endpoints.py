from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import get_client
from ..errors import tool_error_handler, validate_id

_ENDPOINT_SAFE_FIELDS = {
    "Id", "Name", "Type", "URL", "Status", "GroupId", "PublicURL",
    "Snapshots", "EdgeID", "TagIds", "UserTrusted", "Extensions",
}
# Inside each snapshot, DockerSnapshotRaw is the full raw dump of every
# container/image/volume/network at snapshot time — typically hundreds of KB
# and often empty. The summary counters next to it are what an agent needs;
# the list tools give the live objects.
_SNAPSHOT_DROP_FIELDS = frozenset({"DockerSnapshotRaw", "SnapshotRaw"})


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
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp.tool()
    @tool_error_handler
    async def portainer_endpoint_inspect(endpoint_id: int) -> str:
        """Get details of a specific Portainer environment (endpoint).

        Args:
            endpoint_id: The ID of the endpoint to inspect
        """
        validate_id(endpoint_id, "endpoint_id")
        client = get_client()
        ep = await client.get(f"/api/endpoints/{endpoint_id}")
        filtered = {k: v for k, v in ep.items() if k in _ENDPOINT_SAFE_FIELDS}
        if isinstance(filtered.get("Snapshots"), list):
            filtered["Snapshots"] = [
                {k: v for k, v in snap.items() if k not in _SNAPSHOT_DROP_FIELDS}
                if isinstance(snap, dict) else snap
                for snap in filtered["Snapshots"]
            ]
        return json.dumps(filtered, indent=2, ensure_ascii=False)
