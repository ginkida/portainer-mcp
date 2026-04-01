from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import get_client
from ..errors import tool_error_handler


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @tool_error_handler
    async def portainer_users_list() -> str:
        """List all Portainer users."""
        client = get_client()
        users = await client.get("/api/users")
        result = []
        for u in users:
            result.append({
                "id": u["Id"],
                "username": u["Username"],
                "role": u.get("Role"),
            })
        return json.dumps(result, indent=2)

    @mcp.tool()
    @tool_error_handler
    async def portainer_user_inspect(user_id: int) -> str:
        """Get details of a specific Portainer user.

        Args:
            user_id: The ID of the user to inspect
        """
        client = get_client()
        user = await client.get(f"/api/users/{user_id}")
        return json.dumps(user, indent=2)
