from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import get_client
from ..config import get_config
from ..errors import tool_error_handler


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @tool_error_handler
    async def portainer_status() -> str:
        """Check Portainer connection and authentication status."""
        client = get_client()
        config = get_config()
        try:
            status = await client.get("/api/status")
        except Exception as exc:
            return json.dumps({
                "connected": False,
                "url": config.url,
                "error": str(exc),
            }, indent=2)
        return json.dumps({
            "connected": True,
            "url": config.url,
            "version": status.get("Version", "unknown"),
            "instance_id": status.get("InstanceID", "unknown"),
        }, indent=2)
