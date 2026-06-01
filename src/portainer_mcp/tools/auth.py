from __future__ import annotations

import json

import httpx
from mcp.server.fastmcp import FastMCP

from ..client import get_client
from ..config import get_config
from ..errors import redact_secrets, tool_error_handler


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @tool_error_handler
    async def portainer_status() -> str:
        """Check Portainer connection and authentication status."""
        client = get_client()
        config = get_config()
        # This is a health check: report connectivity as data rather than
        # throwing. Only expected network/HTTP failures are turned into
        # {"connected": false}; anything else (a real bug) still propagates to
        # @tool_error_handler. The reason is run through redact_secrets so a
        # credential can never leak into the response.
        try:
            status = await client.get("/api/status")
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as exc:
            return json.dumps({
                "connected": False,
                "url": config.url,
                "error": redact_secrets(str(exc)),
            }, indent=2, ensure_ascii=False)
        return json.dumps({
            "connected": True,
            "url": config.url,
            "version": status.get("Version", "unknown"),
            "instance_id": status.get("InstanceID", "unknown"),
        }, indent=2, ensure_ascii=False)
