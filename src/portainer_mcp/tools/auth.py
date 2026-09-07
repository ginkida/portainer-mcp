from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from ..client import get_client
from ..config import get_config
from ..errors import redact_secrets, tool_error_handler

logger = logging.getLogger(__name__)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @tool_error_handler
    async def portainer_status() -> str:
        """Check Portainer connection and authentication status.

        Also reports how many endpoints Portainer knows and whether the
        default endpoint is a Swarm cluster — the first thing an agent needs
        to decide between the service-level and container-level tools.
        """
        client = get_client()
        config = get_config()
        # This is a health check: report connectivity as data rather than
        # throwing. Only expected network/HTTP failures are turned into
        # {"connected": false}; anything else (a real bug) still propagates to
        # @tool_error_handler. The reason is run through redact_secrets so a
        # credential can never leak into the response.
        try:
            status = await client.get("/api/status")
        except (httpx.TransportError, httpx.HTTPStatusError) as exc:
            return json.dumps({
                "connected": False,
                "url": config.url,
                "error": redact_secrets(str(exc)),
            }, indent=2, ensure_ascii=False)
        status = status or {}
        # Everything below is enrichment: a failure there must not turn a
        # reachable Portainer into "connected: false". Each piece degrades to
        # null independently.
        endpoints: Any = None
        try:
            endpoints = await client.get("/api/endpoints")
        except (httpx.TransportError, httpx.HTTPStatusError) as exc:
            logger.debug("status: endpoint listing failed: %s", exc)
        endpoint_list = [e for e in (endpoints or []) if isinstance(e, dict)]
        default: dict[str, Any] = {"id": config.default_endpoint, "name": None, "swarm": None}
        for ep in endpoint_list:
            if ep.get("Id") == config.default_endpoint:
                default["name"] = ep.get("Name")
                default["status"] = ep.get("Status")  # 1 = up, 2 = down
                break
        try:
            info = await client.get(f"/api/endpoints/{config.default_endpoint}/docker/info")
        except (httpx.TransportError, httpx.HTTPStatusError) as exc:
            logger.debug("status: docker info for default endpoint failed: %s", exc)
        else:
            swarm = (info or {}).get("Swarm") or {}
            default["swarm"] = swarm.get("LocalNodeState") == "active"
            default["swarm_manager"] = bool(swarm.get("ControlAvailable"))
        return json.dumps(
            {
                "connected": True,
                "url": config.url,
                "version": status.get("Version", "unknown"),
                "instance_id": status.get("InstanceID", "unknown"),
                "auth": "api_key" if config.api_key else "password",
                "endpoints": len(endpoint_list) if endpoints is not None else None,
                "default_endpoint": default,
            },
            indent=2,
            ensure_ascii=False,
        )
