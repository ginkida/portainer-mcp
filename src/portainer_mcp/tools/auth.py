from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from ..client import get_client
from ..config import get_config
from ..errors import PortainerResponseError, redact_secrets, tool_error_handler
from .system import swarm_flags

logger = logging.getLogger(__name__)

# Enrichment calls may fail in every way client.get can fail — transport,
# HTTP status, a proxy's HTML page (PortainerResponseError), the response-size
# guard (ValueError) — and none of them says anything about connectivity.
_ENRICHMENT_ERRORS = (httpx.HTTPError, PortainerResponseError, ValueError)
_ENDPOINT_DOWN = 2


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
        # reachable Portainer into "connected: false". Every key is present
        # on every path (null when unknown) so callers can branch safely.
        endpoints: Any = None
        default: dict[str, Any] = {
            "id": config.default_endpoint,
            "name": None,
            "status": None,
            "swarm": None,
            "swarm_role": None,
        }
        try:
            # excludeSnapshots: the listing is only used for count/name/status,
            # not the multi-KB snapshot each endpoint carries.
            endpoints = await client.get("/api/endpoints", params={"excludeSnapshots": "true"})
        except _ENRICHMENT_ERRORS as exc:
            logger.debug("status: endpoint listing failed: %s", exc)
        endpoint_list = [e for e in (endpoints or []) if isinstance(e, dict)]
        for ep in endpoint_list:
            if ep.get("Id") == config.default_endpoint:
                default["name"] = ep.get("Name")
                default["status"] = ep.get("Status")  # 1 = up, 2 = down
                break
        if default["status"] != _ENDPOINT_DOWN:
            # Skip the agent round-trip when Portainer already says the
            # endpoint is down — it would only burn the full timeout.
            try:
                info = await client.get(f"/api/endpoints/{config.default_endpoint}/docker/info")
            except _ENRICHMENT_ERRORS as exc:
                logger.debug("status: docker info for default endpoint failed: %s", exc)
            else:
                joined, manager = swarm_flags(info)
                # `swarm` answers "will the service/stack tools work here?" —
                # that is the manager question; a worker says false.
                default["swarm"] = manager
                default["swarm_role"] = "manager" if manager else "worker" if joined else None
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
