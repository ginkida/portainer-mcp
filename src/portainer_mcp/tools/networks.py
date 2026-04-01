from __future__ import annotations

import json
import logging
import re

from mcp.server.fastmcp import FastMCP

from ..client import get_client
from ..config import get_config
from ..errors import tool_error_handler
from .containers import _validate_container_id

logger = logging.getLogger(__name__)

_NETWORK_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,254}$")


def _validate_network_name(name: str) -> None:
    if not _NETWORK_NAME_RE.match(name):
        raise ValueError(
            f"Invalid network name: {name!r}. "
            "Must be alphanumeric with _ . - only, 1-255 chars"
        )


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @tool_error_handler
    async def portainer_networks_list(endpoint_id: int | None = None) -> str:
        """List Docker networks on an endpoint.

        Args:
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        networks = await client.get(f"/api/endpoints/{eid}/docker/networks")
        result = []
        for n in networks:
            result.append({
                "id": n["Id"][:12],
                "name": n.get("Name"),
                "driver": n.get("Driver"),
                "scope": n.get("Scope"),
                "internal": n.get("Internal", False),
                "containers": len(n.get("Containers") or {}),
            })
        return json.dumps(result, indent=2)

    @mcp.tool()
    @tool_error_handler
    async def portainer_network_inspect(
        network_id: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Get detailed information about a Docker network.

        Args:
            network_id: Network ID or name
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_network_name(network_id)
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        data = await client.get(
            f"/api/endpoints/{eid}/docker/networks/{network_id}",
        )
        return json.dumps(data, indent=2)

    @mcp.tool()
    @tool_error_handler
    async def portainer_network_create(
        name: str,
        driver: str = "bridge",
        internal: bool = False,
        labels: dict[str, str] | None = None,
        endpoint_id: int | None = None,
    ) -> str:
        """Create a Docker network.

        Args:
            name: Network name
            driver: Network driver (default 'bridge'; use 'overlay' for Swarm)
            internal: Restrict external access (default false)
            labels: Optional labels as key-value pairs
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_network_name(name)
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        logger.info("AUDIT: Creating network %r on endpoint %d", name, eid)
        body: dict = {
            "Name": name,
            "Driver": driver,
            "Internal": internal,
            "CheckDuplicate": True,
        }
        if labels:
            body["Labels"] = labels
        data = await client.post(
            f"/api/endpoints/{eid}/docker/networks/create",
            json=body,
        )
        if data:
            return json.dumps(data, indent=2)
        return json.dumps({"status": "created", "name": name})

    @mcp.tool()
    @tool_error_handler
    async def portainer_network_remove(
        network_id: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Remove a Docker network.

        Args:
            network_id: Network ID or name
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_network_name(network_id)
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        logger.info("AUDIT: Removing network %r on endpoint %d", network_id, eid)
        await client.delete(
            f"/api/endpoints/{eid}/docker/networks/{network_id}",
        )
        return json.dumps({"status": "removed", "network_id": network_id})

    @mcp.tool()
    @tool_error_handler
    async def portainer_network_connect(
        network_id: str,
        container_id: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Connect a container to a network.

        Args:
            network_id: Network ID or name
            container_id: Container ID or name
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_network_name(network_id)
        _validate_container_id(container_id)
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        logger.info(
            "AUDIT: Connecting container %s to network %s on endpoint %d",
            container_id, network_id, eid,
        )
        await client.post(
            f"/api/endpoints/{eid}/docker/networks/{network_id}/connect",
            json={"Container": container_id},
        )
        return json.dumps({
            "status": "connected",
            "network_id": network_id,
            "container_id": container_id,
        })

    @mcp.tool()
    @tool_error_handler
    async def portainer_network_disconnect(
        network_id: str,
        container_id: str,
        force: bool = False,
        endpoint_id: int | None = None,
    ) -> str:
        """Disconnect a container from a network.

        Args:
            network_id: Network ID or name
            container_id: Container ID or name
            force: Force disconnect (default false)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_network_name(network_id)
        _validate_container_id(container_id)
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        logger.info(
            "AUDIT: Disconnecting container %s from network %s on endpoint %d",
            container_id, network_id, eid,
        )
        await client.post(
            f"/api/endpoints/{eid}/docker/networks/{network_id}/disconnect",
            json={"Container": container_id, "Force": force},
        )
        return json.dumps({
            "status": "disconnected",
            "network_id": network_id,
            "container_id": container_id,
        })
