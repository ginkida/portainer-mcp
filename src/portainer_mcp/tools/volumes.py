from __future__ import annotations

import json
import logging
import re

from mcp.server.fastmcp import FastMCP

from ..client import get_client
from ..config import get_config
from ..errors import tool_error_handler

logger = logging.getLogger(__name__)

_VOLUME_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,254}$")


def _validate_volume_name(name: str) -> None:
    if not _VOLUME_NAME_RE.match(name):
        raise ValueError(
            f"Invalid volume name: {name!r}. "
            "Must be alphanumeric with _ . - only, 1-255 chars"
        )


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @tool_error_handler
    async def portainer_volumes_list(endpoint_id: int | None = None) -> str:
        """List Docker volumes on an endpoint.

        Args:
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        data = await client.get(f"/api/endpoints/{eid}/docker/volumes")
        volumes = data.get("Volumes") or []
        result = []
        for v in volumes:
            result.append({
                "name": v.get("Name"),
                "driver": v.get("Driver"),
                "mountpoint": v.get("Mountpoint"),
                "scope": v.get("Scope"),
                "created_at": v.get("CreatedAt"),
                "labels": v.get("Labels") or {},
            })
        return json.dumps(result, indent=2)

    @mcp.tool()
    @tool_error_handler
    async def portainer_volume_inspect(
        volume_name: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Get detailed information about a Docker volume.

        Args:
            volume_name: Volume name
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_volume_name(volume_name)
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        data = await client.get(
            f"/api/endpoints/{eid}/docker/volumes/{volume_name}",
        )
        return json.dumps(data, indent=2)

    @mcp.tool()
    @tool_error_handler
    async def portainer_volume_create(
        name: str,
        driver: str = "local",
        labels: dict[str, str] | None = None,
        endpoint_id: int | None = None,
    ) -> str:
        """Create a Docker volume.

        Args:
            name: Volume name
            driver: Volume driver (default 'local')
            labels: Optional labels as key-value pairs
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_volume_name(name)
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        logger.info("AUDIT: Creating volume %r on endpoint %d", name, eid)
        body: dict = {"Name": name, "Driver": driver}
        if labels:
            body["Labels"] = labels
        data = await client.post(
            f"/api/endpoints/{eid}/docker/volumes/create",
            json=body,
        )
        if data:
            return json.dumps(data, indent=2)
        return json.dumps({"status": "created", "name": name})

    @mcp.tool()
    @tool_error_handler
    async def portainer_volume_remove(
        volume_name: str,
        force: bool = False,
        endpoint_id: int | None = None,
    ) -> str:
        """Remove a Docker volume.

        Args:
            volume_name: Volume name
            force: Force removal even if in use (default false)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_volume_name(volume_name)
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        logger.info("AUDIT: Removing volume %r on endpoint %d", volume_name, eid)
        await client.delete(
            f"/api/endpoints/{eid}/docker/volumes/{volume_name}",
            params={"force": "true" if force else "false"},
        )
        return json.dumps({"status": "removed", "volume_name": volume_name})
