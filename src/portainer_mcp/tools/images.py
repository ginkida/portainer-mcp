from __future__ import annotations

import json
import logging
import re
from urllib.parse import quote

from mcp.server.fastmcp import FastMCP

from ..client import get_client
from ..config import get_config
from ..errors import tool_error_handler

logger = logging.getLogger(__name__)

_IMAGE_REF_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9_.\-/]*[a-zA-Z0-9])?(:[a-zA-Z0-9_.\-]+)?$"
)


def _validate_image_ref(ref: str) -> None:
    if not _IMAGE_REF_RE.match(ref) or ".." in ref:
        raise ValueError(
            f"Invalid image reference: {ref!r}. "
            "Expected format: [registry/]name[:tag], no path traversal (..)"
        )


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @tool_error_handler
    async def portainer_images_list(endpoint_id: int | None = None) -> str:
        """List Docker images on an endpoint.

        Args:
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        images = await client.get(
            f"/api/endpoints/{eid}/docker/images/json",
        )
        result = []
        for img in images:
            result.append({
                "id": img["Id"][:19],
                "tags": img.get("RepoTags", []),
                "size_mb": round(img.get("Size", 0) / 1_048_576, 1),
                "created": img.get("Created"),
            })
        return json.dumps(result, indent=2)

    @mcp.tool()
    @tool_error_handler
    async def portainer_image_inspect(
        image_id: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Get detailed information about a Docker image.

        Args:
            image_id: Image ID or name:tag
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_image_ref(image_id)
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        safe_id = quote(image_id, safe="")
        data = await client.get(
            f"/api/endpoints/{eid}/docker/images/{safe_id}/json",
        )
        return json.dumps(data, indent=2)

    @mcp.tool()
    @tool_error_handler
    async def portainer_image_pull(
        image_name: str,
        tag: str = "latest",
        endpoint_id: int | None = None,
    ) -> str:
        """Pull a Docker image from a registry.

        Args:
            image_name: Image name (e.g. 'nginx', 'ghcr.io/org/app')
            tag: Image tag (default 'latest')
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_image_ref(f"{image_name}:{tag}")
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        logger.info("AUDIT: Pulling image %s:%s on endpoint %d", image_name, tag, eid)
        await client.request(
            "POST",
            f"/api/endpoints/{eid}/docker/images/create",
            params={"fromImage": image_name, "tag": tag},
        )
        return json.dumps({
            "status": "pulled",
            "image": f"{image_name}:{tag}",
        })

    @mcp.tool()
    @tool_error_handler
    async def portainer_image_remove(
        image_id: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Remove a Docker image.

        Args:
            image_id: Image ID or name:tag
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_image_ref(image_id)
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        logger.info("AUDIT: Removing image %s on endpoint %d", image_id, eid)
        safe_id = quote(image_id, safe="")
        await client.delete(
            f"/api/endpoints/{eid}/docker/images/{safe_id}",
        )
        return json.dumps({"status": "removed", "image_id": image_id})
