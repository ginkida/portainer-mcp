from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..client import get_client
from ..config import get_config
from ..errors import resolve_endpoint, tool_error_handler

logger = logging.getLogger(__name__)

# What portainer_docker_prune may clean. Volumes are deliberately absent:
# pruning them destroys data, which no "free some disk" request should do
# implicitly — remove a volume by name with portainer_volume_remove instead.
_PRUNE_TARGETS: dict[str, tuple[str, str]] = {
    # target -> (Docker API path, key holding the list of deleted items)
    "containers": ("containers/prune", "ContainersDeleted"),
    "images": ("images/prune", "ImagesDeleted"),
    "build_cache": ("build/prune", "CachesDeleted"),
}


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @tool_error_handler
    async def portainer_docker_info(endpoint_id: int | None = None) -> str:
        """Get Docker system information for an endpoint (OS, CPU, memory, containers count, etc).

        Args:
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        info = await client.get(f"/api/endpoints/{eid}/docker/info") or {}
        return json.dumps({
            "name": info.get("Name"),
            "os": info.get("OperatingSystem"),
            "architecture": info.get("Architecture"),
            "cpus": info.get("NCPU"),
            "memory_gb": round(info.get("MemTotal", 0) / 1_073_741_824, 1),
            "kernel_version": info.get("KernelVersion"),
            "docker_version": info.get("ServerVersion"),
            "containers": info.get("Containers"),
            "containers_running": info.get("ContainersRunning"),
            "containers_paused": info.get("ContainersPaused"),
            "containers_stopped": info.get("ContainersStopped"),
            "images": info.get("Images"),
            "storage_driver": info.get("Driver"),
            "swarm_active": info.get("Swarm", {}).get("LocalNodeState") == "active",
        }, indent=2, ensure_ascii=False)

    @mcp.tool()
    @tool_error_handler
    async def portainer_docker_disk_usage(endpoint_id: int | None = None) -> str:
        """Get Docker disk usage (containers, images, volumes, build cache).

        Args:
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        df = await client.get(f"/api/endpoints/{eid}/docker/system/df") or {}

        def _size_mb(b: int) -> float:
            return round(b / 1_048_576, 1)

        images = df.get("Images") or []
        containers = df.get("Containers") or []
        volumes = df.get("Volumes") or []
        build_cache = df.get("BuildCache") or []

        return json.dumps({
            "images": {
                "count": len(images),
                "total_mb": _size_mb(sum(i.get("Size", 0) for i in images)),
                "reclaimable_mb": _size_mb(
                    sum(i.get("Size", 0) for i in images if i.get("Containers", 0) == 0)
                ),
            },
            "containers": {
                "count": len(containers),
                "total_mb": _size_mb(sum(c.get("SizeRw", 0) or 0 for c in containers)),
            },
            "volumes": {
                "count": len(volumes),
                "total_mb": _size_mb(
                    sum(v.get("UsageData", {}).get("Size", 0) or 0 for v in volumes)
                ),
            },
            "build_cache": {
                "count": len(build_cache),
                "total_mb": _size_mb(sum(b.get("Size", 0) or 0 for b in build_cache)),
            },
        }, indent=2, ensure_ascii=False)

    @mcp.tool()
    @tool_error_handler
    async def portainer_docker_prune(
        target: str,
        all_images: bool = False,
        endpoint_id: int | None = None,
    ) -> str:
        """Reclaim disk space: remove stopped containers, unused images or build cache.

        Volumes are never pruned by this tool (that destroys data); use
        portainer_volume_remove for a specific volume. Check
        portainer_docker_disk_usage first to see what is reclaimable.

        Args:
            target: "containers" (all stopped), "images" (dangling only, or
                every unused image with all_images=true) or "build_cache"
            all_images: For target="images": also remove tagged images not
                used by any container (default false — dangling layers only)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        if target not in _PRUNE_TARGETS:
            raise ValueError(
                f"Invalid target: {target!r}. Must be one of {', '.join(_PRUNE_TARGETS)}"
            )
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        path, deleted_key = _PRUNE_TARGETS[target]
        params: dict[str, str] = {}
        if target == "images":
            params["filters"] = json.dumps({"dangling": ["false" if all_images else "true"]})
        logger.info(
            "AUDIT: Pruning %s on endpoint %d (all_images=%s)", target, eid, all_images
        )
        result: dict[str, Any] = (
            await client.post(
                f"/api/endpoints/{eid}/docker/{path}",
                params=params,
                # Deleting hundreds of layers can take a while.
                timeout=config.long_timeout,
            )
            or {}
        )
        deleted = result.get(deleted_key) or []
        return json.dumps(
            {
                "status": "pruned",
                "target": target,
                "deleted_count": len(deleted),
                "space_reclaimed_mb": round((result.get("SpaceReclaimed") or 0) / 1_048_576, 1),
            },
            indent=2,
            ensure_ascii=False,
        )
