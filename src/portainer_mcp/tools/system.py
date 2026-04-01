from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import get_client
from ..config import get_config
from ..errors import tool_error_handler


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
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        info = await client.get(f"/api/endpoints/{eid}/docker/info")
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
        }, indent=2)

    @mcp.tool()
    @tool_error_handler
    async def portainer_docker_disk_usage(endpoint_id: int | None = None) -> str:
        """Get Docker disk usage (containers, images, volumes, build cache).

        Args:
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        df = await client.get(f"/api/endpoints/{eid}/docker/system/df")

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
        }, indent=2)
