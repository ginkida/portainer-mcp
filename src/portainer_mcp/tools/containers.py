from __future__ import annotations

import json
import logging
import re

from mcp.server.fastmcp import FastMCP

from ..client import get_client
from ..config import get_config
from ..errors import tool_error_handler

logger = logging.getLogger(__name__)

_CONTAINER_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$")
_MAX_LOG_CHARS = 100_000


def _validate_container_id(container_id: str) -> None:
    if not _CONTAINER_ID_RE.match(container_id):
        raise ValueError(
            f"Invalid container_id: {container_id!r}. "
            "Must be alphanumeric with _ . - only"
        )


def _parse_docker_stream(raw: bytes) -> str:
    """Parse Docker multiplexed stream (8-byte header per frame)."""
    lines: list[str] = []
    i = 0
    while i < len(raw):
        if i + 8 <= len(raw):
            size = int.from_bytes(raw[i + 4 : i + 8], "big")
            i += 8
            if size > 0 and i + size <= len(raw):
                lines.append(raw[i : i + size].decode("utf-8", errors="replace"))
            i += size
        else:
            break
    return "".join(lines) if lines else raw.decode("utf-8", errors="replace")


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @tool_error_handler
    async def portainer_containers_list(
        endpoint_id: int | None = None,
        show_all: bool = False,
    ) -> str:
        """List containers on an endpoint.

        Args:
            endpoint_id: Target endpoint ID (uses default if omitted)
            show_all: If true, show all containers including stopped ones
        """
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        params = {"all": "true" if show_all else "false"}
        containers = await client.get(
            f"/api/endpoints/{eid}/docker/containers/json",
            params=params,
        )
        result = []
        for c in containers:
            result.append({
                "id": c["Id"][:12],
                "names": c.get("Names", []),
                "image": c.get("Image"),
                "state": c.get("State"),
                "status": c.get("Status"),
                "created": c.get("Created"),
            })
        return json.dumps(result, indent=2)

    @mcp.tool()
    @tool_error_handler
    async def portainer_container_inspect(
        container_id: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Get detailed information about a container.

        Args:
            container_id: Container ID or name
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_container_id(container_id)
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        data = await client.get(
            f"/api/endpoints/{eid}/docker/containers/{container_id}/json",
        )
        return json.dumps(data, indent=2)

    @mcp.tool()
    @tool_error_handler
    async def portainer_container_start(
        container_id: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Start a stopped container.

        Args:
            container_id: Container ID or name
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_container_id(container_id)
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        await client.post(
            f"/api/endpoints/{eid}/docker/containers/{container_id}/start",
        )
        return json.dumps({"status": "started", "container_id": container_id})

    @mcp.tool()
    @tool_error_handler
    async def portainer_container_stop(
        container_id: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Stop a running container.

        Args:
            container_id: Container ID or name
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_container_id(container_id)
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        await client.post(
            f"/api/endpoints/{eid}/docker/containers/{container_id}/stop",
        )
        return json.dumps({"status": "stopped", "container_id": container_id})

    @mcp.tool()
    @tool_error_handler
    async def portainer_container_restart(
        container_id: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Restart a container.

        Args:
            container_id: Container ID or name
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_container_id(container_id)
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        await client.post(
            f"/api/endpoints/{eid}/docker/containers/{container_id}/restart",
        )
        return json.dumps({"status": "restarted", "container_id": container_id})

    @mcp.tool()
    @tool_error_handler
    async def portainer_container_remove(
        container_id: str,
        force: bool = False,
        endpoint_id: int | None = None,
    ) -> str:
        """Remove a container.

        Args:
            container_id: Container ID or name
            force: Force removal of a running container (default false)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_container_id(container_id)
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        logger.info(
            "AUDIT: Removing container %s (force=%s) on endpoint %d",
            container_id, force, eid,
        )
        await client.delete(
            f"/api/endpoints/{eid}/docker/containers/{container_id}",
            params={"force": "true" if force else "false"},
        )
        return json.dumps({"status": "removed", "container_id": container_id})

    @mcp.tool()
    @tool_error_handler
    async def portainer_container_logs(
        container_id: str,
        tail: int = 100,
        endpoint_id: int | None = None,
    ) -> str:
        """Get container logs.

        Args:
            container_id: Container ID or name
            tail: Number of lines from the end of the logs (default 100, max 1000)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_container_id(container_id)
        tail = max(1, min(tail, 1000))
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        resp = await client.request(
            "GET",
            f"/api/endpoints/{eid}/docker/containers/{container_id}/logs",
            params={"stdout": "true", "stderr": "true", "tail": str(tail)},
        )
        output = _parse_docker_stream(resp.content)
        if len(output) > _MAX_LOG_CHARS:
            output = output[:_MAX_LOG_CHARS] + f"\n... truncated ({len(output)} total chars)"
        return output

    @mcp.tool()
    @tool_error_handler
    async def portainer_container_stats(
        container_id: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Get live CPU, memory, and network stats for a container.

        Args:
            container_id: Container ID or name
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_container_id(container_id)
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        resp = await client.request(
            "GET",
            f"/api/endpoints/{eid}/docker/containers/{container_id}/stats",
            params={"stream": "false"},
        )
        s = resp.json()

        # CPU usage calculation
        cpu_delta = (
            s.get("cpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0)
            - s.get("precpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0)
        )
        system_delta = (
            s.get("cpu_stats", {}).get("system_cpu_usage", 0)
            - s.get("precpu_stats", {}).get("system_cpu_usage", 0)
        )
        online_cpus = s.get("cpu_stats", {}).get("online_cpus", 1)
        cpu_percent = 0.0
        if system_delta > 0:
            cpu_percent = round((cpu_delta / system_delta) * online_cpus * 100, 2)

        # Memory
        mem = s.get("memory_stats", {})
        mem_usage = mem.get("usage", 0)
        mem_limit = mem.get("limit", 1)
        mem_percent = round((mem_usage / mem_limit) * 100, 2) if mem_limit > 0 else 0

        # Network I/O
        net = s.get("networks", {})
        net_rx = sum(v.get("rx_bytes", 0) for v in net.values())
        net_tx = sum(v.get("tx_bytes", 0) for v in net.values())

        # Block I/O
        blk = s.get("blkio_stats", {}).get("io_service_bytes_recursive") or []
        blk_read = sum(e.get("value", 0) for e in blk if e.get("op") == "Read")
        blk_write = sum(e.get("value", 0) for e in blk if e.get("op") == "Write")

        def _mb(b: int) -> float:
            return round(b / 1_048_576, 1)

        return json.dumps({
            "cpu_percent": cpu_percent,
            "online_cpus": online_cpus,
            "memory_usage_mb": _mb(mem_usage),
            "memory_limit_mb": _mb(mem_limit),
            "memory_percent": mem_percent,
            "network_rx_mb": _mb(net_rx),
            "network_tx_mb": _mb(net_tx),
            "block_read_mb": _mb(blk_read),
            "block_write_mb": _mb(blk_write),
            "pids": s.get("pids_stats", {}).get("current", 0),
        }, indent=2)

    @mcp.tool()
    @tool_error_handler
    async def portainer_container_exec(
        container_id: str,
        command: str,
        workdir: str | None = None,
        user: str | None = None,
        endpoint_id: int | None = None,
    ) -> str:
        """Execute a command inside a running container and return its output.

        Args:
            container_id: Container ID or name
            command: Shell command to execute (run via sh -c)
            workdir: Working directory inside the container
            user: User to run the command as (e.g. 'root', '1000:1000')
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_container_id(container_id)
        if len(command) > 4096:
            raise ValueError("Command too long (max 4096 chars)")
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        logger.info(
            "AUDIT: Exec in container %s on endpoint %d: %s",
            container_id, eid, command[:200],
        )

        # Step 1: Create exec instance
        exec_body: dict = {
            "AttachStdout": True,
            "AttachStderr": True,
            "Cmd": ["sh", "-c", command],
        }
        if workdir:
            exec_body["WorkingDir"] = workdir
        if user:
            exec_body["User"] = user

        exec_resp = await client.post(
            f"/api/endpoints/{eid}/docker/containers/{container_id}/exec",
            json=exec_body,
        )
        exec_id = exec_resp["Id"]

        # Step 2: Start exec and capture output
        start_resp = await client.request(
            "POST",
            f"/api/endpoints/{eid}/docker/exec/{exec_id}/start",
            json={"Detach": False, "Tty": False},
        )

        output = _parse_docker_stream(start_resp.content)

        # Step 3: Get exit code
        inspect = await client.get(
            f"/api/endpoints/{eid}/docker/exec/{exec_id}/json",
        )
        exit_code = inspect.get("ExitCode", -1)

        if len(output) > _MAX_LOG_CHARS:
            output = output[:_MAX_LOG_CHARS] + f"\n... truncated ({len(output)} total chars)"

        return json.dumps({
            "exit_code": exit_code,
            "output": output,
        }, indent=2)
