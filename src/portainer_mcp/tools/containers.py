from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..client import get_client
from ..config import get_config
from ..errors import redact_secrets, resolve_endpoint, tool_error_handler

logger = logging.getLogger(__name__)

_CONTAINER_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$")
# Must stay in sync with stacks.py:_STACK_NAME_RE — Docker Swarm stack names
# do not allow dots, so neither should we when accepting one as input.
_STACK_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]{0,63}$")
_MAX_LOG_CHARS = 100_000

# Bounds for the multi-container scan helpers: cap how many containers a single
# call will touch, and how many of those run concurrently, so a huge stack can't
# exhaust the connection pool / Docker host or stall every other tool.
_STACK_FANOUT_LIMIT = 10
_MAX_STACK_TARGETS = 500

# Hard limits for the user-supplied regex in logs_grep. A pathological pattern
# can backtrack catastrophically (ReDoS); we cap its length and run the scan in
# a worker thread under an overall deadline so it can never wedge the event loop.
_MAX_GREP_PATTERN_CHARS = 512
_GREP_SCAN_TIMEOUT = 5.0

_ERROR_LINE_RE = re.compile(
    r"(?:"
    r'" [45]\d{2} '
    r"|\b(?:ERROR|CRITICAL|FATAL|EMERGENCY|ALERT)\b"
    r"|\bException\b"
    r"|\bTraceback\b"
    r"|\bpanic:\s"
    r"|\bFAILED\b"
    r"|\bsegfault\b"
    r"|\bOOM\b|\bout of memory\b"
    r"|\bPHP (?:Fatal|Warning|Parse)\b"
    r")",
    re.IGNORECASE,
)


def _validate_container_id(container_id: str) -> None:
    if not _CONTAINER_ID_RE.match(container_id):
        raise ValueError(
            f"Invalid container_id: {container_id!r}. "
            "Must be alphanumeric with _ . - only"
        )


def _parse_docker_stream(raw: bytes) -> str:
    """Parse Docker multiplexed stream (8-byte header per frame).

    Falls back to a plain UTF-8 decode of the whole buffer when no frames can
    be parsed (e.g. responses from non-TTY exec without multiplexing).
    Truncated trailing frames are decoded best-effort and a debug log emitted.
    """
    lines: list[str] = []
    i = 0
    n = len(raw)
    while i < n:
        if i + 8 > n:
            logger.debug(
                "Docker stream ended mid-header at byte %d/%d", i, n,
            )
            break
        size = int.from_bytes(raw[i + 4 : i + 8], "big")
        i += 8
        if size <= 0:
            continue
        if i + size > n:
            # Either the stream was truncated mid-frame, or the buffer isn't
            # multiplexed at all and we just misread random bytes as a header.
            # If we've already decoded at least one frame, treat as truncation;
            # otherwise fall back to a plain decode of the whole buffer so we
            # don't silently drop the first 8 bytes of plain text.
            if not lines:
                return raw.decode("utf-8", errors="replace")
            logger.debug(
                "Docker stream truncated frame: need %d bytes, have %d",
                size, n - i,
            )
            lines.append(raw[i:].decode("utf-8", errors="replace"))
            break
        lines.append(raw[i : i + size].decode("utf-8", errors="replace"))
        i += size
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
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
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
        return json.dumps(result, indent=2, ensure_ascii=False)

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
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        data = await client.get(
            f"/api/endpoints/{eid}/docker/containers/{container_id}/json",
        )
        return json.dumps(data, indent=2, ensure_ascii=False)

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
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        await client.post(
            f"/api/endpoints/{eid}/docker/containers/{container_id}/start",
        )
        return json.dumps(
            {"status": "started", "container_id": container_id}, ensure_ascii=False
        )

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
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        await client.post(
            f"/api/endpoints/{eid}/docker/containers/{container_id}/stop",
        )
        return json.dumps(
            {"status": "stopped", "container_id": container_id}, ensure_ascii=False
        )

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
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        await client.post(
            f"/api/endpoints/{eid}/docker/containers/{container_id}/restart",
        )
        return json.dumps(
            {"status": "restarted", "container_id": container_id}, ensure_ascii=False
        )

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
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        logger.info(
            "AUDIT: Removing container %s (force=%s) on endpoint %d",
            container_id, force, eid,
        )
        await client.delete(
            f"/api/endpoints/{eid}/docker/containers/{container_id}",
            params={"force": "true" if force else "false"},
        )
        return json.dumps(
            {"status": "removed", "container_id": container_id}, ensure_ascii=False
        )

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
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        resp = await client.request(
            "GET",
            f"/api/endpoints/{eid}/docker/containers/{container_id}/logs",
            params={"stdout": "true", "stderr": "true", "tail": str(tail)},
            timeout=config.long_timeout,
        )
        output = _parse_docker_stream(resp.content)
        if len(output) > _MAX_LOG_CHARS:
            output = output[:_MAX_LOG_CHARS] + f"\n... truncated ({len(output)} total chars)"
        return output

    @mcp.tool()
    @tool_error_handler
    async def portainer_container_logs_grep(
        container_id: str,
        pattern: str,
        tail: int = 500,
        context_lines: int = 0,
        endpoint_id: int | None = None,
    ) -> str:
        """Search container logs for lines matching a regex pattern.

        Returns only matching lines (with optional context). Useful for
        finding specific errors, status codes, or keywords without
        downloading the full log.

        Args:
            container_id: Container ID or name
            pattern: Regex pattern to search for (case-insensitive)
            tail: Number of log lines to fetch before filtering (default 500, max 1000)
            context_lines: Lines of context around each match (default 0, max 5)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_container_id(container_id)
        tail = max(1, min(tail, 1000))
        context_lines = max(0, min(context_lines, 5))
        if len(pattern) > _MAX_GREP_PATTERN_CHARS:
            raise ValueError(
                f"Regex pattern too long (max {_MAX_GREP_PATTERN_CHARS} chars)"
            )
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"Invalid regex pattern: {exc}") from None

        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        resp = await client.request(
            "GET",
            f"/api/endpoints/{eid}/docker/containers/{container_id}/logs",
            params={"stdout": "true", "stderr": "true", "tail": str(tail)},
            timeout=config.long_timeout,
        )
        text = _parse_docker_stream(resp.content)
        lines = text.splitlines()

        # A user-supplied regex can backtrack catastrophically. Run the whole
        # scan in a worker thread under a hard deadline so a pathological
        # pattern can never block the event loop / freeze the server.
        def _scan(buf: list[str]) -> list[int]:
            return [i for i, line in enumerate(buf) if regex.search(line)]

        try:
            hit_indices = await asyncio.wait_for(
                asyncio.to_thread(_scan, lines), timeout=_GREP_SCAN_TIMEOUT
            )
        except asyncio.TimeoutError:
            raise ValueError(
                "Regex search timed out (pattern too complex for this log volume)"
            ) from None

        if context_lines > 0 and hit_indices:
            visible: set[int] = set()
            for idx in hit_indices:
                for j in range(
                    max(0, idx - context_lines),
                    min(len(lines), idx + context_lines + 1),
                ):
                    visible.add(j)
            output_lines = [lines[i] for i in sorted(visible)]
        else:
            output_lines = [lines[i] for i in hit_indices]

        result = json.dumps(
            {
                "container_id": container_id,
                "pattern": pattern,
                "lines_scanned": len(lines),
                "matches_found": len(hit_indices),
                "lines": output_lines,
            },
            indent=2,
            ensure_ascii=False,
        )
        if len(result) > _MAX_LOG_CHARS:
            result = result[:_MAX_LOG_CHARS] + "\n... truncated"
        return result

    @mcp.tool()
    @tool_error_handler
    async def portainer_stack_logs_errors(
        stack_name: str,
        tail: int = 500,
        endpoint_id: int | None = None,
    ) -> str:
        """Scan all running containers in a stack for errors.

        Fetches logs from every running container whose name starts with
        the given stack name and filters for common error patterns:
        HTTP 4xx/5xx, exceptions, fatal/critical/emergency log levels,
        panics, OOM, PHP errors, segfaults, etc.

        Args:
            stack_name: Stack name prefix (e.g. "taylor", "blog", "somnlyx")
            tail: Log lines per container to scan (default 500, max 1000)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        if not _STACK_NAME_RE.match(stack_name):
            raise ValueError(f"Invalid stack_name: {stack_name!r}")
        tail = max(1, min(tail, 1000))

        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)

        containers = await client.get(
            f"/api/endpoints/{eid}/docker/containers/json",
            params={"all": "false"},
        )

        prefix = f"/{stack_name}_"
        targets: list[tuple[str, str]] = []
        for c in containers:
            for name in c.get("Names", []):
                if name.startswith(prefix):
                    short = name[1:].rsplit(".", 1)[0]
                    targets.append((c["Id"][:12], short))
                    break

        if not targets:
            return json.dumps({
                "stack": stack_name,
                "containers_scanned": 0,
                "total_errors": 0,
                "message": f"No running containers found for stack '{stack_name}'",
            }, ensure_ascii=False)

        if len(targets) > _MAX_STACK_TARGETS:
            logger.warning(
                "Stack %r has %d containers; scanning only the first %d",
                stack_name, len(targets), _MAX_STACK_TARGETS,
            )
            targets = targets[:_MAX_STACK_TARGETS]

        # Bound concurrency so a large stack can't exhaust the connection pool.
        sem = asyncio.Semaphore(_STACK_FANOUT_LIMIT)

        async def _fetch_errors(cid: str, name: str) -> tuple[str, str, int, list[str]]:
            async with sem:
                resp = await client.request(
                    "GET",
                    f"/api/endpoints/{eid}/docker/containers/{cid}/logs",
                    params={"stdout": "true", "stderr": "true", "tail": str(tail)},
                    timeout=config.long_timeout,
                )
                text = _parse_docker_stream(resp.content)
                all_lines = text.splitlines()
                errors = [ln for ln in all_lines if _ERROR_LINE_RE.search(ln)]
                return name, cid, len(all_lines), errors

        # return_exceptions=True so one container's failure yields partial
        # results instead of aborting the whole scan.
        results = await asyncio.gather(
            *[_fetch_errors(cid, name) for cid, name in targets],
            return_exceptions=True,
        )

        container_results = {}
        total_errors = 0
        failed = 0
        for result in results:
            if isinstance(result, BaseException):
                failed += 1
                logger.warning("Failed to fetch logs for a container: %s", result)
                continue
            name, cid, lines_scanned, errors = result
            total_errors += len(errors)
            container_results[name] = {
                "container_id": cid,
                "lines_scanned": lines_scanned,
                "errors_found": len(errors),
                "errors": errors,
            }

        output = json.dumps(
            {
                "stack": stack_name,
                "containers_scanned": len(container_results),
                "containers_failed": failed,
                "total_errors": total_errors,
                "containers": container_results,
            },
            indent=2,
            ensure_ascii=False,
        )
        if len(output) > _MAX_LOG_CHARS:
            output = output[:_MAX_LOG_CHARS] + "\n... truncated"
        return output

    @mcp.tool()
    @tool_error_handler
    async def portainer_laravel_errors(
        stack_name: str,
        tail: int = 50,
        endpoint_id: int | None = None,
    ) -> str:
        """Get Laravel application-level errors from storage/logs/laravel.log.

        Executes inside each running backend/horizon container of a stack
        to read the actual Laravel error log (not nginx access log).
        Returns production.ERROR entries with exception messages and context.

        Use this AFTER portainer_stack_logs_errors to get root cause details
        behind HTTP 500 errors seen in nginx access logs.

        Args:
            stack_name: Stack name prefix (e.g. "taylor", "blog", "somnlyx")
            tail: Number of error lines to return per container (default 50, max 200)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        if not _STACK_NAME_RE.match(stack_name):
            raise ValueError(f"Invalid stack_name: {stack_name!r}")
        tail = max(1, min(tail, 200))

        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)

        containers = await client.get(
            f"/api/endpoints/{eid}/docker/containers/json",
            params={"all": "false"},
        )

        prefix = f"/{stack_name}_"
        targets: list[tuple[str, str]] = []
        for c in containers:
            for name in c.get("Names", []):
                if name.startswith(prefix):
                    short = name[1:].rsplit(".", 1)[0]
                    targets.append((c["Id"][:12], short))
                    break

        if not targets:
            return json.dumps({
                "stack": stack_name,
                "containers_scanned": 0,
                "message": f"No running containers found for stack '{stack_name}'",
            }, ensure_ascii=False)

        if len(targets) > _MAX_STACK_TARGETS:
            logger.warning(
                "Stack %r has %d containers; scanning only the first %d",
                stack_name, len(targets), _MAX_STACK_TARGETS,
            )
            targets = targets[:_MAX_STACK_TARGETS]

        log_path = "/var/www/app/storage/logs/laravel.log"

        # Bound concurrency: each target costs two API calls plus an in-container
        # shell, so an unbounded fan-out over a big stack could overwhelm the host.
        sem = asyncio.Semaphore(_STACK_FANOUT_LIMIT)

        async def _fetch_laravel_errors(
            cid: str, name: str,
        ) -> tuple[str, str, str]:
            safe_tail = int(tail)
            # grep -E (ERE) is portable; \. matches a literal dot so we don't
            # also catch e.g. "productionXERROR".
            cmd = (
                f'grep -E "production\\.(ERROR|CRITICAL|EMERGENCY)" '
                f"{log_path} 2>/dev/null | tail -{safe_tail}"
            )
            exec_body = {
                "AttachStdout": True,
                "AttachStderr": True,
                "Cmd": ["sh", "-c", cmd],
            }
            async with sem:
                try:
                    exec_resp = await client.post(
                        f"/api/endpoints/{eid}/docker/containers/{cid}/exec",
                        json=exec_body,
                    )
                    exec_id = exec_resp["Id"]
                    start_resp = await client.request(
                        "POST",
                        f"/api/endpoints/{eid}/docker/exec/{exec_id}/start",
                        json={"Detach": False, "Tty": False},
                        timeout=config.long_timeout,
                    )
                    output = _parse_docker_stream(start_resp.content)
                except Exception:
                    # Keep details out of the tool output; log them server-side.
                    logger.exception("laravel_errors exec failed for %s", name)
                    output = "exec failed"
            return name, cid, output

        results = await asyncio.gather(
            *[_fetch_laravel_errors(cid, name) for cid, name in targets],
        )

        container_results = {}
        for name, cid, output in results:
            lines = [ln for ln in output.splitlines() if ln.strip()]
            container_results[name] = {
                "container_id": cid,
                "errors_found": len(lines),
                "errors": lines,
            }

        result = json.dumps(
            {
                "stack": stack_name,
                "containers_scanned": len(targets),
                "log_path": log_path,
                "containers": container_results,
            },
            indent=2,
            ensure_ascii=False,
        )
        if len(result) > _MAX_LOG_CHARS:
            result = result[:_MAX_LOG_CHARS] + "\n... truncated"
        return result

    @mcp.tool()
    @tool_error_handler
    async def portainer_laravel_tinker(
        stack_name: str,
        code: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Execute PHP code via Laravel Tinker inside a stack's backend container.

        Finds a running backend container for the given stack and runs
        `php artisan tinker --execute="<code>"`. Useful for inspecting
        database records, checking model state, running one-off fixes,
        and debugging application issues.

        Args:
            stack_name: Stack name prefix (e.g. "taylor", "blog", "somnlyx")
            code: PHP code to execute (will be passed to tinker --execute)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        if not _STACK_NAME_RE.match(stack_name):
            raise ValueError(f"Invalid stack_name: {stack_name!r}")
        if len(code) > 4096:
            raise ValueError("Code too long (max 4096 chars)")

        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)

        containers = await client.get(
            f"/api/endpoints/{eid}/docker/containers/json",
            params={"all": "false"},
        )

        # Find first running backend container for the stack
        prefix = f"/{stack_name}_backend."
        target_id: str | None = None
        target_name: str | None = None
        for c in containers:
            for name in c.get("Names", []):
                if name.startswith(prefix):
                    target_id = c["Id"][:12]
                    target_name = name[1:].rsplit(".", 1)[0]
                    break
            if target_id:
                break

        if not target_id:
            return json.dumps({
                "error": f"No running backend container found for stack '{stack_name}'",
            }, ensure_ascii=False)

        logger.info(
            "AUDIT: Laravel tinker in %s (%s) on endpoint %d: %s",
            target_name, target_id, eid, redact_secrets(code[:200]),
        )

        # Escape single quotes in code for safe shell embedding
        safe_code = code.replace("'", "'\\''")
        exec_body = {
            "AttachStdout": True,
            "AttachStderr": True,
            "Cmd": [
                "sh", "-c",
                f"cd /var/www/app && php artisan tinker --execute='{safe_code}'",
            ],
        }
        exec_resp = await client.post(
            f"/api/endpoints/{eid}/docker/containers/{target_id}/exec",
            json=exec_body,
        )
        exec_id = exec_resp["Id"]

        start_resp = await client.request(
            "POST",
            f"/api/endpoints/{eid}/docker/exec/{exec_id}/start",
            json={"Detach": False, "Tty": False},
            timeout=config.long_timeout,
        )
        output = _parse_docker_stream(start_resp.content)

        inspect = await client.get(
            f"/api/endpoints/{eid}/docker/exec/{exec_id}/json",
        )
        exit_code = inspect.get("ExitCode", -1)

        if len(output) > _MAX_LOG_CHARS:
            output = output[:_MAX_LOG_CHARS] + "\n... truncated"

        return json.dumps(
            {
                "container": target_name,
                "container_id": target_id,
                "exit_code": exit_code,
                "output": output,
            },
            indent=2,
            ensure_ascii=False,
        )

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
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
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
        }, indent=2, ensure_ascii=False)

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
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        logger.info(
            "AUDIT: Exec in container %s on endpoint %d: %s",
            container_id, eid, redact_secrets(command[:200]),
        )

        # Step 1: Create exec instance
        exec_body: dict[str, Any] = {
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
            timeout=config.long_timeout,
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
        }, indent=2, ensure_ascii=False)
