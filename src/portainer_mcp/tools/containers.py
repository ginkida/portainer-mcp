from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections import deque
from contextlib import aclosing
from typing import Any, NamedTuple
from urllib.parse import quote

import httpx
from mcp.server.fastmcp import FastMCP

from ..client import PortainerClient, get_client
from ..config import get_config
from ..errors import (
    PortainerResponseError,
    redact_secrets,
    resolve_endpoint,
    tool_error_handler,
    validate_filter,
)
from .logs import (
    _DEFAULT_LOG_BYTES,
    _DEFAULT_LOG_MATCHES,
    _MAX_LOG_CHARS,
    _docker_window_lines,
    _LogCoverage,
    _LogMatches,
    _LogWindow,
    _match_budget,
)
from .logs import (
    _parse_since as _parse_since,
)

logger = logging.getLogger(__name__)

_CONTAINER_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$")
# Must stay in sync with stacks.py:_STACK_NAME_RE — Docker Swarm stack names
# do not allow dots, so neither should we when accepting one as input.
_STACK_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]{0,63}$")

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
# Only the first N chars of each line are matched: catastrophic backtracking
# grows with input length, and no useful log line needs more than this.
_MAX_GREP_LINE_CHARS = 8192

# Docker labels that tie a container to its stack / service (Swarm and Compose).
_STACK_LABELS = ("com.docker.stack.namespace", "com.docker.compose.project")
_SERVICE_LABELS = ("com.docker.swarm.service.name", "com.docker.compose.service")

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


def _log_params(tail: int, since: str | None, timestamps: bool) -> dict[str, str]:
    """Query parameters for the buffered tail readers."""
    params = {"stdout": "true", "stderr": "true", "tail": str(tail)}
    if timestamps:
        params["timestamps"] = "true"
    since_ts = _parse_since(since)
    if since_ts is not None:
        params["since"] = str(since_ts)
    return params


def _container_labels(c: dict[str, Any]) -> tuple[str | None, str | None]:
    """``(stack, service)`` from Swarm / Compose labels, or ``None``s."""
    labels = c.get("Labels") or {}
    stack = next((labels[k] for k in _STACK_LABELS if labels.get(k)), None)
    service = next((labels[k] for k in _SERVICE_LABELS if labels.get(k)), None)
    return stack, service


def _parse_docker_stream(raw: bytes) -> str:
    """Parse Docker multiplexed stream (8-byte header per frame).

    A frame header is ``[stream_type, 0, 0, 0, size(4 bytes, big-endian)]``
    with stream_type in {0: stdin, 1: stdout, 2: stderr}. Headers are validated
    for plausibility so a non-multiplexed plain-text response (e.g. TTY exec)
    is decoded as-is instead of having bytes misread as frame headers, and a
    truncated first frame yields its payload tail rather than leaking the
    8 binary header bytes into the output.
    """
    lines: list[str] = []
    i = 0
    n = len(raw)
    while i < n:
        if i + 8 > n:
            if not lines:
                return raw.decode("utf-8", errors="replace")
            logger.debug("Docker stream ended mid-header at byte %d/%d", i, n)
            break
        header = raw[i : i + 8]
        if header[0] not in (0, 1, 2) or header[1:4] != b"\x00\x00\x00":
            # Not a multiplexed frame header: plain text from a TTY response.
            if not lines:
                return raw.decode("utf-8", errors="replace")
            lines.append(raw[i:].decode("utf-8", errors="replace"))
            break
        size = int.from_bytes(header[4:8], "big")
        i += 8
        if size == 0:
            continue
        if i + size > n:
            # Plausible header but the payload was cut short (transport
            # truncation): decode the partial payload best-effort.
            logger.debug(
                "Docker stream truncated frame: need %d bytes, have %d",
                size, n - i,
            )
            lines.append(raw[i:].decode("utf-8", errors="replace"))
            break
        lines.append(raw[i : i + size].decode("utf-8", errors="replace"))
        i += size
    return "".join(lines)


def _stack_targets(
    containers: list[dict[str, Any]],
    stack_name: str,
    service: str | None = None,
) -> list[tuple[str, str]]:
    """Find ``(short_id, short_name)`` for running containers of a stack.

    Without ``service``, matches any container named ``/{stack}_...``. With
    ``service``, matches that service across naming schemes: exact
    ``/{stack}_{service}`` (plain ``docker run`` / Compose), Swarm replicas
    ``/{stack}_{service}.1.task-id`` and Compose v1 ``/{stack}_{service}_1``.
    The Compose-v1 underscore suffix must be all digits — otherwise sibling
    services like ``{service}_worker`` would be misidentified as ``{service}``.
    """
    base = f"/{stack_name}_{service}" if service else f"/{stack_name}_"
    targets: list[tuple[str, str]] = []
    for c in containers:
        for name in c.get("Names", []):
            if service:
                matched = (
                    name == base
                    or name.startswith(base + ".")
                    or (
                        name.startswith(base + "_")
                        and name[len(base) + 1 :].isdigit()
                    )
                )
            else:
                matched = name.startswith(base)
            if matched:
                targets.append((c["Id"][:12], name[1:].rsplit(".", 1)[0]))
                break
    return targets


# When a single line blows the output budget, keep this much of it (plus a
# marker) rather than returning nothing: one giant JSON dump or minified stack
# trace must not turn a 100K budget into an empty answer.
_MIN_PARTIAL_LINE_CHARS = 200
_LINE_TRUNCATED_MARKER = " …[line truncated: {total} chars]"


def _cap_lines(lines: list[str], budget: int) -> tuple[list[str], bool]:
    """Trim ``lines`` so their combined size fits ``budget`` characters.

    Data is capped *before* JSON serialization so the tool output stays valid
    JSON (slicing a serialized document would cut mid-string). Whole lines are
    dropped from the end; the one line that doesn't fit is kept as a partial
    slice when there is meaningful room left for it, so a single oversized
    line can never make the result empty. Returns the kept lines and whether
    anything was dropped or cut.
    """
    total = 0
    for idx, line in enumerate(lines):
        total += len(line) + 1
        if total > budget:
            remaining = budget - (total - len(line) - 1)
            marker = _LINE_TRUNCATED_MARKER.format(total=len(line))
            if remaining - len(marker) >= _MIN_PARTIAL_LINE_CHARS:
                return [*lines[:idx], line[: remaining - len(marker)] + marker], True
            return lines[:idx], True
    return lines, False


class _GrepTimeout(ValueError):
    pass


async def _grep_indices(regex: re.Pattern[str], lines: list[str], timeout: float) -> list[int]:
    # Check between lines in the worker as well as on the caller's deadline.
    deadline = time.monotonic() + timeout

    def scan() -> list[int]:
        hits = []
        for index, line in enumerate(lines):
            if time.monotonic() > deadline:
                raise TimeoutError
            if regex.search(line[:_MAX_GREP_LINE_CHARS]):
                hits.append(index)
        return hits

    try:
        return await asyncio.wait_for(asyncio.to_thread(scan), timeout=timeout)
    except (asyncio.TimeoutError, TimeoutError):
        raise _GrepTimeout(
            "Regex search timed out (pattern too complex for this log volume)"
        ) from None


async def _grep_window(
    client: PortainerClient, path: str, coverage: _LogCoverage, timeout: float,
    regex: re.Pattern[str], context_lines: int, timestamps: bool, max_matches: int,
) -> _LogMatches:
    matches = _LogMatches(_match_budget(max_matches))
    previous: deque[tuple[int, str, int, str]] = deque(maxlen=context_lines)
    position = 0
    last_output = -1
    context_end = -1

    async def scan(batch: list[tuple[str, int, str]]) -> None:
        nonlocal position, last_output, context_end
        hits = set(await _grep_indices(regex, [row[0] for row in batch], _GREP_SCAN_TIMEOUT))
        for index, (line, ns, stamp) in enumerate(batch):
            coverage.scan(ns, stamp)
            if index in hits:
                kept = matches.match(line)
                if kept is not None:
                    for pos, before, before_ns, before_stamp in previous:
                        if pos > last_output and pos >= position - context_lines:
                            add_context(before, before_ns, before_stamp)
                    matches.lines.append(kept)
                    coverage.returned(ns, stamp)
                    last_output = position
                    context_end = position + context_lines
            else:
                if position <= context_end:
                    add_context(line, ns, stamp)
                    last_output = position
                previous.append((position, line, ns, stamp))
            position += 1

    def add_context(line: str, ns: int, stamp: str) -> None:
        kept = matches.budget.context(line)
        if kept is None:
            matches.limited = True
        else:
            matches.lines.append(kept)
            coverage.returned(ns, stamp)

    batch: list[tuple[str, int, str]] = []
    try:
        async with aclosing(_docker_window_lines(
            client, path, coverage, timeout, timestamps=timestamps, track_coverage=False,
        )) as lines:
            async for _, text, ns, stamp in lines:
                batch.append((text, ns, stamp))
                if len(batch) == 128:
                    await scan(batch)
                    batch.clear()
            if batch:
                await scan(batch)
    except _GrepTimeout:
        coverage.stop_reason = "regex_timeout"
    return matches


class _WindowTarget(NamedTuple):
    id: str
    name: str
    service: str
    headers: dict[str, str]


def _window_stack_targets(
    containers: list[dict[str, Any]] | None, stack_name: str,
) -> list[_WindowTarget]:
    targets = []
    for container in containers or []:
        stack, service = _container_labels(container)
        cid = container["Id"]
        names = container.get("Names") or []
        if stack == stack_name:
            name = names[0].lstrip("/") if names else cid
        elif stack is None and (matches := _stack_targets([container], stack_name)):
            _, name = matches[0]
            # Legacy, unlabelled Swarm and Compose-v1 replica names.
            service = re.sub(r"[._]\d+$", "", name)
        else:
            continue
        _validate_container_id(cid)
        portainer = container.get("Portainer")
        agent = portainer.get("Agent") if isinstance(portainer, dict) else None
        node = agent.get("NodeName") if isinstance(agent, dict) else None
        headers = {"X-PortainerAgent-Target": node} if isinstance(node, str) and node else {}
        targets.append(_WindowTarget(cid, name, service or name, headers))
    return targets


async def _stack_log_window(
    client: PortainerClient, eid: int, stack_name: str, targets: list[_WindowTarget],
    window: _LogWindow, timeout: float, max_matches: int, max_bytes: int,
) -> str:
    services: dict[str, list[_WindowTarget]] = {}
    for target in targets[:_MAX_STACK_TARGETS]:
        services.setdefault(target.service, []).append(target)

    budget = _match_budget(max_matches)
    sem = asyncio.Semaphore(_STACK_FANOUT_LIMIT)
    combined = _LogCoverage(window, max_bytes)

    async def scan(replicas: list[_WindowTarget]) -> dict[str, Any]:
        coverage = _LogCoverage(window, max_bytes)
        matches = _LogMatches(budget)
        failed = []
        scanned = 0
        attempted = 0
        async with sem:
            for target in replicas:
                attempted += 1
                path = f"/api/endpoints/{eid}/docker/containers/{quote(target.id, safe='')}/logs"
                try:
                    async with aclosing(_docker_window_lines(
                        client, path, coverage, timeout, headers=target.headers,
                    )) as lines:
                        async for _, text, ns, stamp in lines:
                            if _ERROR_LINE_RE.search(text):
                                kept = matches.match(text)
                                if kept is not None:
                                    matches.lines.append(kept)
                                    coverage.returned(ns, stamp)
                    scanned += 1
                except (httpx.HTTPError, PortainerResponseError) as exc:
                    failed.append(target.name)
                    logger.warning("Failed to read logs for %s: %s", target.name, exc)
                if coverage.bytes_limited:
                    break
        combined.include(coverage)
        return {
            **coverage.summary(matches.limited), "errors_found": matches.found,
            "errors": matches.lines, "containers_scanned": scanned,
            "containers_failed": failed, "containers_skipped": len(replicas) - attempted,
        }

    scans = await asyncio.gather(*(scan(replicas) for replicas in services.values()))
    results = dict(zip(services, scans, strict=True))
    matches_limited = any(r["truncation_reason"] == "matches_limit" for r in scans)
    body = {
        "stack": stack_name, **window.bounds(), **combined.summary(matches_limited),
        "total_errors": sum(r["errors_found"] for r in results.values()),
        "containers_omitted": max(0, len(targets) - _MAX_STACK_TARGETS),
        "services": results,
    }
    if not targets:
        body["message"] = f"No running containers found for stack '{stack_name}'"
    return json.dumps(body, indent=2, ensure_ascii=False)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @tool_error_handler
    async def portainer_containers_list(
        endpoint_id: int | None = None,
        show_all: bool = False,
        name_filter: str | None = None,
        stack_filter: str | None = None,
    ) -> str:
        """List containers on an endpoint, with their stack and service.

        On a Swarm endpoint prefer portainer_services_list / stack_status —
        containers there are task instances that come and go.

        Args:
            endpoint_id: Target endpoint ID (uses default if omitted)
            show_all: If true, show all containers including stopped ones
            name_filter: Only return containers whose name contains this
                substring (server-side Docker filter)
            stack_filter: Only return containers belonging to this stack
                (Swarm namespace or Compose project label, exact match)
        """
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        params = {"all": "true" if show_all else "false"}
        if name_filter is not None:
            validate_filter(name_filter, "name_filter")
            params["filters"] = json.dumps({"name": [name_filter]})
        if stack_filter is not None and not _STACK_NAME_RE.match(stack_filter):
            raise ValueError(f"Invalid stack_filter: {stack_filter!r}")
        containers = await client.get(
            f"/api/endpoints/{eid}/docker/containers/json",
            params=params,
        )
        result = []
        for c in containers or []:
            # Swarm and Compose use different label keys, so the stack match
            # is done client-side (Docker's label filter can't express OR).
            stack, service = _container_labels(c)
            if stack_filter is not None and stack != stack_filter:
                continue
            result.append({
                "id": c["Id"][:12],
                "names": c.get("Names", []),
                "image": c.get("Image"),
                "state": c.get("State"),
                "status": c.get("Status"),
                "created": c.get("Created"),
                "stack": stack,
                "service": service,
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
        logger.info("AUDIT: Starting container %s on endpoint %d", container_id, eid)
        await client.post(
            f"/api/endpoints/{eid}/docker/containers/{container_id}/start",
        )
        return json.dumps(
            {"status": "started", "container_id": container_id},
            indent=2, ensure_ascii=False,
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
        logger.info("AUDIT: Stopping container %s on endpoint %d", container_id, eid)
        await client.post(
            f"/api/endpoints/{eid}/docker/containers/{container_id}/stop",
        )
        return json.dumps(
            {"status": "stopped", "container_id": container_id},
            indent=2, ensure_ascii=False,
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
        logger.info("AUDIT: Restarting container %s on endpoint %d", container_id, eid)
        await client.post(
            f"/api/endpoints/{eid}/docker/containers/{container_id}/restart",
        )
        return json.dumps(
            {"status": "restarted", "container_id": container_id},
            indent=2, ensure_ascii=False,
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
            {"status": "removed", "container_id": container_id},
            indent=2, ensure_ascii=False,
        )

    @mcp.tool()
    @tool_error_handler
    async def portainer_container_logs(
        container_id: str,
        tail: int = 100,
        since: str | None = None,
        timestamps: bool = False,
        endpoint_id: int | None = None,
    ) -> str:
        """Get container logs.

        Args:
            container_id: Container ID or name
            tail: Number of lines from the end of the logs (default 100, max 1000)
            since: Only lines newer than this: a duration ("10m", "2h", "1d"),
                a Unix timestamp or an ISO-8601 datetime
            timestamps: Prefix every line with its timestamp (default false)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_container_id(container_id)
        tail = max(1, min(tail, 1000))
        params = _log_params(tail, since, timestamps)
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        resp = await client.request(
            "GET",
            f"/api/endpoints/{eid}/docker/containers/{container_id}/logs",
            params=params,
            timeout=config.long_timeout,
        )
        output = _parse_docker_stream(resp.content)
        total_chars = len(output)
        truncated = total_chars > _MAX_LOG_CHARS
        if truncated:
            output = output[:_MAX_LOG_CHARS]
        return json.dumps(
            {
                "container_id": container_id,
                "tail": tail,
                "since": since,
                "truncated": truncated,
                "total_chars": total_chars,
                "logs": output,
            },
            indent=2,
            ensure_ascii=False,
        )

    @mcp.tool()
    @tool_error_handler
    async def portainer_container_logs_grep(
        container_id: str,
        pattern: str,
        tail: int = 500,
        context_lines: int = 0,
        since: str | None = None,
        timestamps: bool = False,
        endpoint_id: int | None = None,
        until: str | None = None,
        max_matches: int = _DEFAULT_LOG_MATCHES,
        max_bytes: int = _DEFAULT_LOG_BYTES,
    ) -> str:
        """Search container logs for lines matching a regex pattern.

        Returns only matching lines (with optional context). Useful for
        finding specific errors, status codes, or keywords. With `since`, the
        MCP server scans the time window even after reaching the match limit.

        Args:
            container_id: Container ID or name
            pattern: Regex pattern to search for (case-insensitive)
            tail: Lines to fetch without since (default 500, max 1000)
            context_lines: Lines of context around each match (default 0, max 5)
            since: Only scan lines newer than this: a duration ("10m", "2h",
                "1d"), a Unix timestamp or an ISO-8601 datetime
            timestamps: Prefix every line with its timestamp (default false)
            endpoint_id: Target endpoint ID (uses default if omitted)
            until: End of the window, same formats as since (default: now)
            max_matches: Window matches to return (default 200, max 1000)
            max_bytes: Window Docker response byte limit (default 32 MiB)
        """
        _validate_container_id(container_id)
        tail = max(1, min(tail, 1000))
        context_lines = max(0, min(context_lines, 5))
        window = _LogWindow.parse(since, until)
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
        path = f"/api/endpoints/{eid}/docker/containers/{quote(container_id, safe='')}/logs"
        if window is not None:
            coverage = _LogCoverage(window, max(1, max_bytes))
            matches = await _grep_window(
                client, path, coverage, config.long_timeout, regex, context_lines,
                timestamps, max_matches,
            )
            return json.dumps({
                "container_id": container_id, "pattern": pattern, **window.bounds(),
                **coverage.summary(matches.limited), "matches_found": matches.found,
                "lines": matches.lines,
            }, indent=2, ensure_ascii=False)

        resp = await client.request(
            "GET", path,
            params=_log_params(tail, since, timestamps),
            timeout=config.long_timeout,
        )
        text = _parse_docker_stream(resp.content)
        lines = text.splitlines()

        hit_indices = await _grep_indices(regex, lines, _GREP_SCAN_TIMEOUT)

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

        # Cap the data before serializing so the envelope stays valid JSON.
        output_lines, truncated = _cap_lines(output_lines, _MAX_LOG_CHARS)
        return json.dumps(
            {
                "container_id": container_id,
                "pattern": pattern,
                "lines_scanned": len(lines),
                "matches_found": len(hit_indices),
                "truncated": truncated,
                "lines": output_lines,
            },
            indent=2,
            ensure_ascii=False,
        )

    @mcp.tool()
    @tool_error_handler
    async def portainer_stack_logs_errors(
        stack_name: str,
        tail: int = 500,
        endpoint_id: int | None = None,
        since: str | None = None,
        until: str | None = None,
        max_matches: int = _DEFAULT_LOG_MATCHES,
        max_bytes: int = _DEFAULT_LOG_BYTES,
    ) -> str:
        """Scan all running containers in a stack for errors.

        Looks for HTTP 4xx/5xx, exceptions, fatal/critical/emergency log
        levels, panics, OOM, PHP errors, and similar patterns. Window scans
        find running replicas by stack labels or legacy names, share a byte
        limit across replicas, and report coverage and failures by service.

        Args:
            stack_name: Stack name prefix (e.g. "taylor", "blog", "somnlyx")
            tail: Lines to scan per container without since (default 500, max 1000)
            endpoint_id: Target endpoint ID (uses default if omitted)
            since: Start of window: duration, Unix seconds or ISO-8601 datetime
            until: End of the window, same formats as since (default: now)
            max_matches: Window matches to return across the stack (default 200, max 1000)
            max_bytes: Window Docker response byte limit per service (default 32 MiB)
        """
        if not _STACK_NAME_RE.match(stack_name):
            raise ValueError(f"Invalid stack_name: {stack_name!r}")
        tail = max(1, min(tail, 1000))
        window = _LogWindow.parse(since, until)

        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)

        containers = await client.get(
            f"/api/endpoints/{eid}/docker/containers/json",
            params={"all": "false"},
        )
        if window is not None:
            return await _stack_log_window(
                client, eid, stack_name, _window_stack_targets(containers, stack_name),
                window, config.long_timeout, max_matches, max(1, max_bytes),
            )
        targets = _stack_targets(containers, stack_name)

        if not targets:
            return json.dumps({
                "stack": stack_name,
                "containers_scanned": 0,
                "total_errors": 0,
                "message": f"No running containers found for stack '{stack_name}'",
            }, indent=2, ensure_ascii=False)

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
        # First-come-first-served output budget across containers, applied to
        # the data before serialization so the envelope stays valid JSON.
        remaining = _MAX_LOG_CHARS
        truncated = False
        for result in results:
            if isinstance(result, BaseException):
                failed += 1
                logger.warning("Failed to fetch logs for a container: %s", result)
                continue
            name, cid, lines_scanned, errors = result
            total_errors += len(errors)
            kept, dropped = _cap_lines(errors, remaining)
            remaining -= sum(len(ln) + 1 for ln in kept)
            truncated = truncated or dropped
            container_results[name] = {
                "container_id": cid,
                "lines_scanned": lines_scanned,
                "errors_found": len(errors),
                "errors": kept,
            }

        return json.dumps(
            {
                "stack": stack_name,
                "containers_scanned": len(container_results),
                "containers_failed": failed,
                "total_errors": total_errors,
                "truncated": truncated,
                "containers": container_results,
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
            # stream=false still waits for two CPU samples on the daemon side.
            timeout=config.long_timeout,
        )
        s = resp.json()

        # CPU usage calculation
        cpu_stats = s.get("cpu_stats", {})
        precpu_stats = s.get("precpu_stats", {})
        cpu_delta = (
            cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
            - precpu_stats.get("cpu_usage", {}).get("total_usage", 0)
        )
        system_delta = (
            cpu_stats.get("system_cpu_usage", 0)
            - precpu_stats.get("system_cpu_usage", 0)
        )
        # Docker's canonical fallback chain: some daemons report
        # online_cpus: 0 explicitly (cgroup v1), others omit it entirely.
        online_cpus = (
            cpu_stats.get("online_cpus")
            or len(cpu_stats.get("cpu_usage", {}).get("percpu_usage") or [])
            or 1
        )
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
        # Redact the full command before truncating the preview, so a secret
        # split across the cut can never land in the log half-masked.
        logger.info(
            "AUDIT: Exec in container %s on endpoint %d: %s",
            container_id, eid, redact_secrets(command)[:500],
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

        # Step 3: Get exit code (`or {}`: never lose the exec output over a
        # flaky metadata read)
        inspect = await client.get(
            f"/api/endpoints/{eid}/docker/exec/{exec_id}/json",
        )
        exit_code = (inspect or {}).get("ExitCode", -1)

        if len(output) > _MAX_LOG_CHARS:
            output = output[:_MAX_LOG_CHARS] + f"\n... truncated ({len(output)} total chars)"

        return json.dumps({
            "exit_code": exit_code,
            "output": output,
        }, indent=2, ensure_ascii=False)
