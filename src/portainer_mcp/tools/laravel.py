from __future__ import annotations

import asyncio
import json
import logging

from mcp.server.fastmcp import FastMCP

from ..client import get_client
from ..config import get_config
from ..errors import redact_secrets, resolve_endpoint, tool_error_handler
from .containers import (
    _MAX_LOG_CHARS,
    _MAX_STACK_TARGETS,
    _STACK_FANOUT_LIMIT,
    _STACK_NAME_RE,
    _cap_lines,
    _parse_docker_stream,
    _stack_targets,
)

logger = logging.getLogger(__name__)

# Opinionated helpers for Laravel stacks (a `backend` service with the app at
# /var/www/app). They are registered only when PORTAINER_ENABLE_LARAVEL_TOOLS
# is true — on other infrastructures they are just noise in the tool list.


def register(mcp: FastMCP) -> None:
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
        targets = _stack_targets(containers, stack_name)

        if not targets:
            return json.dumps({
                "stack": stack_name,
                "containers_scanned": 0,
                "message": f"No running containers found for stack '{stack_name}'",
            }, indent=2, ensure_ascii=False)

        if len(targets) > _MAX_STACK_TARGETS:
            logger.warning(
                "Stack %r has %d containers; scanning only the first %d",
                stack_name, len(targets), _MAX_STACK_TARGETS,
            )
            targets = targets[:_MAX_STACK_TARGETS]

        log_path = "/var/www/app/storage/logs/laravel.log"
        # The exec command is a fixed read-only grep, but it still runs inside
        # the containers — record the operation and its scope.
        logger.info(
            "AUDIT: laravel_errors grep exec for stack %r on endpoint %d (%d containers)",
            stack_name, eid, len(targets),
        )

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
        # Same pre-serialization output budget as stack_logs_errors.
        remaining = _MAX_LOG_CHARS
        truncated = False
        for name, cid, output in results:
            lines = [ln for ln in output.splitlines() if ln.strip()]
            kept, dropped = _cap_lines(lines, remaining)
            remaining -= sum(len(ln) + 1 for ln in kept)
            truncated = truncated or dropped
            container_results[name] = {
                "container_id": cid,
                "errors_found": len(lines),
                "errors": kept,
            }

        return json.dumps(
            {
                "stack": stack_name,
                "containers_scanned": len(targets),
                "log_path": log_path,
                "truncated": truncated,
                "containers": container_results,
            },
            indent=2,
            ensure_ascii=False,
        )

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

        # Find the first running backend container for the stack (matches
        # Swarm, plain-Compose and Compose-v1 naming — see _stack_targets).
        backends = _stack_targets(containers, stack_name, service="backend")
        if not backends:
            return json.dumps({
                "error": f"No running backend container found for stack '{stack_name}'",
            }, indent=2, ensure_ascii=False)
        target_id, target_name = backends[0]

        # Redact the full code before truncating the preview, so a secret
        # split across the cut can never land in the log half-masked.
        logger.info(
            "AUDIT: Laravel tinker in %s (%s) on endpoint %d: %s",
            target_name, target_id, eid, redact_secrets(code)[:500],
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
        # `or {}`: never lose the exec output over a flaky metadata read.
        exit_code = (inspect or {}).get("ExitCode", -1)

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
