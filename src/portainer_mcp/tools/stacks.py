from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from ..client import PortainerClient, get_client
from ..config import get_config
from ..errors import (
    REDACTED,
    redact_compose_text,
    redact_env_pairs,
    resolve_endpoint,
    tool_error_handler,
    validate_id,
)

logger = logging.getLogger(__name__)

# 1-64 chars: one leading alphanumeric + up to 63 of [alnum _ -] (no dots);
# aligns with Docker Swarm stack-name rules. Keep in sync with containers.py.
_STACK_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]{0,63}$")

# Compose files are normally a few KB; this is a defensive ceiling on the
# inspect payload so a pathological stack file can't blow up memory.
_MAX_COMPOSE_CHARS = 500_000

# Stack environment variables (Portainer "Env" pairs). Names follow POSIX
# shell rules; values are bounded so a runaway argument can't bloat the
# stored stack, and the pair count so a model can't send thousands at once.
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,255}$")
_MAX_ENV_VALUE_CHARS = 32_768
_MAX_ENV_PAIRS = 500

# Portainer stack Type values (portainer.StackType).
_SWARM_STACK_TYPE = 1


def _validate_stack_name(name: str) -> None:
    if not _STACK_NAME_RE.match(name):
        raise ValueError(
            f"Invalid stack name: {name!r}. Must match ^[a-zA-Z0-9][a-zA-Z0-9_\\-]{{0,63}}$"
        )


def _validate_compose_content(content: str) -> None:
    if not content.strip():
        raise ValueError("compose_content must not be empty")
    if len(content) > _MAX_COMPOSE_CHARS:
        raise ValueError(
            f"compose_content too large ({len(content)} chars, max {_MAX_COMPOSE_CHARS})"
        )
    if REDACTED in content:
        # The model round-tripped a redacted stack_inspect output. Writing it
        # back would replace real credentials with the placeholder.
        raise ValueError(
            f"compose_content contains the {REDACTED} placeholder. Re-run "
            "portainer_stack_inspect with reveal_env=true and edit the real "
            "file, or leave those lines untouched."
        )


def _validate_env(env: dict[str, str] | None, env_remove: list[str] | None) -> None:
    names = list(env or {}) + list(env_remove or [])
    if len(names) > _MAX_ENV_PAIRS:
        raise ValueError(f"Too many env entries ({len(names)}, max {_MAX_ENV_PAIRS})")
    for name in names:
        if not isinstance(name, str) or not _ENV_NAME_RE.match(name):
            raise ValueError(
                f"Invalid env variable name: {name!r}. Must match ^[A-Za-z_][A-Za-z0-9_]{{0,255}}$"
            )
    for name, value in (env or {}).items():
        if not isinstance(value, str):
            raise ValueError(f"env[{name!r}] must be a string, got {type(value).__name__}")
        if len(value) > _MAX_ENV_VALUE_CHARS:
            raise ValueError(
                f"env[{name!r}] too long ({len(value)} chars, max {_MAX_ENV_VALUE_CHARS})"
            )
        if REDACTED in value:
            raise ValueError(
                f"env[{name!r}] contains the {REDACTED} placeholder; "
                "pass the real value or omit the variable to keep it unchanged."
            )


def _pairs_to_dict(pairs: Any) -> dict[str, str]:
    """Portainer ``[{"name": .., "value": ..}]`` -> ordered dict (skips junk)."""
    out: dict[str, str] = {}
    for pair in pairs or []:
        if isinstance(pair, dict) and isinstance(pair.get("name"), str):
            out[pair["name"]] = str(pair.get("value", ""))
    return out


def _dict_to_pairs(values: dict[str, str]) -> list[dict[str, str]]:
    return [{"name": k, "value": v} for k, v in values.items()]


async def _load_stack(client: PortainerClient, stack_id: int) -> dict[str, Any]:
    stack = await client.get(f"/api/stacks/{stack_id}")
    if not isinstance(stack, dict):
        raise ValueError(f"Stack {stack_id} not found or returned no data")
    return stack


async def _stack_endpoint(
    client: PortainerClient, stack: dict[str, Any], endpoint_id: int | None
) -> int:
    """Endpoint for a stack-scoped call: the stack's own, unless overridden.

    Stacks are bound to one endpoint; deriving it from the stack avoids
    targeting the wrong endpoint in multi-endpoint setups where the default
    doesn't match. An explicit ``endpoint_id`` that differs from the stack's
    is accepted only when the stack's endpoint no longer exists (an orphaned
    stack — Portainer lets an admin remove it via another endpoint);
    otherwise it is rejected, because Portainer would run the operation on
    the wrong endpoint and, for delete, drop the stack record while the real
    services keep running.
    """
    config = get_config()
    own = stack.get("EndpointId")
    own_eid = own if isinstance(own, int) and not isinstance(own, bool) and own > 0 else None
    if endpoint_id is None:
        return own_eid if own_eid is not None else config.default_endpoint
    eid = resolve_endpoint(endpoint_id, config.default_endpoint)
    if own_eid is None or eid == own_eid:
        return eid
    try:
        await client.get(f"/api/endpoints/{own_eid}")
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            logger.warning(
                "Stack %s is orphaned (endpoint %d no longer exists); using explicit endpoint %d",
                stack.get("Id"), own_eid, eid,
            )
            return eid
        raise
    raise ValueError(
        f"Stack {stack.get('Id')} ({stack.get('Name')!r}) belongs to endpoint {own_eid}, "
        f"not {eid}. Omit endpoint_id or pass {own_eid}."
    )


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @tool_error_handler
    async def portainer_stacks_list() -> str:
        """List all Portainer stacks."""
        client = get_client()
        stacks = await client.get("/api/stacks")
        result = []
        for s in stacks:
            result.append(
                {
                    "id": s["Id"],
                    "name": s["Name"],
                    "type": s.get("Type"),
                    "type_name": "swarm" if s.get("Type") == _SWARM_STACK_TYPE else "compose",
                    "status": s.get("Status"),
                    "endpoint_id": s.get("EndpointId"),
                    "creation_date": s.get("CreationDate"),
                    "update_date": s.get("UpdateDate"),
                }
            )
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp.tool()
    @tool_error_handler
    async def portainer_stack_inspect(stack_id: int, reveal_env: bool = False) -> str:
        """Get details of a stack including its compose file content.

        Credential-looking values (stack Env variables named like *PASSWORD,
        *SECRET, *TOKEN, *KEY, ... and inline environment values in the
        compose file) are masked as [REDACTED] unless reveal_env=true.
        Always inspect with reveal_env=true before resending the compose
        file through portainer_stack_update — a masked file is rejected.

        Args:
            stack_id: The ID of the stack to inspect
            reveal_env: Return credential values unmasked (default false)
        """
        validate_id(stack_id, "stack_id")
        client = get_client()
        stack = await _load_stack(client, stack_id)
        try:
            file_resp = await client.get(f"/api/stacks/{stack_id}/file") or {}
            content = file_resp.get("StackFileContent") or ""
            if len(content) > _MAX_COMPOSE_CHARS:
                logger.warning(
                    "Compose file for stack %d is %d chars; truncating to %d",
                    stack_id,
                    len(content),
                    _MAX_COMPOSE_CHARS,
                )
                content = content[:_MAX_COMPOSE_CHARS] + "\n... truncated"
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "Could not fetch compose file for stack %d: HTTP %d",
                stack_id,
                exc.response.status_code,
            )
            content = ""
        if not reveal_env:
            content = redact_compose_text(content)
            if isinstance(stack.get("Env"), list):
                stack["Env"] = redact_env_pairs(stack["Env"])
        stack["ComposeFileContent"] = content
        stack["env_redacted"] = not reveal_env
        return json.dumps(stack, indent=2, ensure_ascii=False)

    @mcp.tool()
    @tool_error_handler
    async def portainer_stack_deploy(
        name: str,
        compose_content: str,
        env: dict[str, str] | None = None,
        endpoint_id: int | None = None,
    ) -> str:
        """Deploy a new stack from a docker-compose string.

        Args:
            name: Name of the new stack
            compose_content: Docker Compose file content (YAML string)
            env: Stack environment variables (substituted into the compose
                file by Portainer), e.g. {"DB_PASSWORD": "..."}
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_stack_name(name)
        _validate_compose_content(compose_content)
        _validate_env(env, None)
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        logger.info(
            "AUDIT: Deploying stack %r on endpoint %d (env vars: %s)",
            name,
            eid,
            sorted(env) if env else [],
        )

        # Detect Swarm vs standalone to use the correct API path
        swarm_id = None
        try:
            swarm_info = await client.get(f"/api/endpoints/{eid}/docker/swarm")
            swarm_id = swarm_info.get("ID")
        except Exception:
            logger.debug("Endpoint %d is not a Swarm node, using standalone deploy", eid)

        body: dict[str, Any] = {
            "Name": name,
            "StackFileContent": compose_content,
            "Env": _dict_to_pairs(env or {}),
        }
        if swarm_id:
            body["SwarmID"] = swarm_id
            deploy_type = "swarm"
        else:
            deploy_type = "standalone"

        result = await client.post(
            f"/api/stacks/create/{deploy_type}/string",
            params={"endpointId": eid},
            json=body,
        )
        if result:
            if isinstance(result, dict) and isinstance(result.get("Env"), list):
                result["Env"] = redact_env_pairs(result["Env"])
            return json.dumps(result, indent=2, ensure_ascii=False)
        return json.dumps({"status": "deployed", "name": name}, indent=2, ensure_ascii=False)

    @mcp.tool()
    @tool_error_handler
    async def portainer_stack_update(
        stack_id: int,
        compose_content: str | None = None,
        env: dict[str, str] | None = None,
        env_remove: list[str] | None = None,
        prune: bool | None = None,
        pull_image: bool | None = None,
        endpoint_id: int | None = None,
    ) -> str:
        """Update (redeploy) an existing stack.

        The stack's stored Env variables are always preserved: Portainer
        replaces the whole Env list on every update, so this tool reads the
        current list first and merges your changes into it. Omit every
        optional argument to simply redeploy the stack as it is.

        To pick up a newly pushed build of a `:latest` image, pass
        pull_image=true — a plain redeploy reuses the image already on the
        nodes.

        Args:
            stack_id: The ID of the stack to update
            compose_content: New Docker Compose content (YAML). If omitted,
                the stored file is redeployed unchanged. Must not contain
                [REDACTED] (inspect with reveal_env=true first).
            env: Env variables to add or overwrite, e.g. {"TAG": "v2"}
            env_remove: Names of Env variables to delete
            prune: Remove services no longer in the compose file (Swarm only).
                Defaults to the stack's current setting.
            pull_image: Force re-pulling images before redeploying
                (Portainer's "Re-pull image and redeploy"; default false)
            endpoint_id: Endpoint ID (derived from the stack itself if omitted)
        """
        validate_id(stack_id, "stack_id")
        if compose_content is not None:
            _validate_compose_content(compose_content)
        _validate_env(env, env_remove)
        client = get_client()

        # Always read the stack first: we need its Env (to preserve it), its
        # Prune option (default "as configured"), and its endpoint.
        stack = await _load_stack(client, stack_id)
        eid = await _stack_endpoint(client, stack, endpoint_id)

        current_env = _pairs_to_dict(stack.get("Env"))
        merged_env = dict(current_env)
        merged_env.update(env or {})
        for name in env_remove or []:
            merged_env.pop(name, None)

        option = stack.get("Option") or {}
        current_prune = bool(option.get("Prune", False)) if isinstance(option, dict) else False
        effective_prune = current_prune if prune is None else prune
        effective_pull = bool(pull_image)

        logger.info(
            "AUDIT: Updating stack %d on endpoint %d (compose=%s, env_set=%s, "
            "env_removed=%s, prune=%s, pull_image=%s)",
            stack_id,
            eid,
            compose_content is not None,
            sorted(env) if env else [],
            sorted(env_remove) if env_remove else [],
            effective_prune,
            effective_pull,
        )

        if compose_content is None:
            file_resp = await client.get(f"/api/stacks/{stack_id}/file") or {}
            compose_content = file_resp.get("StackFileContent") or ""
            if not compose_content.strip():
                raise ValueError(
                    f"Stack {stack_id} has no stored compose file; pass compose_content"
                )

        body = {
            "StackFileContent": compose_content,
            "Env": _dict_to_pairs(merged_env),
            "Prune": effective_prune,
            # 2.36+ reads RepullImageAndRedeploy; older versions read the
            # deprecated PullImage. Sending both keeps the flag effective
            # across versions (the server ORs them).
            "RepullImageAndRedeploy": effective_pull,
            "PullImage": effective_pull,
        }
        result = await client.put(
            f"/api/stacks/{stack_id}",
            params={"endpointId": eid},
            json=body,
        )
        summary = {
            "status": "updated",
            "stack_id": stack_id,
            "endpoint_id": eid,
            "prune": effective_prune,
            "pull_image": effective_pull,
            "env_names": sorted(merged_env),
        }
        if isinstance(result, dict):
            if isinstance(result.get("Env"), list):
                result["Env"] = redact_env_pairs(result["Env"])
            return json.dumps({**summary, "stack": result}, indent=2, ensure_ascii=False)
        return json.dumps(summary, indent=2, ensure_ascii=False)

    @mcp.tool()
    @tool_error_handler
    async def portainer_stack_delete(
        stack_id: int,
        endpoint_id: int | None = None,
    ) -> str:
        """Delete a stack.

        Args:
            stack_id: The ID of the stack to delete
            endpoint_id: Endpoint ID (derived from the stack itself if omitted)
        """
        validate_id(stack_id, "stack_id")
        client = get_client()
        stack = await _load_stack(client, stack_id)
        eid = await _stack_endpoint(client, stack, endpoint_id)
        logger.info(
            "AUDIT: Deleting stack %d (%r) on endpoint %d",
            stack_id,
            stack.get("Name"),
            eid,
        )
        await client.delete(f"/api/stacks/{stack_id}", params={"endpointId": eid})
        return json.dumps(
            {"status": "deleted", "stack_id": stack_id, "endpoint_id": eid},
            indent=2,
            ensure_ascii=False,
        )

    @mcp.tool()
    @tool_error_handler
    async def portainer_stack_start(
        stack_id: int,
        endpoint_id: int | None = None,
    ) -> str:
        """Start a stopped stack.

        Args:
            stack_id: The ID of the stack to start
            endpoint_id: Endpoint ID (derived from the stack itself if omitted)
        """
        validate_id(stack_id, "stack_id")
        client = get_client()
        stack = await _load_stack(client, stack_id)
        eid = await _stack_endpoint(client, stack, endpoint_id)
        logger.info("AUDIT: Starting stack %d on endpoint %d", stack_id, eid)
        result = await client.post(f"/api/stacks/{stack_id}/start", params={"endpointId": eid})
        if isinstance(result, dict):
            if isinstance(result.get("Env"), list):
                result["Env"] = redact_env_pairs(result["Env"])
            return json.dumps(result, indent=2, ensure_ascii=False)
        return json.dumps(
            {"status": "started", "stack_id": stack_id, "endpoint_id": eid},
            indent=2,
            ensure_ascii=False,
        )

    @mcp.tool()
    @tool_error_handler
    async def portainer_stack_stop(
        stack_id: int,
        endpoint_id: int | None = None,
    ) -> str:
        """Stop a running stack.

        Args:
            stack_id: The ID of the stack to stop
            endpoint_id: Endpoint ID (derived from the stack itself if omitted)
        """
        validate_id(stack_id, "stack_id")
        client = get_client()
        stack = await _load_stack(client, stack_id)
        eid = await _stack_endpoint(client, stack, endpoint_id)
        logger.info("AUDIT: Stopping stack %d on endpoint %d", stack_id, eid)
        result = await client.post(f"/api/stacks/{stack_id}/stop", params={"endpointId": eid})
        if isinstance(result, dict):
            if isinstance(result.get("Env"), list):
                result["Env"] = redact_env_pairs(result["Env"])
            return json.dumps(result, indent=2, ensure_ascii=False)
        return json.dumps(
            {"status": "stopped", "stack_id": stack_id, "endpoint_id": eid},
            indent=2,
            ensure_ascii=False,
        )
