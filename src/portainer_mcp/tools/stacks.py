from __future__ import annotations

import json
import logging
import re

from mcp.server.fastmcp import FastMCP

from ..client import get_client
from ..config import get_config
from ..errors import tool_error_handler

logger = logging.getLogger(__name__)

_STACK_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]{0,63}$")


def _validate_stack_name(name: str) -> None:
    if not _STACK_NAME_RE.match(name):
        raise ValueError(
            f"Invalid stack name: {name!r}. "
            "Must match ^[a-zA-Z0-9][a-zA-Z0-9_\\-]{{0,63}}$"
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
            result.append({
                "id": s["Id"],
                "name": s["Name"],
                "type": s.get("Type"),
                "status": s.get("Status"),
                "endpoint_id": s.get("EndpointId"),
                "creation_date": s.get("CreationDate"),
            })
        return json.dumps(result, indent=2)

    @mcp.tool()
    @tool_error_handler
    async def portainer_stack_inspect(stack_id: int) -> str:
        """Get details of a stack including its compose file content.

        Args:
            stack_id: The ID of the stack to inspect
        """
        client = get_client()
        stack = await client.get(f"/api/stacks/{stack_id}")
        try:
            file_resp = await client.get(f"/api/stacks/{stack_id}/file")
            stack["ComposeFileContent"] = file_resp.get("StackFileContent", "")
        except Exception:
            logger.debug("Could not fetch compose file for stack %d", stack_id)
            stack["ComposeFileContent"] = ""
        return json.dumps(stack, indent=2)

    @mcp.tool()
    @tool_error_handler
    async def portainer_stack_deploy(
        name: str,
        compose_content: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Deploy a new stack from a docker-compose string.

        Args:
            name: Name of the new stack
            compose_content: Docker Compose file content (YAML string)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_stack_name(name)
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        logger.info("AUDIT: Deploying stack %r on endpoint %d", name, eid)

        # Detect Swarm vs standalone to use the correct API path
        swarm_id = None
        try:
            swarm_info = await client.get(f"/api/endpoints/{eid}/docker/swarm")
            swarm_id = swarm_info.get("ID")
        except Exception:
            logger.debug("Endpoint %d is not a Swarm node, using standalone deploy", eid)

        body = {
            "Name": name,
            "StackFileContent": compose_content,
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
            return json.dumps(result, indent=2)
        return json.dumps({"status": "deployed", "name": name})

    @mcp.tool()
    @tool_error_handler
    async def portainer_stack_update(
        stack_id: int,
        compose_content: str | None = None,
        endpoint_id: int | None = None,
    ) -> str:
        """Update an existing stack, optionally with new compose content.

        Args:
            stack_id: The ID of the stack to update
            compose_content: New Docker Compose content (YAML). If omitted, redeploys existing.
            endpoint_id: Endpoint ID (uses default if omitted)
        """
        client = get_client()
        config = get_config()
        eid = config.default_endpoint if endpoint_id is None else endpoint_id
        logger.info("AUDIT: Updating stack %d on endpoint %d", stack_id, eid)

        if compose_content is None:
            file_resp = await client.get(f"/api/stacks/{stack_id}/file")
            compose_content = file_resp.get("StackFileContent", "")

        body = {
            "StackFileContent": compose_content,
            "Prune": False,
        }
        result = await client.put(
            f"/api/stacks/{stack_id}",
            params={"endpointId": eid},
            json=body,
        )
        if result:
            return json.dumps(result, indent=2)
        return json.dumps({"status": "updated", "stack_id": stack_id})

    @mcp.tool()
    @tool_error_handler
    async def portainer_stack_delete(stack_id: int) -> str:
        """Delete a stack.

        Args:
            stack_id: The ID of the stack to delete
        """
        client = get_client()
        logger.info("AUDIT: Deleting stack %d", stack_id)
        await client.delete(f"/api/stacks/{stack_id}")
        return json.dumps({"status": "deleted", "stack_id": stack_id})

    @mcp.tool()
    @tool_error_handler
    async def portainer_stack_start(stack_id: int) -> str:
        """Start a stopped stack.

        Args:
            stack_id: The ID of the stack to start
        """
        client = get_client()
        logger.info("AUDIT: Starting stack %d", stack_id)
        result = await client.post(f"/api/stacks/{stack_id}/start")
        if result:
            return json.dumps(result, indent=2)
        return json.dumps({"status": "started", "stack_id": stack_id})

    @mcp.tool()
    @tool_error_handler
    async def portainer_stack_stop(stack_id: int) -> str:
        """Stop a running stack.

        Args:
            stack_id: The ID of the stack to stop
        """
        client = get_client()
        logger.info("AUDIT: Stopping stack %d", stack_id)
        result = await client.post(f"/api/stacks/{stack_id}/stop")
        if result:
            return json.dumps(result, indent=2)
        return json.dumps({"status": "stopped", "stack_id": stack_id})
