from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP

from .client import close_client
from .config import laravel_tools_enabled
from .tools import (
    auth,
    containers,
    endpoints,
    images,
    laravel,
    networks,
    stacks,
    swarm,
    system,
    users,
    volumes,
)

# Shown to the MCP client as server instructions — a short operating guide
# that steers an agent toward the right tool for this kind of infrastructure.
INSTRUCTIONS = """\
Portainer MCP: manages Docker endpoints (Swarm clusters and standalone hosts) \
through Portainer's API. Every tool returns JSON; mutating tools are audit-logged.

How to work:
- Start with portainer_endpoints_list / portainer_docker_info to learn whether an \
endpoint is a Swarm cluster (swarm_active). On Swarm, think in services and tasks, \
not containers: use portainer_stack_status, portainer_services_list, \
portainer_service_tasks and portainer_service_logs first; containers are transient \
task instances.
- Before editing a stack, ALWAYS call portainer_stack_inspect (with reveal_env=true \
if you intend to resend the compose file) and base your change on the current \
file. Values shown as [REDACTED] are masked credentials — never write them back.
- portainer_stack_update preserves the stack's Env variables automatically; use its \
env / env_remove arguments to change them, and pull_image=true to roll out a new \
build of a :latest image. A plain redeploy reuses the images already on the nodes.
- To restart or re-pull a single Swarm service, use portainer_service_update \
(force_restart / image / replicas) instead of touching its containers; \
portainer_service_rollback undoes the last update. After any rollout call \
portainer_stack_wait / portainer_service_wait to confirm it converged instead of \
polling by hand. Cron-driven services (cron: true) rest at 0 replicas — judge them \
by last_run_state, not by replicas.
- Private registries configured in Portainer are used by passing registry_id \
(see portainer_registries_list); never ask for registry passwords.
"""


@asynccontextmanager
async def lifespan(_: FastMCP) -> AsyncIterator[None]:
    try:
        yield
    finally:
        # Always release the httpx client, even on an error-driven shutdown,
        # so connections / file descriptors don't leak.
        await close_client()


def create_server(*, enable_laravel_tools: bool) -> FastMCP:
    """Build the FastMCP app and register every tool group.

    The Laravel helpers are opt-in (PORTAINER_ENABLE_LARAVEL_TOOLS): on a
    non-Laravel infrastructure they only add noise to the tool list.
    """
    server = FastMCP("portainer", instructions=INSTRUCTIONS, lifespan=lifespan)
    auth.register(server)
    endpoints.register(server)
    stacks.register(server)
    containers.register(server)
    swarm.register(server)
    images.register(server)
    volumes.register(server)
    networks.register(server)
    system.register(server)
    users.register(server)
    if enable_laravel_tools:
        laravel.register(server)
    return server


mcp = create_server(enable_laravel_tools=laravel_tools_enabled())


def main() -> None:
    # Configure logging at startup rather than import time, so embedding the
    # package as a library doesn't hijack the root logger.
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
