from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP

from .client import close_client
from .tools import auth, containers, endpoints, images, networks, stacks, system, users, volumes


@asynccontextmanager
async def lifespan(_: FastMCP) -> AsyncIterator[None]:
    try:
        yield
    finally:
        # Always release the httpx client, even on an error-driven shutdown,
        # so connections / file descriptors don't leak.
        await close_client()


mcp = FastMCP("portainer", lifespan=lifespan)

# Register all tool groups
auth.register(mcp)
endpoints.register(mcp)
stacks.register(mcp)
containers.register(mcp)
images.register(mcp)
volumes.register(mcp)
networks.register(mcp)
system.register(mcp)
users.register(mcp)


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
