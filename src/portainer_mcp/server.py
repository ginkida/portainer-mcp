from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from mcp.server.fastmcp import FastMCP

from .client import close_client
from .tools import auth, containers, endpoints, images, networks, stacks, system, users, volumes

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(_: FastMCP) -> AsyncIterator[None]:
    yield
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
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
