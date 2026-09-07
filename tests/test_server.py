from __future__ import annotations

import pytest

import portainer_mcp.client as client_mod
from portainer_mcp.server import INSTRUCTIONS, create_server, lifespan, mcp


class _RecordingClient:
    def __init__(self) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True


async def test_lifespan_closes_client_on_clean_exit() -> None:
    stub = _RecordingClient()
    client_mod._client = stub  # type: ignore[assignment]
    async with lifespan(mcp):
        pass
    assert stub.closed is True
    assert client_mod._client is None


async def test_lifespan_closes_client_when_body_raises() -> None:
    stub = _RecordingClient()
    client_mod._client = stub  # type: ignore[assignment]
    with pytest.raises(RuntimeError):
        async with lifespan(mcp):
            raise RuntimeError("boom")
    assert stub.closed is True
    assert client_mod._client is None


async def test_all_47_tools_registered() -> None:
    # Keep the registered surface in sync with the documented tool count
    # (pyproject description / README). Uses the public list_tools() API.
    # Build explicitly: the module-level `mcp` reads the Laravel flag from the
    # ambient environment at import time, before conftest's per-test delenv.
    tools = await create_server(enable_laravel_tools=False).list_tools()
    assert len(tools) == 47
    assert all(t.name.startswith("portainer_") for t in tools)
    names = {t.name for t in tools}
    assert "portainer_laravel_tinker" not in names
    assert "portainer_laravel_errors" not in names


async def test_laravel_flag_adds_two_tools() -> None:
    tools = await create_server(enable_laravel_tools=True).list_tools()
    assert len(tools) == 49
    names = {t.name for t in tools}
    assert {"portainer_laravel_tinker", "portainer_laravel_errors"} <= names


def test_server_instructions_are_set() -> None:
    assert mcp.instructions == INSTRUCTIONS
    # The guide must steer toward services on Swarm and inspect-before-update.
    assert "portainer_stack_inspect" in INSTRUCTIONS
    assert "portainer_services_list" in INSTRUCTIONS
    assert "[REDACTED]" in INSTRUCTIONS
