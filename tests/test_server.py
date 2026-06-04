from __future__ import annotations

import pytest

import portainer_mcp.client as client_mod
from portainer_mcp.server import lifespan, mcp


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


async def test_all_41_tools_registered() -> None:
    # Keep the registered surface in sync with the documented tool count
    # (pyproject description / README). Uses the public list_tools() API.
    tools = await mcp.list_tools()
    assert len(tools) == 41
    assert all(t.name.startswith("portainer_") for t in tools)
