from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from mcp.server.fastmcp import FastMCP

import portainer_mcp.client as client_mod
from portainer_mcp.tools import auth, containers


def _text(result: Any) -> str:
    """Extract the tool's JSON string from a FastMCP call_tool() result."""
    content = result[0] if isinstance(result, tuple) else result
    return content[0].text  # type: ignore[no-any-return]


# --- portainer_status resilience -------------------------------------------------


class _StatusClient:
    def __init__(self, *, exc: Exception | None = None, data: dict[str, Any] | None = None):
        self._exc = exc
        self._data = data

    async def get(self, path: str, **kwargs: Any) -> Any:
        if self._exc is not None:
            raise self._exc
        return self._data


async def test_status_connected() -> None:
    mcp = FastMCP("t")
    auth.register(mcp)
    client_mod._client = _StatusClient(  # type: ignore[assignment]
        data={"Version": "2.19.0", "InstanceID": "inst-1"}
    )
    body = json.loads(_text(await mcp.call_tool("portainer_status", {})))
    assert body == {
        "connected": True,
        "url": "https://portainer.test",
        "version": "2.19.0",
        "instance_id": "inst-1",
    }


async def test_status_unreachable_reports_disconnected_and_redacts() -> None:
    mcp = FastMCP("t")
    auth.register(mcp)
    client_mod._client = _StatusClient(  # type: ignore[assignment]
        exc=httpx.ConnectError("refused token=SUPERSECRET")
    )
    body = json.loads(_text(await mcp.call_tool("portainer_status", {})))
    assert body["connected"] is False
    assert body["url"] == "https://portainer.test"
    assert "SUPERSECRET" not in body["error"]
    assert "[REDACTED]" in body["error"]


# --- stack_logs_errors partial-failure resilience --------------------------------


class _ScanClient:
    """Returns a fixed container list; one container's log fetch raises."""

    def __init__(self, fail_cid: str) -> None:
        self.fail_cid = fail_cid

    async def get(self, path: str, **kwargs: Any) -> Any:
        assert path.endswith("/containers/json")
        return [
            {"Id": "aaaaaaaaaaaa0000", "Names": ["/demo_web.1.xyz"]},
            {"Id": "bbbbbbbbbbbb0000", "Names": ["/demo_api.1.xyz"]},
        ]

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        cid = path.split("/containers/")[1].split("/logs")[0]
        if cid == self.fail_cid:
            raise httpx.ConnectError("boom")
        return httpx.Response(200, content=b'nginx "GET /" 500 \njust a normal line\n')


async def test_stack_logs_errors_partial_failure() -> None:
    mcp = FastMCP("t")
    containers.register(mcp)
    # "aaaaaaaaaaaa0000"[:12] == "aaaaaaaaaaaa" — the web container's fetch fails.
    client_mod._client = _ScanClient("aaaaaaaaaaaa")  # type: ignore[assignment]
    body = json.loads(
        _text(await mcp.call_tool("portainer_stack_logs_errors", {"stack_name": "demo"}))
    )
    assert body["containers_failed"] == 1
    assert body["containers_scanned"] == 1  # the surviving container
    assert body["total_errors"] == 1  # the " 500 " line in demo_api
    assert "demo_api.1" in body["containers"]
    assert "demo_web.1" not in body["containers"]


# --- logs_grep ReDoS guard -------------------------------------------------------


class _GrepClient:
    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        return httpx.Response(200, content=b"line one\nline two\n")


async def test_logs_grep_rejects_overlong_pattern() -> None:
    mcp = FastMCP("t")
    containers.register(mcp)
    client_mod._client = _GrepClient()  # type: ignore[assignment]
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_container_logs_grep",
                {"container_id": "abc", "pattern": "a" * 600},
            )
        )
    )
    assert body["error"] == "Validation error"
    assert "too long" in body["details"]


async def test_logs_grep_times_out_safely(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force the scan deadline to 0 so the wait_for path fires deterministically
    # without running a real catastrophic regex (no thread-hang risk).
    monkeypatch.setattr(containers, "_GREP_SCAN_TIMEOUT", 0.0)
    mcp = FastMCP("t")
    containers.register(mcp)
    client_mod._client = _GrepClient()  # type: ignore[assignment]
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_container_logs_grep",
                {"container_id": "abc", "pattern": "line"},
            )
        )
    )
    assert body["error"] == "Validation error"
    assert "timed out" in body["details"]
