from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

import httpx
import pytest

import portainer_mcp.client as client_mod
from portainer_mcp.client import _MAX_RESPONSE_BYTES, PortainerClient, close_client

Handler = Callable[[httpx.Request], httpx.Response]


def build_client(handler: Handler) -> PortainerClient:
    """A PortainerClient whose transport is driven by ``handler``."""
    client = PortainerClient()
    client._http = httpx.AsyncClient(
        base_url="https://portainer.test",
        transport=httpx.MockTransport(handler),
    )
    return client


def _auth_ok(
    request: httpx.Request, *, jwt: str = "JWT", csrf: str = "C1"
) -> httpx.Response | None:
    """Standard happy-path responses for the two auth bootstrap calls."""
    if request.url.path == "/api/auth":
        return httpx.Response(200, json={"jwt": jwt})
    if request.url.path == "/api/status":
        return httpx.Response(200, json={"Version": "2.x"}, headers={"X-CSRF-Token": csrf})
    return None


async def test_initial_auth_and_csrf_harvest() -> None:
    calls = {"auth": 0, "status": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            calls["auth"] += 1
            return httpx.Response(200, json={"jwt": "JWT1"})
        if request.url.path == "/api/status":
            calls["status"] += 1
            return httpx.Response(200, json={"Version": "2.x"}, headers={"X-CSRF-Token": "C1"})
        return httpx.Response(200, json={"ok": True})

    client = build_client(handler)
    try:
        data = await client.get("/api/endpoints")
    finally:
        await client.close()

    assert data == {"ok": True}
    assert calls == {"auth": 1, "status": 1}
    assert client._auth_version == 1
    assert client._csrf_token == "C1"


async def test_get_omits_referer_and_csrf_but_post_includes_them() -> None:
    seen: list[tuple[str, str | None, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bootstrap = _auth_ok(request)
        if bootstrap is not None:
            return bootstrap
        seen.append(
            (
                request.method,
                request.headers.get("referer"),
                request.headers.get("x-csrf-token"),
            )
        )
        return httpx.Response(200, json={})

    client = build_client(handler)
    try:
        await client.get("/api/read")
        await client.post("/api/write")
    finally:
        await client.close()

    get_method, get_referer, get_csrf = seen[0]
    post_method, post_referer, post_csrf = seen[1]
    assert get_method == "GET" and get_referer is None and get_csrf is None
    assert post_method == "POST"
    assert post_referer == "https://portainer.test"
    assert post_csrf == "C1"


async def test_401_triggers_reauth_and_retry() -> None:
    calls = {"auth": 0, "data": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            calls["auth"] += 1
            return httpx.Response(200, json={"jwt": f"JWT{calls['auth']}"})
        if request.url.path == "/api/status":
            return httpx.Response(200, json={}, headers={"X-CSRF-Token": "C1"})
        calls["data"] += 1
        if calls["data"] == 1:
            return httpx.Response(401, text="unauthorized")
        return httpx.Response(200, json={"ok": True})

    client = build_client(handler)
    try:
        data = await client.get("/api/endpoints")
    finally:
        await client.close()

    assert data == {"ok": True}
    assert calls["auth"] == 2  # initial + re-auth on 401
    assert client._auth_version == 2


async def test_403_csrf_refresh_and_token_reharvest() -> None:
    calls = {"auth": 0, "data": 0, "csrf": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            calls["auth"] += 1
            return httpx.Response(200, json={"jwt": f"JWT{calls['auth']}"})
        if request.url.path == "/api/status":
            calls["csrf"] += 1
            return httpx.Response(200, json={}, headers={"X-CSRF-Token": f"C{calls['csrf']}"})
        calls["data"] += 1
        if calls["data"] == 1:
            return httpx.Response(403, text="invalid CSRF token")
        return httpx.Response(200, json={"ok": True}, headers={"X-CSRF-Token": "CRESP"})

    client = build_client(handler)
    try:
        data = await client.post("/api/stacks/1/start")
    finally:
        await client.close()

    assert data == {"ok": True}
    assert calls["auth"] == 2  # initial + refresh on 403 CSRF
    # New token harvested from the successful retry response (the 403 path now
    # captures it, matching the 401 path).
    assert client._csrf_token == "CRESP"


async def test_failed_status_during_auth_does_not_commit_state() -> None:
    """If GET /api/status fails, the half-set JWT must NOT be committed.

    Committing it would wedge the client: a bumped _auth_version with a bad JWT
    makes _refresh_auth a no-op forever.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            return httpx.Response(200, json={"jwt": "JWT1"})
        if request.url.path == "/api/status":
            return httpx.Response(500, text="boom")
        return httpx.Response(200, json={"ok": True})

    client = build_client(handler)
    try:
        with pytest.raises(httpx.HTTPStatusError):
            await client.get("/api/endpoints")
        assert client._jwt is None
        assert client._csrf_token is None
        assert client._auth_version == 0
    finally:
        await client.close()


async def test_concurrent_first_calls_authenticate_once() -> None:
    calls = {"auth": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            calls["auth"] += 1
            return httpx.Response(200, json={"jwt": "JWT1"})
        if request.url.path == "/api/status":
            return httpx.Response(200, json={}, headers={"X-CSRF-Token": "C1"})
        return httpx.Response(200, json={"ok": True})

    client = build_client(handler)
    try:
        await asyncio.gather(*[client.get("/api/read") for _ in range(10)])
    finally:
        await client.close()

    # The double-checked _auth_lock must collapse the stampede to one auth.
    assert calls["auth"] == 1


async def test_no_content_returns_none_on_post_and_delete() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        bootstrap = _auth_ok(request)
        if bootstrap is not None:
            return bootstrap
        return httpx.Response(204)

    client = build_client(handler)
    try:
        assert await client.post("/api/x") is None
        assert await client.delete("/api/x") is None
    finally:
        await client.close()


def test_enforce_response_size_rejects_oversized() -> None:
    too_big = httpx.Response(200, headers={"content-length": str(_MAX_RESPONSE_BYTES + 1)})
    with pytest.raises(ValueError):
        PortainerClient._enforce_response_size(too_big)
    # Within limit / missing header must not raise.
    PortainerClient._enforce_response_size(
        httpx.Response(200, headers={"content-length": "100"})
    )
    PortainerClient._enforce_response_size(httpx.Response(200))


def test_enforce_response_size_checks_buffered_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Chunked responses carry no content-length; the actual body size must
    still be enforced once buffered."""
    monkeypatch.setattr(client_mod, "_MAX_RESPONSE_BYTES", 10)
    with pytest.raises(ValueError):
        PortainerClient._enforce_response_size(httpx.Response(200, content=b"x" * 11))
    PortainerClient._enforce_response_size(httpx.Response(200, content=b"x" * 10))


async def test_401_then_403_csrf_does_not_chain_retries() -> None:
    """A 403-CSRF on the 401-retry response must NOT trigger a second re-auth
    and a third send — one retry per request(), whatever the cause."""
    calls = {"auth": 0, "data": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            calls["auth"] += 1
            return httpx.Response(200, json={"jwt": f"JWT{calls['auth']}"})
        if request.url.path == "/api/status":
            return httpx.Response(200, json={}, headers={"X-CSRF-Token": "C1"})
        calls["data"] += 1
        if calls["data"] == 1:
            return httpx.Response(401, text="unauthorized")
        return httpx.Response(403, text="invalid CSRF token")

    client = build_client(handler)
    try:
        with pytest.raises(httpx.HTTPStatusError) as excinfo:
            await client.post("/api/stacks/1/start")
    finally:
        await client.close()

    assert excinfo.value.response.status_code == 403
    assert calls["auth"] == 2  # initial + the single 401 re-auth
    assert calls["data"] == 2  # original + one retry, no third send


async def test_non_csrf_403_raises_without_reauth() -> None:
    calls = {"auth": 0, "data": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            calls["auth"] += 1
            return httpx.Response(200, json={"jwt": "JWT1"})
        if request.url.path == "/api/status":
            return httpx.Response(200, json={}, headers={"X-CSRF-Token": "C1"})
        calls["data"] += 1
        return httpx.Response(403, text="access denied")

    client = build_client(handler)
    try:
        with pytest.raises(httpx.HTTPStatusError):
            await client.get("/api/endpoints")
    finally:
        await client.close()

    assert calls["auth"] == 1  # RBAC 403 is not an auth problem
    assert calls["data"] == 1


async def test_empty_200_body_returns_none_on_all_verbs() -> None:
    """Some Portainer/Docker endpoints return 200 with an empty body (e.g.
    network connect); that must not surface as a JSON decode error."""

    def handler(request: httpx.Request) -> httpx.Response:
        bootstrap = _auth_ok(request)
        if bootstrap is not None:
            return bootstrap
        return httpx.Response(200, content=b"")

    client = build_client(handler)
    try:
        assert await client.get("/api/x") is None
        assert await client.post("/api/x") is None
        assert await client.put("/api/x") is None
        assert await client.delete("/api/x") is None
    finally:
        await client.close()


async def test_jwt_ttl_proactive_refresh() -> None:
    """A stale JWT must be refreshed proactively, without waiting for a 401."""
    calls = {"auth": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth":
            calls["auth"] += 1
            return httpx.Response(200, json={"jwt": f"JWT{calls['auth']}"})
        if request.url.path == "/api/status":
            return httpx.Response(200, json={}, headers={"X-CSRF-Token": "C1"})
        return httpx.Response(200, json={"ok": True})

    client = build_client(handler)
    try:
        await client.get("/api/read")
        assert calls["auth"] == 1
        # Age the token past the TTL; the next call must re-auth proactively.
        client._jwt_obtained_at = time.monotonic() - client._jwt_ttl - 1
        await client.get("/api/read")
    finally:
        await client.close()

    assert calls["auth"] == 2
    assert client._auth_version == 2


async def test_csrf_token_captured_from_ordinary_response() -> None:
    """_capture_csrf must latch a token off any successful response, not just
    the 401/403 retry paths."""

    def handler(request: httpx.Request) -> httpx.Response:
        bootstrap = _auth_ok(request)
        if bootstrap is not None:
            return bootstrap
        return httpx.Response(200, json={}, headers={"X-CSRF-Token": "CNEW"})

    client = build_client(handler)
    try:
        await client.get("/api/read")
    finally:
        await client.close()

    assert client._csrf_token == "CNEW"


async def test_close_client_closes_and_resets_singleton() -> None:
    closed = {"flag": False}

    class _Stub:
        async def close(self) -> None:
            closed["flag"] = True

    client_mod._client = _Stub()  # type: ignore[assignment]
    await close_client()
    assert closed["flag"] is True
    assert client_mod._client is None
    # No-op when there is nothing to close.
    await close_client()
