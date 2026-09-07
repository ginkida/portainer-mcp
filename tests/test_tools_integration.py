from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from mcp.server.fastmcp import FastMCP

import portainer_mcp.client as client_mod
from portainer_mcp.tools import (
    auth,
    containers,
    endpoints,
    images,
    laravel,
    networks,
    stacks,
    users,
    volumes,
)


def _frame(payload: bytes, stream_type: int = 1) -> bytes:
    """One Docker multiplexed frame: 8-byte header + payload."""
    header = bytes([stream_type, 0, 0, 0]) + len(payload).to_bytes(4, "big")
    return header + payload


def _text(result: Any) -> str:
    """Extract the tool's JSON string from a FastMCP call_tool() result."""
    content = result[0] if isinstance(result, tuple) else result
    return content[0].text  # type: ignore[no-any-return]


# --- portainer_status resilience -------------------------------------------------


class _StatusClient:
    def __init__(
        self,
        *,
        exc: Exception | None = None,
        data: dict[str, Any] | None = None,
        endpoints: Any = None,
        info: Any = None,
    ):
        self._exc = exc
        self._data = data
        self._endpoints = endpoints
        self._info = info

    async def get(self, path: str, **kwargs: Any) -> Any:
        if path == "/api/status":
            if self._exc is not None:
                raise self._exc
            return self._data
        target = self._endpoints if path == "/api/endpoints" else self._info
        if isinstance(target, Exception):
            raise target
        return target


_STATUS = {"Version": "2.19.0", "InstanceID": "inst-1"}


async def test_status_connected() -> None:
    mcp = FastMCP("t")
    auth.register(mcp)
    client_mod._client = _StatusClient(  # type: ignore[assignment]
        data=_STATUS,
        endpoints=[{"Id": 1, "Name": "primary", "Status": 1}, {"Id": 3, "Name": "edge"}],
        info={"Swarm": {"LocalNodeState": "active", "ControlAvailable": True}},
    )
    body = json.loads(_text(await mcp.call_tool("portainer_status", {})))
    assert body == {
        "connected": True,
        "url": "https://portainer.test",
        "version": "2.19.0",
        "instance_id": "inst-1",
        "auth": "password",
        "endpoints": 2,
        "default_endpoint": {
            "id": 1,
            "found": True,
            "name": "primary",
            "status": 1,
            "swarm": True,
            "swarm_role": "manager",
        },
    }


async def test_status_enrichment_failures_do_not_break_connectivity() -> None:
    """Endpoint listing / docker info are extras: a 403 or a dead endpoint
    must not turn a reachable Portainer into connected=false."""
    mcp = FastMCP("t")
    auth.register(mcp)
    req = httpx.Request("GET", "https://x")
    client_mod._client = _StatusClient(  # type: ignore[assignment]
        data=_STATUS,
        endpoints=httpx.HTTPStatusError(
            "denied", request=req, response=httpx.Response(403, request=req)
        ),
        info=httpx.ConnectError("agent down"),
    )
    body = json.loads(_text(await mcp.call_tool("portainer_status", {})))
    assert body["connected"] is True
    assert body["endpoints"] is None
    assert body["default_endpoint"] == {
        "id": 1,
        "found": None,
        "name": None,
        "status": None,
        "swarm": None,
        "swarm_role": None,
    }


async def test_status_survives_html_enrichment_and_skips_info_when_down() -> None:
    from portainer_mcp.errors import PortainerResponseError

    mcp = FastMCP("t")
    auth.register(mcp)
    client_mod._client = _StatusClient(  # type: ignore[assignment]
        data=_STATUS, endpoints=PortainerResponseError("html page"), info=ValueError("too big")
    )
    body = json.loads(_text(await mcp.call_tool("portainer_status", {})))
    assert body["connected"] is True and body["endpoints"] is None
    assert body["default_endpoint"]["swarm"] is None

    class _Down(_StatusClient):
        def __init__(self) -> None:
            super().__init__(data=_STATUS, endpoints=[{"Id": 1, "Name": "primary", "Status": 2}])
            self.paths: list[str] = []

        async def get(self, path: str, **kwargs: Any) -> Any:
            self.paths.append(path)
            return await super().get(path, **kwargs)

    down = _Down()
    client_mod._client = down  # type: ignore[assignment]
    body = json.loads(_text(await mcp.call_tool("portainer_status", {})))
    assert body["default_endpoint"]["status"] == 2
    assert body["default_endpoint"]["swarm"] is None
    assert not any(p.endswith("/docker/info") for p in down.paths)  # no agent round-trip


async def test_status_unusable_enrichment_bodies_are_unknown() -> None:
    mcp = FastMCP("t")
    auth.register(mcp)
    client_mod._client = _StatusClient(  # type: ignore[assignment]
        data=_STATUS, endpoints={"message": "forbidden"}, info=None
    )
    body = json.loads(_text(await mcp.call_tool("portainer_status", {})))
    assert body["connected"] is True
    assert body["endpoints"] is None  # a dict body is not "0 endpoints"
    assert body["default_endpoint"]["swarm"] is None  # empty info is not "standalone"
    client_mod._client = _StatusClient(  # type: ignore[assignment]
        data=_STATUS, endpoints=[{"Id": 1, "Name": "x"}], info={"Name": "no-swarm-key"}
    )
    body = json.loads(_text(await mcp.call_tool("portainer_status", {})))
    assert body["default_endpoint"]["swarm"] is None


async def test_status_probes_use_short_timeout() -> None:
    class _Timing(_StatusClient):
        def __init__(self) -> None:
            super().__init__(
                data=_STATUS, endpoints=[{"Id": 1}], info={"Swarm": {"LocalNodeState": "inactive"}}
            )
            self.timeouts: dict[str, Any] = {}

        async def get(self, path: str, **kwargs: Any) -> Any:
            self.timeouts[path] = kwargs.get("timeout")
            return await super().get(path, **kwargs)

    mcp = FastMCP("t")
    auth.register(mcp)
    fake = _Timing()
    client_mod._client = fake  # type: ignore[assignment]
    await mcp.call_tool("portainer_status", {})
    assert fake.timeouts["/api/status"] is None  # the health check itself: default timeout
    assert fake.timeouts["/api/endpoints"] == auth._PROBE_TIMEOUT
    assert fake.timeouts["/api/endpoints/1/docker/info"] == auth._PROBE_TIMEOUT


async def test_status_worker_node_is_not_swarm() -> None:
    mcp = FastMCP("t")
    auth.register(mcp)
    client_mod._client = _StatusClient(  # type: ignore[assignment]
        data=_STATUS,
        endpoints=[{"Id": 1, "Name": "w"}],
        info={"Swarm": {"LocalNodeState": "active", "ControlAvailable": False}},
    )
    body = json.loads(_text(await mcp.call_tool("portainer_status", {})))
    assert body["default_endpoint"]["swarm"] is False
    assert body["default_endpoint"]["swarm_role"] == "worker"


async def test_status_reports_api_key_auth_and_standalone(monkeypatch: pytest.MonkeyPatch) -> None:
    import portainer_mcp.config as config_mod

    monkeypatch.setenv("PORTAINER_API_KEY", "ptr_x")
    config_mod._config = None
    mcp = FastMCP("t")
    auth.register(mcp)
    client_mod._client = _StatusClient(  # type: ignore[assignment]
        data=_STATUS, endpoints=[{"Id": 1}], info={"Swarm": {"LocalNodeState": "inactive"}}
    )
    body = json.loads(_text(await mcp.call_tool("portainer_status", {})))
    assert body["auth"] == "api_key"
    assert body["endpoints"] == 1
    assert body["default_endpoint"]["swarm"] is False
    assert body["default_endpoint"]["swarm_role"] is None


async def test_status_flags_missing_default_endpoint_and_skips_probe() -> None:
    class _Client(_StatusClient):
        def __init__(self) -> None:
            super().__init__(data=_STATUS, endpoints=[{"Id": 3, "Name": "only"}])
            self.paths: list[str] = []

        async def get(self, path: str, **kwargs: Any) -> Any:
            self.paths.append(path)
            return await super().get(path, **kwargs)

    mcp = FastMCP("t")
    auth.register(mcp)
    fake = _Client()
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(_text(await mcp.call_tool("portainer_status", {})))
    assert body["endpoints"] == 1
    assert body["default_endpoint"]["found"] is False
    assert body["default_endpoint"]["swarm"] is None
    assert not any(p.endswith("/docker/info") for p in fake.paths)


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


# --- container_logs JSON envelope -------------------------------------------------


async def test_container_logs_returns_json_envelope() -> None:
    mcp = FastMCP("t")
    containers.register(mcp)
    client_mod._client = _GrepClient()  # type: ignore[assignment]
    body = json.loads(
        _text(await mcp.call_tool("portainer_container_logs", {"container_id": "abc"}))
    )
    assert body["container_id"] == "abc"
    assert body["truncated"] is False
    assert body["logs"] == "line one\nline two\n"


# --- output cap keeps JSON valid --------------------------------------------------


class _HugeLogClient:
    """One container whose logs blow well past the output cap."""

    async def get(self, path: str, **kwargs: Any) -> Any:
        return [{"Id": "aaaaaaaaaaaa0000", "Names": ["/demo_web.1.xyz"]}]

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        line = b"ERROR: something exploded spectacularly badly\n"
        return httpx.Response(200, content=line * 5000)  # ~230K chars


async def test_stack_logs_errors_truncated_output_is_valid_json() -> None:
    mcp = FastMCP("t")
    containers.register(mcp)
    client_mod._client = _HugeLogClient()  # type: ignore[assignment]
    raw = _text(await mcp.call_tool("portainer_stack_logs_errors", {"stack_name": "demo"}))
    body = json.loads(raw)  # must parse — truncation happens before serialization
    assert body["truncated"] is True
    kept = body["containers"]["demo_web.1"]["errors"]
    assert 0 < len(kept) < 5000


async def test_logs_grep_truncated_output_is_valid_json() -> None:
    mcp = FastMCP("t")
    containers.register(mcp)
    client_mod._client = _HugeLogClient()  # type: ignore[assignment]
    raw = _text(
        await mcp.call_tool(
            "portainer_container_logs_grep",
            {"container_id": "abc", "pattern": "ERROR"},
        )
    )
    body = json.loads(raw)
    assert body["truncated"] is True
    assert body["matches_found"] == 5000
    assert len(body["lines"]) < 5000


# --- laravel_tinker backend matching ----------------------------------------------


class _TinkerClient:
    """Fake client driving the two-step exec flow for laravel_tinker."""

    def __init__(self, names: list[str]) -> None:
        self.names = names
        self.exec_bodies: list[dict[str, Any]] = []

    async def get(self, path: str, **kwargs: Any) -> Any:
        if path.endswith("/containers/json"):
            return [{"Id": f"{i:012x}0000", "Names": [name]} for i, name in enumerate(self.names)]
        if "/exec/" in path and path.endswith("/json"):
            return {"ExitCode": 0}
        raise AssertionError(f"unexpected GET {path}")

    async def post(self, path: str, **kwargs: Any) -> Any:
        assert path.endswith("/exec")
        self.exec_bodies.append(kwargs["json"])
        return {"Id": "exec1"}

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        assert path.endswith("/exec/exec1/start")
        return httpx.Response(200, content=_frame(b"= 42\n"))


@pytest.mark.parametrize(
    "name",
    [
        "/demo_backend",  # plain docker run / compose v2 service container
        "/demo_backend.1.abc123",  # swarm replica
        "/demo_backend_1",  # compose v1
    ],
)
async def test_laravel_tinker_matches_backend_naming_schemes(name: str) -> None:
    mcp = FastMCP("t")
    laravel.register(mcp)
    fake = _TinkerClient(["/other_backend.1.x", name])
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_laravel_tinker",
                {"stack_name": "demo", "code": "User::count()"},
            )
        )
    )
    assert body["exit_code"] == 0
    assert body["output"] == "= 42\n"
    # The single-quote escaping wraps the code for sh -c.
    assert "tinker --execute='User::count()'" in fake.exec_bodies[0]["Cmd"][2]


async def test_laravel_tinker_skips_sibling_services() -> None:
    """backend_worker / backend_horizon etc. must NOT be picked as 'backend'."""
    mcp = FastMCP("t")
    laravel.register(mcp)
    fake = _TinkerClient(["/demo_backend_worker_1", "/demo_backend_horizon.1.x", "/demo_backend_1"])
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_laravel_tinker",
                {"stack_name": "demo", "code": "1"},
            )
        )
    )
    # The Compose-v1 replica is the only real backend container in the list.
    assert body["container"] == "demo_backend_1"


async def test_laravel_tinker_sibling_only_stack_reports_no_backend() -> None:
    mcp = FastMCP("t")
    laravel.register(mcp)
    client_mod._client = _TinkerClient(  # type: ignore[assignment]
        ["/demo_backend_scheduler_1", "/demo_backend_worker.1.x"]
    )
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_laravel_tinker",
                {"stack_name": "demo", "code": "1"},
            )
        )
    )
    assert "No running backend container" in body["error"]


async def test_laravel_tinker_no_backend_found() -> None:
    mcp = FastMCP("t")
    laravel.register(mcp)
    client_mod._client = _TinkerClient(["/demo_frontend.1.x"])  # type: ignore[assignment]
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_laravel_tinker",
                {"stack_name": "demo", "code": "1"},
            )
        )
    )
    assert "No running backend container" in body["error"]


# --- image_pull error stream ------------------------------------------------------


class _PullClient:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.params: dict[str, Any] | None = None

    async def get(self, path: str, **kwargs: Any) -> Any:
        assert path == "/api/endpoints/1/registries"
        return []

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        self.params = kwargs.get("params")
        return httpx.Response(200, content=self.payload)


async def test_image_pull_reports_stream_errors() -> None:
    mcp = FastMCP("t")
    images.register(mcp)
    client_mod._client = _PullClient(  # type: ignore[assignment]
        b'{"status":"Pulling from x"}\n{"error":"manifest unknown"}\n'
    )
    body = json.loads(
        _text(await mcp.call_tool("portainer_image_pull", {"image_name": "ghost/none"}))
    )
    assert body["error"] == "Image pull failed"
    assert "manifest unknown" in body["details"]


async def test_image_pull_success() -> None:
    mcp = FastMCP("t")
    images.register(mcp)
    fake = _PullClient(b'{"status":"Pulling from library/nginx"}\n{"status":"Digest: ok"}\n')
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(
        _text(await mcp.call_tool("portainer_image_pull", {"image_name": "nginx", "tag": "1.25"}))
    )
    assert body == {
        "status": "pulled",
        "image": "nginx:1.25",
        "registry_id": None,
        "credentials": "none (official Docker Hub image)",
    }
    assert fake.params == {"fromImage": "nginx", "tag": "1.25"}


# --- name_filter propagation ------------------------------------------------------


class _ListClient:
    def __init__(self) -> None:
        self.params: dict[str, Any] | None = None

    async def get(self, path: str, **kwargs: Any) -> Any:
        self.params = kwargs.get("params")
        return []


async def test_containers_list_name_filter_forwarded() -> None:
    mcp = FastMCP("t")
    containers.register(mcp)
    fake = _ListClient()
    client_mod._client = fake  # type: ignore[assignment]
    await mcp.call_tool("portainer_containers_list", {"name_filter": "web"})
    assert fake.params is not None
    assert json.loads(fake.params["filters"]) == {"name": ["web"]}


async def test_containers_list_rejects_bad_filter() -> None:
    mcp = FastMCP("t")
    containers.register(mcp)
    client_mod._client = _ListClient()  # type: ignore[assignment]
    body = json.loads(
        _text(await mcp.call_tool("portainer_containers_list", {"name_filter": "web; rm -rf /"}))
    )
    assert body["error"] == "Validation error"
    # The message must name the actual parameter, not "container_id".
    assert "name_filter" in body["details"]


async def test_containers_list_filter_allows_leading_underscore() -> None:
    """A name-suffix filter like '_backend' is legitimate — the strict
    leading-alphanumeric id rule must not apply to filter substrings."""
    mcp = FastMCP("t")
    containers.register(mcp)
    fake = _ListClient()
    client_mod._client = fake  # type: ignore[assignment]
    await mcp.call_tool("portainer_containers_list", {"name_filter": "_backend"})
    assert fake.params is not None
    assert json.loads(fake.params["filters"]) == {"name": ["_backend"]}


async def test_volumes_networks_images_filters_forwarded() -> None:
    for module, tool, param, value, key in (
        (volumes, "portainer_volumes_list", "name_filter", "data", "name"),
        (networks, "portainer_networks_list", "name_filter", "web", "name"),
        (images, "portainer_images_list", "reference_filter", "nginx:1.25", "reference"),
    ):
        mcp = FastMCP("t")
        module.register(mcp)
        fake = _ListClient()
        client_mod._client = fake  # type: ignore[assignment]
        await mcp.call_tool(tool, {param: value})
        assert fake.params is not None, tool
        assert json.loads(fake.params["filters"]) == {key: [value]}, tool


# --- container_exec end-to-end ----------------------------------------------------


class _ExecClient:
    """Fake client for the dedicated container_exec two-step flow."""

    def __init__(self) -> None:
        self.exec_bodies: list[dict[str, Any]] = []

    async def get(self, path: str, **kwargs: Any) -> Any:
        assert "/exec/" in path and path.endswith("/json")
        return {"ExitCode": 3}

    async def post(self, path: str, **kwargs: Any) -> Any:
        assert path.endswith("/exec")
        self.exec_bodies.append(kwargs["json"])
        return {"Id": "exec1"}

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        assert path.endswith("/exec/exec1/start")
        return httpx.Response(200, content=_frame(b"hello\n"))


async def test_container_exec_full_flow_with_workdir_and_user(
    caplog: pytest.LogCaptureFixture,
) -> None:
    mcp = FastMCP("t")
    containers.register(mcp)
    fake = _ExecClient()
    client_mod._client = fake  # type: ignore[assignment]
    with caplog.at_level("INFO"):
        body = json.loads(
            _text(
                await mcp.call_tool(
                    "portainer_container_exec",
                    {
                        "container_id": "abc123",
                        "command": "env && echo PASSWORD=hunter2",
                        "workdir": "/srv",
                        "user": "1000:1000",
                    },
                )
            )
        )
    assert body == {"exit_code": 3, "output": "hello\n"}
    exec_body = fake.exec_bodies[0]
    assert exec_body["Cmd"] == ["sh", "-c", "env && echo PASSWORD=hunter2"]
    assert exec_body["WorkingDir"] == "/srv"
    assert exec_body["User"] == "1000:1000"
    # The AUDIT line must be present and redacted.
    audit = [r.message for r in caplog.records if "AUDIT" in r.message]
    assert audit and "hunter2" not in audit[0] and "REDACTED" in audit[0]


async def test_container_exec_rejects_overlong_command() -> None:
    mcp = FastMCP("t")
    containers.register(mcp)
    client_mod._client = _ExecClient()  # type: ignore[assignment]
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_container_exec",
                {"container_id": "abc123", "command": "x" * 5000},
            )
        )
    )
    assert body["error"] == "Validation error"
    assert "too long" in body["details"]


# --- force-parameter propagation --------------------------------------------------


class _MutatingClient:
    def __init__(self) -> None:
        self.params: dict[str, Any] | None = None
        self.body: dict[str, Any] | None = None

    async def delete(self, path: str, **kwargs: Any) -> Any:
        self.params = kwargs.get("params")
        return None

    async def post(self, path: str, **kwargs: Any) -> Any:
        self.body = kwargs.get("json")
        return None


@pytest.mark.parametrize(
    ("args", "expected"),
    [({}, "false"), ({"force": False}, "false"), ({"force": True}, "true")],
)
async def test_container_remove_force_propagation(args: dict[str, Any], expected: str) -> None:
    mcp = FastMCP("t")
    containers.register(mcp)
    fake = _MutatingClient()
    client_mod._client = fake  # type: ignore[assignment]
    await mcp.call_tool("portainer_container_remove", {"container_id": "abc", **args})
    assert fake.params is not None
    assert fake.params["force"] == expected


@pytest.mark.parametrize(
    ("args", "expected"),
    [({}, "false"), ({"force": True}, "true")],
)
async def test_volume_remove_force_propagation(args: dict[str, Any], expected: str) -> None:
    mcp = FastMCP("t")
    volumes.register(mcp)
    fake = _MutatingClient()
    client_mod._client = fake  # type: ignore[assignment]
    await mcp.call_tool("portainer_volume_remove", {"volume_name": "data", **args})
    assert fake.params is not None
    assert fake.params["force"] == expected


@pytest.mark.parametrize(
    ("args", "expected"),
    [({}, False), ({"force": True}, True)],
)
async def test_network_disconnect_force_propagation(args: dict[str, Any], expected: bool) -> None:
    mcp = FastMCP("t")
    networks.register(mcp)
    fake = _MutatingClient()
    client_mod._client = fake  # type: ignore[assignment]
    await mcp.call_tool(
        "portainer_network_disconnect",
        {"network_id": "net1", "container_id": "abc", **args},
    )
    assert fake.body is not None
    assert fake.body == {"Container": "abc", "Force": expected}


# --- stack_update endpoint derivation ----------------------------------------------


_STACK_ENV = [
    {"name": "CLICKHOUSE_PASSWORD", "value": "ch-secret-canary"},
    {"name": "API_KEY", "value": "api-key-canary"},
    {"name": "TAG", "value": "v1"},
]


class _StackUpdateClient:
    def __init__(self, *, prune: bool | None = False, env: list[Any] | None = None) -> None:
        self.put_params: dict[str, Any] | None = None
        self.put_body: dict[str, Any] | None = None
        self.file_fetched = False
        self.env = list(_STACK_ENV) if env is None else env
        self.prune = prune

    async def get(self, path: str, **kwargs: Any) -> Any:
        if path == "/api/stacks/9":
            stack: dict[str, Any] = {"Id": 9, "EndpointId": 5, "Type": 1, "Env": self.env}
            if self.prune is not None:
                stack["Option"] = {"Prune": self.prune}
            return stack
        if path == "/api/stacks/9/file":
            self.file_fetched = True
            return {"StackFileContent": "services: {}"}
        raise AssertionError(path)

    async def put(self, path: str, **kwargs: Any) -> Any:
        assert path == "/api/stacks/9"
        self.put_params = kwargs.get("params")
        self.put_body = kwargs.get("json")
        return None


def _env_dict(body: dict[str, Any]) -> dict[str, str]:
    return {p["name"]: p["value"] for p in body["Env"]}


async def test_stack_update_derives_endpoint_from_stack() -> None:
    """Without endpoint_id the update must target the stack's own endpoint,
    not the configured default (which is 1)."""
    mcp = FastMCP("t")
    stacks.register(mcp)
    fake = _StackUpdateClient()
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(_text(await mcp.call_tool("portainer_stack_update", {"stack_id": 9})))
    assert body["status"] == "updated"
    assert body["stack_id"] == 9
    assert body["endpoint_id"] == 5
    assert fake.put_params == {"endpointId": 5}
    assert fake.file_fetched  # no compose_content -> stored file is redeployed


async def test_stack_update_preserves_existing_env() -> None:
    """Portainer replaces the whole Env list on PUT; a plain redeploy must
    send the current variables back, not an empty list."""
    mcp = FastMCP("t")
    stacks.register(mcp)
    fake = _StackUpdateClient()
    client_mod._client = fake  # type: ignore[assignment]
    raw = _text(await mcp.call_tool("portainer_stack_update", {"stack_id": 9}))
    assert fake.put_body is not None
    assert _env_dict(fake.put_body) == {
        "CLICKHOUSE_PASSWORD": "ch-secret-canary",
        "API_KEY": "api-key-canary",
        "TAG": "v1",
    }
    # The tool result reports names only — never the values.
    assert "ch-secret-canary" not in raw
    assert json.loads(raw)["env_names"] == ["API_KEY", "CLICKHOUSE_PASSWORD", "TAG"]


async def test_stack_update_merges_and_removes_env() -> None:
    mcp = FastMCP("t")
    stacks.register(mcp)
    fake = _StackUpdateClient()
    client_mod._client = fake  # type: ignore[assignment]
    await mcp.call_tool(
        "portainer_stack_update",
        {"stack_id": 9, "env": {"TAG": "v2", "NEW": "x"}, "env_remove": ["API_KEY"]},
    )
    assert fake.put_body is not None
    assert _env_dict(fake.put_body) == {
        "CLICKHOUSE_PASSWORD": "ch-secret-canary",
        "TAG": "v2",
        "NEW": "x",
    }


@pytest.mark.parametrize(
    ("stored_prune", "arg", "expected"),
    [(True, None, True), (False, None, False), (None, None, False), (True, False, False)],
)
async def test_stack_update_prune_defaults_to_stack_setting(
    stored_prune: bool | None, arg: bool | None, expected: bool
) -> None:
    mcp = FastMCP("t")
    stacks.register(mcp)
    fake = _StackUpdateClient(prune=stored_prune)
    client_mod._client = fake  # type: ignore[assignment]
    args: dict[str, Any] = {"stack_id": 9}
    if arg is not None:
        args["prune"] = arg
    body = json.loads(_text(await mcp.call_tool("portainer_stack_update", args)))
    assert fake.put_body is not None
    assert fake.put_body["Prune"] is expected
    assert body["prune"] is expected


@pytest.mark.parametrize("pull", [False, True])
async def test_stack_update_pull_image_sets_both_flags(pull: bool) -> None:
    mcp = FastMCP("t")
    stacks.register(mcp)
    fake = _StackUpdateClient()
    client_mod._client = fake  # type: ignore[assignment]
    await mcp.call_tool("portainer_stack_update", {"stack_id": 9, "pull_image": pull})
    assert fake.put_body is not None
    # RepullImageAndRedeploy is the 2.36+ field; PullImage the deprecated one.
    assert fake.put_body["RepullImageAndRedeploy"] is pull
    assert fake.put_body["PullImage"] is pull


async def test_stack_update_uses_new_compose_without_fetching_file() -> None:
    mcp = FastMCP("t")
    stacks.register(mcp)
    fake = _StackUpdateClient()
    client_mod._client = fake  # type: ignore[assignment]
    await mcp.call_tool(
        "portainer_stack_update", {"stack_id": 9, "compose_content": "services:\n  web: {}"}
    )
    assert fake.put_body is not None
    assert fake.put_body["StackFileContent"] == "services:\n  web: {}"
    assert not fake.file_fetched


async def test_stack_update_rejects_redacted_compose_and_env() -> None:
    mcp = FastMCP("t")
    stacks.register(mcp)
    fake = _StackUpdateClient()
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_stack_update",
                {"stack_id": 9, "compose_content": "environment:\n  DB_PASSWORD=[REDACTED]\n"},
            )
        )
    )
    assert body["error"] == "Validation error"
    assert "reveal_env=true" in body["details"]
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_stack_update", {"stack_id": 9, "env": {"X": "[REDACTED]"}}
            )
        )
    )
    assert body["error"] == "Validation error"
    assert fake.put_body is None  # nothing reached Portainer


@pytest.mark.parametrize("bad", ["1BAD", "with-dash", "", "a b"])
async def test_stack_update_rejects_bad_env_name(bad: str) -> None:
    mcp = FastMCP("t")
    stacks.register(mcp)
    fake = _StackUpdateClient()
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(
        _text(await mcp.call_tool("portainer_stack_update", {"stack_id": 9, "env": {bad: "v"}}))
    )
    assert body["error"] == "Validation error"
    assert fake.put_body is None


# --- stack inspect: env redaction -------------------------------------------------


_COMPOSE_WITH_SECRETS = (
    "services:\n"
    "  db:\n"
    "    image: clickhouse:latest\n"
    "    environment:\n"
    "      - CLICKHOUSE_PASSWORD=inline-canary\n"
    "      - CLICKHOUSE_PORT=9000\n"
    "      REF: ${CLICKHOUSE_PASSWORD}\n"
)


class _StackInspectClient:
    async def get(self, path: str, **kwargs: Any) -> Any:
        if path == "/api/stacks/9":
            return {"Id": 9, "Name": "demo", "EndpointId": 5, "Env": list(_STACK_ENV)}
        if path == "/api/stacks/9/file":
            return {"StackFileContent": _COMPOSE_WITH_SECRETS}
        raise AssertionError(path)


async def test_stack_inspect_redacts_env_and_compose_by_default() -> None:
    mcp = FastMCP("t")
    stacks.register(mcp)
    client_mod._client = _StackInspectClient()  # type: ignore[assignment]
    raw = _text(await mcp.call_tool("portainer_stack_inspect", {"stack_id": 9}))
    for canary in ("ch-secret-canary", "api-key-canary", "inline-canary"):
        assert canary not in raw
    body = json.loads(raw)
    assert body["env_redacted"] is True
    env = {p["name"]: p["value"] for p in body["Env"]}
    assert env["TAG"] == "v1"  # non-secret values pass through
    assert env["CLICKHOUSE_PASSWORD"] == "[REDACTED]"
    compose = body["ComposeFileContent"]
    assert "CLICKHOUSE_PORT=9000" in compose
    assert "image: clickhouse:latest" in compose
    assert "REF: ${CLICKHOUSE_PASSWORD}" in compose  # variable references survive
    assert "CLICKHOUSE_PASSWORD=[REDACTED]" in compose


async def test_stack_inspect_reveal_env_returns_everything() -> None:
    mcp = FastMCP("t")
    stacks.register(mcp)
    client_mod._client = _StackInspectClient()  # type: ignore[assignment]
    raw = _text(await mcp.call_tool("portainer_stack_inspect", {"stack_id": 9, "reveal_env": True}))
    body = json.loads(raw)
    assert body["env_redacted"] is False
    assert body["ComposeFileContent"] == _COMPOSE_WITH_SECRETS
    assert "ch-secret-canary" in raw


# --- stack start/stop/delete: endpointId ------------------------------------------


class _StackLifecycleClient:
    def __init__(self, *, own_endpoint_exists: bool = True) -> None:
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []
        self.own_endpoint_exists = own_endpoint_exists

    async def get(self, path: str, **kwargs: Any) -> Any:
        if path == "/api/stacks/9":
            return {"Id": 9, "Name": "demo", "EndpointId": 5}
        if path == "/api/endpoints/5":
            if self.own_endpoint_exists:
                return {"Id": 5}
            req = httpx.Request("GET", "https://x")
            raise httpx.HTTPStatusError(
                "gone", request=req, response=httpx.Response(404, request=req)
            )
        raise AssertionError(path)

    async def post(self, path: str, **kwargs: Any) -> Any:
        self.calls.append(("POST", path, kwargs.get("params")))
        return None

    async def delete(self, path: str, **kwargs: Any) -> Any:
        self.calls.append(("DELETE", path, kwargs.get("params")))
        return None


_LIFECYCLE = [
    ("portainer_stack_start", "POST", "/api/stacks/9/start", "started"),
    ("portainer_stack_stop", "POST", "/api/stacks/9/stop", "stopped"),
    ("portainer_stack_delete", "DELETE", "/api/stacks/9", "deleted"),
]


@pytest.mark.parametrize(("tool", "method", "path", "status"), _LIFECYCLE)
async def test_stack_lifecycle_sends_endpoint_id(
    tool: str, method: str, path: str, status: str
) -> None:
    """Portainer 2.39 requires endpointId on start/stop (400 without) and
    treats a delete without it as an orphaned stack on endpoint 0."""
    mcp = FastMCP("t")
    stacks.register(mcp)
    fake = _StackLifecycleClient()
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(_text(await mcp.call_tool(tool, {"stack_id": 9})))
    assert body == {"status": status, "stack_id": 9, "endpoint_id": 5}
    assert fake.calls == [(method, path, {"endpointId": 5})]
    # The stack's own endpoint passed explicitly is fine too.
    fake.calls.clear()
    await mcp.call_tool(tool, {"stack_id": 9, "endpoint_id": 5})
    assert fake.calls == [(method, path, {"endpointId": 5})]


@pytest.mark.parametrize(("tool", "method", "path", "status"), _LIFECYCLE)
async def test_stack_lifecycle_rejects_foreign_endpoint(
    tool: str, method: str, path: str, status: str
) -> None:
    """A different endpoint_id would make Portainer act on the wrong endpoint
    (and, for delete, drop the stack record while services keep running)."""
    mcp = FastMCP("t")
    stacks.register(mcp)
    fake = _StackLifecycleClient()
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(_text(await mcp.call_tool(tool, {"stack_id": 9, "endpoint_id": 1})))
    assert body["error"] == "Validation error"
    assert "belongs to endpoint 5" in body["details"]
    assert fake.calls == []


@pytest.mark.parametrize(("tool", "method", "path", "status"), _LIFECYCLE)
async def test_stack_lifecycle_allows_override_for_orphaned_stack(
    tool: str, method: str, path: str, status: str
) -> None:
    """When the stack's endpoint no longer exists, the explicit endpoint is
    the only way to act on it (admin orphan removal)."""
    mcp = FastMCP("t")
    stacks.register(mcp)
    fake = _StackLifecycleClient(own_endpoint_exists=False)
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(_text(await mcp.call_tool(tool, {"stack_id": 9, "endpoint_id": 1})))
    assert body == {"status": status, "stack_id": 9, "endpoint_id": 1}
    assert fake.calls == [(method, path, {"endpointId": 1})]


async def test_stack_update_rejects_foreign_endpoint() -> None:
    class _Client(_StackUpdateClient):
        async def get(self, path: str, **kwargs: Any) -> Any:
            if path == "/api/endpoints/5":
                return {"Id": 5}
            return await super().get(path, **kwargs)

    mcp = FastMCP("t")
    stacks.register(mcp)
    fake = _Client()
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(
        _text(await mcp.call_tool("portainer_stack_update", {"stack_id": 9, "endpoint_id": 2}))
    )
    assert body["error"] == "Validation error"
    assert fake.put_body is None


# --- stack deploy: swarm vs standalone --------------------------------------------


class _DeployClient:
    def __init__(self, swarm: bool) -> None:
        self.swarm = swarm
        self.post_path: str | None = None
        self.post_body: dict[str, Any] | None = None

    async def get(self, path: str, **kwargs: Any) -> Any:
        assert path.endswith("/docker/swarm")
        if self.swarm:
            return {"ID": "swarm-1"}
        raise httpx.HTTPStatusError(
            "not swarm",
            request=httpx.Request("GET", "https://x"),
            response=httpx.Response(503, request=httpx.Request("GET", "https://x")),
        )

    async def post(self, path: str, **kwargs: Any) -> Any:
        self.post_path = path
        self.post_body = kwargs["json"]
        return {"Id": 7, "Name": kwargs["json"]["Name"]}


@pytest.mark.parametrize(("swarm", "deploy_type"), [(True, "swarm"), (False, "standalone")])
async def test_stack_deploy_picks_correct_api_path(swarm: bool, deploy_type: str) -> None:
    mcp = FastMCP("t")
    stacks.register(mcp)
    fake = _DeployClient(swarm)
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_stack_deploy",
                {"name": "demo", "compose_content": "services: {}"},
            )
        )
    )
    assert body["Id"] == 7
    assert fake.post_path == f"/api/stacks/create/{deploy_type}/string"
    assert fake.post_body is not None
    assert ("SwarmID" in fake.post_body) is swarm


async def test_stack_deploy_sends_env_pairs() -> None:
    mcp = FastMCP("t")
    stacks.register(mcp)
    fake = _DeployClient(False)
    client_mod._client = fake  # type: ignore[assignment]
    await mcp.call_tool(
        "portainer_stack_deploy",
        {"name": "demo", "compose_content": "services: {}", "env": {"TAG": "v1", "X": "y"}},
    )
    assert fake.post_body is not None
    assert fake.post_body["Env"] == [{"name": "TAG", "value": "v1"}, {"name": "X", "value": "y"}]


async def test_stack_deploy_rejects_empty_compose() -> None:
    mcp = FastMCP("t")
    stacks.register(mcp)
    client_mod._client = _DeployClient(False)  # type: ignore[assignment]
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_stack_deploy",
                {"name": "demo", "compose_content": "   \n"},
            )
        )
    )
    assert body["error"] == "Validation error"
    assert "empty" in body["details"]


# --- sensitive-field filtering (endpoints, users) ---------------------------------


class _GetClient:
    """Returns canned data for any GET path."""

    def __init__(self, data: Any) -> None:
        self._data = data

    async def get(self, path: str, **kwargs: Any) -> Any:
        return self._data


_RAW_ENDPOINT: dict[str, Any] = {
    "Id": 1,
    "Name": "primary",
    "Type": 1,
    "URL": "unix:///var/run/docker.sock",
    "Status": 1,
    "GroupId": 1,
    "TLSConfig": {"TLS": True, "TLSCACert": "fake-ca-material tls-leak-canary"},
    "AzureCredentials": {"ApplicationID": "app", "AuthenticationKey": "azure-leak-canary"},
    "Edge": {"AsyncMode": False},
    "Agent": {"Version": "2.19"},
    "Kubernetes": {"Configuration": {}},
    "SecuritySettings": {"allowBindMountsForRegularUsers": True},
}


async def test_endpoint_inspect_strips_sensitive_fields() -> None:
    mcp = FastMCP("t")
    endpoints.register(mcp)
    client_mod._client = _GetClient(_RAW_ENDPOINT)  # type: ignore[assignment]
    raw = _text(await mcp.call_tool("portainer_endpoint_inspect", {"endpoint_id": 1}))
    body = json.loads(raw)
    assert body["Id"] == 1
    assert body["Name"] == "primary"
    assert set(body) <= endpoints._ENDPOINT_SAFE_FIELDS
    for canary in ("tls-leak-canary", "azure-leak-canary"):
        assert canary not in raw


async def test_endpoints_list_returns_summary_only() -> None:
    mcp = FastMCP("t")
    endpoints.register(mcp)
    client_mod._client = _GetClient([_RAW_ENDPOINT])  # type: ignore[assignment]
    body = json.loads(_text(await mcp.call_tool("portainer_endpoints_list", {})))
    assert body == [
        {
            "id": 1,
            "name": "primary",
            "type": 1,
            "url": "unix:///var/run/docker.sock",
            "status": 1,
            "group_id": 1,
        }
    ]


_RAW_USER: dict[str, Any] = {
    "Id": 3,
    "Username": "ops",
    "Role": 2,
    "Password": "hash-leak-canary",
    "TOTPSecret": "totp-leak-canary",
    "TokenIssueAt": 1700000000,
    "ThemeSettings": {"color": "dark"},
}


async def test_user_inspect_strips_credentials() -> None:
    mcp = FastMCP("t")
    users.register(mcp)
    client_mod._client = _GetClient(_RAW_USER)  # type: ignore[assignment]
    raw = _text(await mcp.call_tool("portainer_user_inspect", {"user_id": 3}))
    body = json.loads(raw)
    assert body["Username"] == "ops"
    assert body["Role"] == 2
    assert set(body) <= users._USER_SAFE_FIELDS
    for canary in ("hash-leak-canary", "totp-leak-canary"):
        assert canary not in raw


async def test_users_list_returns_summary_only() -> None:
    mcp = FastMCP("t")
    users.register(mcp)
    client_mod._client = _GetClient([_RAW_USER])  # type: ignore[assignment]
    body = json.loads(_text(await mcp.call_tool("portainer_users_list", {})))
    assert body == [{"id": 3, "username": "ops", "role": 2}]


# bool ids are not covered here: FastMCP's pydantic layer coerces True -> 1 before
# validate_id runs; the bool rejection itself is covered in test_helpers.
@pytest.mark.parametrize("bad_id", [0, -1])
async def test_user_inspect_rejects_invalid_id(bad_id: int) -> None:
    mcp = FastMCP("t")
    users.register(mcp)
    client_mod._client = _GetClient(_RAW_USER)  # type: ignore[assignment]
    body = json.loads(_text(await mcp.call_tool("portainer_user_inspect", {"user_id": bad_id})))
    assert body["error"] == "Validation error"


# --- containers_list: stack/service labels + stack_filter ------------------------


_RAW_CONTAINERS: list[dict[str, Any]] = [
    {
        "Id": "aaaaaaaaaaaa0000",
        "Names": ["/etl_backend.1.x"],
        "Image": "app:latest",
        "State": "running",
        "Status": "Up",
        "Created": 1,
        "Labels": {
            "com.docker.stack.namespace": "etl",
            "com.docker.swarm.service.name": "etl_backend",
        },
    },
    {
        "Id": "bbbbbbbbbbbb0000",
        "Names": ["/blog-web-1"],
        "Image": "nginx",
        "State": "running",
        "Status": "Up",
        "Created": 2,
        "Labels": {
            "com.docker.compose.project": "blog",
            "com.docker.compose.service": "web",
        },
    },
    {"Id": "cccccccccccc0000", "Names": ["/loose"], "Image": "x", "State": "exited"},
]


class _ContainersClient:
    async def get(self, path: str, **kwargs: Any) -> Any:
        return _RAW_CONTAINERS


async def test_containers_list_reports_stack_and_service_labels() -> None:
    mcp = FastMCP("t")
    containers.register(mcp)
    client_mod._client = _ContainersClient()  # type: ignore[assignment]
    body = json.loads(_text(await mcp.call_tool("portainer_containers_list", {})))
    by_id = {c["id"]: c for c in body}
    assert by_id["aaaaaaaaaaaa"]["stack"] == "etl"
    assert by_id["aaaaaaaaaaaa"]["service"] == "etl_backend"
    assert by_id["bbbbbbbbbbbb"]["stack"] == "blog"
    assert by_id["bbbbbbbbbbbb"]["service"] == "web"
    assert by_id["cccccccccccc"]["stack"] is None
    assert by_id["cccccccccccc"]["service"] is None


@pytest.mark.parametrize(
    ("stack", "expected"),
    [("etl", ["aaaaaaaaaaaa"]), ("blog", ["bbbbbbbbbbbb"]), ("nope", [])],
)
async def test_containers_list_stack_filter(stack: str, expected: list[str]) -> None:
    mcp = FastMCP("t")
    containers.register(mcp)
    client_mod._client = _ContainersClient()  # type: ignore[assignment]
    body = json.loads(
        _text(await mcp.call_tool("portainer_containers_list", {"stack_filter": stack}))
    )
    assert [c["id"] for c in body] == expected


async def test_containers_list_rejects_bad_stack_filter() -> None:
    mcp = FastMCP("t")
    containers.register(mcp)
    client_mod._client = _ContainersClient()  # type: ignore[assignment]
    body = json.loads(
        _text(await mcp.call_tool("portainer_containers_list", {"stack_filter": "a.b"}))
    )
    assert body["error"] == "Validation error"


# --- container_logs: since / timestamps -------------------------------------------


class _LogParamsClient:
    def __init__(self) -> None:
        self.params: dict[str, Any] | None = None

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        self.params = kwargs.get("params")
        return httpx.Response(200, content=b"x\n")


async def test_container_logs_since_and_timestamps_forwarded() -> None:
    mcp = FastMCP("t")
    containers.register(mcp)
    fake = _LogParamsClient()
    client_mod._client = fake  # type: ignore[assignment]
    await mcp.call_tool(
        "portainer_container_logs",
        {"container_id": "abc", "since": "1700000000", "timestamps": True, "tail": 5},
    )
    assert fake.params == {
        "stdout": "true",
        "stderr": "true",
        "tail": "5",
        "timestamps": "true",
        "since": "1700000000",
    }
    # Defaults: no since / timestamps keys at all (Docker treats "" oddly).
    await mcp.call_tool("portainer_container_logs", {"container_id": "abc"})
    assert fake.params == {"stdout": "true", "stderr": "true", "tail": "100"}


async def test_logs_grep_since_forwarded_and_bad_since_rejected() -> None:
    mcp = FastMCP("t")
    containers.register(mcp)
    fake = _LogParamsClient()
    client_mod._client = fake  # type: ignore[assignment]
    await mcp.call_tool(
        "portainer_container_logs_grep", {"container_id": "abc", "pattern": "x", "since": "10m"}
    )
    assert fake.params is not None and "since" in fake.params
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_container_logs_grep",
                {"container_id": "abc", "pattern": "x", "since": "yesterday"},
            )
        )
    )
    assert body["error"] == "Validation error"
    assert "since" in body["details"]


# --- image_pull: registry_id -> Portainer-managed credentials ----------------------


async def test_image_pull_registry_id_builds_portainer_header() -> None:
    mcp = FastMCP("t")
    images.register(mcp)
    fake = _PullHeaderClient(b'{"status":"ok"}\n')
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_image_pull", {"image_name": "reg.local/app", "registry_id": 3}
            )
        )
    )
    assert body["status"] == "pulled"
    assert fake.headers is not None
    import base64

    assert json.loads(base64.b64decode(fake.headers["X-Registry-Auth"])) == {"registryId": 3}


async def test_image_pull_rejects_registry_id_with_registry_auth() -> None:
    mcp = FastMCP("t")
    images.register(mcp)
    fake = _PullHeaderClient(b"")
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_image_pull",
                {"image_name": "app", "registry_id": 3, "registry_auth": "e30="},
            )
        )
    )
    assert body["error"] == "Validation error"
    assert fake.headers is None


class _PullHeaderClient(_PullClient):
    def __init__(self, payload: bytes) -> None:
        super().__init__(payload)
        self.headers: dict[str, str] | None = None

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        self.headers = kwargs.get("headers")
        return await super().request(method, path, **kwargs)


async def test_registries_list_projects_safe_fields() -> None:
    mcp = FastMCP("t")
    images.register(mcp)
    client_mod._client = _GetClient(  # type: ignore[assignment]
        [
            {
                "Id": 3,
                "Name": "gitlab",
                "URL": "registry.example.com",
                "Type": 4,
                "Authentication": True,
                "Username": "bot",
                "Password": "registry-pass-canary",
            }
        ]
    )
    raw = _text(await mcp.call_tool("portainer_registries_list", {}))
    assert "registry-pass-canary" not in raw
    assert "bot" not in raw
    assert json.loads(raw) == [
        {
            "id": 3,
            "name": "gitlab",
            "url": "registry.example.com",
            "type": 4,
            "type_name": "gitlab",
            "authentication": True,
        }
    ]


# --- endpoint_inspect: DockerSnapshotRaw is dropped -------------------------------


async def test_endpoint_inspect_drops_raw_snapshot() -> None:
    mcp = FastMCP("t")
    endpoints.register(mcp)
    raw_ep = {
        **_RAW_ENDPOINT,
        "Snapshots": [
            {
                "Time": 1,
                "Swarm": True,
                "RunningContainerCount": 4,
                "DockerSnapshotRaw": {"Containers": ["raw-snapshot-canary"]},
            }
        ],
    }
    client_mod._client = _GetClient(raw_ep)  # type: ignore[assignment]
    raw = _text(await mcp.call_tool("portainer_endpoint_inspect", {"endpoint_id": 1}))
    assert "raw-snapshot-canary" not in raw
    body = json.loads(raw)
    assert body["Snapshots"] == [{"Time": 1, "Swarm": True, "RunningContainerCount": 4}]


# --- since parsing ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("since", "expected"),
    [
        ("1700000000", 1700000000),
        ("2026-09-07T10:00:00Z", 1788775200),
        ("2026-09-07T10:00:00.123456789Z", 1788775200),  # Docker's RFC3339Nano
        ("2026-09-07T10:00:00.5+02:00", 1788768000),  # 1-digit fraction: 3.10 needs 3 or 6
        ("2026-09-07T10:00:00.12+02:00", 1788768000),
        ("2026-09-07T10:00:00", 1788775200),  # naive -> UTC
    ],
)
def test_parse_since_formats(since: str, expected: int) -> None:
    assert containers._parse_since(since) == expected


def test_parse_since_relative_and_empty() -> None:
    import time

    now = int(time.time())
    assert containers._parse_since(None) is None
    assert containers._parse_since("  ") is None
    got = containers._parse_since("10m")
    assert got is not None and now - 600 - 2 <= got <= now - 600


@pytest.mark.parametrize("bad", ["20260907", "1", "x" * 65, "yesterday", "10x"])
def test_parse_since_rejects(bad: str) -> None:
    with pytest.raises(ValueError, match="since"):
        containers._parse_since(bad)


# --- docker_prune -----------------------------------------------------------------------


class _PruneClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any] | None, Any]] = []

    async def post(self, path: str, **kwargs: Any) -> Any:
        self.calls.append((path, kwargs.get("params"), kwargs.get("timeout")))
        return {
            "ImagesDeleted": [{"Deleted": "a"}, {"Untagged": "b"}],
            "SpaceReclaimed": 3 * 1_048_576,
        }


@pytest.mark.parametrize(
    ("args", "path", "params"),
    [
        ({"target": "images"}, "images/prune", {"filters": '{"dangling": ["true"]}'}),
        (
            {"target": "images", "all_images": True},
            "images/prune",
            {"filters": '{"dangling": ["false"]}'},
        ),
        ({"target": "containers"}, "containers/prune", {}),
        ({"target": "build_cache"}, "build/prune", {}),
    ],
)
async def test_docker_prune_targets(
    args: dict[str, Any], path: str, params: dict[str, Any]
) -> None:
    from portainer_mcp.tools import system

    mcp = FastMCP("t")
    system.register(mcp)
    fake = _PruneClient()
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(_text(await mcp.call_tool("portainer_docker_prune", args)))
    assert body["status"] == "pruned"
    assert body["space_reclaimed_mb"] == 3.0
    called_path, called_params, timeout = fake.calls[0]
    assert called_path.endswith(f"/docker/{path}")
    assert called_params == params
    assert timeout == 300.0  # long timeout


@pytest.mark.parametrize("target", ["volumes", "everything", ""])
async def test_docker_prune_rejects_volumes_and_unknown(target: str) -> None:
    from portainer_mcp.tools import system

    mcp = FastMCP("t")
    system.register(mcp)
    fake = _PruneClient()
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(_text(await mcp.call_tool("portainer_docker_prune", {"target": target})))
    assert body["error"] == "Validation error"
    assert fake.calls == []


# --- stack deploy/update: long timeout + git guard ------------------------------------------


async def test_stack_update_and_deploy_use_long_timeout() -> None:
    class _Client(_StackUpdateClient):
        def __init__(self) -> None:
            super().__init__()
            self.timeouts: list[Any] = []

        async def put(self, path: str, **kwargs: Any) -> Any:
            self.timeouts.append(kwargs.get("timeout"))
            return await super().put(path, **kwargs)

    mcp = FastMCP("t")
    stacks.register(mcp)
    fake = _Client()
    client_mod._client = fake  # type: ignore[assignment]
    await mcp.call_tool("portainer_stack_update", {"stack_id": 9})
    assert fake.timeouts == [300.0]

    class _Deploy(_DeployClient):
        async def post(self, path: str, **kwargs: Any) -> Any:
            self.timeout = kwargs.get("timeout")
            return await super().post(path, **kwargs)

    deploy = _Deploy(False)
    client_mod._client = deploy  # type: ignore[assignment]
    await mcp.call_tool(
        "portainer_stack_deploy", {"name": "demo", "compose_content": "services: {}"}
    )
    assert deploy.timeout == 300.0


async def test_stack_update_refuses_git_backed_stack_unless_detached() -> None:
    class _Git(_StackUpdateClient):
        async def get(self, path: str, **kwargs: Any) -> Any:
            data = await super().get(path, **kwargs)
            if path == "/api/stacks/9":
                data["GitConfig"] = {"URL": "https://git.example/repo", "ReferenceName": "main"}
            return data

    mcp = FastMCP("t")
    stacks.register(mcp)
    fake = _Git()
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(_text(await mcp.call_tool("portainer_stack_update", {"stack_id": 9})))
    assert body["error"] == "Validation error"
    assert "git-backed" in body["details"] and "detach_from_git" in body["details"]
    assert fake.put_body is None
    body = json.loads(
        _text(
            await mcp.call_tool("portainer_stack_update", {"stack_id": 9, "detach_from_git": True})
        )
    )
    assert body["status"] == "updated"
    assert fake.put_body is not None


# --- _cap_lines: a single oversized line is sliced, never dropped to nothing ---------------


def test_cap_lines_keeps_partial_first_line() -> None:
    huge = "x" * 5000
    kept, truncated = containers._cap_lines([huge, "second"], 1000)
    assert truncated is True
    assert len(kept) == 1
    assert kept[0].startswith("xxxx") and "line truncated: 5000 chars" in kept[0]
    assert len(kept[0]) <= 1000
    # Whole-line dropping still applies when the tail line is the one over budget.
    kept, truncated = containers._cap_lines(["a" * 10, "b" * 50], 30)
    assert kept == ["a" * 10] and truncated is True
    # Too little room for a meaningful slice -> drop it rather than emit a stub.
    kept, truncated = containers._cap_lines(["a" * 10, huge], 100)
    assert kept == ["a" * 10] and truncated is True
    assert containers._cap_lines(["a", "b"], 100) == (["a", "b"], False)


async def test_logs_grep_matches_only_first_8k_of_a_line() -> None:
    class _LongLine:
        async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
            return httpx.Response(200, content=b"x" * 9000 + b"NEEDLE\nNEEDLE early\n")

    mcp = FastMCP("t")
    containers.register(mcp)
    client_mod._client = _LongLine()  # type: ignore[assignment]
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_container_logs_grep", {"container_id": "abc", "pattern": "NEEDLE"}
            )
        )
    )
    assert body["matches_found"] == 1
    assert body["lines"] == ["NEEDLE early"]


# --- registry auto-match by image host -----------------------------------------------------


@pytest.mark.parametrize(
    ("image", "host"),
    [
        ("nginx", "docker.io"),
        ("library/nginx", "docker.io"),
        ("ginkida/app", "docker.io"),
        ("docker.io/library/nginx", "docker.io"),
        ("index.docker.io/ginkida/app", "docker.io"),
        ("reg.ginkida.dev/analytics/analytic", "reg.ginkida.dev"),
        ("REG.Example.COM:5000/app", "reg.example.com:5000"),
        ("localhost/app", "localhost"),
        ("ghcr.io/org/app:v1", "ghcr.io"),
    ],
)
def test_image_registry_host(image: str, host: str) -> None:
    assert images.image_registry_host(image) == host


class _RegistryPullClient(_PullHeaderClient):
    def __init__(self, registries: Any) -> None:
        super().__init__(b'{"status":"ok"}\n')
        self.registries = registries
        self.registry_calls = 0

    async def get(self, path: str, **kwargs: Any) -> Any:
        assert path == "/api/endpoints/1/registries"  # scoped route, not admin-only
        self.registry_calls += 1
        if isinstance(self.registries, Exception):
            raise self.registries
        return self.registries


_REGISTRIES = [
    {"Id": 7, "URL": "https://mirror.example.com/v2/", "Type": 3, "Authentication": True},
    {"Id": 3, "Name": "gitlab", "URL": "reg.ginkida.dev", "Type": 4, "Authentication": True},
    {"Id": 9, "URL": "reg.noauth.example", "Type": 3, "Authentication": False},
]


async def test_image_pull_auto_matches_portainer_registry() -> None:
    mcp = FastMCP("t")
    images.register(mcp)
    fake = _RegistryPullClient(_REGISTRIES)
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(
        _text(await mcp.call_tool("portainer_image_pull", {"image_name": "reg.ginkida.dev/x/app"}))
    )
    assert body["registry_id"] == 3
    assert body["credentials"] == "portainer (auto)"
    import base64

    assert fake.headers is not None
    assert json.loads(base64.b64decode(fake.headers["X-Registry-Auth"])) == {"registryId": 3}
    # Scheme and path in Portainer's URL are ignored when matching.
    body = json.loads(
        _text(await mcp.call_tool("portainer_image_pull", {"image_name": "mirror.example.com/app"}))
    )
    assert body["registry_id"] == 7


async def test_image_pull_docker_hub_matches_only_hub_type_registry() -> None:
    mcp = FastMCP("t")
    images.register(mcp)
    fake = _RegistryPullClient(_REGISTRIES)  # no DockerHub-type registry configured
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(_text(await mcp.call_tool("portainer_image_pull", {"image_name": "x/app"})))
    assert body["registry_id"] is None and body["credentials"] == "none"
    assert fake.headers == {}
    # A DockerHub-type registry (Type 6, URL docker.io) matches a namespaced Hub repo…
    hub = _RegistryPullClient(
        [*_REGISTRIES, {"Id": 11, "URL": "docker.io", "Type": 6, "Authentication": True}]
    )
    client_mod._client = hub  # type: ignore[assignment]
    body = json.loads(
        _text(await mcp.call_tool("portainer_image_pull", {"image_name": "ginkida/private"}))
    )
    assert body["registry_id"] == 11 and body["credentials"] == "portainer (auto)"
    # …but never an official image: those are public and a stale token would break them.
    for name in ("nginx", "library/nginx", "docker.io/library/nginx"):
        body = json.loads(_text(await mcp.call_tool("portainer_image_pull", {"image_name": name})))
        assert body["registry_id"] is None, name
        assert body["credentials"] == "none (official Docker Hub image)", name
        assert hub.headers == {}
    assert hub.registry_calls == 1  # official images never list registries


async def test_image_pull_skips_unauthenticated_and_odd_listings() -> None:
    mcp = FastMCP("t")
    images.register(mcp)
    fake = _RegistryPullClient(_REGISTRIES)
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(
        _text(await mcp.call_tool("portainer_image_pull", {"image_name": "reg.noauth.example/x"}))
    )
    assert body["registry_id"] is None and body["credentials"] == "none"
    odd = _RegistryPullClient(True)  # a 200 whose JSON is a scalar
    client_mod._client = odd  # type: ignore[assignment]
    body = json.loads(
        _text(await mcp.call_tool("portainer_image_pull", {"image_name": "reg.ginkida.dev/x"}))
    )
    assert body["status"] == "pulled"
    assert body["credentials"] == "none (unexpected registry listing)"


@pytest.mark.parametrize(
    ("image", "host"),
    [
        ("Registry/app", "registry"),  # uppercase first component = host (Docker rule)
        ("reg.local:443/app", "reg.local"),
        ("reg.local:80/app", "reg.local"),
        ("reg.local:5000/app", "reg.local:5000"),
    ],
)
def test_image_registry_host_edge_cases(image: str, host: str) -> None:
    assert images.image_registry_host(image) == host


@pytest.mark.parametrize("name", ["ghcr.io/org/app:v2", "nginx:1.25", "app@sha256:" + "a" * 64])
async def test_image_pull_rejects_tag_inside_image_name(name: str) -> None:
    """Docker's `tag` query param would silently replace the embedded tag."""
    mcp = FastMCP("t")
    images.register(mcp)
    fake = _RegistryPullClient(_REGISTRIES)
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(_text(await mcp.call_tool("portainer_image_pull", {"image_name": name})))
    assert body["error"] == "Validation error"
    assert "already carries a tag" in body["details"]
    assert fake.headers is None


async def test_image_pull_ambiguous_registries_fall_back_to_anonymous() -> None:
    """Two registries on one host: guessing would fail a private pull while
    looking authorised, raising would break public pulls — so pull
    anonymously and say why."""
    mcp = FastMCP("t")
    images.register(mcp)
    two = _RegistryPullClient(
        [
            {"Id": 3, "URL": "registry.gitlab.com", "Type": 4, "Authentication": True},
            {"Id": 5, "URL": "https://registry.gitlab.com/", "Type": 4, "Authentication": True},
        ]
    )
    client_mod._client = two  # type: ignore[assignment]
    body = json.loads(
        _text(
            await mcp.call_tool("portainer_image_pull", {"image_name": "registry.gitlab.com/g/app"})
        )
    )
    assert body["status"] == "pulled" and body["registry_id"] is None
    assert body["credentials"].startswith("none (ambiguous: registries [3, 5]")
    assert two.headers == {}
    # registry_id=0 is the explicit anonymous switch, an explicit id resolves it.
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_image_pull",
                {"image_name": "registry.gitlab.com/g/app", "registry_id": 0},
            )
        )
    )
    assert body["credentials"] == "anonymous (forced)" and two.headers == {}
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_image_pull",
                {"image_name": "registry.gitlab.com/g/app", "registry_id": 5},
            )
        )
    )
    assert body["registry_id"] == 5 and body["credentials"] == "portainer"


async def test_image_pull_failure_reports_credential_context() -> None:
    mcp = FastMCP("t")
    images.register(mcp)
    fake = _RegistryPullClient([{"Id": 5, "URL": "docker.io", "Type": 6, "Authentication": True}])
    fake.payload = b'{"errorDetail":{"message":"unauthorized: incorrect username or password"}}\n'
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(
        _text(await mcp.call_tool("portainer_image_pull", {"image_name": "ginkida/private"}))
    )
    assert body["error"] == "Image pull failed"
    assert "unauthorized" in body["details"]
    assert "registry_id=5" in body["details"] and "credentials=portainer (auto)" in body["details"]
    assert "registry_id=0" in body["details"]


@pytest.mark.parametrize("tag", ["5000/app", "v1@sha256:abc", "", " latest", ".hidden"])
async def test_image_pull_validates_tag_separately(tag: str) -> None:
    mcp = FastMCP("t")
    images.register(mcp)
    fake = _RegistryPullClient([])
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(
        _text(await mcp.call_tool("portainer_image_pull", {"image_name": "reg.local", "tag": tag}))
    )
    assert body["error"] == "Validation error"
    assert "tag" in body["details"]
    assert fake.headers is None  # nothing was sent


def test_image_registry_host_drops_default_ports() -> None:
    assert images.image_registry_host("reg.local:443/app") == "reg.local"
    assert images.image_registry_host("reg.local:80/app") == "reg.local"
    assert images.image_registry_host("reg.local:5000/app") == "reg.local:5000"


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("reg.example.com", "reg.example.com"),
        ("https://reg.example.com:443", "reg.example.com"),
        ("http://reg.example.com:80/", "reg.example.com"),
        ("https://user:pw@reg.local/v2/", "reg.local"),
        ("REG.Local:5000", "reg.local:5000"),
        ("https://reg.local:5000/v2/", "reg.local:5000"),
        ("", ""),
        (None, ""),
        ("https://reg.local:notaport/", "reg.local"),
    ],
)
def test_registry_host_normalisation(url: Any, host: str) -> None:
    assert images._registry_host(url) == host


@pytest.mark.parametrize(
    "ref",
    ["reg.local:5000/app", "reg.local:5000/org/app:v1", "localhost:5000/app@sha256:" + "a" * 64],
)
def test_image_ref_accepts_registry_port(ref: str) -> None:
    images._validate_image_ref(ref)


async def test_image_pull_explicit_registry_id_and_failed_lookup() -> None:
    mcp = FastMCP("t")
    images.register(mcp)
    fake = _RegistryPullClient(_REGISTRIES)
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(
        _text(
            await mcp.call_tool(
                "portainer_image_pull", {"image_name": "reg.ginkida.dev/x/app", "registry_id": 9}
            )
        )
    )
    assert body["registry_id"] == 9 and body["credentials"] == "portainer"
    assert fake.registry_calls == 0  # explicit id: no lookup
    # A failing registry listing degrades to an anonymous pull, not an error.
    broken = _RegistryPullClient(httpx.ConnectError("boom"))
    client_mod._client = broken  # type: ignore[assignment]
    body = json.loads(
        _text(await mcp.call_tool("portainer_image_pull", {"image_name": "reg.ginkida.dev/x/app"}))
    )
    assert body["status"] == "pulled" and body["registry_id"] is None
    assert body["credentials"] == "none (registry listing failed)"
    assert broken.headers == {}
