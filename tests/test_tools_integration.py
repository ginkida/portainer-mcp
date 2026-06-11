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
    containers.register(mcp)
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
    containers.register(mcp)
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
    containers.register(mcp)
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
    containers.register(mcp)
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
    assert body == {"status": "pulled", "image": "nginx:1.25"}
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


class _StackUpdateClient:
    def __init__(self) -> None:
        self.put_params: dict[str, Any] | None = None

    async def get(self, path: str, **kwargs: Any) -> Any:
        if path == "/api/stacks/9":
            return {"Id": 9, "EndpointId": 5}
        if path == "/api/stacks/9/file":
            return {"StackFileContent": "services: {}"}
        raise AssertionError(path)

    async def put(self, path: str, **kwargs: Any) -> Any:
        assert path == "/api/stacks/9"
        self.put_params = kwargs.get("params")
        return None


async def test_stack_update_derives_endpoint_from_stack() -> None:
    """Without endpoint_id the update must target the stack's own endpoint,
    not the configured default (which is 1)."""
    mcp = FastMCP("t")
    stacks.register(mcp)
    fake = _StackUpdateClient()
    client_mod._client = fake  # type: ignore[assignment]
    body = json.loads(_text(await mcp.call_tool("portainer_stack_update", {"stack_id": 9})))
    assert body == {"status": "updated", "stack_id": 9}
    assert fake.put_params == {"endpointId": 5}


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
