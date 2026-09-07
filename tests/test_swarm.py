from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest
from mcp.server.fastmcp import FastMCP

import portainer_mcp.client as client_mod
from portainer_mcp.tools import swarm


def _text(result: Any) -> str:
    content = result[0] if isinstance(result, tuple) else result
    return content[0].text  # type: ignore[no-any-return]


def _frame(payload: bytes, stream_type: int = 1) -> bytes:
    header = bytes([stream_type, 0, 0, 0]) + len(payload).to_bytes(4, "big")
    return header + payload


def _service(
    sid: str,
    name: str,
    *,
    stack: str | None = "etl",
    replicas: int | None = 2,
    image: str = "reg.local/app:latest@sha256:" + "a" * 64,
    env: list[str] | None = None,
    version: int = 10,
    force_update: int = 0,
    update_state: str | None = None,
) -> dict[str, Any]:
    mode: dict[str, Any] = (
        {"Replicated": {"Replicas": replicas}} if replicas is not None else {"Global": {}}
    )
    labels = {"com.docker.stack.namespace": stack} if stack else {}
    svc: dict[str, Any] = {
        "ID": sid,
        "Version": {"Index": version},
        "CreatedAt": "2026-01-01T00:00:00Z",
        "UpdatedAt": "2026-01-02T00:00:00Z",
        "Spec": {
            "Name": name,
            "Labels": labels,
            "TaskTemplate": {
                "ContainerSpec": {"Image": image, "Env": env or []},
                "ForceUpdate": force_update,
            },
            "Mode": mode,
        },
        "Endpoint": {"Ports": [{"PublishedPort": 8080, "TargetPort": 80, "Protocol": "tcp"}]},
    }
    if update_state:
        svc["UpdateStatus"] = {"State": update_state, "Message": "update paused"}
    return svc


def _task(
    tid: str,
    sid: str,
    *,
    slot: int = 1,
    state: str = "running",
    desired: str = "running",
    ts: str = "2026-01-02T00:00:00Z",
    err: str | None = None,
    node: str = "node-1-id",
) -> dict[str, Any]:
    status: dict[str, Any] = {
        "State": state,
        "Timestamp": ts,
        "Message": "started",
        "ContainerStatus": {"ContainerID": "c" * 64, "ExitCode": 0},
    }
    if err:
        status["Err"] = err
    return {
        "ID": tid,
        "ServiceID": sid,
        "Slot": slot,
        "NodeID": node,
        "DesiredState": desired,
        "Status": status,
        "Spec": {"ContainerSpec": {"Image": "reg.local/app:latest@sha256:" + "a" * 64}},
    }


_NODES = [
    {
        "ID": "node-1-id",
        "Spec": {"Role": "manager", "Availability": "active", "Labels": {"zone": "a"}},
        "Description": {
            "Hostname": "swarm-1",
            "Engine": {"EngineVersion": "27.0"},
            "Resources": {"NanoCPUs": 4_000_000_000, "MemoryBytes": 8 * 1_073_741_824},
        },
        "Status": {"State": "ready", "Addr": "10.0.0.1"},
        "ManagerStatus": {"Leader": True, "Reachability": "reachable"},
    },
    {
        "ID": "node-2-id",
        "Spec": {"Role": "worker", "Availability": "drain"},
        "Description": {"Hostname": "swarm-2"},
        "Status": {"State": "ready", "Addr": "10.0.0.2"},
    },
]


class _SwarmClient:
    """Fake client for the Docker proxy paths the swarm tools call."""

    def __init__(
        self,
        services: list[dict[str, Any]] | None = None,
        tasks: list[dict[str, Any]] | None = None,
        *,
        not_swarm: bool = False,
        containers: list[dict[str, Any]] | None = None,
    ) -> None:
        self.services = services or []
        self.tasks = tasks or []
        self.not_swarm = not_swarm
        self.containers = containers or []
        self.gets: list[tuple[str, dict[str, Any] | None]] = []
        self.update: dict[str, Any] | None = None
        self.log_params: dict[str, Any] | None = None

    def _fail_not_swarm(self) -> None:
        req = httpx.Request("GET", "https://x")
        raise httpx.HTTPStatusError(
            "not a manager",
            request=req,
            response=httpx.Response(503, text="This node is not a swarm manager", request=req),
        )

    async def get(self, path: str, **kwargs: Any) -> Any:
        params = kwargs.get("params")
        self.gets.append((path, params))
        if path.endswith("/docker/services"):
            if self.not_swarm:
                self._fail_not_swarm()
            filters = json.loads(params["filters"]) if params and "filters" in params else {}
            wanted = filters.get("label", [])
            if not wanted:
                return list(self.services)
            stack = wanted[0].split("=", 1)[1]
            return [
                s
                for s in self.services
                if s["Spec"]["Labels"].get("com.docker.stack.namespace") == stack
            ]
        if "/docker/services/" in path:
            sid = path.rsplit("/", 1)[1]
            for s in self.services:
                if s["ID"] == sid or s["Spec"]["Name"] == sid:
                    return json.loads(json.dumps(s))  # fresh copy each time
            raise AssertionError(f"unknown service {sid}")
        if path.endswith("/docker/tasks"):
            assert params is not None
            ids = json.loads(params["filters"])["service"]
            return [
                t
                for t in self.tasks
                if t["ServiceID"] in ids
                or any(
                    s["Spec"]["Name"] in ids and s["ID"] == t["ServiceID"] for s in self.services
                )
            ]
        if path.endswith("/docker/nodes"):
            return _NODES
        if path.endswith("/docker/containers/json"):
            return self.containers
        raise AssertionError(path)

    async def post(self, path: str, **kwargs: Any) -> Any:
        assert path.endswith("/update")
        self.update = {
            "path": path,
            "params": kwargs.get("params"),
            "json": kwargs.get("json"),
            "headers": kwargs.get("headers"),
        }
        return {"Warnings": ["image resolved"]}

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        assert path.endswith("/logs")
        self.log_params = kwargs.get("params")
        return httpx.Response(200, content=_frame(b"svc line\n"))


def _mcp(fake: _SwarmClient) -> FastMCP:
    mcp = FastMCP("t")
    swarm.register(mcp)
    client_mod._client = fake  # type: ignore[assignment]
    return mcp


# --- services_list ----------------------------------------------------------------


async def test_services_list_counts_running_vs_desired() -> None:
    svc_a = _service("svc-a-id", "etl_backend", replicas=3)
    svc_b = _service("svc-b-id", "etl_worker", replicas=1, update_state="paused")
    tasks = [
        _task("t1", "svc-a-id", slot=1),
        _task("t2", "svc-a-id", slot=2),
        _task("t3", "svc-a-id", slot=3, state="failed", err="task: non-zero exit (1)"),
        _task("t4", "svc-a-id", slot=3, state="shutdown", desired="shutdown"),
        _task("t5", "svc-b-id", slot=1, state="starting"),
    ]
    fake = _SwarmClient([svc_b, svc_a], tasks)
    body = json.loads(_text(await _mcp(fake).call_tool("portainer_services_list", {})))
    assert [s["name"] for s in body] == ["etl_backend", "etl_worker"]  # sorted by name
    backend, worker = body
    assert backend["replicas_running"] == 2
    assert backend["replicas_desired"] == 3
    assert backend["mode"] == "replicated"
    assert backend["image"] == "reg.local/app:latest"
    assert backend["image_digest"] == "sha256:" + "a" * 64
    assert backend["stack"] == "etl"
    assert backend["ports"] == [{"published": 8080, "target": 80, "protocol": "tcp", "mode": None}]
    assert worker["replicas_running"] == 0
    assert worker["update_status"] == "paused"
    # No global service -> the node list is never fetched.
    assert not any(p.endswith("/docker/nodes") for p, _ in fake.gets)


async def test_services_list_global_desired_is_active_ready_nodes() -> None:
    svc = _service("svc-g", "etl_agent", replicas=None)
    fake = _SwarmClient([svc], [_task("t1", "svc-g")])
    body = json.loads(_text(await _mcp(fake).call_tool("portainer_services_list", {})))
    assert body[0]["mode"] == "global"
    # node-2 is drained, so only node-1 counts.
    assert body[0]["replicas_desired"] == 1
    assert body[0]["replicas_running"] == 1


async def test_services_list_stack_filter_uses_label_filter() -> None:
    fake = _SwarmClient([_service("a", "etl_x"), _service("b", "blog_y", stack="blog")])
    body = json.loads(
        _text(await _mcp(fake).call_tool("portainer_services_list", {"stack_filter": "blog"}))
    )
    assert [s["name"] for s in body] == ["blog_y"]
    path, params = fake.gets[0]
    assert params is not None
    assert json.loads(params["filters"]) == {"label": ["com.docker.stack.namespace=blog"]}
    bad = json.loads(
        _text(await _mcp(fake).call_tool("portainer_services_list", {"stack_filter": "a.b"}))
    )
    assert bad["error"] == "Validation error"


# --- service_inspect ----------------------------------------------------------------


async def test_service_inspect_redacts_env_unless_revealed() -> None:
    svc = _service("svc-a-id", "etl_backend", env=["DB_PASSWORD=db-canary", "DB_HOST=db", "PLAIN"])
    svc["PreviousSpec"] = json.loads(json.dumps(svc["Spec"]))
    fake = _SwarmClient([svc])
    raw = _text(
        await _mcp(fake).call_tool("portainer_service_inspect", {"service_id": "etl_backend"})
    )
    assert "db-canary" not in raw
    body = json.loads(raw)
    assert body["env_redacted"] is True
    env = body["Spec"]["TaskTemplate"]["ContainerSpec"]["Env"]
    assert env == ["DB_PASSWORD=[REDACTED]", "DB_HOST=db", "PLAIN"]
    assert (
        body["PreviousSpec"]["TaskTemplate"]["ContainerSpec"]["Env"][0] == "DB_PASSWORD=[REDACTED]"
    )

    raw = _text(
        await _mcp(fake).call_tool(
            "portainer_service_inspect", {"service_id": "etl_backend", "reveal_env": True}
        )
    )
    assert "db-canary" in raw
    assert "env_redacted" not in json.loads(raw)


# --- service_tasks --------------------------------------------------------------------


async def test_service_tasks_orders_by_slot_then_newest_and_maps_nodes() -> None:
    tasks = [
        _task(
            "old2",
            "svc-a-id",
            slot=2,
            state="shutdown",
            desired="shutdown",
            ts="2026-01-01T00:00:00Z",
            node="node-2-id",
        ),
        _task("new1", "svc-a-id", slot=1, ts="2026-01-03T00:00:00Z"),
        _task(
            "old1",
            "svc-a-id",
            slot=1,
            state="failed",
            err="no suitable node",
            ts="2026-01-01T00:00:00Z",
        ),
        _task("new2", "svc-a-id", slot=2, ts="2026-01-03T00:00:00Z"),
        _task("other", "svc-b-id"),
    ]
    fake = _SwarmClient([_service("svc-a-id", "etl_backend")], tasks)
    body = json.loads(
        _text(await _mcp(fake).call_tool("portainer_service_tasks", {"service_id": "svc-a-id"}))
    )
    assert body["tasks_total"] == 4
    assert body["tasks_by_state"] == {"running": 2, "failed": 1, "shutdown": 1}
    assert body["truncated"] is False
    assert [t["id"] for t in body["tasks"]] == ["new1", "old1", "new2", "old2"]
    failed = body["tasks"][1]
    assert failed["error"] == "no suitable node"
    assert failed["node"] == "swarm-1"
    assert failed["container_id"] == "c" * 12
    assert body["tasks"][3]["node"] == "swarm-2"


async def test_service_tasks_limit_is_clamped_and_reported() -> None:
    tasks = [_task(f"t{i}", "svc-a-id", slot=i) for i in range(1, 8)]
    fake = _SwarmClient([_service("svc-a-id", "etl_backend")], tasks)
    body = json.loads(
        _text(
            await _mcp(fake).call_tool(
                "portainer_service_tasks", {"service_id": "svc-a-id", "limit": 3}
            )
        )
    )
    assert len(body["tasks"]) == 3
    assert body["truncated"] is True
    body = json.loads(
        _text(
            await _mcp(fake).call_tool(
                "portainer_service_tasks", {"service_id": "svc-a-id", "limit": 0}
            )
        )
    )
    assert len(body["tasks"]) == 1  # clamped up to 1, not rejected


# --- service_logs ----------------------------------------------------------------------


async def test_service_logs_envelope_and_params() -> None:
    fake = _SwarmClient()
    body = json.loads(
        _text(
            await _mcp(fake).call_tool(
                "portainer_service_logs",
                {"service_id": "etl_backend", "tail": 5000, "since": "2h", "timestamps": True},
            )
        )
    )
    assert body["service"] == "etl_backend"
    assert body["logs"] == "svc line\n"
    assert body["truncated"] is False
    assert body["tail"] == 1000  # clamped
    assert fake.log_params is not None
    assert fake.log_params["tail"] == "1000"
    assert fake.log_params["timestamps"] == "true"
    assert fake.log_params["since"].isdigit()


# --- service_update -------------------------------------------------------------------


async def test_service_update_image_replicas_force_and_registry() -> None:
    svc = _service("svc-a-id", "etl_backend", replicas=2, version=42, force_update=3)
    fake = _SwarmClient([svc])
    body = json.loads(
        _text(
            await _mcp(fake).call_tool(
                "portainer_service_update",
                {
                    "service_id": "etl_backend",
                    "image": "reg.local/app:latest",
                    "replicas": 4,
                    "force_restart": True,
                    "registry_id": 3,
                },
            )
        )
    )
    assert body["status"] == "updated"
    assert body["previous_version"] == 42
    assert body["warnings"] == ["image resolved"]
    assert body["changes"]["image"]["to"] == "reg.local/app:latest"
    assert body["changes"]["replicas"] == {"from": 2, "to": 4}
    assert body["changes"]["force_update"] == 4
    assert fake.update is not None
    assert fake.update["path"].endswith("/docker/services/etl_backend/update")
    assert fake.update["params"] == {"version": "42"}
    spec = fake.update["json"]
    assert spec["TaskTemplate"]["ContainerSpec"]["Image"] == "reg.local/app:latest"
    assert spec["TaskTemplate"]["ForceUpdate"] == 4
    assert spec["Mode"]["Replicated"]["Replicas"] == 4
    assert spec["Name"] == "etl_backend"  # the rest of the spec is submitted unchanged
    header = fake.update["headers"]["X-Registry-Auth"]
    assert json.loads(base64.b64decode(header)) == {"registryId": 3}


async def test_service_update_force_only_keeps_pinned_digest() -> None:
    pinned = "reg.local/app:latest@sha256:" + "b" * 64
    fake = _SwarmClient([_service("svc-a-id", "etl_backend", image=pinned)])
    await _mcp(fake).call_tool(
        "portainer_service_update", {"service_id": "svc-a-id", "force_restart": True}
    )
    assert fake.update is not None
    assert fake.update["json"]["TaskTemplate"]["ContainerSpec"]["Image"] == pinned
    assert fake.update["json"]["TaskTemplate"]["ForceUpdate"] == 1
    assert fake.update["headers"] == {}


@pytest.mark.parametrize(
    ("args", "needle"),
    [
        ({}, "Nothing to do"),
        ({"replicas": -1}, "replicas"),
        ({"image": "../evil"}, "image reference"),
        ({"force_restart": True, "registry_id": 0}, "registry_id"),
    ],
)
async def test_service_update_validation(args: dict[str, Any], needle: str) -> None:
    fake = _SwarmClient([_service("svc-a-id", "etl_backend")])
    body = json.loads(
        _text(
            await _mcp(fake).call_tool(
                "portainer_service_update", {"service_id": "svc-a-id", **args}
            )
        )
    )
    assert body["error"] == "Validation error"
    assert needle in body["details"]
    assert fake.update is None


async def test_service_update_rejects_scaling_global_service() -> None:
    fake = _SwarmClient([_service("svc-g", "etl_agent", replicas=None)])
    body = json.loads(
        _text(
            await _mcp(fake).call_tool(
                "portainer_service_update", {"service_id": "svc-g", "replicas": 2}
            )
        )
    )
    assert body["error"] == "Validation error"
    assert "global" in body["details"]
    assert fake.update is None


# --- nodes_list -----------------------------------------------------------------------


async def test_nodes_list_projection() -> None:
    fake = _SwarmClient()
    body = json.loads(_text(await _mcp(fake).call_tool("portainer_nodes_list", {})))
    assert body[0] == {
        "id": "node-1-id",
        "hostname": "swarm-1",
        "role": "manager",
        "availability": "active",
        "state": "ready",
        "status_message": None,
        "addr": "10.0.0.1",
        "manager_leader": True,
        "manager_reachability": "reachable",
        "engine_version": "27.0",
        "cpus": 4.0,
        "memory_gb": 8.0,
        "labels": {"zone": "a"},
    }
    assert body[1]["role"] == "worker"
    assert body[1]["manager_leader"] is False
    assert body[1]["cpus"] == 0.0


# --- stack_status ---------------------------------------------------------------------


async def test_stack_status_swarm_summary() -> None:
    services = [
        _service("svc-a-id", "etl_backend", replicas=2),
        _service("svc-b-id", "etl_worker", replicas=1, update_state="paused"),
        _service("svc-x", "blog_web", stack="blog"),
    ]
    tasks = [
        _task("t1", "svc-a-id", slot=1),
        _task("t2", "svc-a-id", slot=2),
        _task(
            "t3",
            "svc-b-id",
            slot=1,
            state="rejected",
            err="No such image: reg.local/app",
            ts="2026-01-05T00:00:00Z",
        ),
        _task(
            "t4",
            "svc-b-id",
            slot=1,
            state="failed",
            err="task: non-zero exit (137)",
            ts="2026-01-04T00:00:00Z",
        ),
        _task("t5", "svc-b-id", slot=1),
    ]
    fake = _SwarmClient(services, tasks)
    body = json.loads(
        _text(await _mcp(fake).call_tool("portainer_stack_status", {"stack_name": "etl"}))
    )
    assert body["mode"] == "swarm"
    assert body["services_total"] == 2
    assert body["services_healthy"] == 1
    assert body["healthy"] is False
    backend, worker = body["services"]
    assert backend["name"] == "etl_backend"
    assert backend["healthy"] is True
    assert backend["recent_task_errors"] == []
    assert worker["healthy"] is False  # update paused, even though 1/1 runs
    assert [e["error"] for e in worker["recent_task_errors"]] == [
        "No such image: reg.local/app",
        "task: non-zero exit (137)",
    ]
    assert worker["recent_task_errors"][0]["node"] == "swarm-1"


async def test_stack_status_swarm_no_services_and_no_containers() -> None:
    fake = _SwarmClient([_service("svc-x", "blog_web", stack="blog")])
    body = json.loads(
        _text(await _mcp(fake).call_tool("portainer_stack_status", {"stack_name": "etl"}))
    )
    assert body["mode"] == "compose"
    assert body["services"] == []
    assert body["healthy"] is False
    assert "No Swarm services and no containers" in body["message"]


async def test_stack_status_falls_back_to_compose_on_non_swarm() -> None:
    containers = [
        {
            "Id": "a" * 64,
            "Names": ["/blog-web-1"],
            "Image": "nginx",
            "State": "running",
            "Status": "Up",
            "Labels": {
                "com.docker.compose.project": "blog",
                "com.docker.compose.service": "web",
            },
        },
        {
            "Id": "b" * 64,
            "Names": ["/blog-db-1"],
            "Image": "pg",
            "State": "exited",
            "Status": "Exited (1)",
            "Labels": {
                "com.docker.compose.project": "blog",
                "com.docker.compose.service": "db",
            },
        },
        {"Id": "c" * 64, "Names": ["/other"], "State": "running", "Labels": {}},
    ]
    fake = _SwarmClient(not_swarm=True, containers=containers)
    body = json.loads(
        _text(await _mcp(fake).call_tool("portainer_stack_status", {"stack_name": "blog"}))
    )
    assert body["mode"] == "compose"
    assert body["services_total"] == 2
    assert body["services_healthy"] == 1
    assert body["healthy"] is False
    db, web = body["services"]
    assert db["name"] == "db" and db["healthy"] is False
    assert db["containers"] == [
        {"id": "b" * 12, "name": "blog-db-1", "state": "exited", "status": "Exited (1)"}
    ]
    assert web["containers_running"] == 1


async def test_stack_status_non_503_error_propagates() -> None:
    class _Broken(_SwarmClient):
        async def get(self, path: str, **kwargs: Any) -> Any:
            req = httpx.Request("GET", "https://x")
            raise httpx.HTTPStatusError(
                "denied", request=req, response=httpx.Response(403, request=req)
            )

    body = json.loads(
        _text(await _mcp(_Broken()).call_tool("portainer_stack_status", {"stack_name": "etl"}))
    )
    assert body["error"] == "Portainer API error (403)"


@pytest.mark.parametrize("tool", ["portainer_service_inspect", "portainer_service_logs"])
async def test_service_id_validation(tool: str) -> None:
    fake = _SwarmClient()
    body = json.loads(_text(await _mcp(fake).call_tool(tool, {"service_id": "bad id!"})))
    assert body["error"] == "Validation error"
    assert "service_id" in body["details"]


async def test_stack_status_compose_project_on_swarm_manager() -> None:
    """`docker compose up` on a manager: no Swarm services, but containers
    with Compose labels — report them instead of "nothing found"."""
    containers = [
        {
            "Id": "a" * 64, "Names": ["/mon-grafana-1"], "Image": "grafana", "State": "running",
            "Status": "Up", "Labels": {
                "com.docker.compose.project": "mon", "com.docker.compose.service": "grafana",
            },
        },
        {
            "Id": "b" * 64, "Names": ["/mon-init-1"], "Image": "busybox", "State": "exited",
            "Status": "Exited (0) 2 hours ago", "Labels": {
                "com.docker.compose.project": "mon", "com.docker.compose.service": "init",
            },
        },
    ]
    fake = _SwarmClient([], containers=containers)
    body = json.loads(
        _text(await _mcp(fake).call_tool("portainer_stack_status", {"stack_name": "mon"}))
    )
    assert body["mode"] == "compose"
    assert body["healthy"] is True  # a one-shot container that exited 0 is fine
    assert [s["name"] for s in body["services"]] == ["grafana", "init"]


async def test_stack_status_503_without_not_swarm_marker_propagates() -> None:
    class _NoLeader(_SwarmClient):
        def _fail_not_swarm(self) -> None:
            req = httpx.Request("GET", "https://x")
            raise httpx.HTTPStatusError(
                "no leader",
                request=req,
                response=httpx.Response(
                    503, text="rpc error: The swarm does not have a leader", request=req
                ),
            )

    fake = _NoLeader(not_swarm=True, containers=[{"Id": "a" * 64, "State": "running"}])
    body = json.loads(
        _text(await _mcp(fake).call_tool("portainer_stack_status", {"stack_name": "etl"}))
    )
    assert body["error"] == "Portainer API error (503)"


async def test_stack_status_completed_job_is_healthy() -> None:
    job = _service("job-id", "etl_migrate", replicas=2)
    job["Spec"]["Mode"] = {"ReplicatedJob": {"TotalCompletions": 1, "MaxConcurrent": 1}}
    tasks = [
        _task("t1", "svc-a-id", slot=1),
        _task("t2", "svc-a-id", slot=2),
        _task("j1", "job-id", slot=1, state="complete", desired="shutdown"),
    ]
    fake = _SwarmClient([_service("svc-a-id", "etl_backend"), job], tasks)
    body = json.loads(
        _text(await _mcp(fake).call_tool("portainer_stack_status", {"stack_name": "etl"}))
    )
    assert body["healthy"] is True
    migrate = next(s for s in body["services"] if s["name"] == "etl_migrate")
    assert migrate["mode"] == "replicated-job"
    assert migrate["tasks_completed"] == 1
    assert migrate["replicas_desired"] == 1
    assert migrate["healthy"] is True
    listing = json.loads(_text(await _mcp(fake).call_tool("portainer_services_list", {})))
    assert next(s for s in listing if s["name"] == "etl_migrate")["tasks_completed"] == 1


def test_ts_key_normalises_trimmed_fractions() -> None:
    tasks = [
        _task("a", "s", ts="2026-09-07T10:00:00Z"),
        _task("b", "s", ts="2026-09-07T10:00:00.5Z"),
        _task("c", "s", ts="2026-09-07T10:00:00.51Z"),
        _task("d", "s", ts="2026-09-07T09:59:59.999999999Z"),
    ]
    ordered = swarm._sort_tasks(tasks)
    assert [t["ID"] for t in ordered] == ["c", "b", "a", "d"]


async def test_tasks_are_fetched_in_chunks() -> None:
    services = [_service(f"svc-{i:03d}", f"etl_s{i:03d}") for i in range(95)]
    fake = _SwarmClient(services, [])
    await _mcp(fake).call_tool("portainer_services_list", {})
    sizes = [
        len(json.loads(params["filters"])["service"])
        for p, params in fake.gets
        if p.endswith("/docker/tasks") and params
    ]
    assert sizes == [40, 40, 15]


async def test_service_inspect_and_nodes_reject_empty_body() -> None:
    class _Empty(_SwarmClient):
        async def get(self, path: str, **kwargs: Any) -> Any:
            return None

    body = json.loads(
        _text(await _mcp(_Empty()).call_tool("portainer_service_inspect", {"service_id": "x"}))
    )
    assert body["error"] == "Validation error"
    assert "no data" in body["details"]
    body = json.loads(_text(await _mcp(_Empty()).call_tool("portainer_nodes_list", {})))
    assert body["error"] == "Validation error"
