from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from ..client import PortainerClient, get_client
from ..config import get_config
from ..errors import redact_env_strings, resolve_endpoint, tool_error_handler, validate_id
from .containers import (
    _MAX_LOG_CHARS,
    _STACK_NAME_RE,
    _container_labels,
    _log_params,
    _parse_docker_stream,
)
from .images import _validate_image_ref, portainer_registry_auth_header

logger = logging.getLogger(__name__)

# Swarm service / node identifiers: a 25-char ID or a service name
# (`stack_service`). Same alphabet as container ids.
_SERVICE_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$")
_STACK_NAMESPACE_LABEL = "com.docker.stack.namespace"
# Bounds for the task listings: `docker service ps` history is 5 tasks per
# slot by default, but a long-lived busy stack can still accumulate thousands.
_MAX_TASKS = 500
_DEFAULT_TASKS = 50
_RECENT_TASK_ERRORS = 5
# Task states that mean "this task instance is dead and Swarm knows why".
_TASK_FAILURE_STATES = frozenset({"failed", "rejected", "orphaned"})
# Service IDs per /tasks request: 40 x 25-char ids keep the query string
# around 1 KB, well under the 8 KB request-line limit of common proxies.
_TASK_FILTER_CHUNK = 40
# Docker's 503 body when the endpoint is not a Swarm manager (standalone
# host, or a worker). A 503 with any other body (e.g. "does not have a
# leader") is a real outage and must propagate.
_NOT_SWARM_MARKER = "not a swarm manager"
_TIMESTAMP_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?")


def _validate_service_id(service_id: str) -> None:
    if not _SERVICE_ID_RE.match(service_id):
        raise ValueError(
            f"Invalid service_id: {service_id!r}. Must be alphanumeric with _ . - only"
        )


def _short(value: Any, n: int = 12) -> Any:
    return value[:n] if isinstance(value, str) else value


def _split_image(image: Any) -> tuple[Any, str | None]:
    """``repo:tag@sha256:...`` -> (``repo:tag``, digest)."""
    if not isinstance(image, str) or "@" not in image:
        return image, None
    ref, _, digest = image.partition("@")
    return ref, digest


def _service_mode(spec: dict[str, Any]) -> tuple[str, int | None]:
    """(``replicated`` | ``global`` | ``replicated-job`` | ..., desired replicas)."""
    mode = spec.get("Mode") or {}
    if "Replicated" in mode:
        return "replicated", int((mode.get("Replicated") or {}).get("Replicas", 0) or 0)
    if "Global" in mode:
        return "global", None
    if "ReplicatedJob" in mode:
        return "replicated-job", int(
            (mode.get("ReplicatedJob") or {}).get("TotalCompletions", 0) or 0
        )
    if "GlobalJob" in mode:
        return "global-job", None
    return "unknown", None


def _task_summary(task: dict[str, Any], hostnames: dict[str, str]) -> dict[str, Any]:
    status = task.get("Status") or {}
    container_status = status.get("ContainerStatus") or {}
    spec = task.get("Spec") or {}
    image, _ = _split_image((spec.get("ContainerSpec") or {}).get("Image"))
    node_id = task.get("NodeID")
    return {
        "id": _short(task.get("ID")),
        "slot": task.get("Slot"),
        "node_id": _short(node_id),
        "node": hostnames.get(node_id or "", None),
        "desired_state": task.get("DesiredState"),
        "state": status.get("State"),
        "message": status.get("Message"),
        "error": status.get("Err"),
        "timestamp": status.get("Timestamp"),
        "container_id": _short(container_status.get("ContainerID")),
        "exit_code": container_status.get("ExitCode"),
        "image": image,
    }


def _ts_key(task: dict[str, Any]) -> tuple[str, str]:
    """Sortable key for ``Status.Timestamp``.

    Go prints RFC 3339 with trailing fractional zeros trimmed, so plain
    string comparison misorders timestamps within one second (``:00Z`` >
    ``:00.5Z``). Normalise the fraction to 9 digits before comparing.
    """
    raw = str((task.get("Status") or {}).get("Timestamp") or "")
    m = _TIMESTAMP_RE.match(raw)
    if not m:
        return ("", raw)
    return (m.group(1), (m.group(2) or "").ljust(9, "0"))


def _sort_tasks(tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """`docker service ps` order: by slot, newest task first within a slot.

    Two stable sorts: newest-first by timestamp, then ascending by slot.
    """
    by_time = sorted(tasks, key=_ts_key, reverse=True)
    return sorted(by_time, key=lambda t: t.get("Slot") or 0)


def _running_counts(tasks: list[dict[str, Any]]) -> dict[str, int]:
    """Per-service count of tasks that are actually running (not just desired)."""
    counts: dict[str, int] = {}
    for t in tasks:
        if t.get("DesiredState") == "running" and (t.get("Status") or {}).get("State") == "running":
            sid = str(t.get("ServiceID"))
            counts[sid] = counts.get(sid, 0) + 1
    return counts


def _completed_counts(tasks: list[dict[str, Any]]) -> dict[str, int]:
    """Per-service count of job tasks that ran to completion."""
    counts: dict[str, int] = {}
    for t in tasks:
        if (t.get("Status") or {}).get("State") == "complete":
            sid = str(t.get("ServiceID"))
            counts[sid] = counts.get(sid, 0) + 1
    return counts


def _service_healthy(summary: dict[str, Any]) -> bool:
    """Replicated/global: running >= desired and no paused/rolled-back update.
    Jobs: enough completed tasks (a finished job is healthy, not 0/1)."""
    if summary["update_status"] in ("paused", "rollback_started"):
        return False
    desired = summary["replicas_desired"]
    if summary["mode"] in ("replicated-job", "global-job"):
        completed = summary.get("tasks_completed") or 0
        return completed >= desired if desired is not None else completed >= 1
    return desired is not None and summary["replicas_running"] >= desired


def _service_summary(
    svc: dict[str, Any],
    running: dict[str, int],
    active_nodes: int | None,
    completed: dict[str, int] | None = None,
) -> dict[str, Any]:
    spec = svc.get("Spec") or {}
    container_spec = (spec.get("TaskTemplate") or {}).get("ContainerSpec") or {}
    image, digest = _split_image(container_spec.get("Image"))
    mode, desired = _service_mode(spec)
    if mode == "global":
        desired = active_nodes
    labels = spec.get("Labels") or {}
    ports = []
    for p in (svc.get("Endpoint") or {}).get("Ports") or []:
        ports.append(
            {
                "published": p.get("PublishedPort"),
                "target": p.get("TargetPort"),
                "protocol": p.get("Protocol"),
                "mode": p.get("PublishMode"),
            }
        )
    update_status = svc.get("UpdateStatus") or {}
    summary: dict[str, Any] = {
        "id": _short(svc.get("ID")),
        "name": spec.get("Name"),
        "stack": labels.get(_STACK_NAMESPACE_LABEL),
        "image": image,
        "image_digest": digest,
        "mode": mode,
        "replicas_running": running.get(str(svc.get("ID")), 0),
        "replicas_desired": desired,
        "ports": ports,
        "update_status": update_status.get("State"),
        "update_message": update_status.get("Message"),
        "created_at": svc.get("CreatedAt"),
        "updated_at": svc.get("UpdatedAt"),
    }
    if mode.endswith("-job"):
        summary["tasks_completed"] = (completed or {}).get(str(svc.get("ID")), 0)
    return summary


def _redact_service(svc: dict[str, Any]) -> dict[str, Any]:
    """Mask credential-looking Env values in Spec and PreviousSpec."""
    for key in ("Spec", "PreviousSpec"):
        spec = svc.get(key)
        if not isinstance(spec, dict):
            continue
        container_spec = (spec.get("TaskTemplate") or {}).get("ContainerSpec")
        if isinstance(container_spec, dict) and isinstance(container_spec.get("Env"), list):
            container_spec["Env"] = redact_env_strings(container_spec["Env"])
    return svc


async def _nodes(client: PortainerClient, eid: int) -> list[dict[str, Any]]:
    """Swarm node list; tolerant — a failure degrades to "no node info"."""
    try:
        nodes = await client.get(f"/api/endpoints/{eid}/docker/nodes")
    except Exception as exc:
        logger.debug("Node listing failed on endpoint %d: %s", eid, exc)
        return []
    return [n for n in (nodes or []) if isinstance(n, dict)]


def _hostnames(nodes: list[dict[str, Any]]) -> dict[str, str]:
    """``node id -> hostname``."""
    out: dict[str, str] = {}
    for n in nodes:
        hostname = (n.get("Description") or {}).get("Hostname")
        if n.get("ID") and hostname:
            out[n["ID"]] = hostname
    return out


def _active_node_count(nodes: list[dict[str, Any]]) -> int | None:
    """Nodes a global service is expected to run on (ready + active)."""
    if not nodes:
        return None
    return sum(
        1
        for n in nodes
        if (n.get("Status") or {}).get("State") == "ready"
        and (n.get("Spec") or {}).get("Availability") == "active"
    )


async def _tasks_for_services(
    client: PortainerClient, eid: int, service_ids: list[str]
) -> list[dict[str, Any]]:
    """Tasks of the given services, fetched in bounded-size filter chunks so
    a cluster with hundreds of services can't produce an over-long URL."""
    out: list[dict[str, Any]] = []
    for start in range(0, len(service_ids), _TASK_FILTER_CHUNK):
        chunk = service_ids[start : start + _TASK_FILTER_CHUNK]
        tasks = await client.get(
            f"/api/endpoints/{eid}/docker/tasks",
            params={"filters": json.dumps({"service": chunk})},
        )
        out.extend(t for t in (tasks or []) if isinstance(t, dict))
    return out


def _is_not_swarm_error(exc: httpx.HTTPStatusError) -> bool:
    # Docker answers 503 "This node is not a swarm manager" on a non-Swarm
    # (or worker-only) endpoint. Other 503s (lost raft quorum, a proxy in
    # front of Portainer) are outages, not "use the Compose view".
    return exc.response.status_code == 503 and _NOT_SWARM_MARKER in exc.response.text.lower()


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @tool_error_handler
    async def portainer_services_list(
        endpoint_id: int | None = None,
        stack_filter: str | None = None,
    ) -> str:
        """List Swarm services with running/desired replica counts.

        On a Swarm endpoint this is the primary view (like `docker service
        ls`): services are the stable units, containers are their tasks.

        Args:
            endpoint_id: Target endpoint ID (uses default if omitted)
            stack_filter: Only services of this stack (exact stack name)
        """
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        params: dict[str, str] = {}
        if stack_filter is not None:
            if not _STACK_NAME_RE.match(stack_filter):
                raise ValueError(f"Invalid stack_filter: {stack_filter!r}")
            params["filters"] = json.dumps({"label": [f"{_STACK_NAMESPACE_LABEL}={stack_filter}"]})
        services = await client.get(f"/api/endpoints/{eid}/docker/services", params=params)
        services = [s for s in (services or []) if isinstance(s, dict)]
        tasks = await _tasks_for_services(client, eid, [str(s.get("ID")) for s in services])
        running = _running_counts(tasks)
        completed = _completed_counts(tasks)
        needs_nodes = any(_service_mode(s.get("Spec") or {})[0] == "global" for s in services)
        active_nodes = _active_node_count(await _nodes(client, eid)) if needs_nodes else None
        result = [_service_summary(s, running, active_nodes, completed) for s in services]
        result.sort(key=lambda s: str(s.get("name") or ""))
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp.tool()
    @tool_error_handler
    async def portainer_service_inspect(
        service_id: str,
        reveal_env: bool = False,
        endpoint_id: int | None = None,
    ) -> str:
        """Get the full Swarm service definition (spec, update status, endpoint).

        Credential-looking environment values in the container spec are
        masked as [REDACTED] unless reveal_env=true.

        Args:
            service_id: Service ID or name (e.g. "arena-etl_backend")
            reveal_env: Return credential values unmasked (default false)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_service_id(service_id)
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        svc = await client.get(f"/api/endpoints/{eid}/docker/services/{service_id}")
        if not isinstance(svc, dict):
            raise ValueError(f"Service {service_id!r} not found or returned no data")
        if not reveal_env:
            svc = _redact_service(svc)
            svc["env_redacted"] = True
        return json.dumps(svc, indent=2, ensure_ascii=False)

    @mcp.tool()
    @tool_error_handler
    async def portainer_service_tasks(
        service_id: str,
        limit: int = _DEFAULT_TASKS,
        endpoint_id: int | None = None,
    ) -> str:
        """List a service's tasks with state, node and error (`docker service ps`).

        The first place to look when replicas are not coming up: a task's
        `error` carries the scheduler / container start failure ("no suitable
        node", "task: non-zero exit (1)", image pull errors, ...).

        Args:
            service_id: Service ID or name
            limit: Max tasks to return, newest per slot first (default 50, max 500)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_service_id(service_id)
        limit = max(1, min(limit, _MAX_TASKS))
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        tasks = await _tasks_for_services(client, eid, [service_id])
        hostnames = _hostnames(await _nodes(client, eid)) if tasks else {}
        ordered = _sort_tasks(tasks)
        by_state: dict[str, int] = {}
        for t in tasks:
            state = str((t.get("Status") or {}).get("State"))
            by_state[state] = by_state.get(state, 0) + 1
        return json.dumps(
            {
                "service": service_id,
                "tasks_total": len(tasks),
                "tasks_by_state": by_state,
                "truncated": len(ordered) > limit,
                "tasks": [_task_summary(t, hostnames) for t in ordered[:limit]],
            },
            indent=2,
            ensure_ascii=False,
        )

    @mcp.tool()
    @tool_error_handler
    async def portainer_service_logs(
        service_id: str,
        tail: int = 100,
        since: str | None = None,
        timestamps: bool = False,
        endpoint_id: int | None = None,
    ) -> str:
        """Get logs of a Swarm service (all its tasks, across nodes).

        Args:
            service_id: Service ID or name
            tail: Number of lines from the end of the logs (default 100, max 1000)
            since: Only lines newer than this: a duration ("10m", "2h", "1d"),
                a Unix timestamp or an ISO-8601 datetime
            timestamps: Prefix every line with its timestamp (default false)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_service_id(service_id)
        tail = max(1, min(tail, 1000))
        params = _log_params(tail, since, timestamps)
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        resp = await client.request(
            "GET",
            f"/api/endpoints/{eid}/docker/services/{service_id}/logs",
            params=params,
            timeout=config.long_timeout,
        )
        output = _parse_docker_stream(resp.content)
        total_chars = len(output)
        truncated = total_chars > _MAX_LOG_CHARS
        if truncated:
            output = output[:_MAX_LOG_CHARS]
        return json.dumps(
            {
                "service": service_id,
                "tail": tail,
                "since": since,
                "truncated": truncated,
                "total_chars": total_chars,
                "logs": output,
            },
            indent=2,
            ensure_ascii=False,
        )

    @mcp.tool()
    @tool_error_handler
    async def portainer_service_update(
        service_id: str,
        image: str | None = None,
        replicas: int | None = None,
        force_restart: bool = False,
        registry_id: int | None = None,
        endpoint_id: int | None = None,
    ) -> str:
        """Update a Swarm service: change its image, scale it, or force a restart.

        Reads the current spec and version, applies the requested changes and
        submits the spec back (rolling update per the service's UpdateConfig).
        At least one of image / replicas / force_restart is required.

        To roll out a new build of the same `:latest` tag, pass image=
        "<repo>:<tag>" without a digest — Swarm resolves the tag to its
        current digest at update time. force_restart alone re-creates the
        tasks with the image digest already pinned in the spec.

        Args:
            service_id: Service ID or name
            image: New image reference (e.g. "registry.example.com/app:latest")
            replicas: New replica count (replicated services only)
            force_restart: Re-create all tasks even if the spec is unchanged
                (`docker service update --force`)
            registry_id: ID of a Portainer-configured registry whose stored
                credentials the nodes should use to pull the image
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_service_id(service_id)
        if image is None and replicas is None and not force_restart:
            raise ValueError("Nothing to do: pass image, replicas and/or force_restart=true")
        if image is not None:
            _validate_image_ref(image)
        if replicas is not None and (
            not isinstance(replicas, int) or isinstance(replicas, bool) or replicas < 0
        ):
            raise ValueError(f"Invalid replicas: {replicas!r}. Must be a non-negative integer.")
        headers: dict[str, str] = {}
        if registry_id is not None:
            validate_id(registry_id, "registry_id")
            headers["X-Registry-Auth"] = portainer_registry_auth_header(registry_id)

        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)

        svc = await client.get(f"/api/endpoints/{eid}/docker/services/{service_id}")
        if not isinstance(svc, dict) or not isinstance(svc.get("Spec"), dict):
            raise ValueError(f"Service {service_id!r} not found or returned no spec")
        spec: dict[str, Any] = svc["Spec"]
        version = (svc.get("Version") or {}).get("Index")
        if not isinstance(version, int):
            raise ValueError(f"Service {service_id!r} has no Version.Index to update against")

        changes: dict[str, Any] = {}
        task_template = spec.setdefault("TaskTemplate", {})
        if image is not None:
            container_spec = task_template.setdefault("ContainerSpec", {})
            changes["image"] = {"from": container_spec.get("Image"), "to": image}
            container_spec["Image"] = image
        if replicas is not None:
            mode = spec.get("Mode") or {}
            if "Replicated" not in mode:
                raise ValueError(
                    f"Service {service_id!r} is not replicated (mode: "
                    f"{_service_mode(spec)[0]}); replicas cannot be set"
                )
            changes["replicas"] = {
                "from": (mode.get("Replicated") or {}).get("Replicas"),
                "to": replicas,
            }
            mode["Replicated"] = {**(mode.get("Replicated") or {}), "Replicas": replicas}
            spec["Mode"] = mode
        if force_restart:
            current_force = task_template.get("ForceUpdate") or 0
            task_template["ForceUpdate"] = int(current_force) + 1
            changes["force_update"] = task_template["ForceUpdate"]

        logger.info(
            "AUDIT: Updating service %s on endpoint %d (version %d): %s (registry_id=%s)",
            service_id,
            eid,
            version,
            json.dumps(changes, ensure_ascii=False),
            registry_id,
        )
        result = await client.post(
            f"/api/endpoints/{eid}/docker/services/{service_id}/update",
            params={"version": str(version)},
            json=spec,
            headers=headers,
        )
        warnings = result.get("Warnings") if isinstance(result, dict) else None
        return json.dumps(
            {
                "status": "updated",
                "service": spec.get("Name") or service_id,
                "previous_version": version,
                "changes": changes,
                "warnings": warnings or [],
            },
            indent=2,
            ensure_ascii=False,
        )

    @mcp.tool()
    @tool_error_handler
    async def portainer_nodes_list(endpoint_id: int | None = None) -> str:
        """List Swarm nodes with role, availability, state and resources.

        Args:
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        nodes = await client.get(f"/api/endpoints/{eid}/docker/nodes")
        if not isinstance(nodes, list):
            raise ValueError(f"Endpoint {eid} returned no node list (not a Swarm manager?)")
        result = []
        for n in nodes:
            if not isinstance(n, dict):
                continue
            spec = n.get("Spec") or {}
            desc = n.get("Description") or {}
            resources = desc.get("Resources") or {}
            status = n.get("Status") or {}
            manager = n.get("ManagerStatus") or {}
            result.append(
                {
                    "id": _short(n.get("ID")),
                    "hostname": desc.get("Hostname"),
                    "role": spec.get("Role"),
                    "availability": spec.get("Availability"),
                    "state": status.get("State"),
                    "status_message": status.get("Message"),
                    "addr": status.get("Addr"),
                    "manager_leader": bool(manager.get("Leader")) if manager else False,
                    "manager_reachability": manager.get("Reachability"),
                    "engine_version": (desc.get("Engine") or {}).get("EngineVersion"),
                    "cpus": round((resources.get("NanoCPUs") or 0) / 1_000_000_000, 1),
                    "memory_gb": round((resources.get("MemoryBytes") or 0) / 1_073_741_824, 1),
                    "labels": spec.get("Labels") or {},
                }
            )
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp.tool()
    @tool_error_handler
    async def portainer_stack_status(
        stack_name: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Health summary of a stack: every service with running/desired
        replicas, update state and the most recent task failures.

        Start here when asked "is stack X ok / why is X down". Works on Swarm
        (services + tasks) and falls back to container states on a
        standalone Compose endpoint.

        Args:
            stack_name: Stack name (Swarm namespace / Compose project)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        if not _STACK_NAME_RE.match(stack_name):
            raise ValueError(f"Invalid stack_name: {stack_name!r}")
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)

        try:
            services = await client.get(
                f"/api/endpoints/{eid}/docker/services",
                params={
                    "filters": json.dumps({"label": [f"{_STACK_NAMESPACE_LABEL}={stack_name}"]})
                },
            )
        except httpx.HTTPStatusError as exc:
            if not _is_not_swarm_error(exc):
                raise
            return await _compose_stack_status(client, eid, stack_name)

        services = [s for s in (services or []) if isinstance(s, dict)]
        if not services:
            # A Compose project can run on a Swarm manager too (`docker compose
            # up` on the node): try the container view before declaring the
            # stack absent.
            return await _compose_stack_status(client, eid, stack_name, swarm_checked=True)

        tasks = await _tasks_for_services(client, eid, [str(s.get("ID")) for s in services])
        nodes = await _nodes(client, eid)
        hostnames = _hostnames(nodes)
        running = _running_counts(tasks)
        completed = _completed_counts(tasks)
        needs_nodes = any(_service_mode(s.get("Spec") or {})[0] == "global" for s in services)
        active_nodes = _active_node_count(nodes) if needs_nodes else None

        tasks_by_service: dict[str, list[dict[str, Any]]] = {}
        for t in tasks:
            tasks_by_service.setdefault(str(t.get("ServiceID")), []).append(t)

        summaries = []
        healthy_count = 0
        for svc in services:
            summary = _service_summary(svc, running, active_nodes, completed)
            svc_tasks = tasks_by_service.get(str(svc.get("ID")), [])
            failures = [
                t
                for t in svc_tasks
                if (t.get("Status") or {}).get("Err")
                or (t.get("Status") or {}).get("State") in _TASK_FAILURE_STATES
            ]
            failures.sort(key=_ts_key, reverse=True)
            is_healthy = _service_healthy(summary)
            healthy_count += int(is_healthy)
            summaries.append(
                {
                    **summary,
                    "healthy": is_healthy,
                    "recent_task_errors": [
                        _task_summary(t, hostnames) for t in failures[:_RECENT_TASK_ERRORS]
                    ],
                }
            )
        summaries.sort(key=lambda s: str(s.get("name") or ""))

        return json.dumps(
            {
                "stack": stack_name,
                "mode": "swarm",
                "services_total": len(summaries),
                "services_healthy": healthy_count,
                "healthy": healthy_count == len(summaries),
                "services": summaries,
            },
            indent=2,
            ensure_ascii=False,
        )


def _container_ok(c: dict[str, Any]) -> bool:
    """Running, or a one-shot container that exited cleanly (`Exited (0) ...`)."""
    if c.get("State") == "running":
        return True
    return c.get("State") == "exited" and str(c.get("Status") or "").startswith("Exited (0)")


async def _compose_stack_status(
    client: PortainerClient, eid: int, stack_name: str, *, swarm_checked: bool = False
) -> str:
    """Standalone fallback: group the stack's containers by Compose service."""
    containers = await client.get(
        f"/api/endpoints/{eid}/docker/containers/json", params={"all": "true"}
    )
    services: dict[str, dict[str, Any]] = {}
    for c in containers or []:
        stack, service = _container_labels(c)
        if stack != stack_name:
            continue
        name = service or "unknown"
        entry = services.setdefault(
            name,
            {
                "name": name,
                "image": c.get("Image"),
                "containers_total": 0,
                "containers_running": 0,
                "containers_ok": 0,
                "containers": [],
            },
        )
        state = c.get("State")
        entry["containers_total"] += 1
        entry["containers_running"] += int(state == "running")
        entry["containers_ok"] += int(_container_ok(c))
        entry["containers"].append(
            {
                "id": _short(c.get("Id")),
                "name": (c.get("Names") or ["?"])[0].lstrip("/"),
                "state": state,
                "status": c.get("Status"),
            }
        )
    summaries = []
    healthy_count = 0
    for entry in sorted(services.values(), key=lambda e: str(e["name"])):
        is_healthy = entry["containers_ok"] == entry["containers_total"] > 0
        healthy_count += int(is_healthy)
        summaries.append({**entry, "healthy": is_healthy})
    body: dict[str, Any] = {
        "stack": stack_name,
        "mode": "compose",
        "services_total": len(summaries),
        "services_healthy": healthy_count,
        "healthy": bool(summaries) and healthy_count == len(summaries),
        "services": summaries,
    }
    if not summaries:
        body["message"] = (
            f"No Swarm services and no containers found for stack '{stack_name}' "
            f"on endpoint {eid}"
            if swarm_checked
            else f"No containers found for stack '{stack_name}' on endpoint {eid}"
        )
    return json.dumps(body, indent=2, ensure_ascii=False)
