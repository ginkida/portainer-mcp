from __future__ import annotations

import asyncio
import json
import logging
import re
import time
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
# swarm-cronjob (crazymax/swarm-cronjob) marks the services it drives with
# these labels. Such a service sits at 0 running replicas between runs and
# Swarm records every run as an "update" that then "pauses" when the task
# exits — normal for a cron job, alarming for anything else. Health for
# them is judged on the outcome of the latest run instead.
_CRON_ENABLE_LABEL = "swarm.cronjob.enable"
_CRON_SCHEDULE_LABEL = "swarm.cronjob.schedule"
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
# UpdateStatus.State values that mean "the rollout stopped and needs a human".
_UPDATE_STUCK_STATES = frozenset({"paused", "rollback_paused"})
_UPDATE_IN_PROGRESS_STATES = frozenset({"updating", "rollback_started"})
# Wait tools: poll interval and the bounds of the caller's deadline. The
# ceiling is config.long_timeout so a wait can never outlive one MCP call
# budget; the floor keeps a "0-second wait" from degenerating into a single
# sample that always reports "timed out".
_WAIT_POLL_SECONDS = 3.0
_MIN_WAIT_SECONDS = 5
_DEFAULT_WAIT_SECONDS = 120


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


def _is_cron(spec: dict[str, Any]) -> bool:
    labels = spec.get("Labels") or {}
    return str(labels.get(_CRON_ENABLE_LABEL, "")).lower() == "true"


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


def _task_state(task: dict[str, Any]) -> str:
    return str((task.get("Status") or {}).get("State") or "")


def _is_running(task: dict[str, Any]) -> bool:
    return task.get("DesiredState") == "running" and _task_state(task) == "running"


def _is_failure(task: dict[str, Any]) -> bool:
    status = task.get("Status") or {}
    return bool(status.get("Err")) or _task_state(task) in _TASK_FAILURE_STATES


def _latest_task(tasks: list[dict[str, Any]]) -> dict[str, Any] | None:
    return max(tasks, key=_ts_key) if tasks else None


def _recent_failures(
    svc_tasks: list[dict[str, Any]], *, good_states: frozenset[str]
) -> list[dict[str, Any]]:
    """Failed tasks that are newer than the service's newest *good* task.

    Swarm keeps the last few tasks per slot, so a service that recovered days
    ago still carries its old failures; reporting those next to a healthy
    service is noise. Failures are only interesting when nothing good has
    happened since — or when nothing good has ever happened.
    """
    good = [t for t in svc_tasks if _task_state(t) in good_states and not _is_failure(t)]
    newest_good = _ts_key(max(good, key=_ts_key)) if good else None
    failures = [
        t for t in svc_tasks if _is_failure(t) and (newest_good is None or _ts_key(t) > newest_good)
    ]
    failures.sort(key=_ts_key, reverse=True)
    return failures[:_RECENT_TASK_ERRORS]


def _service_summary(
    svc: dict[str, Any],
    svc_tasks: list[dict[str, Any]],
    active_nodes: int | None,
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
        "replicas_running": sum(1 for t in svc_tasks if _is_running(t)),
        "replicas_desired": desired,
        "ports": ports,
        "update_status": update_status.get("State"),
        "update_message": update_status.get("Message"),
        "created_at": svc.get("CreatedAt"),
        "updated_at": svc.get("UpdatedAt"),
    }
    if mode.endswith("-job"):
        summary["tasks_completed"] = sum(1 for t in svc_tasks if _task_state(t) == "complete")
    if _is_cron(spec):
        latest = _latest_task(svc_tasks)
        status = (latest or {}).get("Status") or {}
        summary["cron"] = True
        summary["cron_schedule"] = labels.get(_CRON_SCHEDULE_LABEL)
        summary["last_run_at"] = status.get("Timestamp")
        summary["last_run_state"] = status.get("State")
        summary["last_run_exit_code"] = (status.get("ContainerStatus") or {}).get("ExitCode")
        summary["last_run_error"] = status.get("Err")
    return summary


def _service_healthy(summary: dict[str, Any]) -> bool:
    """What "healthy" means per kind of service.

    - cron (swarm-cronjob): the latest run did not fail — 0 running replicas
      and a "paused" update are its normal resting state;
    - jobs: enough tasks reached ``complete`` (a finished job is not "0/1");
    - everything else: running >= desired and no paused / rolled-back update.
    """
    if summary.get("cron"):
        state = summary.get("last_run_state")
        if state is None:
            return True  # never ran yet — nothing has failed
        exit_code = summary.get("last_run_exit_code")
        return (
            state not in _TASK_FAILURE_STATES
            and not summary.get("last_run_error")
            and exit_code in (0, None)
        )
    if summary["update_status"] in _UPDATE_STUCK_STATES:
        return False
    desired = summary["replicas_desired"]
    if summary["mode"] in ("replicated-job", "global-job"):
        completed = summary.get("tasks_completed") or 0
        return completed >= desired if desired is not None else completed >= 1
    return desired is not None and summary["replicas_running"] >= desired


def _good_states_for(summary: dict[str, Any]) -> frozenset[str]:
    if summary.get("cron") or summary["mode"].endswith("-job"):
        return frozenset({"complete"})
    return frozenset({"running"})


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


def _group_by_service(tasks: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for t in tasks:
        grouped.setdefault(str(t.get("ServiceID")), []).append(t)
    return grouped


def _is_not_swarm_error(exc: httpx.HTTPStatusError) -> bool:
    # Docker answers 503 "This node is not a swarm manager" on a non-Swarm
    # (or worker-only) endpoint. Other 503s (lost raft quorum, a proxy in
    # front of Portainer) are outages, not "use the Compose view".
    return exc.response.status_code == 503 and _NOT_SWARM_MARKER in exc.response.text.lower()


async def _load_service(
    client: PortainerClient, eid: int, service_id: str
) -> tuple[dict[str, Any], dict[str, Any], int]:
    """``(service, spec, version index)`` for a read-modify-write update."""
    svc = await client.get(f"/api/endpoints/{eid}/docker/services/{service_id}")
    if not isinstance(svc, dict) or not isinstance(svc.get("Spec"), dict):
        raise ValueError(f"Service {service_id!r} not found or returned no spec")
    version = (svc.get("Version") or {}).get("Index")
    if not isinstance(version, int):
        raise ValueError(f"Service {service_id!r} has no Version.Index to update against")
    return svc, svc["Spec"], version


async def _service_state(client: PortainerClient, eid: int, service_id: str) -> dict[str, Any]:
    """One service's summary plus health and recent failures (for wait/status)."""
    svc = await client.get(f"/api/endpoints/{eid}/docker/services/{service_id}")
    if not isinstance(svc, dict):
        raise ValueError(f"Service {service_id!r} not found or returned no data")
    svc_tasks = await _tasks_for_services(client, eid, [str(svc.get("ID"))])
    nodes = await _nodes(client, eid)
    active_nodes = (
        _active_node_count(nodes) if _service_mode(svc.get("Spec") or {})[0] == "global" else None
    )
    summary = _service_summary(svc, svc_tasks, active_nodes)
    summary["healthy"] = _service_healthy(summary)
    summary["recent_task_errors"] = [
        _task_summary(t, _hostnames(nodes))
        for t in _recent_failures(svc_tasks, good_states=_good_states_for(summary))
    ]
    return summary


async def _collect_stack(client: PortainerClient, eid: int, stack_name: str) -> dict[str, Any]:
    """The stack_status body: Swarm services + tasks, or the Compose fallback."""
    try:
        services = await client.get(
            f"/api/endpoints/{eid}/docker/services",
            params={"filters": json.dumps({"label": [f"{_STACK_NAMESPACE_LABEL}={stack_name}"]})},
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
    needs_nodes = any(_service_mode(s.get("Spec") or {})[0] == "global" for s in services)
    active_nodes = _active_node_count(nodes) if needs_nodes else None
    tasks_by_service = _group_by_service(tasks)

    summaries = []
    healthy_count = 0
    for svc in services:
        svc_tasks = tasks_by_service.get(str(svc.get("ID")), [])
        summary = _service_summary(svc, svc_tasks, active_nodes)
        is_healthy = _service_healthy(summary)
        healthy_count += int(is_healthy)
        summaries.append(
            {
                **summary,
                "healthy": is_healthy,
                "recent_task_errors": [
                    _task_summary(t, hostnames)
                    for t in _recent_failures(svc_tasks, good_states=_good_states_for(summary))
                ],
            }
        )
    summaries.sort(key=lambda s: str(s.get("name") or ""))
    return {
        "stack": stack_name,
        "mode": "swarm",
        "services_total": len(summaries),
        "services_healthy": healthy_count,
        "healthy": healthy_count == len(summaries),
        "services": summaries,
    }


def _stack_converged(body: dict[str, Any]) -> tuple[bool, str]:
    """(done, reason) for stack_wait: healthy, or stuck on a paused rollout."""
    if body.get("healthy"):
        return True, "healthy"
    stuck = [
        s["name"]
        for s in body.get("services", [])
        if not s.get("cron") and s.get("update_status") in _UPDATE_STUCK_STATES
    ]
    if stuck:
        return True, f"rollout stuck ({', '.join(stuck)}): update paused or rollback paused"
    if not body.get("services"):
        return True, "no services found"
    return False, "converging"


def _clamp_wait(timeout_seconds: int) -> int:
    ceiling = int(get_config().long_timeout)
    return max(_MIN_WAIT_SECONDS, min(timeout_seconds, ceiling))


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
        Cron-driven services (swarm-cronjob) carry `cron: true` and their
        last run's outcome instead of a meaningful replica count.

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
        tasks_by_service = _group_by_service(tasks)
        needs_nodes = any(_service_mode(s.get("Spec") or {})[0] == "global" for s in services)
        active_nodes = _active_node_count(await _nodes(client, eid)) if needs_nodes else None
        result = [
            _service_summary(s, tasks_by_service.get(str(s.get("ID")), []), active_nodes)
            for s in services
        ]
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
            by_state[_task_state(t)] = by_state.get(_task_state(t), 0) + 1
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
        At least one of image / replicas / force_restart is required. Follow
        up with portainer_service_wait to know when the rollout converged.

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
        _, spec, version = await _load_service(client, eid, service_id)

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
    async def portainer_service_rollback(
        service_id: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Roll a Swarm service back to its previous spec (`docker service rollback`).

        Works only while Swarm still holds a PreviousSpec (i.e. after at
        least one update). Follow up with portainer_service_wait.

        Args:
            service_id: Service ID or name
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_service_id(service_id)
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        svc, spec, version = await _load_service(client, eid, service_id)
        previous = svc.get("PreviousSpec")
        if not isinstance(previous, dict):
            raise ValueError(
                f"Service {service_id!r} has no previous spec to roll back to "
                "(it was never updated, or the history was already consumed)"
            )
        prev_image, _ = _split_image(
            ((previous.get("TaskTemplate") or {}).get("ContainerSpec") or {}).get("Image")
        )
        cur_image, _ = _split_image(
            ((spec.get("TaskTemplate") or {}).get("ContainerSpec") or {}).get("Image")
        )
        logger.info(
            "AUDIT: Rolling back service %s on endpoint %d (version %d): %s -> %s",
            service_id,
            eid,
            version,
            cur_image,
            prev_image,
        )
        # Docker ignores the body when rollback=previous is set, but the
        # endpoint still requires a valid spec; send the current one.
        result = await client.post(
            f"/api/endpoints/{eid}/docker/services/{service_id}/update",
            params={"version": str(version), "rollback": "previous"},
            json=spec,
        )
        warnings = result.get("Warnings") if isinstance(result, dict) else None
        return json.dumps(
            {
                "status": "rollback_started",
                "service": spec.get("Name") or service_id,
                "previous_version": version,
                "image": {"from": cur_image, "to": prev_image},
                "warnings": warnings or [],
            },
            indent=2,
            ensure_ascii=False,
        )

    @mcp.tool()
    @tool_error_handler
    async def portainer_service_wait(
        service_id: str,
        timeout_seconds: int = _DEFAULT_WAIT_SECONDS,
        endpoint_id: int | None = None,
    ) -> str:
        """Wait for a service's rollout to converge after an update/rollback.

        Polls until the service is healthy (running == desired and the
        update finished), the update paused on failure, or the timeout
        elapses. Returns the final service summary with `converged`,
        `reason`, `timed_out` and the recent task errors.

        Args:
            service_id: Service ID or name
            timeout_seconds: How long to wait (default 120, clamped to
                5..PORTAINER_LONG_TIMEOUT)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        _validate_service_id(service_id)
        timeout = _clamp_wait(timeout_seconds)
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        started = time.monotonic()
        while True:
            state = await _service_state(client, eid, service_id)
            elapsed = round(time.monotonic() - started, 1)
            update = state.get("update_status")
            if state["healthy"] and update not in _UPDATE_IN_PROGRESS_STATES:
                converged, reason = True, "healthy"
            elif update in _UPDATE_STUCK_STATES and not state.get("cron"):
                converged, reason = True, f"update {update}: {state.get('update_message')}"
            elif elapsed >= timeout:
                converged, reason = False, "timed out"
            else:
                await asyncio.sleep(_WAIT_POLL_SECONDS)
                continue
            return json.dumps(
                {
                    "converged": converged,
                    "reason": reason,
                    "timed_out": not converged,
                    "elapsed_seconds": elapsed,
                    "timeout_seconds": timeout,
                    **state,
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

    async def _list_swarm_objects(kind: str, endpoint_id: int | None) -> str:
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        objects = await client.get(f"/api/endpoints/{eid}/docker/{kind}")
        if not isinstance(objects, list):
            raise ValueError(f"Endpoint {eid} returned no {kind} list (not a Swarm manager?)")
        result = []
        for o in objects:
            if not isinstance(o, dict):
                continue
            spec = o.get("Spec") or {}
            # Never forward Spec.Data: for configs it is the base64 content
            # itself; secrets don't return it, but keep the projection strict.
            result.append(
                {
                    "id": _short(o.get("ID")),
                    "name": spec.get("Name"),
                    "labels": spec.get("Labels") or {},
                    "created_at": o.get("CreatedAt"),
                    "updated_at": o.get("UpdatedAt"),
                }
            )
        result.sort(key=lambda s: str(s.get("name") or ""))
        return json.dumps(result, indent=2, ensure_ascii=False)

    @mcp.tool()
    @tool_error_handler
    async def portainer_secrets_list(endpoint_id: int | None = None) -> str:
        """List Swarm secrets (names and metadata only — never the values).

        Args:
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        return await _list_swarm_objects("secrets", endpoint_id)

    @mcp.tool()
    @tool_error_handler
    async def portainer_configs_list(endpoint_id: int | None = None) -> str:
        """List Swarm configs (names and metadata only — never the content).

        Args:
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        return await _list_swarm_objects("configs", endpoint_id)

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
        standalone Compose endpoint. Cron-driven services are judged on
        their last run, and only failures newer than the last good task are
        reported.

        Args:
            stack_name: Stack name (Swarm namespace / Compose project)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        if not _STACK_NAME_RE.match(stack_name):
            raise ValueError(f"Invalid stack_name: {stack_name!r}")
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        body = await _collect_stack(client, eid, stack_name)
        return json.dumps(body, indent=2, ensure_ascii=False)

    @mcp.tool()
    @tool_error_handler
    async def portainer_stack_wait(
        stack_name: str,
        timeout_seconds: int = _DEFAULT_WAIT_SECONDS,
        endpoint_id: int | None = None,
    ) -> str:
        """Wait for a stack's rollout to converge after stack_update.

        Polls portainer_stack_status until every service is healthy, a
        service's update paused on failure, or the timeout elapses. Returns
        the final status with `converged`, `reason` and `timed_out`.

        Args:
            stack_name: Stack name (Swarm namespace / Compose project)
            timeout_seconds: How long to wait (default 120, clamped to
                5..PORTAINER_LONG_TIMEOUT)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        if not _STACK_NAME_RE.match(stack_name):
            raise ValueError(f"Invalid stack_name: {stack_name!r}")
        timeout = _clamp_wait(timeout_seconds)
        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)
        started = time.monotonic()
        while True:
            body = await _collect_stack(client, eid, stack_name)
            elapsed = round(time.monotonic() - started, 1)
            done, reason = _stack_converged(body)
            if not done and elapsed < timeout:
                await asyncio.sleep(_WAIT_POLL_SECONDS)
                continue
            if not done:
                reason = "timed out"
            return json.dumps(
                {
                    "converged": done,
                    "reason": reason,
                    "timed_out": not done,
                    "elapsed_seconds": elapsed,
                    "timeout_seconds": timeout,
                    **body,
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
) -> dict[str, Any]:
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
            f"No Swarm services and no containers found for stack '{stack_name}' on endpoint {eid}"
            if swarm_checked
            else f"No containers found for stack '{stack_name}' on endpoint {eid}"
        )
    return body
