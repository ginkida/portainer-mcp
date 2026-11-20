from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import AsyncIterator, Callable, Iterable
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.server.fastmcp import FastMCP

import portainer_mcp.client as client_mod
from portainer_mcp.server import create_server

_TS = "2026-09-07T10:00:00.500000001Z"
_SINCE = "2026-09-07T10:00:00.5Z"
_UNTIL = "2026-09-07T10:00:01Z"


class _Stream(httpx.AsyncByteStream):
    def __init__(self, chunks: Iterable[bytes]) -> None:
        self.chunks = chunks
        self.reads = 0
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            self.reads += 1
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


def _frame(data: bytes, stream: int = 1) -> bytes:
    return bytes([stream, 0, 0, 0]) + len(data).to_bytes(4, "big") + data


def _line(message: str, timestamp: str = _TS) -> bytes:
    return f"{timestamp} {message}\n".encode()


async def _call(mcp: FastMCP, name: str, **arguments: Any) -> dict[str, Any]:
    result: Any = await mcp.call_tool(f"portainer_{name}", arguments)
    content = result[0] if isinstance(result, tuple) else result
    return json.loads(content[0].text)  # type: ignore[no-any-return]


@pytest.fixture
async def http(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[_MockPortainer]:
    monkeypatch.setenv("PORTAINER_API_KEY", "test-api-key")
    fake = _MockPortainer()
    client = client_mod.PortainerClient()
    await client._http.aclose()
    client._http = httpx.AsyncClient(
        base_url="https://portainer.test",
        transport=httpx.MockTransport(fake.handle),
    )
    client_mod._client = client
    try:
        yield fake
    finally:
        await client.close()


class _MockPortainer:
    def __init__(self) -> None:
        self.replies: dict[str, httpx.Response | Callable[[httpx.Request], httpx.Response]] = {}
        self.requests: list[httpx.Request] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["X-API-Key"] == "test-api-key"
        self.requests.append(request)
        reply = self.replies[request.url.path.removeprefix("/api/endpoints/1/docker")]
        return reply(request) if callable(reply) else reply

    def stream(self, path: str, *chunks: bytes) -> _Stream:
        stream = _Stream(chunks)
        self.replies[path] = httpx.Response(200, stream=stream)
        return stream


async def test_grep_scans_window_beyond_1000_lines(http: _MockPortainer) -> None:
    path = "/containers/app/logs"
    stream = http.stream(path, _line("old NEEDLE"), _line("routine") * 1_201)
    body = await _call(
        create_server(enable_laravel_tools=False),
        "container_logs_grep",
        container_id="app",
        pattern="^old NEEDLE",
        tail=1,
        since=_SINCE,
        until=_UNTIL,
    )
    assert body["lines"] == ["old NEEDLE"]
    assert body["lines_scanned"] == 1_202
    assert body["returned_first_ts"] == body["returned_last_ts"] == _TS
    assert body["first_ts"] == body["last_ts"] == _TS
    assert body["truncated"] is False
    assert body["truncation_reason"] is None
    assert http.requests[0].url.params == httpx.QueryParams(
        {
            "stdout": "true",
            "stderr": "true",
            "tail": "all",
            "timestamps": "true",
            "since": "1788775200.5",
            "until": "1788775201",
        }
    )
    assert stream.closed


async def test_grep_joins_split_frames_http_chunks_and_utf8(http: _MockPortainer) -> None:
    message = _line("ERROR Ошибка")
    i = message.index("О".encode()) + 1
    wire = _frame(message[:i], 2) + _frame(_line("stdout")) + _frame(message[i:], 2)
    http.stream("/containers/app/logs", *[wire[j : j + 3] for j in range(0, len(wire), 3)])
    body = await _call(
        create_server(enable_laravel_tools=False),
        "container_logs_grep",
        container_id="app",
        pattern="ERROR",
        since=_SINCE,
        timestamps=True,
    )
    assert body["lines"] == [f"{_TS} ERROR Ошибка"]
    assert body["lines_scanned"] == 2


async def test_swarm_filters_until_across_out_of_order_frames(http: _MockPortainer) -> None:
    last = "2026-09-07T10:00:00.800000000Z"
    http.stream(
        "/services/demo_web/logs",
        _frame(_line("before since", "2026-09-07T10:00:00.499999999Z")),
        _frame(_line("second", last)),
        _frame(_line("outside", "2026-09-07T10:00:02Z")),
        _frame(_line("first")),
    )
    body = await _call(
        create_server(enable_laravel_tools=False),
        "service_logs",
        service_id="demo_web",
        since=_SINCE,
        until=_UNTIL,
    )
    assert body["logs"] == "first\nsecond\n"
    assert (body["returned_first_ts"], body["returned_last_ts"]) == (_TS, last)
    assert body["lines_scanned"] == 2
    assert body["first_ts"] == _TS
    assert body["last_ts"] == last
    assert http.requests[0].url.params["since"] == "1788775200"
    assert "until" not in http.requests[0].url.params


@pytest.mark.parametrize(("max_matches", "expected"), [(None, 200), (5_000, 1_000), (0, 1)])
async def test_service_match_limit_preserves_scan_coverage(
    http: _MockPortainer,
    max_matches: int | None,
    expected: int,
) -> None:
    last = "2026-09-07T10:00:00.900000000Z"
    http.stream("/services/web/logs", _frame(_line("busy") * 1_200 + _line("last", last)))
    args = {"max_matches": max_matches} if max_matches is not None else {}
    body = await _call(
        create_server(enable_laravel_tools=False),
        "service_logs",
        service_id="web",
        since=_SINCE,
        until=_UNTIL,
        **args,
    )
    assert len(body["logs"].splitlines()) == expected
    assert body["logs"].endswith("last\n")
    assert body["returned_last_ts"] == last
    assert body["lines_scanned"] == 1_201
    assert body["last_ts"] == last
    assert body["truncated"] is True
    assert body["truncation_reason"] == "matches_limit"


@pytest.mark.parametrize("extra", [False, True])
async def test_bytes_limit_closes_stream_and_discards_cut_line(
    http: _MockPortainer,
    extra: bool,
) -> None:
    first = _frame(_line("ERROR first"))
    second = _frame(_line("ERROR second"))
    cap = len(first) + (len(second) - 2 if extra else 0)
    remainder = [second, _frame(_line("ERROR never read"))] if extra else []
    wire = http.stream("/containers/app/logs", first, *remainder)
    body = await _call(
        create_server(enable_laravel_tools=False),
        "container_logs_grep",
        container_id="app",
        pattern="ERROR",
        since=_SINCE,
        max_bytes=cap,
    )
    assert body["lines"] == ["ERROR first"]
    assert body["lines_scanned"] == 1
    assert body["bytes_read"] == cap
    assert body["truncated"] is extra
    assert body["truncation_reason"] == ("bytes_limit" if extra else None)
    assert wire.closed and wire.reads == (2 if extra else 1)


async def test_grep_window_context_and_secret_masking(http: _MockPortainer) -> None:
    http.stream(
        "/containers/app/logs",
        b"".join(
            map(
                _line,
                [
                    "before API_KEY=canary-context",
                    "ERROR password=canary-match",
                    "between",
                    "ERROR would exceed match limit",
                    "after",
                ],
            )
        ),
    )
    body = await _call(
        create_server(enable_laravel_tools=False),
        "container_logs_grep",
        container_id="app",
        since=_SINCE,
        pattern="^ERROR",
        context_lines=2,
        max_matches=1,
    )
    assert body["lines"] == ["before [REDACTED]", "ERROR [REDACTED]", "between"]
    assert body["truncation_reason"] == "matches_limit"
    assert body["matches_found"] == 2
    assert body["lines_scanned"] == 5


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("container_logs_grep", {"container_id": "app", "pattern": "x"}),
        ("service_logs", {"service_id": "demo_web"}),
        ("stack_logs_errors", {"stack_name": "demo"}),
        ("laravel_errors", {"stack_name": "demo"}),
    ],
)
async def test_tools_reject_inverted_fractional_bounds_before_http(
    http: _MockPortainer,
    name: str,
    args: dict[str, str],
) -> None:
    body = await _call(
        create_server(enable_laravel_tools=True),
        name,
        **args,
        since="2026-09-07T10:00:00.500000001Z",
        until="2026-09-07T10:00:00.5Z",
    )
    assert body == {"error": "Validation error", "details": "until must be at or after since"}
    assert http.requests == []


async def test_window_relative_and_unix_bounds_share_reference_time(
    http: _MockPortainer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("portainer_mcp.tools.logs.time.time_ns", lambda: 1_788_775_202_000_000_000)
    mcp = create_server(enable_laravel_tools=False)
    http.stream("/containers/app/logs", _line("match"))
    body = await _call(
        mcp,
        "container_logs_grep",
        container_id="app",
        pattern="match",
        since="2s",
        until="1s",
    )
    assert (body["since"], body["until"]) == ("1788775200", "1788775201")
    assert "match" in body["lines"]
    http.stream("/containers/app/logs", _line("match"))
    body = await _call(
        mcp,
        "container_logs_grep",
        container_id="app",
        pattern="match",
        since="1788775200",
        until="1788775201",
    )
    assert (body["since"], body["until"]) == ("1788775200", "1788775201")
    assert "match" in body["lines"]


async def test_log_window_tool_schema_exposes_default_budgets() -> None:
    tools = await create_server(enable_laravel_tools=True).list_tools()
    names = ("container_logs_grep", "service_logs", "stack_logs_errors", "laravel_errors")
    schemas = {tool.name: tool.inputSchema["properties"] for tool in tools}
    for name in names:
        props = schemas[f"portainer_{name}"]
        arg = "max_groups" if name == "laravel_errors" else "max_matches"
        if name == "service_logs":
            assert props["max_bytes"]["default"] is props[arg]["default"] is None
        else:
            assert props["max_bytes"]["default"] == 32 * 1024 * 1024
            assert props[arg]["default"] == 200


def _container(cid: str, service: str) -> dict[str, Any]:
    return {
        "Id": cid,
        "Names": [f"/demo-{cid}-1"],
        "Portainer": {"Agent": {"NodeName": f"node-{cid}"}},
        "Labels": {"com.docker.compose.project": "demo", "com.docker.compose.service": service},
    }


async def test_stack_byte_budget_is_shared_by_replicas_and_reset_per_service(
    http: _MockPortainer,
) -> None:
    http.replies["/containers/json"] = httpx.Response(
        200,
        json=[
            _container("a", "web"),
            _container("b", "web"),
            _container("c", "worker"),
            _container("d", "broken"),
        ],
    )
    first = _line("ERROR replica a")
    second = _line("ERROR replica b")
    worker = _line("ERROR worker TOKEN=canary")
    http.stream("/containers/a/logs", first)
    http.stream("/containers/b/logs", second, _line("ERROR beyond budget"))
    http.stream("/containers/c/logs", worker)
    http.replies["/containers/d/logs"] = httpx.Response(503, json={"message": "node offline"})
    cap = len(first) + len(second)
    body = await _call(
        create_server(enable_laravel_tools=False),
        "stack_logs_errors",
        stack_name="demo",
        since=_SINCE,
        until=_UNTIL,
        max_bytes=cap,
    )
    web, worker_logs = body["services"]["web"], body["services"]["worker"]
    assert web["bytes_read"] == cap and web["truncation_reason"] == "bytes_limit"
    assert web["errors"] == ["ERROR replica a", "ERROR replica b"]
    assert web["returned_first_ts"] == body["returned_last_ts"] == _TS
    assert worker_logs["truncated"] is False and worker_logs["bytes_read"] == len(worker)
    assert worker_logs["errors"] == ["ERROR worker [REDACTED]"]
    assert body["services"]["broken"]["containers_failed"] == ["demo-d-1"]
    assert body["lines_scanned"] == body["total_errors"] == 3
    assert body["truncation_reason"] == "bytes_limit"
    for request in http.requests[1:]:
        cid = request.url.path.split("/")[-2]
        assert request.headers["X-PortainerAgent-Target"] == f"node-{cid}"
        assert request.url.params["tail"] == "all"
        assert request.url.params["until"] == "1788775201"


async def test_stack_match_limit_is_global_with_independent_coverage(http: _MockPortainer) -> None:
    http.replies["/containers/json"] = httpx.Response(
        200,
        json=[
            _container("a", "web"),
            _container("b", "worker"),
        ],
    )
    http.stream("/containers/a/logs", _line("ERROR first"))
    http.stream("/containers/b/logs", _line("ERROR second"))
    body = await _call(
        create_server(enable_laravel_tools=False),
        "stack_logs_errors",
        stack_name="demo",
        since=_SINCE,
        max_matches=1,
    )
    services = body["services"].values()
    assert all(service["lines_scanned"] == 1 for service in services)
    assert sum(len(service["errors"]) for service in services) == 1
    assert body["lines_scanned"] == body["total_errors"] == 2
    assert body["truncation_reason"] == "matches_limit"


@pytest.mark.parametrize("max_groups", [1, 2])
async def test_laravel_combines_stderr_and_file_and_reports_missing_sources(
    http: _MockPortainer,
    max_groups: int,
) -> None:
    http.replies["/containers/json"] = httpx.Response(
        200,
        json=[
            _container("app", "backend"),
            _container("worker", "horizon"),
        ],
    )
    file_time = "2026-09-07T10:00:00.600000000+00:00"
    last_time = "2026-09-07T10:00:00.800000000Z"
    first = (
        "production.ERROR: password=canary "
        r'{"exception":"[object] (App\\DbError(code: 0): bad at /app/Db.php:7)"}'
    )
    entry = json.dumps(
        {
            "message": "canary-json",
            "level": 400,
            "context": {"exception": {"class": r"App\DbError", "file": "/app/Db.php:7"}},
        }
    )
    http.stream(
        "/containers/app/logs",
        _frame(_line(first), 2),
        _frame(_line(first), 1),
        _frame(_line(entry, last_time), 2),
    )
    http.stream(
        "/containers/worker/logs",
        _line(r"PHP Fatal error: Uncaught App\OtherError: failed in /app/Worker.php:5"),
    )
    for cid, exit_code in (("app", 0), ("worker", 3)):
        http.replies[f"/containers/{cid}/exec"] = httpx.Response(201, json={"Id": f"exec-{cid}"})
        http.replies[f"/exec/exec-{cid}/json"] = httpx.Response(200, json={"ExitCode": exit_code})
    file_wire = _frame(
        (
            f"[2026-09-07 09:59:59] {first}\n"
            f"[{file_time}] " + first.replace("bad at", "bad\n  at") + "\n[stacktrace]\n"
            f"[2026-09-07 10:00:02] {first}\n"
        ).encode()
    )
    info = _frame(b"PORTAINER_LARAVEL 1024 +0000\n")
    http.stream("/exec/exec-app/start", info[:5], info[5:] + file_wire[:31], file_wire[31:])
    http.stream("/exec/exec-worker/start")
    body = await _call(
        create_server(enable_laravel_tools=True),
        "laravel_errors",
        stack_name="demo",
        since=_SINCE,
        until=_UNTIL,
        max_groups=max_groups,
    )
    groups = [
        {
            "exception_class": r"App\DbError",
            "file_line": "/app/Db.php:7",
            "count": 3,
            "count_by_source": {"stderr": 2, "file": 1},
            "first_ts": _TS,
            "last_ts": last_time,
        },
        {
            "exception_class": r"App\OtherError",
            "file_line": "/app/Worker.php:5",
            "count": 1,
            "count_by_source": {"stderr": 1, "file": 0},
            "first_ts": _TS,
            "last_ts": _TS,
        },
    ]
    assert body["groups"] == groups[:max_groups]
    assert body["groups_truncated"] is (max_groups == 1)
    app, worker = (body["containers"][cid]["sources"] for cid in ("app", "worker"))
    assert app["docker"]["stream"] == "stderr" and app["docker"]["lines_scanned"] == 2
    assert app["laravel.log"]["status"] == "read" and app["laravel.log"]["first_ts"] == file_time
    assert worker["docker"]["stream"] == "tty_merged"
    assert worker["laravel.log"]["status"] == "missing"
    assert (body["since"], body["until"]) == ("1788775200.5", "1788775201")
    assert "canary" not in json.dumps(body)
    for request in http.requests[1:]:
        assert request.headers["X-PortainerAgent-Target"] in ("node-app", "node-worker")
        if request.url.path.endswith("/exec"):
            assert "/var/www/app/storage/logs/laravel.log" in json.loads(request.content)["Cmd"][2]


async def test_laravel_reports_file_cutoff_independently_of_stderr(http: _MockPortainer) -> None:
    http.replies["/containers/json"] = httpx.Response(200, json=[_container("app", "backend")])
    http.stream("/containers/app/logs", _frame(_line("routine"), 2))
    http.replies["/containers/app/exec"] = httpx.Response(201, json={"Id": "exec-app"})
    http.replies["/exec/exec-app/json"] = httpx.Response(200, json={"ExitCode": 0})
    wire = http.stream("/exec/exec-app/start", _frame(b"PORTAINER_LARAVEL 110 +0000\n" + b"x" * 64))
    body = await _call(
        create_server(enable_laravel_tools=True),
        "laravel_errors",
        stack_name="demo",
        since=_SINCE,
        max_bytes=64,
    )
    sources = body["containers"]["app"]["sources"]
    assert sources["docker"]["status"] == "read"
    assert sources["laravel.log"]["status"] == "partial"
    assert sources["laravel.log"]["truncation_reason"] == "bytes_limit"
    assert sources["laravel.log"]["first_ts"] is None
    assert wire.closed and wire.reads == 1


async def test_legacy_grep_stack_and_laravel_preserve_tail_and_output(http: _MockPortainer) -> None:
    mcp = create_server(enable_laravel_tools=True)
    path = "/containers/app/logs"
    http.stream(path, _frame(b"ERROR plain\n"))
    grep = await _call(mcp, "container_logs_grep", container_id="app", pattern="error", tail=5_000)
    assert grep == {
        "container_id": "app",
        "pattern": "error",
        "lines_scanned": 1,
        "matches_found": 1,
        "truncated": False,
        "lines": ["ERROR plain"],
    }
    assert http.requests[-1].url.params["tail"] == "1000"
    assert "timestamps" not in http.requests[-1].url.params
    http.replies["/containers/json"] = httpx.Response(
        200,
        json=[
            {
                "Id": "app",
                "Names": ["/demo_app"],
            }
        ],
    )
    http.stream(path, _frame(b"ERROR plain\n"))
    stack = await _call(mcp, "stack_logs_errors", stack_name="demo", tail=5_000)
    assert stack == {
        "stack": "demo",
        "containers_scanned": 1,
        "containers_failed": 0,
        "total_errors": 1,
        "truncated": False,
        "containers": {
            "demo_app": {
                "container_id": "app",
                "lines_scanned": 1,
                "errors_found": 1,
                "errors": ["ERROR plain"],
            }
        },
    }
    assert http.requests[-1].url.params["tail"] == "1000"
    http.replies["/containers/app/exec"] = httpx.Response(201, json={"Id": "file"})
    http.stream("/exec/file/start", _frame(b"production.ERROR: file error\n"))
    laravel = await _call(mcp, "laravel_errors", stack_name="demo", tail=5_000)
    assert laravel == {
        "stack": "demo",
        "containers_scanned": 1,
        "truncated": False,
        "log_path": "/var/www/app/storage/logs/laravel.log",
        "containers": {
            "demo_app": {
                "container_id": "app",
                "errors_found": 1,
                "errors": ["production.ERROR: file error"],
            }
        },
    }
    assert json.loads(http.requests[-2].content)["Cmd"][2].endswith("tail -200")


async def test_grep_window_regex_deadline_closes_response(
    http: _MockPortainer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("portainer_mcp.tools.containers._GREP_SCAN_TIMEOUT", 0.0)
    wire = http.stream("/containers/app/logs", _line("ERROR") * 256, b"unread")
    body = await _call(
        create_server(enable_laravel_tools=False),
        "container_logs_grep",
        container_id="app",
        since=_SINCE,
        pattern="ERROR",
    )
    assert body["truncated"] and body["truncation_reason"] == "regex_timeout"
    assert body["lines_scanned"] == 0 and body["lines"] == []
    assert wire.closed and wire.reads == 1


async def test_stream_auth_refresh_closes_rejected_body_before_retry() -> None:
    rejected = _Stream([b"do not buffer rejected body"])
    accepted = _Stream([_frame(_line("ERROR after retry"))])
    jwt_count = 0
    log_attempts = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal jwt_count
        path = request.url.path
        if path == "/api/auth":
            if jwt_count:
                assert rejected.closed and rejected.reads == 0
            jwt_count += 1
            return httpx.Response(200, json={"jwt": f"jwt-{jwt_count}"})
        if path == "/api/status":
            return httpx.Response(200, json={})
        assert path.endswith("/services/web/logs")
        log_attempts.append(request.headers["Authorization"])
        return (
            httpx.Response(401, stream=rejected)
            if jwt_count == 1
            else httpx.Response(200, stream=accepted)
        )

    client = client_mod.PortainerClient()
    await client._http.aclose()
    client._http = httpx.AsyncClient(
        base_url="https://portainer.test",
        transport=httpx.MockTransport(handler),
    )
    client_mod._client = client
    try:
        body = await _call(
            create_server(enable_laravel_tools=False),
            "service_logs",
            service_id="web",
            since=_SINCE,
            until=_UNTIL,
        )
        assert body["logs"] == "ERROR after retry\n"
        assert log_attempts == ["Bearer jwt-1", "Bearer jwt-2"]
        assert accepted.closed
    finally:
        await client.close()


@pytest.mark.parametrize(("tail", "expected"), [(1, 1), (5_000, 1_000)])
async def test_service_since_only_keeps_docker_tail_and_legacy_envelope(
    http: _MockPortainer,
    tail: int,
    expected: int,
) -> None:
    def logs(request: httpx.Request) -> httpx.Response:
        tail = int(request.url.params.get("tail", "0").replace("all", "0"))
        records = [b"old\n"] * 1_001 + [b"recent\n"]
        return httpx.Response(200, content=_frame(b"".join(records[-tail:])))

    http.replies["/services/web/logs"] = logs
    body = await _call(
        create_server(enable_laravel_tools=False),
        "service_logs",
        service_id="web",
        since="1788775200",
        tail=tail,
    )
    expected_logs = "old\n" * (expected - 1) + "recent\n"
    assert body == {
        "service": "web",
        "tail": expected,
        "since": "1788775200",
        "truncated": False,
        "total_chars": len(expected_logs),
        "logs": expected_logs,
    }
    assert http.requests[0].url.params["since"] == "1788775200"


@pytest.mark.parametrize("knob", [{"max_bytes": 1000}, {"max_matches": 200}])
async def test_service_explicit_budget_enables_window_without_until(
    http: _MockPortainer,
    knob: dict[str, int],
) -> None:
    http.stream("/services/web/logs", _frame(_line("recent")))
    body = await _call(
        create_server(enable_laravel_tools=False),
        "service_logs",
        service_id="web",
        since=_SINCE,
        **knob,
    )
    assert body["returned_last_ts"] == _TS
    assert http.requests[0].url.params["tail"] == "all"


@pytest.mark.parametrize("name", ["stack_logs_errors", "laravel_errors"])
async def test_empty_stack_window_reports_no_running_containers(
    http: _MockPortainer,
    name: str,
) -> None:
    http.replies["/containers/json"] = httpx.Response(200, json=[_container("other", "web")])
    body = await _call(
        create_server(enable_laravel_tools=True),
        name,
        stack_name="typo",
        since=_SINCE,
    )
    assert body["message"] == "No running containers found for stack 'typo'"
    assert body["returned_first_ts"] is body["returned_last_ts"] is None
    assert len(http.requests) == 1


async def test_grep_regex_timeout_keeps_completed_batches_with_full_budget_each(
    http: _MockPortainer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from portainer_mcp.tools import containers

    timeouts: list[float] = []
    real_scan = containers._grep_indices

    async def scan(regex: re.Pattern[str], lines: list[str], timeout: float) -> list[int]:
        timeouts.append(timeout)
        return await real_scan(regex, lines, timeout if len(timeouts) == 1 else 0)

    monkeypatch.setattr(containers, "_grep_indices", scan)
    first = "2026-09-07T10:00:00.600000000Z"
    second = "2026-09-07T10:00:00.900000000Z"
    wire = http.stream(
        "/containers/app/logs",
        _line("keep", first) * 128,
        _line("lose", second) * 128,
        b"unread",
    )
    body = await _call(
        create_server(enable_laravel_tools=False),
        "container_logs_grep",
        container_id="app",
        pattern="keep",
        since=_SINCE,
    )
    assert timeouts == [5, 5]
    assert body["lines_scanned"] == 128 and body["lines"] == ["keep"] * 128
    assert body["last_ts"] == body["returned_last_ts"] == first
    assert body["truncation_reason"] == "regex_timeout"
    assert wire.closed and wire.reads == 2


def _laravel_exception(stamp: str, site: str = "/app/Db.php:7") -> str:
    return (
        f"[{stamp}] production.ERROR: query "
        f'{{"exception":"[object] (DbError(code: 0): bad at {site})"}}\n'
    )


def _shell_file(
    http: _MockPortainer,
    cid: str,
    tz: str,
) -> None:
    # Run the exact command sent over MCP against a temporary file. Only the
    # Docker exec wrapper and transport are mocked.
    cmd: list[str] = []
    status: dict[str, int] = {}

    def create(request: httpx.Request) -> httpx.Response:
        cmd[:] = json.loads(request.content)["Cmd"]
        return httpx.Response(201, json={"Id": f"exec-{cid}"})

    def start(_: httpx.Request) -> httpx.Response:
        result = subprocess.run(cmd, env={**os.environ, "TZ": tz}, capture_output=True, check=False)
        status["ExitCode"] = result.returncode
        return httpx.Response(200, stream=_Stream([_frame(result.stdout)]))

    http.replies[f"/containers/{cid}/exec"] = create
    http.replies[f"/exec/exec-{cid}/start"] = start
    http.replies[f"/exec/exec-{cid}/json"] = lambda _: httpx.Response(200, json=status)


@pytest.mark.parametrize("since", ["2026-09-07T10:00:00Z", "2026-09-07T10:00:01Z"])
async def test_laravel_tails_file_discards_cut_record_and_reports_read_boundary(
    http: _MockPortainer,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    since: str,
) -> None:
    path = tmp_path / "laravel.log"
    good = _laravel_exception("2026-09-07 10:00:01")
    cut = _laravel_exception("2026-09-07 10:00:00", "/app/Discard.php:99")
    path.write_text("irrelevant\n" * 1000 + cut + good)
    monkeypatch.setattr("portainer_mcp.tools.laravel._LARAVEL_LOG_PATH", str(path))
    http.replies["/containers/json"] = httpx.Response(200, json=[_container("app", "backend")])
    http.stream("/containers/app/logs")
    _shell_file(http, "app", "UTC0")
    body = await _call(
        create_server(enable_laravel_tools=True),
        "laravel_errors",
        stack_name="demo",
        since=since,
        until="2026-09-07T10:00:02Z",
        max_bytes=len(good) + len(cut) - 10,
    )
    source = body["containers"]["app"]["sources"]["laravel.log"]
    assert source["read_from_ts"] == "2026-09-07 10:00:01"
    clipped = since.endswith("00Z")
    assert source["truncated"] is clipped
    assert source["truncation_reason"] == ("bytes_limit" if clipped else None)
    assert [group["file_line"] for group in body["groups"]] == ["/app/Db.php:7"]
    assert body["returned_first_ts"] == body["returned_last_ts"] == "2026-09-07T10:00:01Z"
    assert "tail -c " in json.loads(http.requests[2].content)["Cmd"][2]


@pytest.mark.parametrize(
    ("override", "container_tz", "offset"),
    [(None, "UTC-5", "+05:00"), ("Asia/Almaty", "UTC0", "+05:00"), ("-03:00", "UTC0", "-03:00")],
)
async def test_laravel_applies_container_offset_and_timezone_override(
    http: _MockPortainer,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    override: str | None,
    container_tz: str,
    offset: str,
) -> None:
    path = tmp_path / "laravel.log"
    local_hour = "15" if offset == "+05:00" else "07"
    path.write_text(_laravel_exception(f"2026-09-07 {local_hour}:00:01"))
    monkeypatch.setattr("portainer_mcp.tools.laravel._LARAVEL_LOG_PATH", str(path))
    http.replies["/containers/json"] = httpx.Response(200, json=[_container("app", "backend")])
    http.stream("/containers/app/logs")
    _shell_file(http, "app", container_tz)
    args = {"timezone": override} if override else {}
    body = await _call(
        create_server(enable_laravel_tools=True),
        "laravel_errors",
        stack_name="demo",
        since=_SINCE,
        until=_UNTIL,
        **args,
    )
    assert len(body["groups"]) == 1 and body["groups"][0]["count"] == 1
    source = body["containers"]["app"]["sources"]["laravel.log"]
    assert source["timezone_offset"] == offset
    assert body["returned_first_ts"] == body["returned_last_ts"] == _UNTIL
    assert "date +%z" in json.loads(http.requests[2].content)["Cmd"][2]


async def test_laravel_multiline_stderr_matches_file_and_keeps_only_primary_exception(
    http: _MockPortainer,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "laravel.log"
    entry = (
        '[2026-09-07 10:00:01] production.ERROR: Query failed {"exception":"[object] '
        "(DbError(code: 0): ERROR: relation widgets does not exist\n"
        "LINE 1: SELECT * FROM widgets\n ^\n at /app/Db.php:7)\n"
        "[previous exception] [object] (PDOException(code: 0): bad at /app/Db.php:42)\n"
        "[stacktrace]\n"
    )
    path.write_text(entry)
    monkeypatch.setattr("portainer_mcp.tools.laravel._LARAVEL_LOG_PATH", str(path))
    http.replies["/containers/json"] = httpx.Response(
        200,
        json=[_container("a", "web")],
    )
    http.stream(
        "/containers/a/logs",
        *(_frame(_line(line, _UNTIL), 2) for line in entry.splitlines()),
    )
    _shell_file(http, "a", "UTC0")
    body = await _call(
        create_server(enable_laravel_tools=True),
        "laravel_errors",
        stack_name="demo",
        since=_SINCE,
        until=_UNTIL,
    )
    assert len(body["groups"]) == 1
    group = body["groups"][0]
    assert (group["exception_class"], group["file_line"]) == ("DbError", "/app/Db.php:7")
    assert group["count"] == 2
    assert group["count_by_source"] == {"stderr": 1, "file": 1}


async def test_laravel_deduplicates_shared_file_without_collapsing_same_second_entries(
    http: _MockPortainer,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "laravel.log"
    entry = _laravel_exception("2026-09-07 10:00:01")
    path.write_text(entry * 2)
    monkeypatch.setattr("portainer_mcp.tools.laravel._LARAVEL_LOG_PATH", str(path))
    http.replies["/containers/json"] = httpx.Response(
        200,
        json=[_container("a", "web"), _container("b", "worker")],
    )
    for cid in ("a", "b"):
        http.stream(f"/containers/{cid}/logs")
        _shell_file(http, cid, "UTC0")
    body = await _call(
        create_server(enable_laravel_tools=True),
        "laravel_errors",
        stack_name="demo",
        since=_SINCE,
        until=_UNTIL,
    )
    assert len(body["groups"]) == 1
    group = body["groups"][0]
    assert group["count"] == 2
    assert group["count_by_source"] == {"stderr": 0, "file": 2}
