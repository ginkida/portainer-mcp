from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from test_log_windows import (
    _SINCE,
    _UNTIL,
    _call,
    _container,
    _frame,
    _laravel_exception,
    _line,
    _MockPortainer,
    _shell_file,
    _Stream,
)
from test_log_windows import (
    http as _http_fixture,
)

from portainer_mcp.server import create_server
from portainer_mcp.tools import laravel, logs

http = _http_fixture

_STAMP = "2026-09-07 10:00:01"
_ENTRY_EPOCH = int(datetime(2026, 9, 7, 10, 0, 1, tzinfo=timezone.utc).timestamp())


def _containers(http: _MockPortainer, *ids: str) -> None:
    http.replies["/containers/json"] = httpx.Response(
        200, json=[_container(cid, "backend") for cid in ids]
    )
    for cid in ids:
        http.stream(f"/containers/{cid}/logs")


def _write_log(path: Path, text: str, mtime_delta: int = 0) -> None:
    path.write_text(text, encoding="utf-8")
    mtime = _ENTRY_EPOCH + mtime_delta
    os.utime(path, (mtime, mtime))


def _scripted_file(http: _MockPortainer, cid: str, *frames: bytes, exit_code: int = 0) -> None:
    http.replies[f"/containers/{cid}/exec"] = httpx.Response(201, json={"Id": f"exec-{cid}"})
    http.stream(f"/exec/exec-{cid}/start", *frames)
    http.replies[f"/exec/exec-{cid}/json"] = httpx.Response(200, json={"ExitCode": exit_code})


@pytest.fixture
def laravel_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "laravel.log"
    monkeypatch.setattr("portainer_mcp.tools.laravel._LARAVEL_LOG_PATH", str(path))
    return path


async def _laravel_window(
    *,
    since: str = _SINCE,
    until: str = _UNTIL,
    **options: str | int,
) -> dict[str, Any]:
    return await _call(
        create_server(enable_laravel_tools=True),
        "laravel_errors",
        stack_name="demo",
        since=since,
        until=until,
        **options,
    )


@pytest.mark.parametrize(
    ("newest", "mtime_delta", "container_tz", "offset", "source"),
    [
        pytest.param("2026-09-07 15:00:01", 0, "UTC0", "+05:00", "file_mtime", id="app-plus-five"),
        pytest.param(_STAMP, 0, "UTC-5", "+00:00", "file_mtime", id="app-utc"),
        pytest.param("2026-09-07 15:00:01", 3, "UTC0", "+05:00", "file_mtime", id="3s-late"),
        pytest.param("2026-09-07 15:00:01", 5, "UTC0", "+05:00", "file_mtime", id="5s-late"),
        pytest.param("2026-09-07 15:00:01", 6, "UTC-5", "+05:00", "container", id="6s-late"),
        pytest.param("2026-09-07 15:00:01", 90, "UTC-5", "+05:00", "container", id="90s-late"),
        pytest.param("2026-09-07 15:45:01", 0, "UTC0", "+05:45", "file_mtime", id="quarter-hour"),
        pytest.param("2026-09-07 15:00:01", 120, "UTC-5", "+05:00", "container", id="120s-late"),
        pytest.param("2026-09-07 15:00:01", 121, "UTC-5", "+05:00", "container", id="121s-late"),
        pytest.param("2026-09-07 15:00:01", 420, "UTC-5", "+05:00", "container", id="7m-late"),
        pytest.param(
            "2026-09-07T10:00:01+00:00", 0, "UTC-5", "+05:00", "container", id="aware-stamp"
        ),
        pytest.param("2026-09-08 00:00:01", 0, "UTC0", "+14:00", "file_mtime", id="14h-offset"),
        pytest.param(_STAMP, -14 * 3600 - 900, "UTC0", "+00:00", "container", id="over-14h"),
    ],
)
async def test_file_timezone_from_newest_stamp_and_mtime(
    http: _MockPortainer,
    laravel_log: Path,
    newest: str,
    mtime_delta: int,
    container_tz: str,
    offset: str,
    source: str,
) -> None:
    older = "[2026-09-06 10:00:01] production.INFO: started\n"
    _write_log(laravel_log, older + _laravel_exception(newest), mtime_delta)
    _containers(http, "app")
    _shell_file(http, "app", container_tz)

    body = await _laravel_window()

    file = body["containers"]["app"]["sources"]["laravel.log"]
    assert file["status"] == "read"
    assert file["timezone_offset"] == offset
    assert file["timezone_source"] == source
    (group,) = body["groups"]
    assert group["count_by_source"] == {"stderr": 0, "file": 1}
    assert group["first_ts"] == group["last_ts"] == "2026-09-07T10:00:01Z"


@pytest.mark.parametrize(
    "continuation",
    [
        pytest.param("[2026-09-07 10:15:01] quoted output", id="quoted-timestamp"),
        # A header needs a real Monolog level, not just "channel.WORD:".
        pytest.param("[2026-09-07 10:15:01] production.OUTPUT: quoted output", id="unknown-level"),
        # A trailing line that starts like a JSON record makes the probe give up
        # on the mtime (see test_file_newest_json_record_disables_mtime_inference):
        # the conservative direction, so it is not a case of this test.
    ],
)
async def test_file_uses_newest_entry_header_ignoring_continuations(
    http: _MockPortainer,
    laravel_log: Path,
    continuation: str,
) -> None:
    entry = _laravel_exception("2026-09-07 15:00:01").replace("bad at", "bad\n[1] => foo\n at")
    _write_log(laravel_log, entry + continuation + "\n")
    _containers(http, "app")
    _shell_file(http, "app", "UTC0")

    body = await _laravel_window()

    file = body["containers"]["app"]["sources"]["laravel.log"]
    assert file["status"] == "read"
    assert (file["timezone_source"], file["timezone_offset"]) == ("file_mtime", "+05:00")
    (group,) = body["groups"]
    assert group["file_line"] == "/app/Db.php:7"
    assert group["count_by_source"] == {"stderr": 0, "file": 1}
    assert group["first_ts"] == group["last_ts"] == _UNTIL


async def test_file_newest_json_record_disables_mtime_inference(
    http: _MockPortainer,
    laravel_log: Path,
) -> None:
    json_stamp = "2026-09-07T10:15:01"
    newest = json.dumps(
        {
            "message": "query",
            "datetime": f"{json_stamp}+00:00",
            "context": {"exception": {"class": "DbError", "file": "/app/Db.php:7"}},
        }
    )
    _write_log(laravel_log, _laravel_exception(_STAMP) + newest + "\n", mtime_delta=900)
    _containers(http, "app")
    _shell_file(http, "app", "UTC0")

    body = await _laravel_window(until=f"{json_stamp}Z")

    file = body["containers"]["app"]["sources"]["laravel.log"]
    assert file["status"] == "read"
    assert (file["timezone_source"], file["timezone_offset"]) == ("container", "+00:00")
    (group,) = body["groups"]
    assert group["count_by_source"] == {"stderr": 0, "file": 2}
    assert (group["first_ts"], group["last_ts"]) == (_UNTIL, f"{json_stamp}Z")


async def test_timezone_argument_overrides_mtime_and_container(
    http: _MockPortainer,
    laravel_log: Path,
) -> None:
    # The mtime implies +05:00 and the container uses UTC. Only -03:00
    # places the entry inside the requested UTC window.
    _write_log(laravel_log, _laravel_exception("2026-09-07 07:00:01"), -8 * 3600)
    _containers(http, "app")
    _shell_file(http, "app", "UTC0")

    body = await _laravel_window(timezone="-03:00")

    file = body["containers"]["app"]["sources"]["laravel.log"]
    assert file["timezone_offset"] == "-03:00"
    assert file["timezone_source"] == "argument"
    (group,) = body["groups"]
    assert group["count_by_source"] == {"stderr": 0, "file": 1}


async def test_file_only_group_reports_first_and_last_instants_in_utc(
    http: _MockPortainer,
    laravel_log: Path,
) -> None:
    first = _laravel_exception("2026-09-07 15:00:01")
    last = _laravel_exception("2026-09-07 15:00:02")
    _write_log(laravel_log, first + last, mtime_delta=1)
    _containers(http, "app")
    _shell_file(http, "app", "UTC0")

    body = await _laravel_window(until="2026-09-07T10:00:03Z")

    (group,) = body["groups"]
    assert group["count_by_source"] == {"stderr": 0, "file": 2}
    assert group["first_ts"] == "2026-09-07T10:00:01Z"
    assert group["last_ts"] == "2026-09-07T10:00:02Z"


async def test_overlong_timezone_is_rejected_before_http_without_echo(http: _MockPortainer) -> None:
    value = "timezone-canary".ljust(65, "x")

    body = await _laravel_window(timezone=value)

    assert body["error"] == "Validation error"
    assert "too long" in body["details"]
    assert "timezone-canary" not in json.dumps(body)
    assert http.requests == []


def _shell_file_in_directory(
    http: _MockPortainer, monkeypatch: pytest.MonkeyPatch, cid: str, directory: Path
) -> None:
    _shell_file(http, cid, "UTC0")
    route = f"/exec/exec-{cid}/start"
    start = http.replies[route]
    assert callable(start)

    def start_in_directory(request: httpx.Request) -> httpx.Response:
        # Model each container's filesystem by running the unchanged command
        # from the directory that contains its laravel.log.
        with monkeypatch.context() as context:
            context.chdir(directory)
            return start(request)

    http.replies[route] = start_in_directory


@pytest.mark.parametrize(
    ("shared", "count"), [(True, 3), (False, 5)], ids=["shared-file", "separate-files"]
)
async def test_file_entry_multiplicity_across_replicas(
    http: _MockPortainer,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    shared: bool,
    count: int,
) -> None:
    entry = _laravel_exception(_STAMP)
    startup = f"[{_STAMP}] production.INFO: " + "x" * 256 + "\n"
    _write_log(tmp_path / "laravel.log", startup + entry * 3)
    second = tmp_path
    if not shared:
        second = tmp_path / "replica"
        second.mkdir()
        # Same head bytes, size and mtime, but distinct inodes.
        first_line = f"[{_STAMP}] production.INFO: replica startup".ljust(len(entry) - 1) + "\n"
        _write_log(second / "laravel.log", startup + first_line + entry * 2)
    monkeypatch.setattr("portainer_mcp.tools.laravel._LARAVEL_LOG_PATH", "laravel.log")
    _containers(http, "a", "b")
    _shell_file_in_directory(http, monkeypatch, "a", tmp_path)
    _shell_file_in_directory(http, monkeypatch, "b", second)

    body = await _laravel_window()

    for cid in ("a", "b"):
        assert body["containers"][cid]["sources"]["laravel.log"]["status"] == "read"
    (group,) = body["groups"]
    assert group["file_line"] == "/app/Db.php:7"
    assert group["count"] == count
    assert group["count_by_source"] == {"stderr": 0, "file": count}


@pytest.mark.parametrize("checksum", ["4294967295:0", "unknown:0"])
async def test_file_without_usable_checksum_is_not_deduplicated(
    http: _MockPortainer,
    checksum: str,
) -> None:
    _containers(http, "a", "b")
    content = _laravel_exception(_STAMP).encode()
    info = f"PORTAINER_LARAVEL {len(content)} {_ENTRY_EPOCH} 42 +0000 {checksum}\n"
    for cid in ("a", "b"):
        _scripted_file(http, cid, _frame(info.encode() + content))

    body = await _laravel_window()

    for cid in ("a", "b"):
        assert body["containers"][cid]["sources"]["laravel.log"]["status"] == "read"
    (group,) = body["groups"]
    assert group["count_by_source"] == {"stderr": 0, "file": 2}


async def test_docker_read_error_keeps_complete_stderr_record_and_redacts_reason(
    http: _MockPortainer,
    laravel_log: Path,
) -> None:
    _write_log(laravel_log, _laravel_exception(_STAMP))
    _containers(http, "app")
    _shell_file(http, "app", "UTC0")

    def chunks() -> Iterator[bytes]:
        yield _frame(_line("PHP Fatal error: Uncaught DbError: bad in /app/Stderr.php:8"), 2)
        raise httpx.ReadError("stream interrupted password=hunter2")

    stream = _Stream(chunks())
    http.replies["/containers/app/logs"] = httpx.Response(200, stream=stream)

    body = await _laravel_window()

    sources = body["containers"]["app"]["sources"]
    assert sources["docker"]["status"] == "error"
    assert "stream interrupted" in sources["docker"]["error"]
    assert sources["laravel.log"]["status"] == "read"
    assert len(body["groups"]) == 2
    assert {group["file_line"]: group["count_by_source"] for group in body["groups"]} == {
        "/app/Stderr.php:8": {"stderr": 1, "file": 0},
        "/app/Db.php:7": {"stderr": 0, "file": 1},
    }
    assert "hunter2" not in json.dumps(body)


@pytest.mark.parametrize(
    ("error_kind", "reason"), [("value-error", "exec-create failed"), ("html", "non-JSON 200")]
)
async def test_exec_create_failure_keeps_other_container_and_redacts_reason(
    http: _MockPortainer,
    laravel_log: Path,
    error_kind: str,
    reason: str,
) -> None:
    _write_log(laravel_log, _laravel_exception(_STAMP))
    _containers(http, "broken", "app")
    _shell_file(http, "app", "UTC0")

    def failed_create(_: httpx.Request) -> httpx.Response:
        if error_kind == "value-error":
            raise ValueError("exec-create failed password=hunter2")
        return httpx.Response(200, html="<html>proxy login password=hunter2 </html>")

    http.replies["/containers/broken/exec"] = failed_create

    body = await _laravel_window()

    file = body["containers"]["broken"]["sources"]["laravel.log"]
    assert file["status"] == "error"
    assert reason in file["error"]
    assert body["containers"]["app"]["sources"]["laravel.log"]["status"] == "read"
    (group,) = body["groups"]
    assert group["file_line"] == "/app/Db.php:7"
    assert group["count_by_source"] == {"stderr": 0, "file": 1}
    assert "hunter2" not in json.dumps(body)


@pytest.mark.parametrize(
    "suffix",
    [
        pytest.param("", id="message"),
        pytest.param(
            "\n[stacktrace]\n#0 /vendor/trace.php(5): log('warning at /vendor/x.php:5)')",
            id="stacktrace",
        ),
        pytest.param(
            "\n[previous exception] [object] (OtherError(code: 0): bad at /vendor/x.php:5)",
            id="previous-multiline",
        ),
        pytest.param(
            r"\n[previous exception] [object] (OtherError(code: 0): bad at /vendor/x.php:5)",
            id="previous-escaped",
        ),
    ],
)
async def test_monolog_groups_by_primary_exception_site(
    http: _MockPortainer,
    laravel_log: Path,
    suffix: str,
) -> None:
    entry = (
        f'[{_STAMP}] production.ERROR: query {{"exception":"[object] '
        f'(DbError(code: 0): message points at /evil.php:1) at /app/Real.php:9){suffix}"}}\n'
    )
    _write_log(laravel_log, entry)
    _containers(http, "app")
    _shell_file(http, "app", "UTC0")

    body = await _laravel_window()

    (group,) = body["groups"]
    assert (group["exception_class"], group["file_line"]) == ("DbError", "/app/Real.php:9")
    assert group["count_by_source"] == {"stderr": 0, "file": 1}


@pytest.mark.parametrize(
    ("since", "status", "reason", "sites"),
    [
        pytest.param(_UNTIL, "partial", "bytes_limit", ["/app/Db.php:7"], id="same-second"),
        pytest.param(
            "2026-09-07T10:00:01.5Z", "partial", "bytes_limit", [], id="half-second-later"
        ),
        pytest.param(
            "2026-09-07T10:00:05.5Z", "partial", "bytes_limit", [], id="inside-order-slack"
        ),
        pytest.param("2026-09-07T10:00:06.5Z", "read", None, [], id="outside-order-slack"),
    ],
)
async def test_file_tail_cutoff_at_since_with_second_resolution(
    http: _MockPortainer,
    laravel_log: Path,
    since: str,
    status: str,
    reason: str | None,
    sites: list[str],
) -> None:
    cut = _laravel_exception(_STAMP, "/app/Cut.php:8")
    kept = _laravel_exception(_STAMP)
    _write_log(laravel_log, cut + kept)
    _containers(http, "app")
    _shell_file(http, "app", "UTC0")

    body = await _laravel_window(
        since=since, until="2026-09-07T10:00:07Z", max_bytes=len(cut + kept) - 10
    )

    file = body["containers"]["app"]["sources"]["laravel.log"]
    assert file["read_from_ts"] == _STAMP
    assert file["status"] == status
    assert file["truncated"] is (status == "partial")
    assert file["truncation_reason"] == reason
    assert [group["file_line"] for group in body["groups"]] == sites


async def test_file_symlink_uses_target_size_for_tail_cutoff(
    http: _MockPortainer,
    laravel_log: Path,
) -> None:
    target = laravel_log.with_name("target.log")
    kept = _laravel_exception(_STAMP)
    _write_log(target, "old output\n" * 100 + kept)
    laravel_log.symlink_to(target.name)
    _containers(http, "app")
    _shell_file(http, "app", "UTC0")

    body = await _laravel_window(max_bytes=len(kept) + 10)

    file = body["containers"]["app"]["sources"]["laravel.log"]
    assert file["status"] == "partial" and file["truncated"] is True
    assert file["truncation_reason"] == "bytes_limit" and file["read_from_ts"] == _STAMP
    (group,) = body["groups"]
    assert group["count_by_source"] == {"stderr": 0, "file": 1}


async def test_file_unknown_container_offset_uses_utc_for_naive_entries(
    http: _MockPortainer,
) -> None:
    _containers(http, "app")
    aware = "2026-09-07T15:00:02+05:00"
    content = (_laravel_exception(_STAMP) + _laravel_exception(aware)).encode()
    info = (
        f"PORTAINER_LARAVEL {len(content)} {_ENTRY_EPOCH + 1} 42 unknown 77:{len(content)} "
        f"[{aware}] production.ERROR:\n"
    )
    _scripted_file(http, "app", _frame(info.encode() + content))

    body = await _laravel_window(until="2026-09-07T10:00:02Z")

    file = body["containers"]["app"]["sources"]["laravel.log"]
    assert file["status"] == "read"
    assert (file["timezone_source"], file["timezone_offset"]) == ("assumed_utc", "+00:00")
    (group,) = body["groups"]
    assert group["count_by_source"] == {"stderr": 0, "file": 2}
    assert (group["first_ts"], group["last_ts"]) == (_UNTIL, "2026-09-07T10:00:02Z")


async def test_file_exec_error_reports_exit_code_and_stderr(http: _MockPortainer) -> None:
    _containers(http, "app")
    _scripted_file(
        http,
        "app",
        _frame(b"PORTAINER_LARAVEL 110 1 42 +0000 77:110\n"),
        _frame(b"sh: tail: not found\n", 2),
        exit_code=127,
    )

    body = await _laravel_window()

    file = body["containers"]["app"]["sources"]["laravel.log"]
    assert file["status"] == "error"
    assert "exit code 127" in file["error"] and "sh: tail: not found" in file["error"]


_STDERR_EXCEPTION = (
    'production.ERROR: boom {"exception":"[object] '
    r'(App\\DbError(code: 0): bad at /app/Db.php:7)"}'
)


async def test_max_bytes_ceiling_reaches_docker_stream_and_file_tail(
    http: _MockPortainer, laravel_log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _frame(_line(_STDERR_EXCEPTION), 2)
    monkeypatch.setattr(logs, "_MAX_LOG_BYTES", len(first))
    _write_log(laravel_log, _laravel_exception(_STAMP))
    _containers(http, "app")
    http.stream("/containers/app/logs", first, _frame(_line("x" * 500), 2))
    _shell_file(http, "app", "UTC0")

    body = await _laravel_window(max_bytes=10**30)

    docker = body["containers"]["app"]["sources"]["docker"]
    assert docker["bytes_read"] == len(first)
    assert (docker["status"], docker["truncation_reason"]) == ("partial", "bytes_limit")
    commands = [
        json.loads(request.content)["Cmd"][2]
        for request in http.requests
        if request.url.path.endswith("/exec")
    ]
    assert len(commands) == 1 and f"tail -c {len(first)} " in commands[0]


async def test_call_deadline_stops_both_sources_and_keeps_what_was_read(
    http: _MockPortainer, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = 50.0
    clock = SimpleNamespace(time_ns=time.time_ns, monotonic=lambda: now)
    monkeypatch.setattr(logs, "time", clock)
    monkeypatch.setattr(laravel, "time", clock)
    _containers(http, "app")

    def chunks() -> Iterator[bytes]:
        nonlocal now
        yield _frame(_line(_STDERR_EXCEPTION), 2)
        now += 301
        yield _frame(_line("production.ERROR: never read"), 2)

    http.replies["/containers/app/logs"] = httpx.Response(200, stream=_Stream(chunks()))
    body = await _laravel_window()

    sources = body["containers"]["app"]["sources"]
    assert (sources["docker"]["status"], sources["docker"]["truncation_reason"]) == (
        "partial",
        "time_limit",
    )
    assert sources["docker"]["lines_scanned"] == 1
    # The deadline has elapsed before the file source starts.
    assert (sources["laravel.log"]["status"], sources["laravel.log"]["truncation_reason"]) == (
        "partial",
        "time_limit",
    )
    assert [request.url.path.rsplit("/docker", 1)[1] for request in http.requests] == [
        "/containers/json",
        "/containers/app/logs",
    ]
    assert [(g["file_line"], g["count_by_source"]) for g in body["groups"]] == [
        ("/app/Db.php:7", {"stderr": 1, "file": 0})
    ]
