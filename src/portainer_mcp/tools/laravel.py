from __future__ import annotations

import asyncio
import json
import logging
import re
import shlex
import time
from collections import deque
from collections.abc import Callable
from contextlib import aclosing
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any
from urllib.parse import quote
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from mcp.server.fastmcp import FastMCP

from ..client import PortainerClient, get_client
from ..config import get_config
from ..errors import PortainerResponseError, redact_secrets, resolve_endpoint, tool_error_handler
from .containers import (
    _ERROR_LINE_RE,
    _MAX_STACK_TARGETS,
    _STACK_FANOUT_LIMIT,
    _STACK_NAME_RE,
    _cap_lines,
    _parse_docker_stream,
    _stack_targets,
    _validate_container_id,
    _window_stack_targets,
    _WindowTarget,
)
from .logs import (
    _DEFAULT_LOG_BYTES,
    _DEFAULT_LOG_MATCHES,
    _MAX_LOG_CHARS,
    _NS,
    _clamp_bytes,
    _clamp_matches,
    _docker_window_lines,
    _iso_ns,
    _LogCoverage,
    _LogWindow,
    _read_log_lines,
)

logger = logging.getLogger(__name__)

# Opinionated helpers for Laravel stacks (a `backend` service with the app at
# /var/www/app). They are registered only when PORTAINER_ENABLE_LARAVEL_TOOLS
# is true — on other infrastructures they are just noise in the tool list.
_LARAVEL_LOG_PATH = "/var/www/app/storage/logs/laravel.log"
_MAX_LARAVEL_GROUP_KEYS = 10_000
_MAX_FILE_RECORD_KEYS = 100_000
_CHANNEL_HEADER = r"[\w.-]+\.(?:DEBUG|INFO|NOTICE|WARNING|ERROR|CRITICAL|ALERT|EMERGENCY):"
_FILE_TIMESTAMP_RE = re.compile(rf"^\[([\dT:.+ Z-]{{19,40}})\] (?={_CHANNEL_HEADER})")
_STDERR_HEADER_RE = re.compile(rf"^(?:{_CHANNEL_HEADER}|PHP Fatal error:|Fatal error:|Uncaught )")
# Printed by the exec before the file tail: size, mtime, inode, the container's
# UTC offset, "crc:length" of the file head, then the newest entry header.
_FILE_INFO_RE = re.compile(
    r"^PORTAINER_LARAVEL (\d{1,20}) (\d{1,20}) (\d{1,20}) (\S{1,16}) (\S{1,40})(?: (.*))?$"
)
_NEWEST_STAMP_RE = re.compile(r"\[([\dT:.+ Z-]{19,40})\] ")
_AWARE_STAMP_RE = re.compile(r"(?:Z|[+-]\d\d:?\d\d)$")
_UTC_OFFSET_RE = re.compile(r"([+-])([01]\d|2[0-3]):?([0-5]\d)")
# Bytes of the file head that, with the inode, identify a log file shared by
# several replicas.
_FILE_HEAD_BYTES = 256
# How far back the exec looks for the newest entry header.
_LAST_STAMP_TAIL_BYTES = 262_144
# Slack between the newest entry's stamp and the file's mtime. Monolog writes
# an entry as soon as it is stamped; a wide tolerance would accept an unrelated
# stamp (an older entry, a touched file) about as often as it rejects one.
_MTIME_TOLERANCE_SECONDS = 5
# Workers stamp an entry, then take the file lock: entries can land a little
# out of timestamp order, so a cut just before `since` proves nothing.
_FILE_ORDER_SLACK_NS = 5 * _NS
_MAX_TIMEZONE_CHARS = 64
_MAX_REASON_CHARS = 300
_EXCEPTION_CLASS = r"[\w\\]{1,255}"
_EXCEPTION_LOCATION = r"(?P<file>/[^\r\n:]{1,512}):(?P<line>[0-9]{1,10})"
_MONOLOG_EXCEPTION_RE = re.compile(
    rf"\[object\] \((?P<class>{_EXCEPTION_CLASS})\(code: [^)]{{1,32}}\): "
)
_MONOLOG_LOCATION_RE = re.compile(rf" at {_EXCEPTION_LOCATION}(?=\)|\\n|$)")
_PHP_EXCEPTION_RE = re.compile(rf"\bUncaught (?P<class>{_EXCEPTION_CLASS}): ")
_PHP_LOCATION_RE = re.compile(rf" in {_EXCEPTION_LOCATION}(?=\s|$)")
_JSON_LOCATION_RE = re.compile(_EXCEPTION_LOCATION)
_EXCEPTION_CLASS_RE = re.compile(_EXCEPTION_CLASS)


def _laravel_record(text: str) -> tuple[str | None, str, dict[str, Any]]:
    """Return the file timestamp, record text and optional Monolog JSON object."""
    if match := _FILE_TIMESTAMP_RE.match(text):
        return match[1], text[match.end() :], {}
    if text.startswith("{") and len(text) <= _MAX_LOG_CHARS:
        try:
            entry = json.loads(text)
        except (ValueError, RecursionError):
            pass
        else:
            if isinstance(entry, dict):
                dt = entry.get("datetime")
                return dt if isinstance(dt, str) else None, text, entry
    return None, text, {}


def _exception_site(text: str, entry: dict[str, Any]) -> tuple[str, str, int] | None:
    if entry:
        context = entry.get("context")
        exception = context.get("exception") if isinstance(context, dict) else None
        if isinstance(exception, dict):
            cls, path = exception.get("class"), exception.get("file")
            if (
                isinstance(cls, str)
                and _EXCEPTION_CLASS_RE.fullmatch(cls)
                and isinstance(path, str)
                and (match := _JSON_LOCATION_RE.fullmatch(path))
            ):
                return cls, match["file"], int(match["line"])
    # Only look for the logged exception header, ignoring stacktrace frames.
    if start := _MONOLOG_EXCEPTION_RE.search(text):
        # Monolog prints "(Class(code: N): <message> at /file:line)". The
        # message is free text and may itself contain " at /x:1)", so the
        # location is the LAST match before the trace or a chained exception.
        end = len(text)
        for marker in ("[stacktrace]", "[previous exception]"):
            found = text.find(marker, start.end())
            if found != -1:
                end = min(end, found)
        last = deque(_MONOLOG_LOCATION_RE.finditer(text, start.end(), end), maxlen=1)
        if last:
            return start["class"].replace("\\\\", "\\"), last[0]["file"], int(last[0]["line"])
    start = _PHP_EXCEPTION_RE.search(text)
    if start and (site := _PHP_LOCATION_RE.search(text, pos=start.end())):
        return start["class"].replace("\\\\", "\\"), site["file"], int(site["line"])
    return None


class _LaravelRecords:
    """Assemble one bounded record at a time for a file or container stream."""

    def __init__(self, record: Callable[[str, dict[str, Any], int, str], None]) -> None:
        self._record = record
        self._stamp: tuple[int, str] | None = None
        self._parts: list[str] = []
        self._remaining = 0

    def start(self, text: str, entry: dict[str, Any], ns: int, stamp: str) -> None:
        self.finish()
        if entry:
            self._record(text, entry, ns, stamp)
        else:
            self._stamp = (ns, stamp)
            self.append(text)

    def append(self, line: str) -> None:
        if self._stamp is None:
            return
        if line.lstrip().startswith(("[stacktrace]", "[previous exception]")):
            self.finish()
        elif not self._parts or self._remaining > 0:
            remaining = self._remaining if self._parts else _MAX_LOG_CHARS
            self._parts.append(line[:remaining])
            self._remaining = remaining - len(line) - 1

    def finish(self) -> None:
        if self._stamp is not None:
            self._record("\n".join(self._parts), {}, *self._stamp)
        self._stamp = None
        self._parts.clear()


# (file identity, entry time, exception site) — one logged event in one file.
_FileKey = tuple[str, int, tuple[str, str, int]]


@dataclass
class _ExceptionGroup:
    first: tuple[int, str]
    last: tuple[int, str]
    counts: dict[str, int] = field(default_factory=lambda: {"stderr": 0, "file": 0})

    @property
    def count(self) -> int:
        return self.counts["stderr"] + self.counts["file"]


def _log_timezone(value: str) -> tzinfo:
    if len(value) > _MAX_TIMEZONE_CHARS:
        raise ValueError("Invalid timezone: too long")
    if match := _UTC_OFFSET_RE.fullmatch(value):
        offset = timedelta(hours=int(match[2]), minutes=int(match[3]))
        return timezone(-offset if match[1] == "-" else offset)
    try:
        return ZoneInfo(value)
    except (ValueError, ZoneInfoNotFoundError):
        raise ValueError(f"Invalid timezone: {value!r}. Use an IANA name or UTC offset.") from None


def _mtime_offset(last: str | None, mtime: int) -> tzinfo | None:
    """UTC offset implied by the newest naive entry stamp and the file's mtime.

    Monolog stamps an entry in Laravel's ``app.timezone`` and writes it at
    once, so the newest stamp read as UTC differs from the mtime by exactly
    that zone's offset. The container's own ``date +%z`` says nothing about
    ``app.timezone`` — an image with ``TZ`` set and the default ``UTC`` app
    zone (or the reverse) would shift every entry out of the window.
    """
    if not last or _AWARE_STAMP_RE.search(last):
        return None
    try:
        wall = _iso_ns(last, timezone.utc) // _NS
    except ValueError:
        return None
    seconds = round((wall - mtime) / 900) * 900
    if abs(wall - mtime - seconds) > _MTIME_TOLERANCE_SECONDS or abs(seconds) > 14 * 3600:
        return None
    return timezone(timedelta(seconds=seconds))


def _failure_reason(exc: Exception) -> str:
    return redact_secrets(str(exc))[:_MAX_REASON_CHARS] or type(exc).__name__


def _utc_timestamp(ns: int) -> str:
    seconds, fraction = divmod(ns, _NS)
    stamp = datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    return (f"{stamp}.{fraction:09d}".rstrip("0") if fraction else stamp) + "Z"


async def _file_window(
    client: PortainerClient,
    base: str,
    target: _WindowTarget,
    coverage: _LogCoverage,
    timeout: float,
    record: Callable[[str, str, dict[str, Any], int, str], None],
    zone_override: tzinfo | None,
) -> dict[str, Any]:
    no_source = {"read_from_ts": None, "timezone_offset": None, "timezone_source": None}
    if coverage.deadline is not None and time.monotonic() >= coverage.deadline:
        # Out of time before this source started: don't exec in the container.
        coverage.stop_reason = "time_limit"
        return {"status": "partial", **no_source, **coverage.summary()}

    # stat and tail can seek directly on regular files, including with BusyBox.
    # Only a fixed path and integer sizes are interpolated into the shell.
    # Every helper is optional except stat and tail: a missing date, head,
    # cksum or grep degrades the metadata, never the read.
    log_path = shlex.quote(_LARAVEL_LOG_PATH)
    tail_bytes = coverage.max_bytes
    # The newest record of either format: a line-format header, or the start
    # of a Monolog JSON record (which carries its own offset — if that is the
    # newest one, the mtime says nothing about the line-format entries).
    newest_header = (
        r"^(\[[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.+Z-]{8,30}\] [A-Za-z0-9_.-]+\."
        r"(DEBUG|INFO|NOTICE|WARNING|ERROR|CRITICAL|ALERT|EMERGENCY):"
        r'|\{")'
    )
    cmd = (
        f"if [ -f {log_path} ]; then "
        # -L: the size must be the file tail reads, not a symlink's own.
        f"meta=$(stat -L -c '%s %Y %i' {log_path} 2>/dev/null "
        f"|| stat -L -f '%z %m %i' {log_path}) || exit 1; "
        "offset=$(date +%z); "
        f"set -- $(head -c {_FILE_HEAD_BYTES} {log_path} | cksum); "
        'crc="${1:-unknown}:${2:-0}"; '
        # Only a real entry header counts — a bracketed date quoted inside a
        # multi-line message must not pass for the newest entry.
        f"last=$(tail -c {_LAST_STAMP_TAIL_BYTES} {log_path} | "
        f"grep -a -E -o '{newest_header}' | tail -n 1); "
        'printf "PORTAINER_LARAVEL %s %s %s %s\\n" '
        '"$meta" "${offset:-unknown}" "$crc" "$last"; '
        f"exec tail -c {tail_bytes} {log_path}; "
        f"elif [ -e {log_path} ]; then exit 4; else exit 3; fi"
    )
    headers = target.headers
    created = await client.post(
        f"{base}/containers/{quote(target.id, safe='')}/exec",
        headers=headers,
        json={"AttachStdout": True, "AttachStderr": True, "Cmd": ["sh", "-c", cmd]},
    )
    exec_id = created.get("Id") if isinstance(created, dict) else None
    if not isinstance(exec_id, str):
        raise PortainerResponseError("Docker did not return a Laravel file exec ID")
    _validate_container_id(exec_id)
    path = f"{base}/exec/{quote(exec_id, safe='')}"
    size = None
    zone = zone_override
    zone_source = "argument" if zone_override is not None else "container"
    # Replicas that mount one log file report the same head checksum and
    # inode; without a usable checksum the file counts as this container's own.
    file_id = f"container:{target.id}"
    stderr: list[str] = []
    from_entry: tuple[int, str] | None = None
    records = _LaravelRecords(
        lambda text, entry, ns, stamp: record(file_id, text, entry, ns, stamp)
    )

    try:
        async with aclosing(
            _read_log_lines(
                client,
                "POST",
                f"{path}/start",
                coverage=coverage,
                timeout=timeout,
                # The shell caps file bytes. Allow metadata and up to eight framing
                # bytes per payload byte without reducing the requested file tail.
                wire_limit=9 * (tail_bytes + 64),
                headers=headers,
                json={"Detach": False, "Tty": False},
            )
        ) as lines:
            async for stream, line in lines:
                if stream == 2:
                    if len(stderr) < 3:
                        stderr.append(line[:200])
                    continue
                if size is None:
                    info = _FILE_INFO_RE.fullmatch(line)
                    if info is None:
                        raise PortainerResponseError(
                            "Missing size and timezone in Laravel file output"
                        )
                    size = int(info[1])
                    crc, _, head_bytes = info[5].partition(":")
                    # cksum of nothing (no `head` in the image) is the same
                    # for every file; "unknown" means there is no cksum.
                    if crc != "unknown" and (head_bytes != "0" or size == 0):
                        file_id = f"file:{info[5]}:{info[3]}"
                    if zone is None:
                        newest = _NEWEST_STAMP_RE.match(info[6] or "")
                        zone = _mtime_offset(newest[1] if newest else None, int(info[2]))
                        if zone is not None:
                            zone_source = "file_mtime"
                        else:
                            try:
                                zone = _log_timezone(info[4])
                            except ValueError:
                                # No `date` in the image: entries that carry
                                # their own offset are still placed exactly.
                                zone, zone_source = timezone.utc, "assumed_utc"
                    continue
                stamp, text, entry = _laravel_record(line)
                if stamp is None:
                    records.append(line)
                    continue
                records.finish()
                if len(stamp) > 40:
                    continue
                assert zone is not None
                try:
                    ns = _iso_ns(stamp, zone)
                except ValueError:
                    continue
                if from_entry is None:
                    from_entry = (ns, stamp)
                if coverage.scan(ns, stamp):
                    records.start(text, entry, ns, stamp)
    finally:
        # An entry that was already read in full survives a late stream failure.
        records.finish()

    error = None
    if coverage.bytes_limited or coverage.stop_reason is not None:
        status = "partial"
    else:
        inspect = await client.get(f"{path}/json", headers=headers)
        code = inspect.get("ExitCode") if isinstance(inspect, dict) else None
        status = "error"
        if isinstance(code, int) and inspect.get("Running") is not True:
            if code == 0 and size is not None:
                status = "read"
            elif code in (3, 4):
                status = "missing" if code == 3 else "not_regular"
        if status == "error":
            said = "; ".join(stderr)
            cause = f"exit code {code}" if isinstance(code, int) else "no exit code reported"
            error = redact_secrets(f"{cause}: {said}" if said else cause)[:_MAX_REASON_CHARS]
        if status == "read" and size is not None and size > tail_bytes:
            # The tail cut into the file. Stamps have one-second resolution
            # and entries are not strictly ordered, so the cut is known to be
            # harmless only when the first surviving entry is clearly older
            # than the window.
            edge = coverage.window.since - _FILE_ORDER_SLACK_NS
            if from_entry is None or edge <= from_entry[0]:
                coverage.bytes_limited = True
                status = "partial"

    offset = None
    if zone is not None and size is not None:
        instant = from_entry[0] if from_entry else coverage.window.since
        value = datetime.fromtimestamp(instant // _NS, zone).strftime("%z")
        offset = value[:3] + ":" + value[3:5]
    return {
        "status": status,
        **({"error": error} if error else {}),
        "read_from_ts": from_entry[1] if from_entry else None,
        "timezone_offset": offset,
        "timezone_source": zone_source if offset else None,
        **coverage.summary(),
    }


async def _laravel_window(
    client: PortainerClient,
    eid: int,
    stack_name: str,
    targets: list[_WindowTarget],
    window: _LogWindow,
    timeout: float,
    max_groups: int,
    max_bytes: int,
    zone_override: tzinfo | None,
    deadline: float,
) -> str:
    groups: dict[tuple[str, str, int], _ExceptionGroup] = {}
    file_max_counts: dict[_FileKey, int] = {}
    ungrouped = 0
    omitted = 0
    sem = asyncio.Semaphore(_STACK_FANOUT_LIMIT)
    base = f"/api/endpoints/{eid}/docker"

    def record(
        text: str,
        entry: dict[str, Any],
        ns: int,
        timestamp: str,
        file_counts: dict[_FileKey, int] | None = None,
        file_id: str = "",
    ) -> None:
        nonlocal ungrouped, omitted
        site = _exception_site(text, entry)
        if site is None:
            level = entry.get("level")
            if _ERROR_LINE_RE.search(text) or (isinstance(level, int) and level >= 400):
                ungrouped += 1
            return
        group = groups.get(site)
        if group is None and len(groups) >= _MAX_LARAVEL_GROUP_KEYS:
            omitted += 1
            return
        if file_counts is not None:
            key = (file_id, ns, site)
            previous = file_max_counts.get(key)
            if previous is None and len(file_max_counts) >= _MAX_FILE_RECORD_KEYS:
                omitted += 1
                return
            # Replicas that mount the SAME file (same head checksum) each read
            # every entry: keep the largest multiplicity across them. Separate
            # files are separate events and add up. Events repeated in the
            # same second within one file are still counted.
            count = file_counts.get(key, 0) + 1
            file_counts[key] = count
            if previous is not None and count <= previous:
                return
            file_max_counts[key] = count
        ts = (ns, timestamp)
        if group is None:
            group = groups[site] = _ExceptionGroup(ts, ts)
        group.counts["stderr" if file_counts is None else "file"] += 1
        group.first = min(group.first, ts)
        group.last = max(group.last, ts)

    async def scan(target: _WindowTarget) -> tuple[str, dict[str, Any]]:
        # One deadline for the whole call: every source of every container shares it.
        docker = _LogCoverage(window, max_bytes, deadline=deadline)
        file = _LogCoverage(window, max_bytes, deadline=deadline)
        stream_name = "stderr_or_tty"
        records = _LaravelRecords(record)
        file_counts: dict[_FileKey, int] = {}
        docker_source: dict[str, Any] = {}
        # One container must never abort the scan: any failure — a broken
        # stream, a failed re-auth, an unexpected body — is that source's
        # error, reported with its reason, while the others still answer.
        async with sem:
            try:
                path = f"{base}/containers/{quote(target.id, safe='')}/logs"
                async with aclosing(
                    _docker_window_lines(
                        client,
                        path,
                        docker,
                        timeout,
                        stderr_only=True,
                        headers=target.headers,
                    )
                ) as lines:
                    async for stream, text, ns, timestamp in lines:
                        stream_name = "tty_merged" if stream is None else "stderr"
                        stamp, payload, entry = _laravel_record(text)
                        if stamp is not None or entry or _STDERR_HEADER_RE.match(text):
                            records.start(payload, entry, ns, timestamp)
                        else:
                            records.append(text)
                partial = docker.bytes_limited or docker.stop_reason is not None
                docker_source["status"] = "partial" if partial else "read"
            except Exception as exc:
                logger.warning("Failed to read Docker logs for %s: %s", target.name, exc)
                docker_source = {"status": "error", "error": _failure_reason(exc)}
            finally:
                # An entry that was already read in full survives the failure.
                records.finish()
            try:
                file_source = await _file_window(
                    client,
                    base,
                    target,
                    file,
                    timeout,
                    lambda file_id, text, entry, ns, stamp: record(
                        text, entry, ns, stamp, file_counts, file_id
                    ),
                    zone_override,
                )
            except Exception as exc:
                logger.warning("Failed to read Laravel log file for %s: %s", target.name, exc)
                file_source = {
                    "status": "error",
                    "error": _failure_reason(exc),
                    "read_from_ts": None,
                    "timezone_offset": None,
                    "timezone_source": None,
                    **file.summary(),
                }
        return target.id, {
            "container": target.name,
            "sources": {
                "docker": {**docker_source, "stream": stream_name, **docker.summary()},
                "laravel.log": file_source,
            },
        }

    logger.info(
        "AUDIT: laravel_errors window file exec for stack %r on endpoint %d (%d containers)",
        stack_name,
        eid,
        min(len(targets), _MAX_STACK_TARGETS),
    )
    results = dict(await asyncio.gather(*(scan(t) for t in targets[:_MAX_STACK_TARGETS])))
    ranked = sorted(groups.items(), key=lambda item: (-item[1].count, item[0]))
    kept = []
    remaining = _MAX_LOG_CHARS
    returned = _LogCoverage(window, max_bytes)
    for (cls, file_path, line), group in ranked[: _clamp_matches(max_groups)]:
        site = redact_secrets(f"{file_path}:{line}")
        # File stamps are naive wall-clock, Docker's are UTC: report one format.
        first_ts, last_ts = _utc_timestamp(group.first[0]), _utc_timestamp(group.last[0])
        remaining -= len(cls) + len(site) + len(first_ts) + len(last_ts)
        if remaining < 0:
            break
        kept.append(
            {
                "exception_class": cls,
                "file_line": site,
                "count": group.count,
                "count_by_source": group.counts,
                "first_ts": first_ts,
                "last_ts": last_ts,
            }
        )
        returned.returned(*group.first)
        returned.returned(*group.last)
    body = {
        "stack": stack_name,
        **window.bounds(),
        "log_path": _LARAVEL_LOG_PATH,
        "containers_scanned": len(results),
        "containers_omitted": max(0, len(targets) - _MAX_STACK_TARGETS),
        "containers": results,
        "groups": kept,
        "groups_truncated": len(kept) < len(groups) or omitted > 0,
        "ungrouped_errors": ungrouped,
        "untracked_group_entries": omitted,
        "returned_first_ts": _utc_timestamp(returned.returned_first[0])
        if returned.returned_first
        else None,
        "returned_last_ts": _utc_timestamp(returned.returned_last[0])
        if returned.returned_last
        else None,
    }
    if not targets:
        body["message"] = f"No running containers found for stack '{stack_name}'"
    return json.dumps(body, indent=2, ensure_ascii=False)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @tool_error_handler
    async def portainer_laravel_errors(
        stack_name: str,
        tail: int = 50,
        endpoint_id: int | None = None,
        since: str | None = None,
        until: str | None = None,
        max_groups: int = _DEFAULT_LOG_MATCHES,
        max_bytes: int = _DEFAULT_LOG_BYTES,
        timezone: str | None = None,
    ) -> str:
        """Find Laravel exceptions in running containers of a stack.

        With `since`, reads Docker stderr (merged output for TTY containers)
        and the current /var/www/app/storage/logs/laravel.log when present.
        Ranks exceptions whose class and file:line can be read from Monolog
        text/JSON or PHP uncaught-exception headers. Entries of one log file
        mounted into several replicas are counted once; separate files add
        up. Counts are reported by source. Docker timestamps govern stderr.
        The file is read from its tail and reports the earliest complete
        entry. Naive file timestamps are placed by the UTC offset between the
        newest entry and the file's mtime (Laravel's app.timezone), falling
        back to the container's own offset; `timezone_source` says which.
        Coverage and failures (`status`, `error`, `truncation_reason`) are
        per container and source under `containers`; `groups_truncated`
        covers the group list. Only laravel.log is read: rotated files, a
        `daily` channel's laravel-YYYY-MM-DD.log (reported as `missing`) and
        stopped containers are outside this scan.

        Without `since`, returns the tail of production.ERROR/CRITICAL/EMERGENCY
        lines from laravel.log in the legacy response format.

        Args:
            stack_name: Stack name prefix (e.g. "taylor", "blog", "somnlyx")
            tail: File error lines per container without since (default 50, max 200)
            endpoint_id: Target endpoint ID (uses default if omitted)
            since: Start of window: duration, Unix seconds or ISO-8601 datetime
            until: End of the window, same formats as since (default: now)
            max_groups: Window exception groups to return (default 200, max 1000)
            max_bytes: Window byte limit per source per container (default 32 MiB, max 1 GiB)
            timezone: Override for naive file timestamps, as an IANA name or UTC offset
        """
        if not _STACK_NAME_RE.match(stack_name):
            raise ValueError(f"Invalid stack_name: {stack_name!r}")
        tail = max(1, min(tail, 200))
        window = _LogWindow.parse(since, until)
        zone_override = _log_timezone(timezone) if window is not None and timezone else None

        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)

        deadline = time.monotonic() + config.long_timeout
        containers = await client.get(
            f"/api/endpoints/{eid}/docker/containers/json",
            params={"all": "false"},
        )
        if window is not None:
            return await _laravel_window(
                client,
                eid,
                stack_name,
                _window_stack_targets(containers, stack_name),
                window,
                config.long_timeout,
                max_groups,
                _clamp_bytes(max_bytes),
                zone_override,
                deadline,
            )
        targets = _stack_targets(containers, stack_name)

        if not targets:
            return json.dumps(
                {
                    "stack": stack_name,
                    "containers_scanned": 0,
                    "message": f"No running containers found for stack '{stack_name}'",
                },
                indent=2,
                ensure_ascii=False,
            )

        if len(targets) > _MAX_STACK_TARGETS:
            logger.warning(
                "Stack %r has %d containers; scanning only the first %d",
                stack_name,
                len(targets),
                _MAX_STACK_TARGETS,
            )
            targets = targets[:_MAX_STACK_TARGETS]

        log_path = _LARAVEL_LOG_PATH
        # The exec command is a fixed read-only grep, but it still runs inside
        # the containers — record the operation and its scope.
        logger.info(
            "AUDIT: laravel_errors grep exec for stack %r on endpoint %d (%d containers)",
            stack_name,
            eid,
            len(targets),
        )

        # Bound concurrency: each target costs two API calls plus an in-container
        # shell, so an unbounded fan-out over a big stack could overwhelm the host.
        sem = asyncio.Semaphore(_STACK_FANOUT_LIMIT)

        async def _fetch_laravel_errors(
            cid: str,
            name: str,
        ) -> tuple[str, str, str]:
            safe_tail = int(tail)
            # grep -E (ERE) is portable; \. matches a literal dot so we don't
            # also catch e.g. "productionXERROR".
            cmd = (
                f'grep -E "production\\.(ERROR|CRITICAL|EMERGENCY)" '
                f"{log_path} 2>/dev/null | tail -{safe_tail}"
            )
            exec_body = {
                "AttachStdout": True,
                "AttachStderr": True,
                "Cmd": ["sh", "-c", cmd],
            }
            async with sem:
                try:
                    exec_resp = await client.post(
                        f"/api/endpoints/{eid}/docker/containers/{cid}/exec",
                        json=exec_body,
                    )
                    exec_id = exec_resp["Id"]
                    start_resp = await client.request(
                        "POST",
                        f"/api/endpoints/{eid}/docker/exec/{exec_id}/start",
                        json={"Detach": False, "Tty": False},
                        timeout=config.long_timeout,
                    )
                    output = _parse_docker_stream(start_resp.content)
                except Exception:
                    # Keep details out of the tool output; log them server-side.
                    logger.exception("laravel_errors exec failed for %s", name)
                    output = "exec failed"
            return name, cid, output

        results = await asyncio.gather(
            *[_fetch_laravel_errors(cid, name) for cid, name in targets],
        )

        container_results = {}
        # Same pre-serialization output budget as stack_logs_errors.
        remaining = _MAX_LOG_CHARS
        truncated = False
        for name, cid, output in results:
            lines = [ln for ln in output.splitlines() if ln.strip()]
            kept, dropped = _cap_lines(lines, remaining)
            remaining -= sum(len(ln) + 1 for ln in kept)
            truncated = truncated or dropped
            container_results[name] = {
                "container_id": cid,
                "errors_found": len(lines),
                "errors": kept,
            }

        return json.dumps(
            {
                "stack": stack_name,
                "containers_scanned": len(targets),
                "log_path": log_path,
                "truncated": truncated,
                "containers": container_results,
            },
            indent=2,
            ensure_ascii=False,
        )

    @mcp.tool()
    @tool_error_handler
    async def portainer_laravel_tinker(
        stack_name: str,
        code: str,
        endpoint_id: int | None = None,
    ) -> str:
        """Execute PHP code via Laravel Tinker inside a stack's backend container.

        Finds a running backend container for the given stack and runs
        `php artisan tinker --execute="<code>"`. Useful for inspecting
        database records, checking model state, running one-off fixes,
        and debugging application issues.

        Args:
            stack_name: Stack name prefix (e.g. "taylor", "blog", "somnlyx")
            code: PHP code to execute (will be passed to tinker --execute)
            endpoint_id: Target endpoint ID (uses default if omitted)
        """
        if not _STACK_NAME_RE.match(stack_name):
            raise ValueError(f"Invalid stack_name: {stack_name!r}")
        if len(code) > 4096:
            raise ValueError("Code too long (max 4096 chars)")

        client = get_client()
        config = get_config()
        eid = resolve_endpoint(endpoint_id, config.default_endpoint)

        containers = await client.get(
            f"/api/endpoints/{eid}/docker/containers/json",
            params={"all": "false"},
        )

        # Find the first running backend container for the stack (matches
        # Swarm, plain-Compose and Compose-v1 naming — see _stack_targets).
        backends = _stack_targets(containers, stack_name, service="backend")
        if not backends:
            return json.dumps(
                {
                    "error": f"No running backend container found for stack '{stack_name}'",
                },
                indent=2,
                ensure_ascii=False,
            )
        target_id, target_name = backends[0]

        # Redact the full code before truncating the preview, so a secret
        # split across the cut can never land in the log half-masked.
        logger.info(
            "AUDIT: Laravel tinker in %s (%s) on endpoint %d: %s",
            target_name,
            target_id,
            eid,
            redact_secrets(code)[:500],
        )

        # Escape single quotes in code for safe shell embedding
        safe_code = code.replace("'", "'\\''")
        exec_body = {
            "AttachStdout": True,
            "AttachStderr": True,
            "Cmd": [
                "sh",
                "-c",
                f"cd /var/www/app && php artisan tinker --execute='{safe_code}'",
            ],
        }
        exec_resp = await client.post(
            f"/api/endpoints/{eid}/docker/containers/{target_id}/exec",
            json=exec_body,
        )
        exec_id = exec_resp["Id"]

        start_resp = await client.request(
            "POST",
            f"/api/endpoints/{eid}/docker/exec/{exec_id}/start",
            json={"Detach": False, "Tty": False},
            timeout=config.long_timeout,
        )
        output = _parse_docker_stream(start_resp.content)

        inspect = await client.get(
            f"/api/endpoints/{eid}/docker/exec/{exec_id}/json",
        )
        # `or {}`: never lose the exec output over a flaky metadata read.
        exit_code = (inspect or {}).get("ExitCode", -1)

        if len(output) > _MAX_LOG_CHARS:
            output = output[:_MAX_LOG_CHARS] + "\n... truncated"

        return json.dumps(
            {
                "container": target_name,
                "container_id": target_id,
                "exit_code": exit_code,
                "output": output,
            },
            indent=2,
            ensure_ascii=False,
        )
