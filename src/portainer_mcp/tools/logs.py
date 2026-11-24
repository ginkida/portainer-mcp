"""Bounded readers for Docker log windows and non-interactive exec output."""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import AsyncGenerator, AsyncIterator, Iterator
from contextlib import aclosing
from dataclasses import dataclass, field
from datetime import datetime, timezone, tzinfo
from typing import Any

import httpx

from ..client import PortainerClient
from ..errors import _MAX_REDACT_CHARS, PortainerResponseError, redact_secrets

_MAX_LOG_CHARS = 100_000
# Longest silence tolerated once a log stream has started delivering data.
_STREAM_IDLE_SECONDS = 15.0
_MAX_REASON_CHARS = 300
_DEFAULT_LOG_BYTES = 32 * 1024 * 1024
_MAX_LOG_BYTES = 1024**3
_DEFAULT_LOG_MATCHES = 200
_MAX_LOG_MATCHES = 1000
_NS = 1_000_000_000
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_RELATIVE_RE = re.compile(r"(\d{1,9})([smhd])")
_RELATIVE_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_EPOCH_RE = re.compile(r"\d{9,10}")
_ISO_FRACTION_RE = re.compile(r"^\d{4}-\d\d-\d\d.\d\d:\d\d:\d\d(\.\d{1,9})(?=[+\-Z]|$)")
_DOCKER_TS_RE = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)")


def _iso_ns(value: str, default_tz: tzinfo = timezone.utc) -> int:
    fraction = _ISO_FRACTION_RE.search(value)
    nanos = int(fraction[1][1:].ljust(9, "0")) if fraction else 0
    iso = value[:-1] + "+00:00" if value.endswith("Z") else value
    if fraction:
        # Python 3.10 requires exactly 3 or 6 fractional digits.
        iso = iso[: fraction.start(1)] + iso[fraction.end(1) :]
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=default_tz)
    elapsed = dt - _UNIX_EPOCH
    return (elapsed.days * 86400 + elapsed.seconds) * _NS + elapsed.microseconds * 1000 + nanos


def _log_time(value: str | None, name: str, now: int) -> int | None:
    if value is None or not value.strip():
        return None
    value = value.strip()
    if len(value) > 64:
        raise ValueError(f"Invalid {name}: too long")
    if relative := _RELATIVE_RE.fullmatch(value):
        return now - int(relative[1]) * _RELATIVE_SECONDS[relative[2]] * _NS
    if _EPOCH_RE.fullmatch(value):
        return int(value) * _NS
    if value.isdigit():
        raise ValueError(
            f"Invalid {name}: {value!r}. A Unix timestamp must be 9-10 digits "
            "(seconds); use ISO-8601 for a date."
        )
    try:
        return _iso_ns(value)
    except ValueError:
        raise ValueError(
            f"Invalid {name}: {value!r}. Use a duration (10m, 2h, 1d), "
            "a Unix timestamp or an ISO-8601 datetime."
        ) from None


def _parse_since(since: str | None) -> int | None:
    """Whole Unix seconds for the existing buffered container logs tool."""
    ts = _log_time(since, "since", int(time.time()) * _NS)
    if ts is None:
        return None
    return ts // _NS if ts >= 0 else -(-ts // _NS)


def _docker_time(ns: int) -> str:
    seconds, fraction = divmod(ns, _NS)
    return f"{seconds}.{fraction:09d}".rstrip("0") if fraction else str(seconds)


@dataclass(frozen=True)
class _LogWindow:
    since: int
    until: int

    @classmethod
    def parse(cls, since: str | None, until: str | None) -> _LogWindow | None:
        now = time.time_ns()
        start = _log_time(since, "since", now)
        end = _log_time(until, "until", now)
        if start is None:
            if end is not None:
                raise ValueError("until requires since")
            return None
        end = now if end is None else end
        if end < start:
            raise ValueError("until must be at or after since")
        return cls(start, end)

    def bounds(self) -> dict[str, str]:
        return {"since": _docker_time(self.since), "until": _docker_time(self.until)}

    def params(self, *, swarm: bool) -> dict[str, str]:
        params = {"stdout": "true", "stderr": "true", "tail": "all", "timestamps": "true"}
        if swarm:
            # Swarm's service logs API only exposes since. Round down to a
            # whole second and apply both exact bounds to timestamped records.
            params["since"] = str(self.since // _NS)
        else:
            params["since"] = _docker_time(self.since)
            # json-file stops at the first record newer than until. Allow
            # for out-of-order records near the edge and filter exactly here.
            params["until"] = str((self.until + _NS - 1) // _NS + 1)
        return params


@dataclass
class _LogCoverage:
    window: _LogWindow
    max_bytes: int
    bytes_read: int = 0
    bytes_limited: bool = False
    lines_scanned: int = 0
    first: tuple[int, str] | None = None
    last: tuple[int, str] | None = None
    returned_first: tuple[int, str] | None = None
    returned_last: tuple[int, str] | None = None
    stop_reason: str | None = None
    deadline: float | None = None
    error: str | None = None

    def fail(self, exc: Exception) -> None:
        """A single source broke after delivering lines: keep them and say why."""
        self.error = redact_secrets(str(exc))[:_MAX_REASON_CHARS] or type(exc).__name__
        if self.stop_reason is None:
            self.stop_reason = "stream_error"

    def scan(self, ns: int, timestamp: str) -> bool:
        if not self.window.since <= ns <= self.window.until:
            return False
        self.lines_scanned += 1
        if self.first is None or ns < self.first[0]:
            self.first = (ns, timestamp)
        if self.last is None or ns > self.last[0]:
            self.last = (ns, timestamp)
        return True

    def returned(self, ns: int, timestamp: str) -> None:
        if self.returned_first is None or ns < self.returned_first[0]:
            self.returned_first = (ns, timestamp)
        if self.returned_last is None or ns > self.returned_last[0]:
            self.returned_last = (ns, timestamp)

    def include(self, other: _LogCoverage) -> None:
        self.bytes_read += other.bytes_read
        self.bytes_limited |= other.bytes_limited
        if other.stop_reason is not None:
            self.stop_reason = other.stop_reason
        self.lines_scanned += other.lines_scanned
        if other.first and (self.first is None or other.first[0] < self.first[0]):
            self.first = other.first
        if other.last and (self.last is None or other.last[0] > self.last[0]):
            self.last = other.last
        for returned in (other.returned_first, other.returned_last):
            if returned:
                self.returned(*returned)

    def summary(self, matches_limited: bool = False, lines_clipped: int = 0) -> dict[str, Any]:
        reason = self.stop_reason
        if reason is None:
            if self.bytes_limited:
                reason = "bytes_limit"
            elif matches_limited:
                reason = "matches_limit"
            elif lines_clipped:
                reason = "line_clipped"
        body = {
            "lines_scanned": self.lines_scanned,
            "lines_clipped": lines_clipped,
            "first_ts": self.first[1] if self.first else None,
            "last_ts": self.last[1] if self.last else None,
            "returned_first_ts": self.returned_first[1] if self.returned_first else None,
            "returned_last_ts": self.returned_last[1] if self.returned_last else None,
            "bytes_read": self.bytes_read,
            "truncated": reason is not None,
            "truncation_reason": reason,
        }
        if self.error is not None:
            body["stream_error"] = self.error
        return body


@dataclass
class _MatchBudget:
    limit: int
    chars_left: int = _MAX_LOG_CHARS
    kept: int = 0
    clipped: int = 0

    def context(self, text: str) -> str | None:
        output = redact_secrets(text)
        if len(output) + 1 > self.chars_left:
            return None
        self.chars_left -= len(output) + 1
        self.clipped += len(text) > _MAX_REDACT_CHARS
        return output

    def match(self, text: str) -> str | None:
        if self.kept >= self.limit:
            return None
        output = self.context(text)
        if output is not None:
            self.kept += 1
        return output


def _clamp_bytes(max_bytes: int) -> int:
    return max(1, min(max_bytes, _MAX_LOG_BYTES))


def _clamp_matches(max_matches: int) -> int:
    return max(1, min(max_matches, _MAX_LOG_MATCHES))


def _match_budget(max_matches: int) -> _MatchBudget:
    return _MatchBudget(_clamp_matches(max_matches))


@dataclass
class _LogMatches:
    budget: _MatchBudget
    lines: list[str] = field(default_factory=list)
    found: int = 0
    limited: bool = False

    def match(self, text: str) -> str | None:
        self.found += 1
        result = self.budget.match(text)
        self.limited |= result is None
        return result


@dataclass
class _PartialLine:
    prefix: bytearray = field(default_factory=bytearray)
    length: int = 0

    def extend(self, data: bytes) -> None:
        self.prefix.extend(data[: max(0, _MAX_LOG_CHARS - self.length)])
        self.length += len(data)

    def finish(self) -> str:
        result = self.prefix.decode("utf-8", errors="replace").removesuffix("\r")
        if self.length > len(self.prefix):
            result += f" …[line truncated: {self.length} bytes]"
        self.prefix.clear()
        self.length = 0
        return result


class _DockerLines:
    """Incremental framing and line assembly, with one partial line per stream."""

    def __init__(self) -> None:
        self._header = bytearray()
        self._multiplexed: bool | None = None
        self._stream = 0
        self._remaining = 0
        self._lines: dict[int | None, _PartialLine] = {}
        self._error = bytearray()

    def _system_error(self) -> PortainerResponseError:
        text = self._error.decode("utf-8", errors="replace").strip()
        return PortainerResponseError(
            f"Docker reported an error in its log stream: {redact_secrets(text)[:500]}"
        )

    def _payload(self, stream: int | None, data: bytes) -> Iterator[tuple[int | None, str]]:
        line = self._lines.setdefault(stream, _PartialLine())
        start = 0
        while (end := data.find(b"\n", start)) != -1:
            line.extend(data[start:end])
            yield stream, line.finish()
            start = end + 1
        line.extend(data[start:])

    def feed(self, data: bytes) -> Iterator[tuple[int | None, str]]:
        pos = 0
        while pos < len(data):
            if self._multiplexed is False:
                yield from self._payload(None, data[pos:])
                return
            if self._remaining:
                size = min(self._remaining, len(data) - pos)
                if self._stream == 3:
                    collect = min(size, _MAX_REDACT_CHARS - len(self._error))
                    self._error.extend(data[pos : pos + collect])
                else:
                    yield from self._payload(self._stream, data[pos : pos + size])
                self._remaining -= size
                pos += size
                if self._stream == 3 and not self._remaining:
                    raise self._system_error()
                continue
            size = min(8 - len(self._header), len(data) - pos)
            self._header.extend(data[pos : pos + size])
            pos += size
            if len(self._header) < 8:
                continue
            stream = self._header[0]
            if stream not in (0, 1, 2, 3) or self._header[1:4] != b"\0\0\0":
                if self._multiplexed:
                    raise PortainerResponseError("Invalid Docker log frame header")
                self._multiplexed = False
                yield from self._payload(None, bytes(self._header))
            else:
                self._multiplexed = True
                self._stream = stream
                self._remaining = int.from_bytes(self._header[4:8], "big")
                if stream == 3 and not self._remaining:
                    raise self._system_error()
            self._header.clear()

    def finish(self) -> Iterator[tuple[int | None, str]]:
        if self._stream == 3:
            raise self._system_error()
        if self._multiplexed and (self._header or self._remaining):
            raise PortainerResponseError("Docker log stream ended mid-frame")
        if self._header:
            yield from self._payload(None, bytes(self._header))
        for stream, line in self._lines.items():
            if line.length:
                yield stream, line.finish()


def _raw_chunks(resp: httpx.Response) -> AsyncIterator[bytes]:
    if resp.is_stream_consumed:
        # A body that arrived already read (httpx.MockTransport with content=).
        return resp.aiter_bytes()
    # Not aiter_raw(): it closes the response on its own at EOF, and a task
    # cancellation landing inside that close leaves the pool slot occupied
    # while the response already claims to be closed. Reading the transport
    # stream directly leaves one close — client.stream()'s, which is shielded.
    stream = resp.stream
    assert isinstance(stream, httpx.AsyncByteStream)
    return stream.__aiter__()


async def _read_log_lines(
    client: PortainerClient,
    method: str,
    path: str,
    *,
    coverage: _LogCoverage,
    timeout: float,
    wire_limit: int | None = None,
    **kwargs: Any,
) -> AsyncGenerator[tuple[int | None, str], None]:
    decoder = _DockerLines()
    limit = coverage.max_bytes if wire_limit is None else wire_limit
    async with client.stream(method, path, timeout=timeout, **kwargs) as resp:
        if resp.headers.get("content-encoding", "identity").lower() != "identity":
            raise PortainerResponseError("Portainer compressed a log stream requested as identity")
        chunks = _raw_chunks(resp)
        received = False
        while True:
            # Bound the wait itself, not just the gap between chunks: Docker
            # can stop sending without closing (seen on Swarm service logs),
            # and the HTTP read timeout would turn that into an error that
            # throws away everything already read.
            wait = None if coverage.deadline is None else coverage.deadline - time.monotonic()
            if wait is not None and wait <= 0:
                coverage.stop_reason = "time_limit"
                return
            reason = "time_limit"
            if received and (wait is None or wait > _STREAM_IDLE_SECONDS):
                # Before the first byte Docker may be skipping old records to
                # reach `since`; once data flows, a long silence is a stall.
                wait, reason = _STREAM_IDLE_SECONDS, "idle_timeout"
            try:
                chunk = await asyncio.wait_for(chunks.__anext__(), wait)
            except StopAsyncIteration:
                break
            except asyncio.TimeoutError:
                coverage.stop_reason = reason
                return
            received = True
            if coverage.deadline is not None and time.monotonic() >= coverage.deadline:
                coverage.stop_reason = "time_limit"
                return
            # The last transport chunk can straddle the byte limit. Process
            # just its prefix and leave any unread tail on the connection.
            size = min(len(chunk), limit - coverage.bytes_read)
            coverage.bytes_read += size
            coverage.bytes_limited = size < len(chunk)
            for line in decoder.feed(chunk[:size]):
                yield line
            if coverage.bytes_limited:
                return
        for line in decoder.finish():
            yield line


async def _docker_window_lines(
    client: PortainerClient,
    path: str,
    coverage: _LogCoverage,
    timeout: float,
    *,
    swarm: bool = False,
    timestamps: bool = False,
    stderr_only: bool = False,
    headers: dict[str, str] | None = None,
    track_coverage: bool = True,
) -> AsyncGenerator[tuple[int | None, str, int, str], None]:
    async with aclosing(
        _read_log_lines(
            client,
            "GET",
            path,
            coverage=coverage,
            timeout=timeout,
            params=coverage.window.params(swarm=swarm),
            headers=headers,
        )
    ) as lines:
        async for stream, line in lines:
            # A TTY merges both streams. For multiplexed responses ignore stdout
            # if a caller only wants stderr.
            if stderr_only and stream not in (2, None):
                continue
            timestamp, sep, text = line.partition(" ")
            try:
                if not sep or not _DOCKER_TS_RE.fullmatch(timestamp):
                    raise ValueError
                ns = _iso_ns(timestamp)
            except ValueError:
                raise PortainerResponseError(
                    "Docker returned a log line without a timestamp"
                ) from None
            if coverage.window.since <= ns <= coverage.window.until:
                if track_coverage:
                    coverage.scan(ns, timestamp)
                yield stream, line if timestamps else text, ns, timestamp
