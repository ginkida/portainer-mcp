from __future__ import annotations

import functools
import json
import logging
import re
from collections.abc import Awaitable, Callable
from typing import Any, ParamSpec

import httpx

logger = logging.getLogger(__name__)

P = ParamSpec("P")


class PortainerResponseError(RuntimeError):
    """Portainer answered 2xx with a body that is not JSON.

    The realistic trigger is a reverse proxy or SSO gateway in front of
    Portainer answering with an HTML login/error page: the HTTP status says
    "fine", the body says nothing usable. Surfaced as its own envelope so the
    user sees *what* came back instead of a generic "Internal error".
    """

# Redacts the most common secret shapes from audit-log previews so credentials
# passed inside an exec command / tinker snippet never land in stderr logs.
# Covered shapes: Authorization headers, bare bearer tokens, KEY=value /
# KEY: value (including suffixed keys like SECRET_ACCESS_KEY and quoted values
# with spaces), --password flags, and connection-string credentials.
# Known residual gaps (deliberate, to avoid mangling ordinary commands and
# prose like "CSRF token expired" or "find . -print"): bare space-separated
# pairs ("password hunter2") and glued short flags ("mysql -pSECRET").
# IMPORTANT: keep every wildcard in this pattern bounded or anchored. A
# leading `\w*` (or an unbounded `\w*` between the keyword and `[=:]`) makes
# re.sub backtrack quadratically on long secret-free / keyword-run text —
# measured 100x slowdowns. The `{0,64}` suffix bound keeps scanning linear
# while still covering long key names like SECRET_ACCESS_KEY_ID.
_SECRET_RE = re.compile(
    r"(?i)(?:"
    r"authorization\s*:\s*bearer\s+\S+"
    r"|\bbearer\s+[a-z0-9._~+/=-]{8,}"
    r"|(?:api[_-]?key|secret|token|password|passwd|pwd)\w{0,64}\s*[=:]\s*"
    r"(?:\"[^\"]*\"|'[^']*'|\S+)"
    r"|(?:^|(?<=\s))--password[= ]\S+"
    r")"
)
# Credentials embedded in connection strings: scheme://user:pass@host/... —
# the user part may be empty (redis://:pass@host) and the password may itself
# contain '@' (postgres://u:p@ss@host), so consume greedily to the LAST '@'
# within the token.
_URL_CREDS_RE = re.compile(r"://[^/\s:@]*:[^/\s]+@")

# Bound the redaction input so a huge exception/command string can't burn CPU
# on the event loop (and so error envelopes stay reasonably sized). Truncating
# BEFORE redaction is safe: if the cut splits a KEY=value pair, the value tail
# is discarded entirely and the surviving portion still matches on the key.
_MAX_REDACT_CHARS = 10_000


REDACTED = "[REDACTED]"


def redact_secrets(text: str) -> str:
    """Replace obvious secret material with a placeholder for safe logging."""
    if len(text) > _MAX_REDACT_CHARS:
        text = text[:_MAX_REDACT_CHARS] + "... (truncated)"
    text = _URL_CREDS_RE.sub(f"://{REDACTED}@", text)
    return _SECRET_RE.sub(REDACTED, text)


# --- Environment-variable redaction (stack Env, service Env, compose text) ------
#
# Name-based: the *variable name* decides whether its value is masked, so a
# value like "3" under CLICKHOUSE_PASSWORD is hidden while "9000" under
# CLICKHOUSE_PORT is not. Recall-biased on purpose: a false positive costs one
# masked value (reveal_env=true shows it), a miss leaks a credential to the
# model's context.
_SENSITIVE_NAME_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "credential",
    "private",
    "signature",
    "salt",
)
# Whole segments (split on _ - .) — short words that would over-match as
# substrings ("key" in "monkey", "pass" in "bypass", "auth" in "author").
_SENSITIVE_NAME_SEGMENTS = frozenset({
    "pwd", "pass", "key", "auth", "dsn", "cert", "hash", "jwt", "otp", "totp",
})
_NAME_SPLIT_RE = re.compile(r"[_\-.]")
# A bare variable reference (`${DB_PASSWORD}` / `$DB_PASSWORD`) is not a
# secret — it is the pointer the model needs to keep when editing compose.
# Forms with a default (`${X:-hunter2}`) are still masked.
_ENV_REFERENCE_RE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]{0,255}\}?$")
# One `KEY=value` / `KEY: value` / `- KEY=value` compose/env line. The name
# also allows `-` for YAML keys like `db-password`. Bounded quantifiers in the
# prefix keep the per-line scan linear; the value runs to end of line so a
# long secret (PEM, base64 cert) can't slip past a length cap unmasked.
_ENV_LINE_RE = re.compile(
    r"^(?P<prefix>\s{0,64}-?\s{0,64}[\"']?)"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_\-]{0,255})"
    r"(?P<sep>[\"']?\s{0,16}[=:]\s{0,16})"
    r"(?P<value>.+)$"
)
# YAML block scalar indicator (`KEY: |`, `KEY: >-`): the value lives on the
# following, deeper-indented lines.
_BLOCK_SCALAR_RE = re.compile(r"^[|>][-+]?\d?$")
# Compose short-syntax secret/config references: `secrets: [db_pass, api_key]`.
# The key matches the name heuristic ("secret") but the value is a list of
# secret *names*; masking it wrecks the file while hiding nothing. The
# exemption is deliberately narrow — key AND a flow-sequence value — so an
# environment variable that happens to be called SECRET / SECRETS is still
# masked (`SECRETS: hunter2` is not a list).
_COMPOSE_REFERENCE_KEYS = frozenset({"secrets", "configs"})
_FLOW_SEQUENCE_RE = re.compile(r"^\[[^\]]{0,4096}\]$")
# Values that point at a secret rather than contain one: a mounted secret
# (`/run/secrets/db`) or, for a `*_FILE` variable, any path-shaped value
# (no spaces, no `=`; starts with `/`, `./` or `../`).
_SECRET_MOUNT_PREFIX = "/run/secrets/"
_PATH_VALUE_RE = re.compile(r"^(?:\.{0,2}/)[^\s=]{0,4096}$")


def is_sensitive_env_name(name: str) -> bool:
    """Heuristic: does this environment-variable name look like a credential?"""
    lowered = name.lower()
    if any(sub in lowered for sub in _SENSITIVE_NAME_SUBSTRINGS):
        return True
    return any(seg in _SENSITIVE_NAME_SEGMENTS for seg in _NAME_SPLIT_RE.split(lowered))


def _is_reference(value: str) -> bool:
    inner = value.strip()
    if len(inner) >= 2 and inner[0] == inner[-1] and inner[0] in "\"'":
        inner = inner[1:-1]
    return bool(_ENV_REFERENCE_RE.match(inner))


def _points_at_secret(name: str, value: str) -> bool:
    """``DB_PASSWORD_FILE=/run/secrets/db`` names *where* a secret is, and is
    exactly what a model editing compose needs to see. The value must look
    like a path — a ``*_FILE`` name alone proves nothing (``API_KEY_FILE=ghp_…``)."""
    bare = value.strip().strip("\"'")
    if bare.startswith(_SECRET_MOUNT_PREFIX):
        return True
    segments = _NAME_SPLIT_RE.split(name.lower())
    return segments[-1] == "file" and bool(_PATH_VALUE_RE.match(bare))


def _redact_shapes(value: str) -> str:
    value = _URL_CREDS_RE.sub(f"://{REDACTED}@", value)
    return _SECRET_RE.sub(REDACTED, value)


def redact_env_value(name: str, value: str) -> str:
    """Mask ``value`` when ``name`` looks sensitive; otherwise mask only
    embedded secret shapes (URL credentials, ``--password`` flags, ``k=v``).

    A sensitive name whose value merely points at a secret (see
    :func:`_points_at_secret`) keeps the pointer — but still goes through
    the shape pass, so ``CONFIG_FILE=https://u:pw@host/x`` loses its
    credentials and only the path survives.
    """
    if not value or _is_reference(value):
        return value
    if is_sensitive_env_name(name) and not _points_at_secret(name, value):
        return REDACTED
    return _redact_shapes(value)


def redact_env_pairs(pairs: list[Any]) -> list[Any]:
    """Redact Portainer ``[{"name": .., "value": ..}]`` stack Env pairs."""
    out: list[Any] = []
    for pair in pairs:
        if isinstance(pair, dict) and isinstance(pair.get("value"), str):
            name = str(pair.get("name", ""))
            out.append({**pair, "value": redact_env_value(name, pair["value"])})
        else:
            out.append(pair)
    return out


def redact_env_strings(items: list[Any]) -> list[Any]:
    """Redact Docker-style ``["KEY=value", ...]`` environment lists."""
    out: list[Any] = []
    for item in items:
        if isinstance(item, str) and "=" in item:
            name, _, value = item.partition("=")
            out.append(f"{name}={redact_env_value(name, value)}")
        else:
            out.append(item)
    return out


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def redact_compose_text(text: str) -> str:
    """Mask credential values in a compose/env file, line by line.

    Handles ``KEY=value`` / ``KEY: value`` / ``- KEY=value`` lines (name-based),
    YAML block scalars under a sensitive key (the indented continuation lines
    are masked too), and — on every line — URL credentials, ``--password``
    flags and ``k=v`` secret shapes via the same patterns as
    :func:`redact_secrets`. Document structure survives intact. Output
    containing ``[REDACTED]`` must never be sent back to Portainer —
    ``stacks.py`` refuses it.
    """
    lines = text.split("\n")
    block_indent: int | None = None  # masking a block scalar deeper than this
    for idx, line in enumerate(lines):
        if block_indent is not None:
            if line.strip() and _indent(line) > block_indent:
                lines[idx] = " " * _indent(line) + REDACTED
                continue
            if line.strip():
                block_indent = None
            else:
                continue
        # Generic shapes first (URL creds, --password, k=v): these may sit in
        # `command:` / `entrypoint:` lines or bare list items.
        line = _URL_CREDS_RE.sub(f"://{REDACTED}@", line)
        m = _ENV_LINE_RE.match(line)
        if m is None:
            # _SECRET_RE needs a `=`/`:` after the keyword; skipping lines
            # without one keeps a 500 K file of keyword runs linear.
            if "=" in line or ":" in line:
                line = _SECRET_RE.sub(REDACTED, line)
            lines[idx] = line
            continue
        prefix, name, sep, value = m.group("prefix", "name", "sep", "value")
        if name.lower() in _COMPOSE_REFERENCE_KEYS and _FLOW_SEQUENCE_RE.match(value.strip()):
            # `secrets: [a, b]` — a list of secret names, keep as is.
            lines[idx] = line
            continue
        if is_sensitive_env_name(name) and _BLOCK_SCALAR_RE.match(value.strip()):
            block_indent = _indent(line)
            lines[idx] = line
            continue
        masked = redact_env_value(name, value)
        if masked != value:
            # `- "KEY=value"`: the opening quote sits in the prefix, so keep
            # the closing one out of the masked value to leave the line
            # well-formed.
            if masked == REDACTED and prefix and prefix[-1] in "\"'" and value.endswith(prefix[-1]):
                masked += prefix[-1]
            line = f"{prefix}{name}{sep}{masked}"
        lines[idx] = line
    return "\n".join(lines)


# List-filter substrings go into a JSON query value (never a URL path), so a
# leading underscore/dot/dash is fine — "_backend" is a legitimate name-suffix
# filter that the stricter id regexes would reject.
_FILTER_RE = re.compile(r"^[a-zA-Z0-9_.\-]{1,255}$")


def validate_filter(value: str, name: str) -> None:
    """Validate a server-side list-filter value, naming the actual parameter."""
    if not _FILTER_RE.match(value):
        raise ValueError(
            f"Invalid {name}: {value!r}. "
            "Must be 1-255 chars of letters, digits, _ . - only"
        )


def validate_id(value: int, name: str) -> None:
    """Validate a required positive integer path parameter (stack_id, etc.).

    ``bool`` is rejected explicitly because ``isinstance(True, int)`` is True.
    """
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"Invalid {name}: {value!r}. Must be a positive integer.")


def resolve_endpoint(endpoint_id: int | None, default_endpoint: int) -> int:
    """Validate an optional endpoint_id and fall back to the configured default.

    Centralises the ``config.default_endpoint if endpoint_id is None else
    endpoint_id`` pattern and rejects negative / boolean values before they are
    interpolated into an API path.
    """
    if endpoint_id is None:
        return default_endpoint
    if not isinstance(endpoint_id, int) or isinstance(endpoint_id, bool) or endpoint_id < 0:
        raise ValueError(
            f"Invalid endpoint_id: {endpoint_id!r}. Must be a non-negative integer."
        )
    return endpoint_id


def error_response(error: str, details: str | None = None) -> str:
    resp: dict[str, Any] = {"error": error}
    if details is not None:
        resp["details"] = details
    return json.dumps(resp, indent=2, ensure_ascii=False)


def tool_error_handler(func: Callable[P, Awaitable[str]]) -> Callable[P, Awaitable[str]]:
    @functools.wraps(func)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> str:
        try:
            return await func(*args, **kwargs)
        except ValueError as exc:
            # Validation messages echo the rejected input back; redact it in
            # case a secret-laden argument failed validation.
            return error_response("Validation error", redact_secrets(str(exc)))
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            detail: str
            try:
                body = exc.response.json()
            except Exception:
                detail = exc.response.text[:500]
            else:
                if isinstance(body, dict):
                    candidate = body.get("message") or body.get("details")
                    if candidate is None:
                        detail = json.dumps(body, ensure_ascii=False)[:500]
                    elif isinstance(candidate, str):
                        detail = candidate
                    else:
                        # message/details was a nested object — serialise it
                        # so we never put a non-string into the response.
                        detail = json.dumps(candidate, ensure_ascii=False)[:500]
                else:
                    # API returned a list / string / number — surface it as-is.
                    detail = json.dumps(body, ensure_ascii=False)[:500]
            return error_response(
                f"Portainer API error ({status})", redact_secrets(detail)
            )
        except PortainerResponseError as exc:
            return error_response("Unexpected response from Portainer", redact_secrets(str(exc)))
        except httpx.TransportError as exc:
            # Covers connect/read/write/protocol/proxy errors and timeouts —
            # any of them means "couldn't complete the HTTP exchange", which
            # should surface as a connection problem, not an internal error.
            return error_response(
                "Connection error",
                f"Cannot reach Portainer server: {redact_secrets(str(exc))}",
            )
        except Exception as exc:
            logger.exception("Unexpected error in %s", func.__name__)
            return error_response("Internal error", redact_secrets(str(exc)))

    return wrapper
