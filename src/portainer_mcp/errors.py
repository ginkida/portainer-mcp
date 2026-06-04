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


def redact_secrets(text: str) -> str:
    """Replace obvious secret material with a placeholder for safe logging."""
    if len(text) > _MAX_REDACT_CHARS:
        text = text[:_MAX_REDACT_CHARS] + "... (truncated)"
    text = _URL_CREDS_RE.sub("://[REDACTED]@", text)
    return _SECRET_RE.sub("[REDACTED]", text)


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
