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
_SECRET_RE = re.compile(
    r"(?i)(?:authorization\s*:\s*bearer\s+\S+"
    r"|(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[=:]\s*\S+)"
)


def redact_secrets(text: str) -> str:
    """Replace obvious secret material with a placeholder for safe logging."""
    return _SECRET_RE.sub("[REDACTED]", text)


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
    return json.dumps(resp, ensure_ascii=False)


def tool_error_handler(func: Callable[P, Awaitable[str]]) -> Callable[P, Awaitable[str]]:
    @functools.wraps(func)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> str:
        try:
            return await func(*args, **kwargs)
        except ValueError as exc:
            return error_response("Validation error", str(exc))
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
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            return error_response(
                "Connection error",
                f"Cannot reach Portainer server: {exc}",
            )
        except Exception as exc:
            logger.exception("Unexpected error in %s", func.__name__)
            return error_response("Internal error", redact_secrets(str(exc)))

    return wrapper
