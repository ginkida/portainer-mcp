from __future__ import annotations

import functools
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any, ParamSpec

import httpx

logger = logging.getLogger(__name__)

P = ParamSpec("P")


def error_response(error: str, details: str | None = None) -> str:
    resp: dict[str, Any] = {"error": error}
    if details is not None:
        resp["details"] = details
    return json.dumps(resp)


def tool_error_handler(func: Callable[P, Awaitable[str]]) -> Callable[P, Awaitable[str]]:
    @functools.wraps(func)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> str:
        try:
            return await func(*args, **kwargs)
        except ValueError as exc:
            return error_response("Validation error", str(exc))
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            try:
                body = exc.response.json()
                detail = body.get("message") or body.get("details") or str(body)
            except Exception:
                detail = exc.response.text[:500]
            return error_response(
                f"Portainer API error ({status})", detail
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            return error_response(
                "Connection error",
                f"Cannot reach Portainer server: {exc}",
            )
        except Exception as exc:
            logger.exception("Unexpected error in %s", func.__name__)
            return error_response("Internal error", str(exc))

    return wrapper
