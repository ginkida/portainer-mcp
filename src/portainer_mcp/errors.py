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
            detail: str
            try:
                body = exc.response.json()
            except Exception:
                detail = exc.response.text[:500]
            else:
                if isinstance(body, dict):
                    candidate = body.get("message") or body.get("details")
                    if candidate is None:
                        detail = json.dumps(body)[:500]
                    elif isinstance(candidate, str):
                        detail = candidate
                    else:
                        # message/details was a nested object — serialise it
                        # so we never put a non-string into the response.
                        detail = json.dumps(candidate)[:500]
                else:
                    # API returned a list / string / number — surface it as-is.
                    detail = json.dumps(body)[:500]
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
