from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from .config import get_config

logger = logging.getLogger(__name__)

_client: PortainerClient | None = None

_UNSAFE_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

# Defense-in-depth cap on a single response body. Portainer/Docker list and
# inspect payloads are normally well under a megabyte; a response advertising
# more than this almost certainly signals a misconfigured endpoint, and parsing
# it would needlessly inflate memory.
_MAX_RESPONSE_BYTES = 50_000_000


class PortainerClient:
    """HTTP client for the Portainer API with JWT authentication."""

    def __init__(self) -> None:
        config = get_config()
        # Proactively refresh the JWT before Portainer's session lifetime
        # (default 8h) expires it server-side; see PORTAINER_JWT_TTL.
        self._jwt_ttl = config.jwt_ttl
        self._jwt: str | None = None
        self._csrf_token: str | None = None
        self._jwt_obtained_at: float = 0
        # Bumped on every successful authentication; used to detect
        # whether another concurrent task already refreshed the JWT.
        self._auth_version: int = 0
        self._auth_lock = asyncio.Lock()
        # Separate lock just for opportunistic CSRF-token writes harvested from
        # response headers, so they can't interleave with each other. Reads in
        # _headers() stay lock-free (a single attribute read is atomic in
        # CPython and any harvested token is valid).
        self._csrf_lock = asyncio.Lock()
        self._base_url_str = config.url
        self._http = httpx.AsyncClient(
            base_url=config.url,
            verify=config.verify_ssl,
            timeout=config.timeout,
            limits=httpx.Limits(
                max_connections=config.http_max_connections,
                max_keepalive_connections=config.http_max_keepalive,
            ),
        )

    def _jwt_is_fresh(self) -> bool:
        return (
            self._jwt is not None
            and time.monotonic() - self._jwt_obtained_at < self._jwt_ttl
        )

    async def _do_authenticate(self) -> None:
        config = get_config()
        logger.debug("Authenticating to Portainer as %s", config.username)
        # POST /api/auth must NOT include Referer (Portainer 2.39+ rejects it)
        resp = await self._http.post(
            "/api/auth",
            json={"username": config.username, "password": config.password},
        )
        resp.raise_for_status()
        jwt = resp.json()["jwt"]
        jwt_obtained_at = time.monotonic()
        # Fetch CSRF token from an authenticated GET (no Referer for reads).
        csrf_resp = await self._http.get(
            "/api/status",
            headers={"Authorization": f"Bearer {jwt}"},
        )
        # If this GET fails we must NOT commit the new auth state: a half-set
        # JWT with a bumped _auth_version would wedge the client, because a
        # later _refresh_auth would see a matching version and refuse to retry.
        csrf_resp.raise_for_status()
        csrf_token = csrf_resp.headers.get("x-csrf-token") or None
        # Commit the new generation only after BOTH calls succeed.
        self._jwt = jwt
        self._jwt_obtained_at = jwt_obtained_at
        self._csrf_token = csrf_token
        self._auth_version += 1
        logger.debug(
            "Authentication successful (CSRF token: %s)",
            "present" if csrf_token else "absent",
        )

    async def _ensure_auth(self) -> None:
        """Authenticate if JWT is missing or stale."""
        if self._jwt_is_fresh():
            return
        async with self._auth_lock:
            # Re-check inside the lock — another task may have refreshed.
            if self._jwt_is_fresh():
                return
            await self._do_authenticate()

    async def _refresh_auth(self, attempted_version: int) -> None:
        """Force re-auth, unless another task has already refreshed."""
        async with self._auth_lock:
            if self._auth_version != attempted_version:
                return
            await self._do_authenticate()

    async def _capture_csrf(self, resp: httpx.Response) -> None:
        """Opportunistically refresh the CSRF token from a response header."""
        new_csrf = resp.headers.get("x-csrf-token")
        if new_csrf:
            async with self._csrf_lock:
                self._csrf_token = new_csrf

    @staticmethod
    def _enforce_response_size(resp: httpx.Response) -> None:
        # NOTE: request() does not stream, so httpx has already buffered the
        # whole body by the time this runs — the guard cannot prevent the
        # memory spike of a huge chunked response. What it does guarantee is
        # that an oversized payload is rejected before JSON parsing and before
        # it can reach a tool result. The header check catches declared sizes;
        # the content check catches chunked responses with no content-length.
        cl = resp.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > _MAX_RESPONSE_BYTES:
            raise ValueError(
                f"Portainer response too large: {cl} bytes "
                f"(max {_MAX_RESPONSE_BYTES})."
            )
        if len(resp.content) > _MAX_RESPONSE_BYTES:
            raise ValueError(
                f"Portainer response too large: {len(resp.content)} bytes "
                f"(max {_MAX_RESPONSE_BYTES})."
            )

    def _headers(self, method: str = "GET") -> dict[str, str]:
        h: dict[str, str] = {"Authorization": f"Bearer {self._jwt}"}
        # Referer + CSRF token only for mutating methods.
        # GET with Referer triggers CSRF validation in Portainer 2.39+.
        if method.upper() in _UNSAFE_METHODS:
            h["Referer"] = self._base_url_str
            if self._csrf_token:
                h["X-CSRF-Token"] = self._csrf_token
        return h

    async def request(
        self,
        method: str,
        path: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        await self._ensure_auth()
        # Capture the auth generation we're about to use, so retry logic
        # can tell whether another concurrent task already refreshed.
        attempted_version = self._auth_version
        # Caller-supplied headers are preserved; auth headers win on conflict
        # so callers can't accidentally drop the Bearer token.
        user_headers = kwargs.pop("headers", None) or {}
        # A per-request timeout override (slow ops like pull/exec) flows to all
        # retries via **kwargs; when None we leave the client default in place.
        if timeout is not None:
            kwargs["timeout"] = timeout
        merged_headers = {**user_headers, **self._headers(method)}
        resp = await self._http.request(method, path, headers=merged_headers, **kwargs)
        await self._capture_csrf(resp)
        if resp.status_code == 401:
            logger.debug("Token expired, re-authenticating")
            await self._refresh_auth(attempted_version)
            attempted_version = self._auth_version
            if method.upper() in _UNSAFE_METHODS:
                logger.warning(
                    "Retrying %s %s after 401; the mutation may be applied twice "
                    "if it had already taken effect server-side.",
                    method,
                    path,
                )
            merged_headers = {**user_headers, **self._headers(method)}
            resp = await self._http.request(method, path, headers=merged_headers, **kwargs)
            await self._capture_csrf(resp)
        # `elif`, not `if`: the 403-CSRF branch must not chain off the 401-retry
        # response, or a single request() could re-auth twice and send a
        # mutating request three times. One retry per call, whatever the cause.
        elif resp.status_code == 403 and "CSRF" in resp.text:
            logger.debug("CSRF token expired, refreshing")
            await self._refresh_auth(attempted_version)
            if method.upper() in _UNSAFE_METHODS:
                logger.warning(
                    "Retrying %s %s after 403 CSRF; the mutation may be applied "
                    "twice if it had already taken effect server-side.",
                    method,
                    path,
                )
            merged_headers = {**user_headers, **self._headers(method)}
            resp = await self._http.request(method, path, headers=merged_headers, **kwargs)
            await self._capture_csrf(resp)
        self._enforce_response_size(resp)
        resp.raise_for_status()
        return resp

    @staticmethod
    def _decode(resp: httpx.Response) -> Any:
        """Decode a successful response body, tolerating empty/non-JSON bodies.

        Some Portainer/Docker endpoints return 200 with an empty body (e.g.
        network connect/disconnect) — treating that as an error would report a
        successful mutation as failed.
        """
        if resp.status_code == 204 or not resp.content:
            return None
        try:
            return resp.json()
        except (ValueError, httpx.DecodingError):
            return None

    async def get(self, path: str, **kwargs: Any) -> Any:
        resp = await self.request("GET", path, **kwargs)
        return self._decode(resp)

    async def post(self, path: str, **kwargs: Any) -> Any:
        resp = await self.request("POST", path, **kwargs)
        return self._decode(resp)

    async def put(self, path: str, **kwargs: Any) -> Any:
        resp = await self.request("PUT", path, **kwargs)
        return self._decode(resp)

    async def delete(self, path: str, **kwargs: Any) -> Any:
        resp = await self.request("DELETE", path, **kwargs)
        return self._decode(resp)

    async def close(self) -> None:
        await self._http.aclose()


def get_client() -> PortainerClient:
    global _client
    if _client is None:
        _client = PortainerClient()
    return _client


async def close_client() -> None:
    global _client
    if _client is not None:
        await _client.close()
        _client = None
