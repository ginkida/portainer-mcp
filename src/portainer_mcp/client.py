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


class PortainerClient:
    """HTTP client for the Portainer API with JWT authentication."""

    # Proactively refresh JWT after 7 hours (Portainer default TTL is 8h)
    _JWT_TTL = 7 * 3600

    def __init__(self) -> None:
        config = get_config()
        self._jwt: str | None = None
        self._csrf_token: str | None = None
        self._jwt_obtained_at: float = 0
        # Bumped on every successful authentication; used to detect
        # whether another concurrent task already refreshed the JWT.
        self._auth_version: int = 0
        self._auth_lock = asyncio.Lock()
        self._base_url_str = config.url
        self._http = httpx.AsyncClient(
            base_url=config.url,
            verify=config.verify_ssl,
            timeout=30.0,
        )

    def _jwt_is_fresh(self) -> bool:
        return (
            self._jwt is not None
            and time.monotonic() - self._jwt_obtained_at < self._JWT_TTL
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
        self._jwt = resp.json()["jwt"]
        self._jwt_obtained_at = time.monotonic()
        self._auth_version += 1
        # Fetch CSRF token from an authenticated GET (no Referer for reads).
        csrf_resp = await self._http.get(
            "/api/status",
            headers={"Authorization": f"Bearer {self._jwt}"},
        )
        self._csrf_token = csrf_resp.headers.get("x-csrf-token") or None
        logger.debug(
            "Authentication successful (CSRF token: %s)",
            "present" if self._csrf_token else "absent",
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
        **kwargs: Any,
    ) -> httpx.Response:
        await self._ensure_auth()
        # Capture the auth generation we're about to use, so retry logic
        # can tell whether another concurrent task already refreshed.
        attempted_version = self._auth_version
        # Caller-supplied headers are preserved; auth headers win on conflict
        # so callers can't accidentally drop the Bearer token.
        user_headers = kwargs.pop("headers", None) or {}
        merged_headers = {**user_headers, **self._headers(method)}
        resp = await self._http.request(
            method, path, headers=merged_headers, **kwargs
        )
        # Refresh CSRF token from response if present
        new_csrf = resp.headers.get("x-csrf-token")
        if new_csrf:
            self._csrf_token = new_csrf
        if resp.status_code == 401:
            logger.debug("Token expired, re-authenticating")
            await self._refresh_auth(attempted_version)
            attempted_version = self._auth_version
            merged_headers = {**user_headers, **self._headers(method)}
            resp = await self._http.request(
                method, path, headers=merged_headers, **kwargs
            )
            new_csrf = resp.headers.get("x-csrf-token")
            if new_csrf:
                self._csrf_token = new_csrf
        if resp.status_code == 403 and "CSRF" in resp.text:
            logger.debug("CSRF token expired, refreshing")
            await self._refresh_auth(attempted_version)
            merged_headers = {**user_headers, **self._headers(method)}
            resp = await self._http.request(
                method, path, headers=merged_headers, **kwargs
            )
        resp.raise_for_status()
        return resp

    async def get(self, path: str, **kwargs: Any) -> Any:
        resp = await self.request("GET", path, **kwargs)
        return resp.json()

    async def post(self, path: str, **kwargs: Any) -> Any:
        resp = await self.request("POST", path, **kwargs)
        if resp.status_code == 204:
            return None
        return resp.json()

    async def put(self, path: str, **kwargs: Any) -> Any:
        resp = await self.request("PUT", path, **kwargs)
        if resp.status_code == 204:
            return None
        return resp.json()

    async def delete(self, path: str, **kwargs: Any) -> Any:
        resp = await self.request("DELETE", path, **kwargs)
        if resp.status_code == 204:
            return None
        try:
            return resp.json()
        except (ValueError, httpx.DecodingError):
            return None

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
