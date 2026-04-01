from __future__ import annotations

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
        self._base_url_str = config.url
        self._http = httpx.AsyncClient(
            base_url=config.url,
            verify=config.verify_ssl,
            timeout=30.0,
        )

    async def _authenticate(self) -> None:
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
        if self._jwt is None or time.monotonic() - self._jwt_obtained_at >= self._JWT_TTL:
            await self._authenticate()

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
        resp = await self._http.request(method, path, headers=self._headers(method), **kwargs)
        # Refresh CSRF token from response if present
        new_csrf = resp.headers.get("x-csrf-token")
        if new_csrf:
            self._csrf_token = new_csrf
        if resp.status_code == 401:
            logger.debug("Token expired, re-authenticating")
            await self._authenticate()
            resp = await self._http.request(method, path, headers=self._headers(method), **kwargs)
        if resp.status_code == 403 and "CSRF" in resp.text:
            logger.debug("CSRF token expired, refreshing")
            await self._authenticate()
            resp = await self._http.request(method, path, headers=self._headers(method), **kwargs)
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
