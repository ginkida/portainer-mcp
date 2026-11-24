from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from http.cookiejar import CookieJar, DefaultCookiePolicy
from typing import Any

import httpx

from .config import get_config
from .errors import PortainerResponseError

logger = logging.getLogger(__name__)

_client: PortainerClient | None = None

_UNSAFE_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

# Defense-in-depth cap on a single response body. Portainer/Docker list and
# inspect payloads are normally well under a megabyte; a response advertising
# more than this almost certainly signals a misconfigured endpoint, and parsing
# it would needlessly inflate memory.
_MAX_RESPONSE_BYTES = 50_000_000
_STREAM_ERROR_BYTES = 8_192


def _cookieless_jar() -> CookieJar:
    """A cookie jar that refuses every cookie.

    ``POST /api/auth`` also sets the browser session cookie
    (``portainer_api_key``). Portainer enforces CSRF — gorilla/csrf's Origin /
    Referer + token check — only on requests that carry that cookie
    (``security.ShouldSkipCSRFCheck``); a Bearer-only request skips it. With a
    default jar httpx would replay the cookie, so a re-auth ``POST /api/auth``
    (no Referer by design) after a 401 or the JWT TTL came back as
    ``403 Forbidden - referer not supplied``. We authenticate with the header,
    never the cookie, so none is stored.
    """
    return CookieJar(policy=DefaultCookiePolicy(allowed_domains=[]))


async def _close_stream(response: httpx.Response) -> None:
    # A cancelled close can leave the pool slot occupied even after httpx
    # marks the response closed. Wait for cleanup before propagating cancellation.
    closing = asyncio.create_task(response.aclose())
    cancelled: asyncio.CancelledError | None = None
    try:
        while not closing.done():
            try:
                await asyncio.shield(closing)
            except asyncio.CancelledError as exc:
                cancelled = exc
        closing.result()
    finally:
        if cancelled is not None:
            raise cancelled


class PortainerClient:
    """HTTP client for the Portainer API with JWT authentication."""

    def __init__(self) -> None:
        config = get_config()
        # Proactively refresh the JWT before Portainer's session lifetime
        # (default 8h) expires it server-side; see PORTAINER_JWT_TTL.
        self._jwt_ttl = config.jwt_ttl
        # API-key mode: a static X-API-Key header replaces the whole JWT/CSRF
        # state machine below (Portainer skips CSRF checks for API-key
        # requests and rejects a request carrying both an API key and a
        # Bearer token, so the two modes are mutually exclusive by design).
        self._api_key: str | None = config.api_key or None
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
            cookies=_cookieless_jar(),
            limits=httpx.Limits(
                max_connections=config.http_max_connections,
                max_keepalive_connections=config.http_max_keepalive,
            ),
        )

    def _jwt_is_fresh(self) -> bool:
        return self._jwt is not None and time.monotonic() - self._jwt_obtained_at < self._jwt_ttl

    async def _do_authenticate(self) -> None:
        config = get_config()
        logger.debug("Authenticating to Portainer as %s", config.username)
        # No Referer / CSRF token here. Without the session cookie (see
        # _cookieless_jar) Portainer skips the CSRF check for this call.
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
        """Authenticate if JWT is missing or stale (no-op in API-key mode)."""
        if self._api_key is not None or self._jwt_is_fresh():
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
                f"Portainer response too large: {cl} bytes (max {_MAX_RESPONSE_BYTES})."
            )
        if len(resp.content) > _MAX_RESPONSE_BYTES:
            raise ValueError(
                f"Portainer response too large: {len(resp.content)} bytes "
                f"(max {_MAX_RESPONSE_BYTES})."
            )

    def _headers(self, method: str = "GET") -> dict[str, str]:
        if self._api_key is not None:
            # No Referer / CSRF token: Portainer's bouncer skips the CSRF
            # check when the request authenticates with an API key.
            return {"X-API-Key": self._api_key}
        h: dict[str, str] = {"Authorization": f"Bearer {self._jwt}"}
        # Referer + CSRF token only for mutating methods. With no session
        # cookie Portainer skips CSRF for Bearer requests, so these are
        # belt-and-braces for a proxy that injects the cookie, not a need.
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
        return await self._request(method, path, timeout, stream=False, **kwargs)

    @asynccontextmanager
    async def stream(
        self,
        method: str,
        path: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[httpx.Response]:
        """Open an authenticated stream. The caller applies its body limit."""
        headers = {**(kwargs.pop("headers", None) or {}), "Accept-Encoding": "identity"}
        resp = await self._request(method, path, timeout, stream=True, headers=headers, **kwargs)
        try:
            yield resp
        finally:
            await _close_stream(resp)

    async def _request(
        self,
        method: str,
        path: str,
        timeout: float | None,
        *,
        stream: bool,
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
        for attempt in range(2):
            merged_headers = {**user_headers, **self._headers(method)}
            if stream:
                request = self._http.build_request(method, path, headers=merged_headers, **kwargs)
                opened = await self._http.send(request, stream=True)
            else:
                opened = await self._http.request(method, path, headers=merged_headers, **kwargs)
            keep_open = False
            try:
                await self._capture_csrf(opened)
                resp = opened
                can_retry = attempt == 0 and self._api_key is None
                retry_401 = can_retry and resp.status_code == 401
                if stream and not resp.is_success and not retry_401:
                    resp = await self._stream_error(opened)
                retry = retry_401 or (can_retry and resp.status_code == 403 and "CSRF" in resp.text)
                if not retry:
                    if not stream:
                        self._enforce_response_size(resp)
                    resp.raise_for_status()
                    keep_open = True
                    return resp
            finally:
                if stream and not keep_open:
                    await _close_stream(opened)

            # Close a rejected stream before refreshing auth, which may need
            # the same connection slot. Both modes retry at most once.
            reason = "401" if resp.status_code == 401 else "403 CSRF"
            logger.debug("Refreshing authentication after %s", reason)
            await self._refresh_auth(attempted_version)
            if method.upper() in _UNSAFE_METHODS:
                logger.warning(
                    "Retrying %s %s after %s; the mutation may be applied "
                    "twice if it had already taken effect server-side.",
                    method,
                    path,
                    reason,
                )
        raise AssertionError("Request retry loop exhausted")

    @staticmethod
    async def _stream_error(resp: httpx.Response) -> httpx.Response:
        # Keep a small body for CSRF detection and the tool's error envelope.
        body = bytearray()
        if resp.is_stream_consumed:
            body.extend(resp.content[:_STREAM_ERROR_BYTES])
        else:
            # Not aiter_raw(): it closes the response on its own at EOF, and a
            # cancellation landing in that close leaks the pool slot. The one
            # close is the caller's _close_stream().
            stream = resp.stream
            assert isinstance(stream, httpx.AsyncByteStream)
            async for chunk in stream:
                body.extend(chunk[: _STREAM_ERROR_BYTES - len(body)])
                if len(body) == _STREAM_ERROR_BYTES:
                    break
        return httpx.Response(resp.status_code, content=bytes(body), request=resp.request)

    @staticmethod
    def _decode(resp: httpx.Response) -> Any:
        """Decode a successful response body.

        204 and empty bodies decode to ``None`` (network connect/disconnect and
        friends answer 200 with nothing — that is success, not an error). A
        *non-empty* body that is not JSON is a different story: it means we
        are not talking to Portainer's API (a proxy's HTML page, most often),
        and every caller would otherwise trip over ``None`` with an opaque
        "Internal error". Raise something descriptive instead.
        """
        if resp.status_code == 204 or not resp.content:
            return None
        try:
            return resp.json()
        except (ValueError, httpx.DecodingError):
            content_type = resp.headers.get("content-type", "unknown")
            preview = resp.text[:200].replace("\n", " ")
            raise PortainerResponseError(
                f"Portainer returned a non-JSON {resp.status_code} response "
                f"(content-type {content_type}) for {resp.request.method} "
                f"{resp.request.url.path}. Is PORTAINER_URL pointing at Portainer "
                f"itself rather than a proxy login page? Body starts: {preview!r}"
            ) from None

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
