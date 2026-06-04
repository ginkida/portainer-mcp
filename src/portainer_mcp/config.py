from __future__ import annotations

import logging
import os
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_config: Config | None = None

# Hosts for which plain http:// is tolerated (credentials never leave the box).
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _positive_float(name: str, default: str) -> float:
    raw = os.environ.get(name, default)
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{name} must be a number, got {raw!r}") from None
    if value <= 0:
        raise ValueError(f"{name} must be positive, got {value}")
    return value


def _positive_int(name: str, default: str) -> int:
    raw = os.environ.get(name, default)
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None
    if value <= 0:
        raise ValueError(f"{name} must be positive, got {value}")
    return value


class Config:
    def __init__(self) -> None:
        self.url = os.environ.get("PORTAINER_URL", "").rstrip("/")
        self.username = os.environ.get("PORTAINER_USERNAME", "")
        self.password = os.environ.get("PORTAINER_PASSWORD", "")

        raw_endpoint = os.environ.get("PORTAINER_DEFAULT_ENDPOINT", "1")
        try:
            self.default_endpoint = int(raw_endpoint)
        except ValueError:
            raise ValueError(
                f"PORTAINER_DEFAULT_ENDPOINT must be an integer, got {raw_endpoint!r}"
            ) from None
        if self.default_endpoint <= 0:
            raise ValueError(
                "PORTAINER_DEFAULT_ENDPOINT must be a positive integer, "
                f"got {self.default_endpoint}"
            )

        self.verify_ssl = os.environ.get("PORTAINER_VERIFY_SSL", "true").lower() in (
            "true",
            "1",
            "yes",
        )

        # Network tuning — all overridable via env, with safe defaults.
        # `timeout` covers ordinary metadata calls; `long_timeout` covers
        # genuinely slow operations (image pull, container exec, large log
        # scans) that legitimately run for minutes and must not be capped at 30s.
        self.timeout = _positive_float("PORTAINER_TIMEOUT", "30")
        self.long_timeout = _positive_float("PORTAINER_LONG_TIMEOUT", "300")
        self.http_max_connections = _positive_int("PORTAINER_HTTP_MAX_CONNECTIONS", "100")
        self.http_max_keepalive = _positive_int("PORTAINER_HTTP_MAX_KEEPALIVE", "20")
        # Proactive JWT refresh interval. Must stay below Portainer's configured
        # session lifetime (default 8h) or every call pays a 401 + re-auth
        # round-trip once the server-side token expires first.
        self.jwt_ttl = _positive_float("PORTAINER_JWT_TTL", str(7 * 3600))

        missing: list[str] = []
        if not self.url:
            missing.append("PORTAINER_URL")
        if not self.username:
            missing.append("PORTAINER_USERNAME")
        if not self.password:
            missing.append("PORTAINER_PASSWORD")
        if missing:
            raise ValueError(
                f"Missing required environment variables: {', '.join(missing)}"
            )

        self._validate_url()

        if not self.verify_ssl:
            logger.warning(
                "SSL verification is disabled (PORTAINER_VERIFY_SSL=false). "
                "This is insecure and should only be used with self-signed certificates."
            )

    def _validate_url(self) -> None:
        """Fail fast on a malformed PORTAINER_URL and warn on insecure transport.

        A path component (e.g. a trailing /api) silently 404s every call, so we
        reject it with a clear message instead. Plain http:// to a remote host
        leaks credentials in cleartext — we warn rather than block (mirroring the
        verify_ssl warning) so existing dev setups keep working.
        """
        parsed = urlparse(self.url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(
                "PORTAINER_URL must be an absolute URL with a scheme, e.g. "
                f"https://portainer.example.com:9443. Got {self.url!r}"
            )
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"PORTAINER_URL scheme must be http or https, got {parsed.scheme!r}"
            )
        if parsed.path:
            raise ValueError(
                "PORTAINER_URL must be a root URL without a path component, not "
                f"{self.url!r}. Remove any trailing /api or other path segment."
            )
        if parsed.scheme == "http" and parsed.hostname not in _LOOPBACK_HOSTS:
            logger.warning(
                "PORTAINER_URL uses plain http:// to a non-loopback host (%s). "
                "Credentials and the JWT are sent in cleartext and can be "
                "intercepted. Use https:// for any remote Portainer.",
                parsed.hostname,
            )


def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config()
    return _config
