from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

_config: Config | None = None


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
        self.verify_ssl = os.environ.get(
            "PORTAINER_VERIFY_SSL", "true"
        ).lower() in ("true", "1", "yes")

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

        if not self.verify_ssl:
            logger.warning(
                "SSL verification is disabled (PORTAINER_VERIFY_SSL=false). "
                "This is insecure and should only be used with self-signed certificates."
            )


def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config()
    return _config
