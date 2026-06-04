from __future__ import annotations

from collections.abc import Iterator

import pytest

import portainer_mcp.client as client_mod
import portainer_mcp.config as config_mod


@pytest.fixture(autouse=True)
def portainer_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Provide valid credentials and reset the module-level singletons.

    Every test starts from a clean Config/PortainerClient so global state can't
    leak between cases.
    """
    monkeypatch.setenv("PORTAINER_URL", "https://portainer.test")
    monkeypatch.setenv("PORTAINER_USERNAME", "admin")
    monkeypatch.setenv("PORTAINER_PASSWORD", "secret")
    for var in (
        "PORTAINER_TIMEOUT",
        "PORTAINER_LONG_TIMEOUT",
        "PORTAINER_HTTP_MAX_CONNECTIONS",
        "PORTAINER_HTTP_MAX_KEEPALIVE",
        "PORTAINER_DEFAULT_ENDPOINT",
        "PORTAINER_VERIFY_SSL",
        "PORTAINER_JWT_TTL",
    ):
        monkeypatch.delenv(var, raising=False)
    config_mod._config = None
    client_mod._client = None
    yield
    config_mod._config = None
    client_mod._client = None
