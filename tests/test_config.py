from __future__ import annotations

import pytest

from portainer_mcp.config import Config


def test_defaults() -> None:
    cfg = Config()
    assert cfg.url == "https://portainer.test"
    assert cfg.default_endpoint == 1
    assert cfg.timeout == 30.0
    assert cfg.long_timeout == 300.0
    assert cfg.http_max_connections == 100
    assert cfg.http_max_keepalive == 20
    assert cfg.verify_ssl is True


def test_trailing_slash_stripped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PORTAINER_URL", "https://portainer.test/")
    assert Config().url == "https://portainer.test"


@pytest.mark.parametrize("missing", ["PORTAINER_URL", "PORTAINER_USERNAME", "PORTAINER_PASSWORD"])
def test_missing_required_var(monkeypatch: pytest.MonkeyPatch, missing: str) -> None:
    monkeypatch.setenv(missing, "")
    with pytest.raises(ValueError, match="Missing required"):
        Config()


@pytest.mark.parametrize(
    "url",
    [
        "https://host/api",  # path component
        "ftp://host",  # bad scheme
        "noscheme.example.com",  # no scheme
        "https://",  # no host
    ],
)
def test_invalid_url_rejected(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    monkeypatch.setenv("PORTAINER_URL", url)
    with pytest.raises(ValueError):
        Config()


@pytest.mark.parametrize("url", ["http://localhost:9000", "http://127.0.0.1", "https://remote.example"])
def test_valid_urls_accepted(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    monkeypatch.setenv("PORTAINER_URL", url)
    assert Config().url == url.rstrip("/")


def test_remote_http_warns(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("PORTAINER_URL", "http://remote.example.com")
    with caplog.at_level("WARNING"):
        Config()
    assert any("cleartext" in r.message for r in caplog.records)


@pytest.mark.parametrize(
    "var",
    ["PORTAINER_TIMEOUT", "PORTAINER_LONG_TIMEOUT", "PORTAINER_HTTP_MAX_CONNECTIONS"],
)
def test_non_numeric_tuning_rejected(monkeypatch: pytest.MonkeyPatch, var: str) -> None:
    monkeypatch.setenv(var, "abc")
    with pytest.raises(ValueError, match=var):
        Config()


@pytest.mark.parametrize("var", ["PORTAINER_TIMEOUT", "PORTAINER_HTTP_MAX_CONNECTIONS"])
def test_non_positive_tuning_rejected(monkeypatch: pytest.MonkeyPatch, var: str) -> None:
    monkeypatch.setenv(var, "0")
    with pytest.raises(ValueError, match="positive"):
        Config()


@pytest.mark.parametrize("value", ["0", "-3"])
def test_default_endpoint_must_be_positive(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("PORTAINER_DEFAULT_ENDPOINT", value)
    with pytest.raises(ValueError, match="positive"):
        Config()


def test_default_endpoint_must_be_int(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PORTAINER_DEFAULT_ENDPOINT", "notint")
    with pytest.raises(ValueError, match="integer"):
        Config()
