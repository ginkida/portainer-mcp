from __future__ import annotations

import json

import pytest

from portainer_mcp.errors import (
    error_response,
    redact_secrets,
    resolve_endpoint,
    validate_id,
)


def test_resolve_endpoint_default_and_explicit() -> None:
    assert resolve_endpoint(None, 7) == 7
    assert resolve_endpoint(3, 7) == 3
    assert resolve_endpoint(0, 7) == 0  # 0 is a valid non-negative id


@pytest.mark.parametrize("bad", [-1, True, "1", 1.5])
def test_resolve_endpoint_rejects_bad(bad: object) -> None:
    with pytest.raises(ValueError):
        resolve_endpoint(bad, 7)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [0, -5, True, "1", 1.5])
def test_validate_id_rejects_bad(bad: object) -> None:
    with pytest.raises(ValueError):
        validate_id(bad, "stack_id")  # type: ignore[arg-type]


def test_validate_id_accepts_positive() -> None:
    validate_id(1, "stack_id")
    validate_id(999, "user_id")


@pytest.mark.parametrize(
    "raw",
    [
        "run --password=hunter2",
        "Authorization: Bearer abc.def.ghi",
        "export API_KEY=sk-12345",
        "TOKEN: deadbeef",
        "secret=topsecret",
    ],
)
def test_redact_secrets_masks(raw: str) -> None:
    out = redact_secrets(raw)
    assert "[REDACTED]" in out
    for leak in ("hunter2", "abc.def.ghi", "sk-12345", "deadbeef", "topsecret"):
        assert leak not in out


def test_redact_secrets_leaves_clean_text() -> None:
    assert redact_secrets("php artisan migrate") == "php artisan migrate"


def test_error_response_preserves_non_ascii() -> None:
    out = error_response("Ошибка", "деталь")
    # Must NOT be \uXXXX-escaped (Russian-language logs matter per CLAUDE.md).
    assert "Ошибка" in out
    assert "деталь" in out
    parsed = json.loads(out)
    assert parsed == {"error": "Ошибка", "details": "деталь"}


def test_error_response_without_details() -> None:
    assert json.loads(error_response("boom")) == {"error": "boom"}
