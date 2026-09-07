from __future__ import annotations

import json

import httpx
import pytest

from portainer_mcp.errors import (
    REDACTED,
    error_response,
    is_sensitive_env_name,
    redact_compose_text,
    redact_env_pairs,
    redact_env_strings,
    redact_env_value,
    redact_secrets,
    resolve_endpoint,
    tool_error_handler,
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
    ("raw", "leak"),
    [
        ("run --password=hunter2", "hunter2"),
        ("Authorization: Bearer abc.def.ghi", "abc.def.ghi"),
        ("export API_KEY=sk-12345", "sk-12345"),
        ("TOKEN: deadbeef", "deadbeef"),
        ("secret=topsecret", "topsecret"),
        # Prefixed/suffixed key names
        ("AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ("DB_PASSWORD=supersecret", "supersecret"),
        # Quoted values with spaces must be redacted in full
        ('PASSWORD="quoted value with space"', "quoted value"),
        ("PASSWORD='single quoted pw'", "single quoted"),
        # CLI password flags
        ("pg_dump --password hunter2", "hunter2"),
        ("pg_dump --password=hunter2", "hunter2"),
        # Connection-string credentials (incl. empty-user form)
        ("postgresql://user:p4ss@host/db", "p4ss"),
        ("mongodb://admin:m0ng0@mongo:27017", "m0ng0"),
        ("redis://:authpass@cache:6379", "authpass"),
        # Password containing a literal '@' must be redacted in full
        ("postgres://user:p@ss@host/db", "p@ss"),
        # Bare bearer token without an Authorization prefix
        ("Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig", "eyJhbGciOiJIUzI1NiJ9"),
    ],
)
def test_redact_secrets_masks(raw: str, leak: str) -> None:
    out = redact_secrets(raw)
    assert "REDACTED" in out
    assert leak not in out


@pytest.mark.parametrize(
    "clean",
    [
        "php artisan migrate",
        "git clone https://github.com/x/y",
        "ls -p /tmp",
        "CSRF token expired, refreshing",
        "https://portainer.example.com:9443/api/status",
        # Common flags must NOT be eaten by the --password/-p rules
        "find /var -print0 -path ./skip -prune",
        "docker run -p8080:80 nginx",
        "tar -pxvf archive.tar",
    ],
)
def test_redact_secrets_leaves_clean_text(clean: str) -> None:
    assert redact_secrets(clean) == clean


@pytest.mark.parametrize(
    "blob",
    [
        "A1b2C3d4" * 12_500,  # 100K word chars, no keywords (leading-\w* trap)
        "password" * 1_250,  # 10K keyword run, no separator (suffix-\w* trap)
        "pwd" * 3_333,
    ],
)
def test_redact_secrets_is_linear_on_pathological_text(blob: str) -> None:
    # Regression guard: an unbounded \w* before or after the keyword group
    # once made re.sub backtrack quadratically (250ms+ per call on the event
    # loop). Any of these inputs must redact in millis.
    import time

    start = time.perf_counter()
    redact_secrets(blob)
    assert time.perf_counter() - start < 0.5


def test_redact_secrets_caps_input_length() -> None:
    out = redact_secrets("x" * 50_000)
    assert len(out) < 11_000
    assert out.endswith("... (truncated)")


def test_error_response_preserves_non_ascii() -> None:
    out = error_response("Ошибка", "деталь")
    # Must NOT be \uXXXX-escaped (Russian-language logs matter per CLAUDE.md).
    assert "Ошибка" in out
    assert "деталь" in out
    parsed = json.loads(out)
    assert parsed == {"error": "Ошибка", "details": "деталь"}


def test_error_response_without_details() -> None:
    assert json.loads(error_response("boom")) == {"error": "boom"}


# --- tool_error_handler branches --------------------------------------------------


def _http_error(
    status: int, *, content: bytes | None = None, body: object = None
) -> httpx.HTTPStatusError:
    req = httpx.Request("GET", "https://portainer.test/api/x")
    if content is not None:
        resp = httpx.Response(status, content=content, request=req)
    else:
        resp = httpx.Response(status, json=body, request=req)
    return httpx.HTTPStatusError("boom", request=req, response=resp)


def _raising_tool(exc: Exception):  # type: ignore[no-untyped-def]
    @tool_error_handler
    async def tool() -> str:
        raise exc

    return tool


async def test_handler_validation_error_is_redacted() -> None:
    body = json.loads(await _raising_tool(ValueError("bad arg: token=SECRET123"))())
    assert body["error"] == "Validation error"
    assert "SECRET123" not in body["details"]
    assert "[REDACTED]" in body["details"]


async def test_handler_http_error_message_field() -> None:
    body = json.loads(await _raising_tool(_http_error(404, body={"message": "no such stack"}))())
    assert body["error"] == "Portainer API error (404)"
    assert body["details"] == "no such stack"


async def test_handler_http_error_nested_message_serialised() -> None:
    body = json.loads(
        await _raising_tool(_http_error(500, body={"message": {"code": 1, "msg": "x"}}))()
    )
    assert isinstance(body["details"], str)
    assert json.loads(body["details"]) == {"code": 1, "msg": "x"}


async def test_handler_http_error_dict_without_message() -> None:
    body = json.loads(await _raising_tool(_http_error(500, body={"foo": "bar"}))())
    assert json.loads(body["details"]) == {"foo": "bar"}


async def test_handler_http_error_list_body() -> None:
    body = json.loads(await _raising_tool(_http_error(500, body=["a", "b"]))())
    assert json.loads(body["details"]) == ["a", "b"]


async def test_handler_http_error_non_json_body_truncated() -> None:
    body = json.loads(
        await _raising_tool(_http_error(502, content=b"<html>" + b"x" * 1000))()
    )
    assert body["error"] == "Portainer API error (502)"
    assert len(body["details"]) <= 500


async def test_handler_transport_errors_map_to_connection_error() -> None:
    for exc in (
        httpx.ConnectError("refused"),
        httpx.ReadTimeout("slow"),
        httpx.ReadError("reset"),
        httpx.RemoteProtocolError("bad frame"),
    ):
        body = json.loads(await _raising_tool(exc)())
        assert body["error"] == "Connection error", type(exc).__name__


async def test_handler_unexpected_error_is_redacted() -> None:
    body = json.loads(await _raising_tool(RuntimeError("oops token=SUPERSECRET"))())
    assert body["error"] == "Internal error"
    assert "SUPERSECRET" not in body["details"]
    assert "[REDACTED]" in body["details"]


# --- environment-variable redaction ------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "CLICKHOUSE_PASSWORD", "DB_PASS", "APP_KEY", "API_KEY", "ApiKey", "JWT_SECRET",
        "AUTH_TOKEN", "AWS_SECRET_ACCESS_KEY", "PRIVATE_KEY", "MAIL_PWD", "DATABASE_DSN",
        "SIGNATURE", "REDIS_AUTH", "SESSION_SALT",
    ],
)
def test_sensitive_env_names(name: str) -> None:
    assert is_sensitive_env_name(name)


@pytest.mark.parametrize(
    "name",
    ["CLICKHOUSE_PORT", "APP_ENV", "MONKEY_COUNT", "BYPASS_CACHE", "AUTHOR", "TAG", "KEYSPACE"],
)
def test_non_sensitive_env_names(name: str) -> None:
    assert not is_sensitive_env_name(name)


def test_redact_env_value_rules() -> None:
    assert redact_env_value("DB_PASSWORD", "hunter2") == REDACTED
    assert redact_env_value("DB_PASSWORD", "") == ""
    # A bare variable reference is kept: the model needs it to edit compose.
    assert redact_env_value("DB_PASSWORD", "${DB_PASSWORD}") == "${DB_PASSWORD}"
    assert redact_env_value("DB_PASSWORD", "$DB_PASSWORD") == "$DB_PASSWORD"
    # ...but a reference with a default may carry the secret itself.
    assert redact_env_value("DB_PASSWORD", "${DB_PASSWORD:-hunter2}") == REDACTED
    # Non-sensitive names pass through, except embedded URL credentials.
    assert redact_env_value("DB_PORT", "5432") == "5432"
    url = "postgres://user:" + "p4ss@db/app"
    assert "p4ss" not in redact_env_value("DATABASE_URL", url)
    assert redact_env_value("DATABASE_URL", url).endswith("@db/app")


def test_redact_env_pairs_and_strings_keep_shape() -> None:
    pairs = [{"name": "TOKEN", "value": "t"}, {"name": "PORT", "value": "80"}, "junk", {"x": 1}]
    assert redact_env_pairs(pairs) == [
        {"name": "TOKEN", "value": REDACTED}, {"name": "PORT", "value": "80"}, "junk", {"x": 1},
    ]
    assert redact_env_strings(["TOKEN=t", "PORT=80", "NOEQ", 5]) == [
        f"TOKEN={REDACTED}", "PORT=80", "NOEQ", 5,
    ]


def test_redact_compose_text_preserves_structure() -> None:
    text = (
        "services:\n"
        "  web:\n"
        "    image: nginx:latest\n"
        "    environment:\n"
        "      - DB_PASSWORD=hunter2\n"
        "      - DB_HOST=db\n"
        '      APP_KEY: "base64:abc"\n'
        "      REF: ${DB_PASSWORD}\n"
        "    secrets:\n"
        "      - db_password\n"
        "  # password: comment-only line\n"
    )
    out = redact_compose_text(text)
    assert out.count("\n") == text.count("\n")
    assert "hunter2" not in out and "base64:abc" not in out
    assert f"      - DB_PASSWORD={REDACTED}\n" in out
    assert f"      APP_KEY: {REDACTED}\n" in out
    assert "      - DB_HOST=db\n" in out
    assert "    image: nginx:latest\n" in out
    assert "      REF: ${DB_PASSWORD}\n" in out
    assert "      - db_password\n" in out  # a list item without a value is untouched
    # Even a comment gets the generic secret-shape pass (recall over precision).
    assert "  # [REDACTED] line\n" in out


def test_redact_compose_text_is_linear_on_long_lines() -> None:
    import time

    blob = "\n".join(["PASSWORD_" * 2000] * 50) + "\n" + ("x" * 200_000)
    start = time.perf_counter()
    redact_compose_text(blob)
    assert time.perf_counter() - start < 0.5


def test_redact_compose_text_keeps_quoted_list_items_balanced() -> None:
    out = redact_compose_text('      - "DB_PASSWORD=x"\n      - \'TOKEN=y\'\n')
    assert out == f'      - "DB_PASSWORD={REDACTED}"\n      - \'TOKEN={REDACTED}\'\n'


@pytest.mark.parametrize(
    ("text", "leak", "keep"),
    [
        ("TLS_KEY=" + "A" * 5000, "AAAA", None),  # no length cap on the value
        ("  DB_PASSWORD: >\n    hunter2\n    tail\n  DB_HOST: db\n", "hunter2", "  DB_HOST: db"),
        ("  PRIVATE_KEY: |\n    -----BEGIN\n    abc\n  next: 1\n", "BEGIN", "  next: 1"),
        ("  command: mysql --password=hunter2 -h db", "hunter2", "-h db"),
        ("  db-password: hunter2", "hunter2", "db-password:"),
        ("    - " + "postgres://user:" + "pw@host/db", "pw@", "@host/db"),
    ],
)
def test_redact_compose_text_extra_shapes(text: str, leak: str, keep: str | None) -> None:
    out = redact_compose_text(text)
    assert leak not in out
    assert REDACTED in out
    if keep:
        assert keep in out
    assert out.count("\n") == text.count("\n")


def test_redact_compose_text_keeps_quoted_reference() -> None:
    line = '  DB_PASSWORD: "${DB_PASSWORD}"\n'
    assert redact_compose_text(line) == line
