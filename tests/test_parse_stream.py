from __future__ import annotations

from portainer_mcp.tools.containers import _parse_docker_stream


def _frame(payload: bytes, stream_type: int = 1) -> bytes:
    """Build one Docker multiplexed frame: 8-byte header + payload."""
    header = bytes([stream_type, 0, 0, 0]) + len(payload).to_bytes(4, "big")
    return header + payload


def test_empty_input() -> None:
    assert _parse_docker_stream(b"") == ""


def test_single_frame() -> None:
    assert _parse_docker_stream(_frame(b"hello\n")) == "hello\n"


def test_multiple_frames_concatenated() -> None:
    raw = _frame(b"line1\n", stream_type=1) + _frame(b"line2\n", stream_type=2)
    assert _parse_docker_stream(raw) == "line1\nline2\n"


def test_non_multiplexed_plaintext_fallback() -> None:
    # Plain bytes whose first 8 bytes don't describe a valid frame should be
    # decoded as-is rather than silently dropping the first 8 bytes.
    assert _parse_docker_stream(b"plain text output") == "plain text output"


def test_truncated_trailing_frame_best_effort() -> None:
    # A valid frame followed by a header promising more bytes than exist:
    # the decoded first frame is preserved and the partial tail decoded.
    good = _frame(b"complete\n")
    truncated_header = bytes([1, 0, 0, 0]) + (100).to_bytes(4, "big") + b"partial"
    out = _parse_docker_stream(good + truncated_header)
    assert "complete\n" in out
    assert "partial" in out


def test_non_ascii_payload_preserved() -> None:
    assert _parse_docker_stream(_frame("Ошибка\n".encode())) == "Ошибка\n"
