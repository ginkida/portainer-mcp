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


def test_truncated_first_frame_drops_header_bytes() -> None:
    # A single frame whose header promises more bytes than exist: the payload
    # tail must be returned WITHOUT the 8 binary header bytes leaking through.
    raw = bytes([1, 0, 0, 0]) + (100).to_bytes(4, "big") + b"partial"
    assert _parse_docker_stream(raw) == "partial"


def test_zero_length_frame_skipped() -> None:
    assert _parse_docker_stream(_frame(b"") + _frame(b"data\n")) == "data\n"


def test_implausible_header_falls_back_to_plain_decode() -> None:
    # First byte is a valid stream type but the padding bytes are non-zero —
    # not a multiplexed header, so the whole buffer is plain text.
    raw = bytes([1, 7, 7, 7]) + b"not a frame"
    assert _parse_docker_stream(raw) == raw.decode()


def test_plaintext_tail_after_valid_frames_preserved() -> None:
    # A valid frame followed by non-frame bytes: the tail is decoded as text
    # rather than silently dropped.
    out = _parse_docker_stream(_frame(b"ok\n") + b"plain tail")
    assert out == "ok\nplain tail"


def test_mid_header_tail_after_valid_frame_dropped() -> None:
    # Fewer than 8 trailing bytes can't be a header; with frames already
    # decoded the fragment is dropped (it's binary header debris, not text).
    out = _parse_docker_stream(_frame(b"ok\n") + bytes([1, 0]))
    assert "ok\n" in out
