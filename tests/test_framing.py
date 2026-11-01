import pytest

from lmp_core.framing import (
    DEFAULT_MAX_FRAME_SIZE, HEADER_SIZE, TYPE_MESSAGE, Frame, FrameError,
    decode_header,
)


def test_header_is_20_bytes_and_round_trips():
    frame = Frame(TYPE_MESSAGE, b"abc", request_id=42)
    encoded = frame.encode()
    assert HEADER_SIZE == 20
    assert len(encoded) == 23
    frame_type, flags, payload_len, request_id = decode_header(encoded[:HEADER_SIZE])
    assert (frame_type, flags, payload_len, request_id) == (TYPE_MESSAGE, 0, 3, 42)
    assert encoded[HEADER_SIZE:] == b"abc"


def test_bad_magic_rejected():
    encoded = bytearray(Frame(TYPE_MESSAGE, b"x").encode())
    encoded[0] = 0
    with pytest.raises(FrameError, match="magic"):
        decode_header(bytes(encoded[:HEADER_SIZE]))


def test_nonzero_flags_rejected():
    encoded = bytearray(Frame(TYPE_MESSAGE, b"x").encode())
    encoded[6] = 0
    encoded[7] = 1
    with pytest.raises(FrameError, match="flags"):
        decode_header(bytes(encoded[:HEADER_SIZE]))


def test_oversized_payload_rejected_before_reading_body():
    encoded = bytearray(Frame(TYPE_MESSAGE, b"").encode())
    # payload length starts at byte offset 8
    encoded[8:12] = (DEFAULT_MAX_FRAME_SIZE + 1).to_bytes(4, "big")
    with pytest.raises(FrameError, match="maximum"):
        decode_header(bytes(encoded[:HEADER_SIZE]))


def test_invalid_request_id_rejected():
    with pytest.raises(FrameError, match="uint64"):
        Frame(TYPE_MESSAGE, b"", request_id=-1).encode()


def test_frame_type_zero_rejected_on_encode():
    with pytest.raises(FrameError, match="frame type"):
        Frame(0, b"").encode()


def test_non_bytes_payload_rejected():
    with pytest.raises(FrameError, match="payload must be bytes"):
        Frame(TYPE_MESSAGE, "hello").encode()
