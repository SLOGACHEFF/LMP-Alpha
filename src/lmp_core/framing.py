"""LMP frame encoding and strict bounded parsing."""
from __future__ import annotations

import struct
from dataclasses import dataclass

MAGIC = b"LMP\x00"
FRAME_VERSION = 1
HEADER = struct.Struct(">4sBBHIQ")
HEADER_SIZE = HEADER.size  # 20 bytes
DEFAULT_MAX_FRAME_SIZE = 1 * 1024 * 1024
HARD_MAX_FRAME_SIZE = 16 * 1024 * 1024

TYPE_HELLO = 0x01
TYPE_HELLO_ACK = 0x02
TYPE_IDENTITY_PROOF = 0x03
TYPE_IDENTITY_ACCEPT = 0x04
TYPE_MESSAGE = 0x30
TYPE_SIGNED_ENVELOPE = 0x31
TYPE_DELIVERY_ACK = 0x40
TYPE_ERROR = 0x70


class FrameError(ValueError):
    """Raised when a frame violates the wire format or local limits."""


@dataclass(frozen=True, slots=True)
class Frame:
    frame_type: int
    payload: bytes
    request_id: int = 0
    flags: int = 0
    version: int = FRAME_VERSION

    def encode(self, *, max_frame_size: int = DEFAULT_MAX_FRAME_SIZE) -> bytes:
        validate_frame(self, max_frame_size=max_frame_size)
        return HEADER.pack(MAGIC, self.version, self.frame_type, self.flags,
                           len(self.payload), self.request_id) + self.payload


def validate_frame(frame: Frame, *, max_frame_size: int = DEFAULT_MAX_FRAME_SIZE) -> None:
    if not 1 <= frame.frame_type <= 255:
        raise FrameError("frame type must be in range 1..255")
    if not isinstance(frame.payload, bytes):
        raise FrameError("payload must be bytes")
    if max_frame_size < 0:
        raise FrameError("maximum frame size cannot be negative")
    if frame.version != FRAME_VERSION:
        raise FrameError("unsupported frame version")
    if frame.flags != 0:
        raise FrameError("nonzero flags are reserved in this alpha")
    if not 0 <= frame.request_id <= 0xFFFFFFFFFFFFFFFF:
        raise FrameError("request ID must fit in uint64")
    if len(frame.payload) > min(max_frame_size, HARD_MAX_FRAME_SIZE):
        raise FrameError("payload exceeds configured maximum")


def decode_header(data: bytes, *, max_frame_size: int = DEFAULT_MAX_FRAME_SIZE) -> tuple[int, int, int, int]:
    if len(data) != HEADER_SIZE:
        raise FrameError("header must be exactly 20 bytes")
    magic, version, frame_type, flags, payload_len, request_id = HEADER.unpack(data)
    if magic != MAGIC:
        raise FrameError("invalid LMP magic")
    if version != FRAME_VERSION:
        raise FrameError("unsupported frame version")
    if flags != 0:
        raise FrameError("nonzero flags are reserved in this alpha")
    if frame_type == 0:
        raise FrameError("frame type 0 is invalid")
    if payload_len > min(max_frame_size, HARD_MAX_FRAME_SIZE):
        raise FrameError("payload exceeds configured maximum")
    return frame_type, flags, payload_len, request_id
