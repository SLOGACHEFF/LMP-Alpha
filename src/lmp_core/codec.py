"""Bounded CBOR payload helpers."""
from __future__ import annotations

import cbor2

from .framing import FrameError


def encode_payload(value: object) -> bytes:
    try:
        # Canonical encoding is used for predictable local test vectors.
        return cbor2.dumps(value, canonical=True)
    except Exception as exc:  # library exceptions vary by input type
        raise FrameError("payload cannot be encoded as CBOR") from exc


def decode_payload(data: bytes) -> object:
    try:
        value = cbor2.loads(data)
    except Exception as exc:
        raise FrameError("malformed CBOR payload") from exc
    # Core control/data payloads are maps in this prototype.
    if not isinstance(value, dict):
        raise FrameError("CBOR payload must be a map")
    return value
