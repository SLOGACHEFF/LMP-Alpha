import pytest

from lmp_core.codec import decode_payload, encode_payload
from lmp_core.framing import FrameError


def test_canonical_cbor_map_round_trip():
    value = {"message_id": "m-1", "body": "hello"}
    assert decode_payload(encode_payload(value)) == value


def test_canonical_cbor_known_vector():
    # RFC 8949 deterministic encoding: {"a": 1, "b": 2}.
    # Exact bytes make accidental changes to canonical map ordering visible.
    expected = bytes.fromhex("a2616101616202")
    value = {"b": 2, "a": 1}
    assert encode_payload(value) == expected
    assert decode_payload(expected) == {"a": 1, "b": 2}


def test_non_map_payload_rejected():
    import cbor2
    with pytest.raises(FrameError, match="map"):
        decode_payload(cbor2.dumps([1, 2, 3]))


def test_malformed_cbor_rejected():
    with pytest.raises(FrameError, match="malformed"):
        decode_payload(b"\xff\xff")
