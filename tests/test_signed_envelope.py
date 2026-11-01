from dataclasses import replace
import pytest

from lmp_core.errors import AuthenticationError
from lmp_core.messaging.envelope import (
    SignedMessageEnvelope,
    create_signed_envelope,
    verify_signed_envelope,
)
from lmp_core.security.identity import IdentityKeyPair


def _envelope(body=None, ttl=300):
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document()
    envelope = create_signed_envelope(
        keys, doc, message_id="msg-001", recipient="lmp:p:recipient",
        body={"text": "hello"} if body is None else body,
        ttl_seconds=ttl, now=1_800_000_000,
    )
    return keys, doc, envelope


def test_signed_envelope_roundtrip_and_verification():
    _, doc, envelope = _envelope()
    encoded = envelope.to_bytes()
    parsed = SignedMessageEnvelope.from_bytes(encoded)
    verified_doc = verify_signed_envelope(parsed, now=1_800_000_100,
                                          expected_recipient="lmp:p:recipient")
    assert verified_doc == doc
    assert parsed.body == {"text": "hello"}
    assert parsed.to_bytes() == encoded


@pytest.mark.parametrize("body", ["hello", b"\x00\x01", [1, "two"], {"nested": {"x": True}}])
def test_signed_envelope_supports_message_body_types(body):
    _, _, envelope = _envelope(body=body)
    assert verify_signed_envelope(envelope, now=1_800_000_100)
    assert envelope.body == body


def test_signed_envelope_rejects_modified_body_or_recipient():
    _, _, envelope = _envelope()
    tampered = replace(envelope, recipient="lmp:p:attacker")
    with pytest.raises(AuthenticationError):
        verify_signed_envelope(tampered, now=1_800_000_100)
    tampered_body = replace(envelope, body_data='{"value":"tampered"}')
    with pytest.raises(AuthenticationError):
        verify_signed_envelope(tampered_body, now=1_800_000_100)


def test_signed_envelope_rejects_expired_and_wrong_recipient():
    _, _, envelope = _envelope(ttl=30)
    with pytest.raises(AuthenticationError, match="verification failed"):
        verify_signed_envelope(envelope, now=1_800_000_031)
    with pytest.raises(AuthenticationError, match="verification failed"):
        verify_signed_envelope(envelope, now=1_800_000_010, expected_recipient="lmp:p:other")


def test_signed_envelope_rejects_noncanonical_and_unknown_fields():
    _, _, envelope = _envelope()
    raw = envelope.to_bytes()
    with pytest.raises(AuthenticationError):
        SignedMessageEnvelope.from_bytes(raw + b" ")
    value = envelope.to_dict()
    value["extra"] = True
    import json
    with pytest.raises(AuthenticationError):
        SignedMessageEnvelope.from_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def test_signed_envelope_creation_rejects_bad_ttl_and_wrong_identity():
    keys, doc, _ = _envelope()
    other = IdentityKeyPair.generate()
    with pytest.raises(AuthenticationError):
        create_signed_envelope(other, doc, message_id="x", recipient="r", body="hi")
    with pytest.raises(ValueError):
        create_signed_envelope(keys, doc, message_id="x", recipient="r", body="hi", ttl_seconds=0)
