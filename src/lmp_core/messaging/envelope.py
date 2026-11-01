"""Origin-signed message envelopes for future safe federation relays.

The envelope preserves origin authorship when the authenticated network peer is
an intermediary. It does not itself authorize a relay or guarantee delivery.
The alpha wire representation is canonical JSON and may change before v1.0.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..errors import AuthenticationError
from ..security.identity import IdentityDocument, IdentityKeyPair, verify_identity_document

_DOMAIN = b"LMP:SIGNED-MESSAGE-ENVELOPE:V1\x00"
_MAX_MESSAGE_ID = 128
_MAX_RECIPIENT = 256
_MAX_TTL_SECONDS = 7 * 24 * 60 * 60
_CLOCK_SKEW_SECONDS = 300


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("expected base64url string")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _body_fields(body: Any) -> tuple[str, str]:
    if isinstance(body, bytes):
        return "bytes", _b64(body)
    if isinstance(body, (str, dict, list)):
        return "json", _canonical({"value": body}).decode("utf-8")
    raise ValueError("body must be str, bytes, dict, or list")


def _decode_body(kind: str, value: str) -> Any:
    if kind == "bytes":
        return _unb64(value)
    if kind == "json":
        parsed = json.loads(value)
        if not isinstance(parsed, dict) or set(parsed) != {"value"}:
            raise ValueError("invalid JSON body envelope")
        return parsed["value"]
    raise ValueError("unsupported body encoding")


@dataclass(frozen=True, slots=True)
class SignedMessageEnvelope:
    """Immutable origin-signed message with stable ID and bounded validity."""
    version: int
    origin_principal_id: str
    identity_document: str
    message_id: str
    recipient: str
    created_at: int
    expires_at: int
    body_type: str
    body_data: str
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "origin_principal_id": self.origin_principal_id,
            "identity_document": self.identity_document,
            "message_id": self.message_id,
            "recipient": self.recipient,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "body_type": self.body_type,
            "body_data": self.body_data,
            "signature_algorithm": "Ed25519",
        }

    def to_dict(self) -> dict[str, Any]:
        result = self.unsigned_dict()
        result["signature"] = self.signature
        return result

    def to_bytes(self) -> bytes:
        return _canonical(self.to_dict())

    @property
    def body(self) -> Any:
        return _decode_body(self.body_type, self.body_data)

    @property
    def body_hash(self) -> str:
        return hashlib.sha256(self.body_data.encode("utf-8")).hexdigest()

    @classmethod
    def from_bytes(cls, raw: bytes) -> "SignedMessageEnvelope":
        try:
            value = json.loads(raw.decode("utf-8"))
            required = {
                "version", "origin_principal_id", "identity_document", "message_id",
                "recipient", "created_at", "expires_at", "body_type", "body_data",
                "signature_algorithm", "signature",
            }
            if not isinstance(value, dict) or set(value) != required:
                raise ValueError("envelope has missing or unknown fields")
            if value["signature_algorithm"] != "Ed25519":
                raise ValueError("unsupported signature algorithm")
            if _canonical(value) != raw:
                raise ValueError("envelope is not canonically encoded")
            strings = ("origin_principal_id", "identity_document", "message_id", "recipient",
                       "body_type", "body_data", "signature")
            if any(not isinstance(value[key], str) for key in strings):
                raise ValueError("invalid envelope field type")
            if any(isinstance(value[k], bool) or not isinstance(value[k], int)
                   for k in ("version", "created_at", "expires_at")):
                raise ValueError("invalid envelope integer field")
            return cls(value["version"], value["origin_principal_id"], value["identity_document"],
                       value["message_id"], value["recipient"], value["created_at"],
                       value["expires_at"], value["body_type"], value["body_data"], value["signature"])
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise AuthenticationError("invalid signed message envelope encoding") from exc


def create_signed_envelope(
    identity_keys: IdentityKeyPair,
    identity_document: IdentityDocument,
    *,
    message_id: str,
    recipient: str,
    body: Any,
    ttl_seconds: int = 24 * 60 * 60,
    now: int | None = None,
) -> SignedMessageEnvelope:
    """Create an origin signature; intermediaries cannot alter signed fields."""
    verify_identity_document(identity_document)
    if identity_document.principal_id != base64.urlsafe_b64encode(identity_keys.principal_id.value).rstrip(b"=").decode("ascii"):
        raise AuthenticationError("identity document does not belong to origin keypair")
    if not isinstance(message_id, str) or not 1 <= len(message_id) <= _MAX_MESSAGE_ID:
        raise ValueError("message_id must contain 1..128 characters")
    if not isinstance(recipient, str) or not 1 <= len(recipient) <= _MAX_RECIPIENT:
        raise ValueError("recipient must contain 1..256 characters")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= _MAX_TTL_SECONDS:
        raise ValueError("ttl_seconds must be between 1 second and 7 days")
    body_type, body_data = _body_fields(body)
    created = int(time.time()) if now is None else int(now)
    unsigned = {
        "version": 1,
        "origin_principal_id": identity_keys.principal_id_text,
        "identity_document": _b64(identity_document.to_bytes()),
        "message_id": message_id,
        "recipient": recipient,
        "created_at": created,
        "expires_at": created + ttl_seconds,
        "body_type": body_type,
        "body_data": body_data,
        "signature_algorithm": "Ed25519",
    }
    signature = identity_keys.signing_private_key.sign(_DOMAIN + _canonical(unsigned))
    return SignedMessageEnvelope(1, unsigned["origin_principal_id"], unsigned["identity_document"],
                                 message_id, recipient, created, created + ttl_seconds,
                                 body_type, body_data, _b64(signature))


def verify_signed_envelope(
    envelope: SignedMessageEnvelope,
    *,
    now: int | None = None,
    expected_recipient: str | None = None,
) -> IdentityDocument:
    """Verify origin document, signature, bounded TTL, and optional recipient."""
    try:
        if envelope.version != 1:
            raise ValueError("unsupported envelope version")
        if not 1 <= len(envelope.message_id) <= _MAX_MESSAGE_ID:
            raise ValueError("invalid message ID")
        if not 1 <= len(envelope.recipient) <= _MAX_RECIPIENT:
            raise ValueError("invalid recipient")
        if expected_recipient is not None and envelope.recipient != expected_recipient:
            raise ValueError("recipient mismatch")
        lifetime = envelope.expires_at - envelope.created_at
        if not 1 <= lifetime <= _MAX_TTL_SECONDS:
            raise ValueError("invalid envelope lifetime")
        current = int(time.time()) if now is None else int(now)
        if envelope.created_at > current + _CLOCK_SKEW_SECONDS:
            raise ValueError("envelope creation time is too far in the future")
        if envelope.expires_at <= current:
            raise ValueError("envelope has expired")
        body = envelope.body
        if not isinstance(body, (str, bytes, dict, list)):
            raise ValueError("unsupported message body")
        doc_raw = _unb64(envelope.identity_document)
        from ..security.identity import verify_document_bytes
        document, principal = verify_document_bytes(doc_raw)
        expected_principal = "lmp:p:" + base64.b32encode(principal.value).decode("ascii").rstrip("=").lower()
        if envelope.origin_principal_id != expected_principal:
            raise ValueError("origin Principal ID does not match identity document")
        signature = _unb64(envelope.signature)
        if len(signature) != 64:
            raise ValueError("invalid signature length")
        unsigned = envelope.unsigned_dict()
        unsigned["signature_algorithm"] = "Ed25519"
        Ed25519PublicKey.from_public_bytes(_unb64(document.signing_public_key)).verify(
            signature, _DOMAIN + _canonical(unsigned)
        )
        return document
    except AuthenticationError:
        raise
    except (ValueError, TypeError, KeyError, InvalidSignature) as exc:
        raise AuthenticationError("signed message envelope verification failed") from exc
