"""Signed relay receipts and bounded forwarding policy for LMP alpha.

The origin-signed envelope remains immutable. Each relay appends a signed receipt
that binds its identity to the envelope hash and prior receipt chain. This is a
prototype policy primitive, not yet wired into the network frame handler.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..errors import AuthenticationError, AuthorizationError
from ..security.identity import IdentityDocument, IdentityKeyPair, verify_identity_document, verify_document_bytes
from .envelope import SignedMessageEnvelope, verify_signed_envelope

_DOMAIN = b"LMP:RELAY-RECEIPT:V1\x00"
_MAX_HOPS_HARD = 16
_GENESIS = "0" * 64


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


@dataclass(frozen=True, slots=True)
class RelayReceipt:
    version: int
    message_id: str
    envelope_hash: str
    hop_index: int
    relay_principal_id: str
    identity_document: str
    previous_receipt_hash: str
    created_at: int
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "message_id": self.message_id,
            "envelope_hash": self.envelope_hash,
            "hop_index": self.hop_index,
            "relay_principal_id": self.relay_principal_id,
            "identity_document": self.identity_document,
            "previous_receipt_hash": self.previous_receipt_hash,
            "created_at": self.created_at,
            "signature_algorithm": "Ed25519",
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    def to_bytes(self) -> bytes:
        return _canonical(self.to_dict())

    @property
    def receipt_hash(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class RelayTrace:
    receipts: tuple[RelayReceipt, ...] = ()

    @property
    def hop_count(self) -> int:
        return len(self.receipts)

    def to_bytes(self) -> bytes:
        """Serialize the ordered receipt chain using canonical JSON."""
        return _canonical({"version": 1, "receipts": [r.to_dict() for r in self.receipts]})

    @classmethod
    def from_bytes(cls, raw: bytes) -> "RelayTrace":
        """Parse a bounded, canonical relay trace; cryptographic checks are separate."""
        try:
            if not isinstance(raw, bytes) or len(raw) > 256 * 1024:
                raise ValueError("relay trace must be bytes no larger than 256 KiB")
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict) or set(value) != {"version", "receipts"} or value["version"] != 1:
                raise ValueError("invalid relay trace envelope")
            if not isinstance(value["receipts"], list) or len(value["receipts"]) > _MAX_HOPS_HARD:
                raise ValueError("invalid relay receipt list")
            if _canonical(value) != raw:
                raise ValueError("relay trace is not canonical")
            receipts = []
            required = {"version", "message_id", "envelope_hash", "hop_index", "relay_principal_id",
                        "identity_document", "previous_receipt_hash", "created_at", "signature_algorithm", "signature"}
            for item in value["receipts"]:
                if not isinstance(item, dict) or set(item) != required or item["signature_algorithm"] != "Ed25519":
                    raise ValueError("invalid relay receipt fields")
                for key in ("version", "hop_index", "created_at"):
                    if isinstance(item[key], bool) or not isinstance(item[key], int):
                        raise ValueError("invalid relay receipt integer")
                for key in ("message_id", "envelope_hash", "relay_principal_id", "identity_document", "previous_receipt_hash", "signature"):
                    if not isinstance(item[key], str):
                        raise ValueError("invalid relay receipt string")
                receipts.append(RelayReceipt(item["version"], item["message_id"], item["envelope_hash"],
                    item["hop_index"], item["relay_principal_id"], item["identity_document"],
                    item["previous_receipt_hash"], item["created_at"], item["signature"]))
            return cls(tuple(receipts))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, KeyError, ValueError) as exc:
            raise AuthenticationError("invalid relay trace encoding") from exc

    def append(
        self,
        envelope: SignedMessageEnvelope,
        relay_keys: IdentityKeyPair,
        relay_document: IdentityDocument,
        *,
        now: int | None = None,
        max_hops: int = 8,
        allowed_relays: Iterable[str] | None = None,
    ) -> "RelayTrace":
        """Append this relay's signed receipt after enforcing local forwarding policy."""
        verify_signed_envelope(envelope, now=now)
        principal = verify_identity_document(relay_document)
        principal_text = "lmp:p:" + base64.b32encode(principal.value).decode("ascii").rstrip("=").lower()
        if principal != relay_keys.principal_id or principal_text != relay_keys.principal_id_text:
            raise AuthenticationError("relay document does not match supplied keypair")
        if not isinstance(max_hops, int) or isinstance(max_hops, bool) or not 1 <= max_hops <= _MAX_HOPS_HARD:
            raise ValueError(f"max_hops must be between 1 and {_MAX_HOPS_HARD}")
        if len(self.receipts) >= max_hops:
            raise AuthorizationError("relay hop limit exceeded")
        if allowed_relays is None:
            raise AuthorizationError("an explicit relay allow-list is required")
        allowed = set(allowed_relays)
        if principal_text not in allowed:
            raise AuthorizationError("this node is not authorized to relay messages")
        seen = {r.relay_principal_id for r in self.receipts}
        if principal_text in seen:
            raise AuthorizationError("relay loop detected")
        # Origin itself must not be a relay in its own forwarding chain.
        if principal_text == envelope.origin_principal_id:
            raise AuthorizationError("origin cannot appear as a relay")
        prior_hash = self.receipts[-1].receipt_hash if self.receipts else _GENESIS
        created = int(time.time()) if now is None else now
        if not isinstance(created, int) or isinstance(created, bool) or created < 0:
            raise ValueError("now must be a non-negative integer timestamp")
        unsigned = {
            "version": 1,
            "message_id": envelope.message_id,
            "envelope_hash": hashlib.sha256(envelope.to_bytes()).hexdigest(),
            "hop_index": len(self.receipts) + 1,
            "relay_principal_id": principal_text,
            "identity_document": _b64(relay_document.to_bytes()),
            "previous_receipt_hash": prior_hash,
            "created_at": created,
            "signature_algorithm": "Ed25519",
        }
        signature = relay_keys.signing_private_key.sign(_DOMAIN + _canonical(unsigned))
        receipt = RelayReceipt(
            unsigned["version"], unsigned["message_id"], unsigned["envelope_hash"],
            unsigned["hop_index"], unsigned["relay_principal_id"], unsigned["identity_document"],
            unsigned["previous_receipt_hash"], unsigned["created_at"], _b64(signature),
        )
        return RelayTrace(self.receipts + (receipt,))


def verify_relay_trace(
    envelope: SignedMessageEnvelope,
    trace: RelayTrace,
    *,
    allowed_relays: Iterable[str],
    now: int | None = None,
    max_hops: int = 8,
    max_receipt_age_seconds: int = 7 * 24 * 60 * 60,
) -> tuple[str, ...]:
    """Verify a receipt chain and enforce explicit relay allow-list and bounds."""
    try:
        verify_signed_envelope(envelope, now=now)
        if not isinstance(max_hops, int) or isinstance(max_hops, bool) or not 1 <= max_hops <= _MAX_HOPS_HARD:
            raise ValueError("invalid max_hops")
        if len(trace.receipts) > max_hops:
            raise AuthorizationError("relay hop limit exceeded")
        if max_receipt_age_seconds < 1:
            raise ValueError("max_receipt_age_seconds must be positive")
        allowed = set(allowed_relays)
        envelope_hash = hashlib.sha256(envelope.to_bytes()).hexdigest()
        previous_hash = _GENESIS
        seen: set[str] = set()
        current = int(time.time()) if now is None else now
        for index, receipt in enumerate(trace.receipts, start=1):
            if receipt.version != 1 or receipt.hop_index != index:
                raise ValueError("invalid relay receipt sequence")
            if receipt.message_id != envelope.message_id or receipt.envelope_hash != envelope_hash:
                raise AuthenticationError("relay receipt is bound to a different message")
            if receipt.previous_receipt_hash != previous_hash:
                raise AuthenticationError("relay receipt chain is broken")
            if receipt.relay_principal_id not in allowed:
                raise AuthorizationError("untrusted relay in receipt chain")
            if receipt.relay_principal_id in seen or receipt.relay_principal_id == envelope.origin_principal_id:
                raise AuthorizationError("relay loop detected")
            if receipt.created_at > current + 300 or current - receipt.created_at > max_receipt_age_seconds:
                raise AuthenticationError("relay receipt timestamp outside policy")
            doc_raw = _unb64(receipt.identity_document)
            doc, principal = verify_document_bytes(doc_raw)
            principal_text = "lmp:p:" + base64.b32encode(principal.value).decode("ascii").rstrip("=").lower()
            if principal_text != receipt.relay_principal_id:
                raise AuthenticationError("relay identity mismatch")
            signature = _unb64(receipt.signature)
            if len(signature) != 64:
                raise ValueError("invalid relay signature length")
            Ed25519PublicKey.from_public_bytes(_unb64(doc.signing_public_key)).verify(
                signature, _DOMAIN + _canonical(receipt.unsigned_dict())
            )
            seen.add(principal_text)
            previous_hash = receipt.receipt_hash
        return tuple(r.relay_principal_id for r in trace.receipts)
    except (InvalidSignature, AuthenticationError, AuthorizationError):
        raise
    except (ValueError, TypeError, KeyError) as exc:
        raise AuthenticationError("relay trace verification failed") from exc
