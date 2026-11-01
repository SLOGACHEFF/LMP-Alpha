"""Draft LMP identity documents using Ed25519.

This is a prototype profile, not a finalized wire standard. It uses a small,
deterministic JSON representation until the canonical CBOR profile is frozen.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import time
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..api import PrincipalId
from ..errors import AuthenticationError

_DOMAIN = b"LMP:PRINCIPAL:V1\x00"
_DOCUMENT_DOMAIN = b"LMP:IDENTITY-DOCUMENT:V1\x00"
_PROOF_DOMAIN = b"LMP:IDENTITY-PROOF:V1\x00"
_CHALLENGE_SIZE = 32
_MAX_BINDING_SIZE = 1024
_KEY_TYPE = "Ed25519"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("expected base64url string")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    """Stable JSON encoding for this draft; NaN and non-JSON values are forbidden."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


@dataclass(frozen=True, slots=True)
class IdentityDocument:
    """Signed identity document. Signature covers all fields except itself."""
    version: int
    principal_id: str
    revision: int
    root_public_key: str
    signing_public_key: str
    created_at: int
    previous_document_hash: str | None
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "principal_id": self.principal_id,
            "revision": self.revision,
            "root_public_key": self.root_public_key,
            "signing_public_key": self.signing_public_key,
            "created_at": self.created_at,
            "previous_document_hash": self.previous_document_hash,
            "signature_algorithm": _KEY_TYPE,
        }

    def to_dict(self) -> dict[str, Any]:
        result = self.unsigned_dict()
        result["signature"] = self.signature
        return result

    def to_bytes(self) -> bytes:
        return _canonical_json(self.to_dict())

    @property
    def document_hash(self) -> str:
        return hashlib.sha256(_DOCUMENT_DOMAIN + self.to_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "IdentityDocument":
        required = {
            "version", "principal_id", "revision", "root_public_key",
            "signing_public_key", "created_at", "previous_document_hash",
            "signature_algorithm", "signature",
        }
        if set(value) != required:
            raise ValueError("identity document has missing or unknown fields")
        if value["signature_algorithm"] != _KEY_TYPE:
            raise ValueError("unsupported identity signature algorithm")
        if not isinstance(value["version"], int) or not isinstance(value["revision"], int):
            raise ValueError("version and revision must be integers")
        if not isinstance(value["created_at"], int):
            raise ValueError("created_at must be an integer")
        for name in ("principal_id", "root_public_key", "signing_public_key", "signature"):
            if not isinstance(value[name], str):
                raise ValueError(f"{name} must be a string")
        previous = value["previous_document_hash"]
        if previous is not None and not isinstance(previous, str):
            raise ValueError("previous_document_hash must be a string or null")
        return cls(value["version"], value["principal_id"], value["revision"],
                   value["root_public_key"], value["signing_public_key"],
                   value["created_at"], previous, value["signature"])


@dataclass(slots=True)
class IdentityKeyPair:
    """Local root and active signing keys; private keys are never serialized here."""
    root_private_key: Ed25519PrivateKey
    signing_private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "IdentityKeyPair":
        return cls(Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate())

    @property
    def principal_id(self) -> PrincipalId:
        return PrincipalId(hashlib.sha256(_DOMAIN + _public_bytes(self.root_private_key.public_key())).digest())

    @property
    def principal_id_text(self) -> str:
        return "lmp:p:" + base64.b32encode(self.principal_id.value).decode("ascii").rstrip("=").lower()

    def create_initial_document(self, *, created_at: int | None = None) -> IdentityDocument:
        """Create revision 1; root key signs the genesis identity document."""
        root_raw = _public_bytes(self.root_private_key.public_key())
        signing_raw = _public_bytes(self.signing_private_key.public_key())
        unsigned = {
            "version": 1,
            "principal_id": _b64(self.principal_id.value),
            "revision": 1,
            "root_public_key": _b64(root_raw),
            "signing_public_key": _b64(signing_raw),
            "created_at": int(time.time()) if created_at is None else int(created_at),
            "previous_document_hash": None,
            "signature_algorithm": _KEY_TYPE,
        }
        signature = self.root_private_key.sign(_DOCUMENT_DOMAIN + _canonical_json(unsigned))
        return IdentityDocument(unsigned["version"], unsigned["principal_id"], unsigned["revision"],
                                unsigned["root_public_key"], unsigned["signing_public_key"],
                                unsigned["created_at"], None, _b64(signature))

    def sign_challenge(self, document: IdentityDocument, challenge: bytes, session_binding: bytes) -> bytes:
        """Sign a verifier's fresh challenge for this identity and connection context.

        The caller must generate a cryptographically random 32-byte challenge and
        supply a fresh, connection-specific binding. This function does not itself
        create or authenticate a TLS channel binding.
        """
        verify_identity_document(document)
        if _unb64(document.root_public_key) != _public_bytes(self.root_private_key.public_key()):
            raise AuthenticationError("identity document does not belong to this root key")
        if _unb64(document.signing_public_key) != _public_bytes(self.signing_private_key.public_key()):
            raise AuthenticationError("identity document does not belong to this signing key")
        payload = _proof_payload(document, challenge, session_binding)
        return self.signing_private_key.sign(payload)

    def save_encrypted(self, path: str | Path, password: str) -> None:
        """Save private keys encrypted with a user-supplied password.

        The file contains secrets: protect it with filesystem permissions and keep
        backups secure. This format is alpha-only and may change before v1.0.
        """
        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("identity password must contain at least 8 characters")
        encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
        root_pem = self.root_private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
        )
        signing_pem = self.signing_private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
        )
        payload = _canonical_json({"format": "lmp-identity-keypair-v1", "root_private_key": _b64(root_pem),
                                   "signing_private_key": _b64(signing_pem)})
        target = Path(path)
        target.write_bytes(payload)
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass

    @classmethod
    def load_encrypted(cls, path: str | Path, password: str) -> "IdentityKeyPair":
        """Load an encrypted alpha key file; fail closed on malformed input."""
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
            if set(value) != {"format", "root_private_key", "signing_private_key"} or value["format"] != "lmp-identity-keypair-v1":
                raise ValueError("unsupported identity key file")
            root = serialization.load_pem_private_key(_unb64(value["root_private_key"]), password=password.encode("utf-8"))
            signing = serialization.load_pem_private_key(_unb64(value["signing_private_key"]), password=password.encode("utf-8"))
            if not isinstance(root, Ed25519PrivateKey) or not isinstance(signing, Ed25519PrivateKey):
                raise ValueError("identity keys must be Ed25519")
            return cls(root, signing)
        except Exception as exc:
            raise AuthenticationError("unable to load encrypted identity key file") from exc

    def export_public_material(self) -> dict[str, str]:
        """Export public keys only; no private key material is returned."""
        return {
            "principal_id": _b64(self.principal_id.value),
            "root_public_key": _b64(_public_bytes(self.root_private_key.public_key())),
            "signing_public_key": _b64(_public_bytes(self.signing_private_key.public_key())),
        }


def verify_identity_document(document: IdentityDocument) -> PrincipalId:
    """Verify genesis identity document and return its Principal ID.

    This alpha accepts only revision 1. Revision chains and key rotation are not
    implemented, so unsupported revisions fail closed rather than being guessed.
    """
    if document.version != 1 or document.revision != 1:
        raise AuthenticationError("unsupported identity document revision")
    if document.previous_document_hash is not None:
        raise AuthenticationError("genesis document must not have a previous hash")
    try:
        root_raw = _unb64(document.root_public_key)
        signing_raw = _unb64(document.signing_public_key)
        claimed_principal = _unb64(document.principal_id)
        signature = _unb64(document.signature)
        if len(root_raw) != 32 or len(signing_raw) != 32:
            raise ValueError("Ed25519 public keys must be 32 bytes")
        if len(claimed_principal) != 32 or len(signature) != 64:
            raise ValueError("invalid identity or signature length")
        expected = hashlib.sha256(_DOMAIN + root_raw).digest()
        if claimed_principal != expected:
            raise AuthenticationError("Principal ID does not match root public key")
        Ed25519PublicKey.from_public_bytes(root_raw).verify(
            signature, _DOCUMENT_DOMAIN + _canonical_json(document.unsigned_dict())
        )
        Ed25519PublicKey.from_public_bytes(signing_raw)  # validate key encoding
    except AuthenticationError:
        raise
    except (ValueError, InvalidSignature, TypeError, KeyError) as exc:
        raise AuthenticationError("identity document verification failed") from exc
    return PrincipalId(claimed_principal)


def verify_document_bytes(raw: bytes) -> tuple[IdentityDocument, PrincipalId]:
    """Strictly parse, canonicalization-check, and verify serialized document."""
    try:
        parsed = json.loads(raw.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("document must be a JSON object")
        document = IdentityDocument.from_dict(parsed)
        if _canonical_json(document.to_dict()) != raw:
            raise ValueError("document is not canonically encoded")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise AuthenticationError("invalid identity document encoding") from exc
    return document, verify_identity_document(document)


def _proof_payload(document: IdentityDocument, challenge: bytes, session_binding: bytes) -> bytes:
    """Build the domain-separated bytes authenticated by a challenge proof."""
    if not isinstance(challenge, bytes) or len(challenge) != _CHALLENGE_SIZE:
        raise AuthenticationError("challenge must be exactly 32 bytes")
    if not isinstance(session_binding, bytes) or not 1 <= len(session_binding) <= _MAX_BINDING_SIZE:
        raise AuthenticationError("session binding must contain 1..1024 bytes")
    # Fixed-size challenge and document digest plus length-delimited binding avoid
    # ambiguous concatenation. The binding must be unique to the current session.
    document_digest = hashlib.sha256(_DOCUMENT_DOMAIN + document.to_bytes()).digest()
    return (_PROOF_DOMAIN + document_digest + challenge + len(session_binding).to_bytes(2, "big")
            + session_binding)


def verify_peer_proof(
    document: IdentityDocument,
    challenge: bytes,
    session_binding: bytes,
    signature: bytes,
) -> PrincipalId:
    """Verify proof of possession of the active signing key for a fresh challenge.

    The caller is responsible for issuing a never-reused random challenge and
    matching it to the pending handshake. A successful result authenticates key
    possession, not authorization to perform an application operation.
    """
    principal = verify_identity_document(document)
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise AuthenticationError("identity proof signature must be 64 bytes")
    payload = _proof_payload(document, challenge, session_binding)
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(document.signing_public_key)).verify(signature, payload)
    except (ValueError, InvalidSignature) as exc:
        raise AuthenticationError("identity challenge proof verification failed") from exc
    return principal
