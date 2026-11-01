"""One-shot identity challenge state for a future LMP peer handshake.

This module manages challenge freshness and single-use semantics locally. It is
not wired into the current TCP/TLS node and does not create TLS channel bindings.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from ..api import PrincipalId
from ..errors import AuthenticationError
from .identity import IdentityDocument, verify_peer_proof


@dataclass(slots=True)
class IdentityChallenge:
    """Verifier-side, single-use challenge bound to one pending connection."""
    session_binding: bytes
    challenge: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    _consumed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.session_binding, bytes) or not 1 <= len(self.session_binding) <= 1024:
            raise ValueError("session_binding must contain 1..1024 bytes")
        if not isinstance(self.challenge, bytes) or len(self.challenge) != 32:
            raise ValueError("challenge must be exactly 32 bytes")

    def verify_response(self, document: IdentityDocument, signature: bytes) -> PrincipalId:
        """Consume this challenge and verify one proof; never permits a second try."""
        if self._consumed:
            raise AuthenticationError("identity challenge has already been consumed")
        # Consume before verification: even a failed proof cannot be retried against
        # the same challenge, avoiding ambiguous retry/replay state.
        self._consumed = True
        return verify_peer_proof(document, self.challenge, self.session_binding, signature)

    @property
    def consumed(self) -> bool:
        return self._consumed

@dataclass(frozen=True, slots=True)
class HandshakeTranscript:
    """Canonical connection context for a mutual LMP identity handshake.

    Both peers must construct this from the same client/server nonces and the
    exact identity documents exchanged on this connection. This is an LMP-level
    transcript binding, not a TLS exporter/channel binding.
    """
    client_nonce: bytes
    server_nonce: bytes
    client_document: IdentityDocument
    server_document: IdentityDocument

    def __post_init__(self) -> None:
        if not isinstance(self.client_nonce, bytes) or len(self.client_nonce) != 32:
            raise ValueError("client_nonce must be exactly 32 bytes")
        if not isinstance(self.server_nonce, bytes) or len(self.server_nonce) != 32:
            raise ValueError("server_nonce must be exactly 32 bytes")
        if self.client_nonce == self.server_nonce:
            raise ValueError("client and server nonces must differ")

    @property
    def binding(self) -> bytes:
        """Return a fixed-size binding to both nonces and both identity documents."""
        import hashlib
        from .identity import verify_identity_document

        verify_identity_document(self.client_document)
        verify_identity_document(self.server_document)
        digest = hashlib.sha256()
        digest.update(b"LMP:HANDSHAKE-TRANSCRIPT:V1\x00")
        digest.update(self.client_nonce)
        digest.update(self.server_nonce)
        digest.update(bytes.fromhex(self.client_document.document_hash))
        digest.update(bytes.fromhex(self.server_document.document_hash))
        return digest.digest()
