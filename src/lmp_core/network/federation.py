"""Signed, expiring node route advertisements for the LMP federation draft.

A valid signature proves that an identity key advertised an endpoint; it does
not prove the endpoint is reachable, safe, or authorized for a particular user.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..errors import AuthenticationError
from ..security.identity import IdentityDocument, IdentityKeyPair, verify_identity_document

_DOMAIN = b"LMP:ROUTE-RECORD:V1\x00"
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_MAX_TTL_SECONDS = 3600
_CLOCK_SKEW_SECONDS = 60


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("signature must be a base64url string")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _validate_host(host: str) -> str:
    if not isinstance(host, str) or not host or len(host) > 253:
        raise ValueError("host must contain 1..253 characters")
    if host != host.strip() or any(c in host for c in "/\\@?#\x00"):
        raise ValueError("host must be a hostname or IP address, not a URL")
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        # Treat as DNS name. A trailing dot is accepted but normalized away.
        normalized = host[:-1] if host.endswith(".") else host
        if not normalized or any(not _DNS_LABEL.fullmatch(label) for label in normalized.split(".")):
            raise ValueError("host is not a valid IP address or DNS hostname")
        return normalized.lower()


@dataclass(frozen=True, slots=True)
class NodeRouteRecord:
    """A signed claim that a Principal ID can be contacted at host:port."""
    version: int
    principal_id: str
    host: str
    port: int
    issued_at: int
    expires_at: int
    identity_document_hash: str
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "principal_id": self.principal_id,
            "host": self.host,
            "port": self.port,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "identity_document_hash": self.identity_document_hash,
            "signature_algorithm": "Ed25519",
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    def to_bytes(self) -> bytes:
        return _canonical(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NodeRouteRecord":
        expected = {"version", "principal_id", "host", "port", "issued_at", "expires_at",
                    "identity_document_hash", "signature_algorithm", "signature"}
        if not isinstance(data, Mapping) or set(data) != expected:
            raise ValueError("route record has missing or unknown fields")
        if data["signature_algorithm"] != "Ed25519":
            raise ValueError("unsupported route signature algorithm")
        string_fields = ("principal_id", "host", "identity_document_hash", "signature")
        if any(not isinstance(data[name], str) for name in string_fields):
            raise ValueError("route record string fields must be strings")
        int_fields = ("version", "port", "issued_at", "expires_at")
        if any(not isinstance(data[name], int) or isinstance(data[name], bool) for name in int_fields):
            raise ValueError("route record integer fields must be integers")
        return cls(*(data[name] for name in (
            "version", "principal_id", "host", "port", "issued_at", "expires_at",
            "identity_document_hash", "signature")))


def create_route_record(
    keys: IdentityKeyPair,
    identity_document: IdentityDocument,
    host: str,
    port: int,
    *,
    ttl_seconds: int = 300,
    now: int | None = None,
) -> NodeRouteRecord:
    """Create a route record signed by the identity's active Ed25519 key."""
    principal = verify_identity_document(identity_document)
    if principal != keys.principal_id:
        raise AuthenticationError("identity document does not belong to the supplied keypair")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= _MAX_TTL_SECONDS:
        raise ValueError(f"ttl_seconds must be between 1 and {_MAX_TTL_SECONDS}")
    normalized_host = _validate_host(host)
    issued_at = int(time.time()) if now is None else now
    if not isinstance(issued_at, int) or isinstance(issued_at, bool) or issued_at < 0:
        raise ValueError("now must be a non-negative integer timestamp")
    unsigned = {
        "version": 1,
        "principal_id": keys.principal_id_text,
        "host": normalized_host,
        "port": port,
        "issued_at": issued_at,
        "expires_at": issued_at + ttl_seconds,
        "identity_document_hash": hashlib.sha256(identity_document.to_bytes()).hexdigest(),
        "signature_algorithm": "Ed25519",
    }
    signature = keys.signing_private_key.sign(_DOMAIN + _canonical(unsigned))
    return NodeRouteRecord(1, unsigned["principal_id"], normalized_host, port, issued_at,
                           issued_at + ttl_seconds, unsigned["identity_document_hash"], _b64(signature))


def verify_route_record(
    record: NodeRouteRecord,
    identity_document: IdentityDocument,
    *,
    now: int | None = None,
    max_ttl_seconds: int = _MAX_TTL_SECONDS,
) -> NodeRouteRecord:
    """Verify route signature, identity binding, endpoint syntax, and freshness."""
    try:
        principal = verify_identity_document(identity_document)
        if record.version != 1:
            raise ValueError("unsupported route record version")
        principal_text = "lmp:p:" + base64.b32encode(principal.value).decode("ascii").rstrip("=").lower()
        if record.principal_id != principal_text:
            raise AuthenticationError("route Principal ID does not match identity document")
        if record.identity_document_hash != hashlib.sha256(identity_document.to_bytes()).hexdigest():
            raise AuthenticationError("route record is bound to a different identity document")
        if not isinstance(record.port, int) or isinstance(record.port, bool) or not 1 <= record.port <= 65535:
            raise ValueError("invalid route port")
        if not isinstance(record.issued_at, int) or isinstance(record.issued_at, bool):
            raise ValueError("invalid route issued_at")
        if not isinstance(record.expires_at, int) or isinstance(record.expires_at, bool):
            raise ValueError("invalid route expires_at")
        normalized_host = _validate_host(record.host)
        if normalized_host != record.host:
            raise ValueError("route host is not normalized")
        current = int(time.time()) if now is None else now
        if not isinstance(current, int) or isinstance(current, bool):
            raise ValueError("now must be an integer timestamp")
        if not 1 <= max_ttl_seconds <= _MAX_TTL_SECONDS:
            raise ValueError("max_ttl_seconds must be between 1 and 3600")
        lifetime = record.expires_at - record.issued_at
        if lifetime < 1 or lifetime > max_ttl_seconds:
            raise AuthenticationError("route record lifetime is outside policy")
        if record.issued_at > current + _CLOCK_SKEW_SECONDS:
            raise AuthenticationError("route record was issued in the future")
        if record.expires_at <= current:
            raise AuthenticationError("route record has expired")
        signature = _unb64(record.signature)
        if len(signature) != 64:
            raise ValueError("invalid route signature length")
        unsigned = record.unsigned_dict()
        Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(
            identity_document.signing_public_key + "=" * (-len(identity_document.signing_public_key) % 4)
        )).verify(signature, _DOMAIN + _canonical(unsigned))
        return record
    except AuthenticationError:
        raise
    except (InvalidSignature, ValueError, TypeError, KeyError) as exc:
        raise AuthenticationError("invalid route record") from exc


class RouteCache:
    """Small in-memory cache of already-verified routes, indexed by Principal ID."""
    def __init__(self) -> None:
        self._routes: dict[str, NodeRouteRecord] = {}

    def add(self, record: NodeRouteRecord, identity_document: IdentityDocument, *, now: int | None = None) -> None:
        verify_route_record(record, identity_document, now=now)
        current = self._routes.get(record.principal_id)
        if current is not None and current.expires_at > (int(time.time()) if now is None else now):
            # Do not let a still-valid older advertisement roll back a newer route.
            if record.issued_at < current.issued_at:
                raise AuthenticationError("stale route record cannot replace a newer route")
        self._routes[record.principal_id] = record

    def get(self, principal_id: str, *, now: int | None = None) -> NodeRouteRecord | None:
        record = self._routes.get(principal_id)
        if record is None:
            return None
        current = int(time.time()) if now is None else now
        if record.expires_at <= current:
            self._routes.pop(principal_id, None)
            return None
        return record

    def discard(self, principal_id: str) -> None:
        self._routes.pop(principal_id, None)

    def __len__(self) -> int:
        return len(self._routes)
