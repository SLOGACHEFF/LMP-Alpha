"""Stable internal interfaces shared by LMP Core modules.

These are Python APIs, not yet normative wire-protocol definitions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable


@dataclass(frozen=True, slots=True)
class PrincipalId:
    """Opaque stable identifier for a principal; construction does not prove ownership."""
    value: bytes

    def __post_init__(self) -> None:
        if len(self.value) != 32:
            raise ValueError("PrincipalId must contain exactly 32 bytes in this draft")


@dataclass(frozen=True, slots=True)
class NodeId:
    """Opaque identifier for a protocol node; not an authentication credential."""
    value: bytes

    def __post_init__(self) -> None:
        if len(self.value) != 32:
            raise ValueError("NodeId must contain exactly 32 bytes in this draft")


@dataclass(frozen=True, slots=True)
class Message:
    message_id: str
    sender: str
    recipient: str
    body: Any
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.message_id or len(self.message_id) > 128:
            raise ValueError("message_id must contain 1..128 characters")
        if not self.sender or not self.recipient:
            raise ValueError("sender and recipient must be non-empty")


class AuthorizationDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    subject: str
    action: str
    resource: str
    context: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AuthorizationResult:
    decision: AuthorizationDecision
    reason_code: str = ""


@runtime_checkable
class IdentityProvider(Protocol):
    async def verify_peer(self, peer_evidence: bytes) -> PrincipalId: ...


@runtime_checkable
class Authorizer(Protocol):
    async def authorize(self, request: AuthorizationRequest) -> AuthorizationResult: ...


@runtime_checkable
class MessageStore(Protocol):
    async def put_if_absent(self, message: Message) -> bool:
        """Atomically store once; return False if the ID already exists."""
        ...

    async def get(self, message_id: str) -> Message | None: ...

    async def delete(self, message_id: str) -> None: ...


@runtime_checkable
class RouteResolver(Protocol):
    async def resolve(self, recipient: str, *, traffic_class: str) -> Sequence[str]: ...


@runtime_checkable
class Transport(Protocol):
    async def send(self, endpoint: str, data: bytes) -> None: ...


@runtime_checkable
class Clock(Protocol):
    def monotonic(self) -> float: ...
    def unix_time(self) -> float: ...
