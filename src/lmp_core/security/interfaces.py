"""Fail-closed security interfaces; no production identity verifier is implemented yet."""
from __future__ import annotations
from ..api import AuthorizationDecision, AuthorizationRequest, AuthorizationResult, PrincipalId
from ..errors import AuthenticationError


class RejectUnconfiguredIdentityProvider:
    """Safe default: never treats TLS or a claimed string as LMP identity proof."""
    async def verify_peer(self, peer_evidence: bytes) -> PrincipalId:
        raise AuthenticationError("LMP identity verification is not configured")


class DenyByDefaultAuthorizer:
    """Safe default until a concrete local authorization policy is configured."""
    async def authorize(self, request: AuthorizationRequest) -> AuthorizationResult:
        return AuthorizationResult(AuthorizationDecision.DENY, "NO_POLICY_CONFIGURED")
