import pytest

from lmp_core.api import (
    AuthorizationDecision, AuthorizationRequest, Message, NodeId, PrincipalId,
)
from lmp_core.errors import AuthenticationError
from lmp_core.security.interfaces import DenyByDefaultAuthorizer, RejectUnconfiguredIdentityProvider


def test_principal_and_node_ids_require_32_bytes():
    assert len(PrincipalId(b"p" * 32).value) == 32
    assert len(NodeId(b"n" * 32).value) == 32
    with pytest.raises(ValueError):
        PrincipalId(b"short")


def test_message_requires_ids_and_participants():
    assert Message("m1", "alice", "bob", "hello").recipient == "bob"
    with pytest.raises(ValueError):
        Message("", "alice", "bob", "hello")


@pytest.mark.asyncio
async def test_authorizer_fails_closed():
    result = await DenyByDefaultAuthorizer().authorize(
        AuthorizationRequest("alice", "message.send", "bob")
    )
    assert result.decision is AuthorizationDecision.DENY


@pytest.mark.asyncio
async def test_unconfigured_identity_provider_rejects():
    with pytest.raises(AuthenticationError):
        await RejectUnconfiguredIdentityProvider().verify_peer(b"untrusted")
