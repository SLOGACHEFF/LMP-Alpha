import time

import pytest

from lmp_core.errors import AuthenticationError
from lmp_core.network import FederationSender, RouteCache, create_route_record
from lmp_core.security.identity import IdentityKeyPair
from lmp_core.storage.message_store import StoredMessage


def _fixture():
    local = IdentityKeyPair.generate()
    remote = IdentityKeyPair.generate()
    remote_doc = remote.create_initial_document()
    now = int(time.time())
    route = create_route_record(remote, remote_doc, "node.example", 7443, ttl_seconds=300, now=now)
    cache = RouteCache()
    cache.add(route, remote_doc, now=now)
    message = StoredMessage(
        message_id="message-123", sender=local.principal_id_text,
        recipient="lmp:p:recipient", body={"text": "hello"},
        created_at=time.time(), status="STORED",
    )
    return local, remote, remote_doc, route, cache, message


@pytest.mark.asyncio
async def test_federation_sender_sends_to_verified_route_and_checks_ack():
    local, remote, remote_doc, route, cache, message = _fixture()
    calls = []

    async def fake_send(*args, **kwargs):
        calls.append((args, kwargs))
        return {"message_id": message.message_id, "status": "STORED", "duplicate": False}

    sender = FederationSender(
        identity_keys=local, ca_file="ca.pem", route_cache=cache,
        identity_documents={remote.principal_id_text: remote_doc},
        recipient_routes={message.recipient: remote.principal_id_text}, send_func=fake_send,
    )
    assert await sender(message) is True
    args, kwargs = calls[0]
    assert args[:3] == (route.host, route.port, "ca.pem")
    assert kwargs["expected_server_principal"] == remote.principal_id_text
    assert kwargs["recipient"] == message.recipient
    assert kwargs["message_id"] == message.message_id


@pytest.mark.asyncio
async def test_federation_sender_rejects_ack_for_different_message():
    local, remote, remote_doc, route, cache, message = _fixture()

    async def fake_send(*args, **kwargs):
        return {"message_id": "other-message", "status": "STORED"}

    sender = FederationSender(
        identity_keys=local, ca_file="ca.pem", route_cache=cache,
        identity_documents={remote.principal_id_text: remote_doc},
        recipient_routes={message.recipient: remote.principal_id_text}, send_func=fake_send,
    )
    assert await sender(message) is False


@pytest.mark.asyncio
async def test_federation_sender_returns_false_when_route_is_missing():
    local, remote, remote_doc, route, cache, message = _fixture()
    sender = FederationSender(
        identity_keys=local, ca_file="ca.pem", route_cache=RouteCache(),
        identity_documents={remote.principal_id_text: remote_doc},
        recipient_routes={message.recipient: remote.principal_id_text},
        send_func=lambda *args, **kwargs: None,
    )
    assert await sender(message) is False


@pytest.mark.asyncio
async def test_federation_sender_does_not_forward_third_party_origin_messages():
    local, remote, remote_doc, route, cache, message = _fixture()
    foreign_message = StoredMessage(
        message_id=message.message_id, sender=remote.principal_id_text,
        recipient=message.recipient, body=message.body,
        created_at=message.created_at, status="STORED",
    )
    sender = FederationSender(
        identity_keys=local, ca_file="ca.pem", route_cache=cache,
        identity_documents={remote.principal_id_text: remote_doc},
        recipient_routes={message.recipient: remote.principal_id_text},
    )
    with pytest.raises(AuthenticationError, match="cannot relay"):
        await sender(foreign_message)
