"""Real TLS integration test for A -> B -> C federation and relay restart recovery."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import ipaddress
import ssl
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from lmp_core.federation import FederationOutbox, FederationOutboxWorker
from lmp_core.messaging.envelope import create_signed_envelope
from lmp_core.network import RouteCache, create_route_record
from lmp_core.node import LMPNode, NodeConfig, send_signed_envelope
from lmp_core.security.identity import IdentityKeyPair


def _tls_files(directory, label: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256()))
    cert_path, key_path = directory / f"{label}.crt", directory / f"{label}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return cert_path, key_path


def _server_context(cert_path, key_path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(cert_path), str(key_path))
    return context


@pytest.mark.asyncio
async def test_three_node_delivery_survives_relay_restart(tmp_path):
    now = int(time.time())
    cert_b, key_b = _tls_files(tmp_path, "node-b")
    cert_c, key_c = _tls_files(tmp_path, "node-c")
    origin = IdentityKeyPair.generate()
    relay = IdentityKeyPair.generate()
    destination = IdentityKeyPair.generate()
    origin_doc = origin.create_initial_document(created_at=now)
    relay_doc = relay.create_initial_document(created_at=now)
    destination_doc = destination.create_initial_document(created_at=now)

    outbox_path = str(tmp_path / "relay-outbox.sqlite3")
    outbox = FederationOutbox(outbox_path)
    recipient = "lmp:p:destination-user"
    route_cache = RouteCache()
    destination_node = LMPNode(NodeConfig(identity_keys=destination,
        allowed_principals=frozenset({relay.principal_id_text}),
        allowed_relays=frozenset({relay.principal_id_text})))
    c_server = await destination_node.serve("127.0.0.1", 0, _server_context(cert_c, key_c))
    c_port = c_server.sockets[0].getsockname()[1]
    route_cache.add(create_route_record(destination, destination_doc, "localhost", c_port,
        ttl_seconds=300, now=now), destination_doc, now=now)

    def new_relay_node():
        return LMPNode(NodeConfig(identity_keys=relay,
            allowed_principals=frozenset({origin.principal_id_text}),
            storage_path=str(tmp_path / "relay-inbox.sqlite3"),
            federation_outbox=outbox,
            federation_route_selector=lambda target: destination.principal_id_text if target == recipient else None))

    relay_node = new_relay_node()
    b_server = await relay_node.serve("127.0.0.1", 0, _server_context(cert_b, key_b))
    b_port = b_server.sockets[0].getsockname()[1]
    envelope = create_signed_envelope(origin, origin_doc, message_id="a-b-c-restart-1",
        recipient=recipient, body={"text": "hello across federation"}, ttl_seconds=600, now=now)

    try:
        # A -> B: B must durably enqueue the exact origin-signed bytes before ACK.
        async with b_server:
            incoming_ack = await asyncio.wait_for(send_signed_envelope("localhost", b_port,
                str(cert_b), envelope, identity_keys=origin,
                expected_server_principal=relay.principal_id_text), timeout=10)
        assert incoming_ack["status"] == "STORED"
        queued = outbox.get(origin.principal_id_text, envelope.message_id)
        assert queued is not None and queued.status == "PENDING"
        assert queued.envelope_bytes == envelope.to_bytes()

        # A retry of the same origin-signed envelope at A -> B must be idempotent.
        duplicate_ack = await asyncio.wait_for(send_signed_envelope("localhost", b_port,
            str(cert_b), envelope, identity_keys=origin,
            expected_server_principal=relay.principal_id_text), timeout=10)
        assert duplicate_ack["status"] == "STORED"
        duplicate_queued = outbox.get(origin.principal_id_text, envelope.message_id)
        assert duplicate_queued is not None
        assert duplicate_queued.envelope_bytes == envelope.to_bytes()
        assert duplicate_queued.status == "PENDING"

        # Simulate process restart: close both SQLite handles and reopen the outbox.
        b_server.close()
        await b_server.wait_closed()
        relay_node.message_store.close()
        outbox.close()
        outbox = FederationOutbox(outbox_path)
        relay_node = new_relay_node()
        b_server = await relay_node.serve("127.0.0.1", 0, _server_context(cert_b, key_b))

        # B -> C: worker uses real TLS, identity handshake, signed receipt and wire frames.
        # Simulate the classic ambiguous outcome: C durably accepts the message,
        # but B loses the acknowledgement and must retry the same logical message.
        send_calls = 0
        send_observations = []
        async def lose_first_ack(*args, **kwargs):
            nonlocal send_calls
            send_calls += 1
            sent_envelope = args[3]
            relay_trace = kwargs["relay_trace"]
            send_observations.append((sent_envelope.to_bytes(), relay_trace.to_bytes()))
            ack = await send_signed_envelope(*args, **kwargs)
            if send_calls == 1:
                assert ack["status"] == "STORED"
                raise ConnectionError("simulated acknowledgement loss after remote STORED")
            return ack

        worker = FederationOutboxWorker(outbox=outbox, identity_keys=relay,
            ca_file=str(cert_c), route_cache=route_cache,
            identity_documents={destination.principal_id_text: destination_doc},
            allowed_relays=frozenset({relay.principal_id_text}), worker_id="integration-relay-b",
            send_func=lose_first_ack, base_retry_seconds=0.1, max_retry_seconds=1)
        first_result = await asyncio.wait_for(worker.run_once(), timeout=15)
        assert first_result.claimed == 1 and first_result.retried == 1
        assert outbox.get(origin.principal_id_text, envelope.message_id).status == "PENDING"
        await asyncio.sleep(0.2)
        result = await asyncio.wait_for(worker.run_once(), timeout=15)
        assert result.claimed == 1 and result.sent == 1 and result.failed == 0
        assert send_calls == 2
        # Retry must preserve both immutable envelope bytes and the exact relay trace.
        assert send_observations[0][0] == envelope.to_bytes()
        assert send_observations[1][0] == envelope.to_bytes()
        assert send_observations[0][0] == send_observations[1][0]
        assert send_observations[0][1] == send_observations[1][1]
        relay_persisted = relay_node.message_store.pending_for(recipient)
        assert len(relay_persisted) == 1 and relay_persisted[0].message_id == envelope.message_id
        received = destination_node.message_store.pending_for(recipient)
        assert len(received) == 1
        assert received[0].message_id == envelope.message_id
        assert received[0].sender == origin.principal_id_text
        assert outbox.get(origin.principal_id_text, envelope.message_id).status == "SENT"
    finally:
        b_server.close()
        await b_server.wait_closed()
        c_server.close()
        await c_server.wait_closed()
        relay_node.message_store.close()
        destination_node.message_store.close()
        outbox.close()
