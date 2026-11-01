"""Security and loopback integration tests for the alpha node.

These tests require the declared project dependencies, including cbor2.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import ipaddress
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from lmp_core.errors import AuthenticationError
from lmp_core.node import LMPNode, NodeConfig, send_message, send_signed_envelope
from lmp_core.security.identity import IdentityKeyPair


def _make_local_tls_files(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    return cert_path, key_path


@pytest.mark.parametrize("bad_config", [
    {"max_frame_size": 0},
    {"max_frame_size": 16 * 1024 * 1024 + 1},
    {"dedup_capacity": 0},
    {"frame_read_timeout": 0},
    {"frame_read_timeout": float("inf")},
    {"protocol_version": ""},
    {"allowed_principals": frozenset({"not-a-principal"})},
])
def test_node_config_rejects_invalid_limits_and_principal_pins(bad_config):
    with pytest.raises(ValueError):
        NodeConfig(**bad_config)


@pytest.mark.asyncio
async def test_two_nodes_authenticate_and_accept_message(tmp_path):
    cert_path, key_path = _make_local_tls_files(tmp_path)
    server_identity = IdentityKeyPair.generate()
    client_identity = IdentityKeyPair.generate()
    node = LMPNode(NodeConfig(
        identity_keys=server_identity,
        allowed_principals=frozenset({client_identity.principal_id_text}),
    ))
    server = await node.serve("127.0.0.1", 0, _server_context(cert_path, key_path))
    port = server.sockets[0].getsockname()[1]
    try:
        async with server:
            result = await asyncio.wait_for(send_message(
                "localhost", port, str(cert_path), "integration test",
                identity_keys=client_identity,
                expected_server_principal=server_identity.principal_id_text,
            ), timeout=5)
        assert result["status"] == "STORED"
        assert result["duplicate"] is False
        assert "not proof of recipient delivery" in result["note"]
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_server_allowlist_rejects_authenticated_but_unauthorized_client(tmp_path):
    cert_path, key_path = _make_local_tls_files(tmp_path)
    server_identity = IdentityKeyPair.generate()
    client_identity = IdentityKeyPair.generate()
    other_identity = IdentityKeyPair.generate()
    node = LMPNode(NodeConfig(
        identity_keys=server_identity,
        allowed_principals=frozenset({other_identity.principal_id_text}),
    ))
    server = await node.serve("127.0.0.1", 0, _server_context(cert_path, key_path))
    port = server.sockets[0].getsockname()[1]
    try:
        async with server:
            with pytest.raises((AuthenticationError, RuntimeError)):
                await asyncio.wait_for(send_message(
                    "localhost", port, str(cert_path), "should be denied",
                    identity_keys=client_identity,
                    expected_server_principal=server_identity.principal_id_text,
                ), timeout=5)
    finally:
        server.close()
        await server.wait_closed()


def _server_context(cert_path, key_path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(cert_path), str(key_path))
    return context


@pytest.mark.asyncio
async def test_two_nodes_accept_origin_signed_envelope_from_origin(tmp_path):
    from lmp_core.messaging.envelope import create_signed_envelope
    cert_path, key_path = _make_local_tls_files(tmp_path)
    server_identity = IdentityKeyPair.generate()
    origin_identity = IdentityKeyPair.generate()
    node = LMPNode(NodeConfig(identity_keys=server_identity,
                              allowed_principals=frozenset({origin_identity.principal_id_text})))
    server = await node.serve("127.0.0.1", 0, _server_context(cert_path, key_path))
    port = server.sockets[0].getsockname()[1]
    envelope = create_signed_envelope(origin_identity, origin_identity.create_initial_document(),
                                      message_id="signed-direct-1", recipient="recipient-id",
                                      body={"text": "signed"})
    try:
        async with server:
            ack = await asyncio.wait_for(send_signed_envelope(
                "localhost", port, str(cert_path), envelope,
                identity_keys=origin_identity,
                expected_server_principal=server_identity.principal_id_text,
            ), timeout=5)
        assert ack["status"] == "STORED"
        assert ack["origin_principal_id"] == origin_identity.principal_id_text
        stored = node.message_store.pending_for("recipient-id")
        assert len(stored) == 1 and stored[0].message_id == "signed-direct-1"
        assert stored[0].expires_at == envelope.expires_at
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_two_nodes_accept_envelope_from_allowlisted_relay(tmp_path):
    from lmp_core.messaging.envelope import create_signed_envelope
    from lmp_core.messaging.relay import RelayTrace
    cert_path, key_path = _make_local_tls_files(tmp_path)
    server_identity = IdentityKeyPair.generate()
    origin_identity = IdentityKeyPair.generate()
    relay_identity = IdentityKeyPair.generate()
    node = LMPNode(NodeConfig(identity_keys=server_identity,
                              allowed_principals=frozenset({relay_identity.principal_id_text}),
                              allowed_relays=frozenset({relay_identity.principal_id_text})))
    server = await node.serve("127.0.0.1", 0, _server_context(cert_path, key_path))
    port = server.sockets[0].getsockname()[1]
    envelope = create_signed_envelope(origin_identity, origin_identity.create_initial_document(),
                                      message_id="signed-relay-1", recipient="recipient-id",
                                      body={"text": "forwarded"})
    try:
        async with server:
            ack = await asyncio.wait_for(send_signed_envelope(
                "localhost", port, str(cert_path), envelope,
                identity_keys=relay_identity,
                expected_server_principal=server_identity.principal_id_text,
                relay_trace=RelayTrace(),
                relay_allowed_principals=frozenset({relay_identity.principal_id_text}),
            ), timeout=5)
        assert ack["status"] == "STORED"
        assert ack["origin_principal_id"] == origin_identity.principal_id_text
        stored = node.message_store.pending_for("recipient-id")
        assert len(stored) == 1 and stored[0].sender == origin_identity.principal_id_text
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_two_nodes_reject_signed_envelope_from_untrusted_relay(tmp_path):
    from lmp_core.messaging.envelope import create_signed_envelope
    from lmp_core.errors import AuthenticationError
    cert_path, key_path = _make_local_tls_files(tmp_path)
    server_identity = IdentityKeyPair.generate()
    origin_identity = IdentityKeyPair.generate()
    relay_identity = IdentityKeyPair.generate()
    node = LMPNode(NodeConfig(identity_keys=server_identity,
                              allowed_principals=frozenset({relay_identity.principal_id_text}),
                              allowed_relays=frozenset()))
    server = await node.serve("127.0.0.1", 0, _server_context(cert_path, key_path))
    port = server.sockets[0].getsockname()[1]
    envelope = create_signed_envelope(origin_identity, origin_identity.create_initial_document(),
                                      message_id="signed-relay-denied", recipient="recipient-id", body="no")
    try:
        async with server:
            with pytest.raises(AuthenticationError):
                await asyncio.wait_for(send_signed_envelope(
                    "localhost", port, str(cert_path), envelope,
                    identity_keys=relay_identity,
                    expected_server_principal=server_identity.principal_id_text,
                    relay_allowed_principals=frozenset({relay_identity.principal_id_text}),
                ), timeout=5)
        assert node.message_store.pending_for("recipient-id") == []
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_authenticated_idle_connection_is_closed_after_frame_timeout(tmp_path):
    import base64
    import secrets
    from lmp_core.codec import decode_payload, encode_payload
    from lmp_core.framing import (
        DEFAULT_MAX_FRAME_SIZE, TYPE_HELLO, TYPE_HELLO_ACK,
        TYPE_IDENTITY_PROOF, TYPE_IDENTITY_ACCEPT, Frame,
    )
    from lmp_core.node import read_frame, write_frame, make_client_tls_context
    from lmp_core.security.handshake import HandshakeTranscript
    from lmp_core.security.identity import verify_document_bytes, verify_peer_proof

    cert_path, key_path = _make_local_tls_files(tmp_path)
    server_identity = IdentityKeyPair.generate()
    client_identity = IdentityKeyPair.generate()
    node = LMPNode(NodeConfig(identity_keys=server_identity, frame_read_timeout=0.2))
    server = await node.serve("127.0.0.1", 0, _server_context(cert_path, key_path))
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection(
        "localhost", port, ssl=make_client_tls_context(str(cert_path)),
        server_hostname="localhost", limit=DEFAULT_MAX_FRAME_SIZE + 8,
    )
    try:
        client_nonce = secrets.token_bytes(32)
        client_doc = client_identity.create_initial_document()
        await write_frame(writer, Frame(TYPE_HELLO, encode_payload({
            "protocol": "LMP", "versions": ["0.1-draft"],
            "nonce": client_nonce, "identity_document": client_doc.to_bytes(),
        }), request_id=1), max_frame_size=DEFAULT_MAX_FRAME_SIZE)
        hello_ack = await asyncio.wait_for(read_frame(reader, max_frame_size=DEFAULT_MAX_FRAME_SIZE), 2)
        assert hello_ack.frame_type == TYPE_HELLO_ACK
        data = decode_payload(hello_ack.payload)
        server_doc, server_principal = verify_document_bytes(data["identity_document"])
        expected_server = "lmp:p:" + base64.b32encode(server_principal.value).decode("ascii").rstrip("=").lower()
        assert expected_server == server_identity.principal_id_text
        transcript = HandshakeTranscript(client_nonce, data["nonce"], client_doc, server_doc)
        verify_peer_proof(server_doc, client_nonce, transcript.binding, data["identity_proof"])
        proof = client_identity.sign_challenge(client_doc, data["nonce"], transcript.binding)
        await write_frame(writer, Frame(TYPE_IDENTITY_PROOF, encode_payload({"signature": proof}), request_id=2),
                          max_frame_size=DEFAULT_MAX_FRAME_SIZE)
        accepted = await asyncio.wait_for(read_frame(reader, max_frame_size=DEFAULT_MAX_FRAME_SIZE), 2)
        assert accepted.frame_type == TYPE_IDENTITY_ACCEPT
        # Do not send another frame. The server must close this authenticated idle session.
        assert await asyncio.wait_for(reader.read(1), timeout=1.5) == b""
    finally:
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()
