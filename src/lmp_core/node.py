"""Minimal async TLS node for the LMP Core alpha."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import math
import re
import secrets
import ssl
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from .codec import decode_payload, encode_payload
from .storage.message_store import MessageConflictError, SQLiteMessageStore
from .framing import (
    DEFAULT_MAX_FRAME_SIZE, HEADER_SIZE, TYPE_DELIVERY_ACK, TYPE_ERROR,
    TYPE_HELLO, TYPE_HELLO_ACK, TYPE_IDENTITY_PROOF, TYPE_IDENTITY_ACCEPT, TYPE_MESSAGE, TYPE_SIGNED_ENVELOPE, Frame, FrameError, decode_header,
)

log = logging.getLogger("lmp_core")

from .security.handshake import HandshakeTranscript
from .security.identity import IdentityKeyPair, verify_document_bytes, verify_peer_proof
from .errors import AuthenticationError, AuthorizationError


@dataclass(slots=True)
class NodeConfig:
    max_frame_size: int = DEFAULT_MAX_FRAME_SIZE
    frame_read_timeout: float = 30.0
    dedup_capacity: int = 10_000
    protocol_version: str = "0.1-draft"
    node_label: str = "lmp-node"
    identity_keys: IdentityKeyPair | None = None
    allowed_principals: frozenset[str] | None = None
    allowed_relays: frozenset[str] | None = None
    max_relay_hops: int = 8
    storage_path: str = ":memory:"
    federation_outbox: Any | None = None
    federation_route_selector: Callable[[str], str | None] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.max_frame_size, int) or not 1 <= self.max_frame_size <= DEFAULT_MAX_FRAME_SIZE:
            raise ValueError(f"max_frame_size must be between 1 and {DEFAULT_MAX_FRAME_SIZE}")
        if (isinstance(self.frame_read_timeout, bool)
                or not isinstance(self.frame_read_timeout, (int, float))
                or not math.isfinite(self.frame_read_timeout)
                or not 0.1 <= self.frame_read_timeout <= 300):
            raise ValueError("frame_read_timeout must be between 0.1 and 300 seconds")
        if not isinstance(self.dedup_capacity, int) or self.dedup_capacity < 1:
            raise ValueError("dedup_capacity must be positive")
        if not isinstance(self.protocol_version, str) or not self.protocol_version or len(self.protocol_version) > 64:
            raise ValueError("protocol_version must contain 1..64 characters")
        if not isinstance(self.storage_path, str) or not self.storage_path:
            raise ValueError("storage_path must be a non-empty string")
        if (self.federation_outbox is None) != (self.federation_route_selector is None):
            raise ValueError("federation_outbox and federation_route_selector must be configured together")
        if self.federation_outbox is not None and not callable(getattr(self.federation_outbox, "enqueue", None)):
            raise ValueError("federation_outbox must provide enqueue()")
        if self.federation_route_selector is not None and not callable(self.federation_route_selector):
            raise ValueError("federation_route_selector must be callable")
        if self.allowed_principals is not None:
            for principal in self.allowed_principals:
                if not isinstance(principal, str) or re.fullmatch(r"lmp:p:[a-z2-7]{52}", principal) is None:
                    raise ValueError("allowed_principals must contain canonical lmp:p: Principal IDs")
        if self.allowed_relays is not None:
            for principal in self.allowed_relays:
                if not isinstance(principal, str) or re.fullmatch(r"lmp:p:[a-z2-7]{52}", principal) is None:
                    raise ValueError("allowed_relays must contain canonical lmp:p: Principal IDs")
        if not isinstance(self.max_relay_hops, int) or isinstance(self.max_relay_hops, bool) or not 1 <= self.max_relay_hops <= 16:
            raise ValueError("max_relay_hops must be between 1 and 16")


async def read_frame(reader: asyncio.StreamReader, *, max_frame_size: int) -> Frame:
    header = await reader.readexactly(HEADER_SIZE)
    frame_type, flags, payload_len, request_id = decode_header(
        header, max_frame_size=max_frame_size
    )
    payload = await reader.readexactly(payload_len)
    return Frame(frame_type=frame_type, payload=payload, request_id=request_id, flags=flags)


async def write_frame(writer: asyncio.StreamWriter, frame: Frame, *, max_frame_size: int) -> None:
    writer.write(frame.encode(max_frame_size=max_frame_size))
    await writer.drain()


class LMPNode:
    def __init__(self, config: NodeConfig | None = None) -> None:
        self.config = config or NodeConfig()
        self.message_store = SQLiteMessageStore(self.config.storage_path)

    async def serve(self, host: str, port: int, ssl_context: ssl.SSLContext) -> asyncio.AbstractServer:
        if self.config.identity_keys is None:
            raise ValueError("server identity_keys are required for authenticated LMP service")
        if ssl_context.protocol != ssl.PROTOCOL_TLS_SERVER:
            raise ValueError("server requires a TLS server context")
        if ssl_context.minimum_version < ssl.TLSVersion.TLSv1_3:
            raise ValueError("TLS minimum version must be 1.3 or newer")
        return await asyncio.start_server(
            self._handle_client, host, port, ssl=ssl_context,
            limit=self.config.max_frame_size + HEADER_SIZE,
        )

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            tls_object = writer.get_extra_info("ssl_object")
            if tls_object is None or tls_object.version() != "TLSv1.3":
                await self._send_error(writer, "TLS_REQUIRED", "LMP requires a negotiated TLS 1.3 session")
                return
            hello = await asyncio.wait_for(
                read_frame(reader, max_frame_size=self.config.max_frame_size), timeout=10
            )
            if hello.frame_type != TYPE_HELLO:
                await self._send_error(writer, "EXPECTED_HELLO", "first frame must be HELLO")
                return
            hello_data = decode_payload(hello.payload)
            if hello_data.get("protocol") != "LMP":
                await self._send_error(writer, "PROTOCOL_MISMATCH", "unsupported protocol")
                return
            versions = hello_data.get("versions")
            if not isinstance(versions, list) or self.config.protocol_version not in versions:
                await self._send_error(writer, "VERSION_MISMATCH", "no common protocol version")
                return

            client_nonce = hello_data.get("nonce")
            client_doc_bytes = hello_data.get("identity_document")
            if not isinstance(client_nonce, bytes) or len(client_nonce) != 32 or not isinstance(client_doc_bytes, bytes):
                await self._send_error(writer, "AUTHENTICATION_FAILED", "identity evidence required")
                return
            client_doc, client_principal = verify_document_bytes(client_doc_bytes)
            client_nonce_server = secrets.token_bytes(32)
            while client_nonce_server == client_nonce:
                client_nonce_server = secrets.token_bytes(32)
            server_keys = self.config.identity_keys
            server_doc = server_keys.create_initial_document()
            transcript = HandshakeTranscript(client_nonce, client_nonce_server, client_doc, server_doc)
            binding = transcript.binding
            server_proof = server_keys.sign_challenge(server_doc, client_nonce, binding)
            await write_frame(writer, Frame(TYPE_HELLO_ACK, encode_payload({
                "protocol": "LMP",
                "version": self.config.protocol_version,
                "capabilities": ["message-basic", "delivery-ack", "identity-ed25519-v1"],
                "max_frame_size": self.config.max_frame_size,
                "nonce": client_nonce_server,
                "identity_document": server_doc.to_bytes(),
                "identity_proof": server_proof,
            }), request_id=hello.request_id), max_frame_size=self.config.max_frame_size)

            proof_frame = await asyncio.wait_for(read_frame(reader, max_frame_size=self.config.max_frame_size), timeout=10)
            if proof_frame.frame_type != TYPE_IDENTITY_PROOF:
                await self._send_error(writer, "AUTHENTICATION_FAILED", "client identity proof required")
                return
            proof_data = decode_payload(proof_frame.payload)
            client_proof = proof_data.get("signature")
            if not isinstance(client_proof, bytes):
                await self._send_error(writer, "AUTHENTICATION_FAILED", "invalid client identity proof")
                return
            verified_client = verify_peer_proof(client_doc, client_nonce_server, binding, client_proof)
            if verified_client != client_principal:
                await self._send_error(writer, "AUTHENTICATION_FAILED", "client principal mismatch")
                return
            client_principal_text = "lmp:p:" + base64.b32encode(verified_client.value).decode("ascii").rstrip("=").lower()
            if self.config.allowed_principals is not None and client_principal_text not in self.config.allowed_principals:
                await self._send_error(writer, "AUTHORIZATION_DENIED", "principal is not allowed")
                return
            await write_frame(writer, Frame(TYPE_IDENTITY_ACCEPT, encode_payload({
                "authenticated": True,
                "principal_id": client_principal_text,
                "server_principal_id": server_keys.principal_id_text,
            }), request_id=proof_frame.request_id), max_frame_size=self.config.max_frame_size)

            while True:
                # Bound both idle time and partial-frame reads after authentication.
                # Otherwise a peer can pin a handler by never completing a frame.
                frame = await asyncio.wait_for(
                    read_frame(reader, max_frame_size=self.config.max_frame_size),
                    timeout=self.config.frame_read_timeout,
                )
                if frame.frame_type == TYPE_MESSAGE:
                    await self._handle_message(frame, writer, authenticated_principal=client_principal_text)
                elif frame.frame_type == TYPE_SIGNED_ENVELOPE:
                    await self._handle_signed_envelope(frame, writer, authenticated_principal=client_principal_text)
                else:
                    await self._send_error(writer, "UNSUPPORTED_FRAME", "frame type not supported")
        except asyncio.IncompleteReadError:
            pass  # normal disconnect or truncated frame; no sensitive details returned
        except (FrameError, asyncio.TimeoutError) as exc:
            log.info("Closing invalid or timed-out connection from %r: %s", peer, exc)
        except (ConnectionError, ssl.SSLError):
            log.info("Connection closed: %r", peer)
        except Exception:
            log.exception("Unexpected LMP connection error from %r", peer)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_message(self, frame: Frame, writer: asyncio.StreamWriter, *, authenticated_principal: str) -> None:
        data: dict[str, Any] = decode_payload(frame.payload)
        message_id = data.get("message_id")
        sender = data.get("sender")
        recipient = data.get("recipient")
        body = data.get("body")
        if not isinstance(message_id, str) or not 1 <= len(message_id) <= 128:
            await self._send_error(writer, "INVALID_MESSAGE", "message_id is required")
            return
        if not isinstance(sender, str) or not isinstance(recipient, str):
            await self._send_error(writer, "INVALID_MESSAGE", "sender and recipient are required")
            return
        if not isinstance(body, (str, bytes, dict, list)):
            await self._send_error(writer, "INVALID_MESSAGE", "unsupported body type")
            return

        if sender != authenticated_principal:
            await self._send_error(writer, "AUTHENTICATION_FAILED", "sender must match authenticated Principal ID")
            return

        try:
            stored, duplicate = self.message_store.store(
                sender=authenticated_principal,
                message_id=message_id,
                recipient=recipient,
                body=body,
            )
        except MessageConflictError:
            await self._send_error(writer, "MESSAGE_ID_CONFLICT",
                                   "message ID was already used with different content")
            return
        body_bytes = body if isinstance(body, bytes) else encode_payload(body)
        log.info("Message stored id=%s sender=%s recipient=%s body_sha256=%s duplicate=%s",
                 message_id, sender, recipient, hashlib.sha256(body_bytes).hexdigest(), duplicate)
        ack = {
            "message_id": message_id,
            "status": stored.status,
            "duplicate": duplicate,
            "note": "durably stored by this node; not proof of recipient delivery",
        }
        await write_frame(writer, Frame(TYPE_DELIVERY_ACK, encode_payload(ack), request_id=frame.request_id),
                          max_frame_size=self.config.max_frame_size)

    async def _handle_signed_envelope(self, frame: Frame, writer: asyncio.StreamWriter, *, authenticated_principal: str) -> None:
        """Accept an origin-signed envelope from its author or an authorized relay."""
        from .messaging.envelope import SignedMessageEnvelope, verify_signed_envelope
        from .messaging.relay import RelayTrace, verify_relay_trace
        try:
            data = decode_payload(frame.payload)
            if not isinstance(data, dict) or set(data) != {"envelope", "relay_trace"}:
                raise AuthenticationError("invalid signed-envelope frame fields")
            raw_envelope, raw_trace = data["envelope"], data["relay_trace"]
            if not isinstance(raw_envelope, bytes) or not isinstance(raw_trace, bytes):
                raise AuthenticationError("signed envelope and relay trace must be byte strings")
            envelope = SignedMessageEnvelope.from_bytes(raw_envelope)
            verify_signed_envelope(envelope)
            trace = RelayTrace.from_bytes(raw_trace)
            if authenticated_principal == envelope.origin_principal_id:
                if trace.receipts:
                    raise AuthenticationError("origin submission must not include relay receipts")
            else:
                if self.config.allowed_relays is None or authenticated_principal not in self.config.allowed_relays:
                    raise AuthenticationError("authenticated peer is not an authorized relay")
                verify_relay_trace(envelope, trace, allowed_relays=self.config.allowed_relays,
                                   max_hops=self.config.max_relay_hops)
                if not trace.receipts or trace.receipts[-1].relay_principal_id != authenticated_principal:
                    raise AuthenticationError("last relay receipt must match authenticated peer")
            stored, duplicate = self.message_store.store(
                sender=envelope.origin_principal_id, message_id=envelope.message_id,
                recipient=envelope.recipient, body=envelope.body, expires_at=envelope.expires_at,
            )
            # Persist the exact origin-signed envelope and received relay trace before
            # acknowledging acceptance whenever this node has a configured next hop.
            # A failed enqueue intentionally prevents STORED from being acknowledged;
            # a retry is safe because both stores deduplicate by origin + message ID.
            if self.config.federation_outbox is not None:
                next_hop = self.config.federation_route_selector(envelope.recipient)
                if next_hop is not None:
                    self.config.federation_outbox.enqueue(
                        envelope_bytes=raw_envelope,
                        relay_trace_bytes=raw_trace,
                        next_hop=next_hop,
                    )
        except MessageConflictError:
            await self._send_error(writer, "MESSAGE_ID_CONFLICT", "message ID was already used with different content")
            return
        except (AuthenticationError, AuthorizationError, ValueError, TypeError) as exc:
            await self._send_error(writer, "INVALID_SIGNED_ENVELOPE", str(exc))
            return
        await write_frame(writer, Frame(TYPE_DELIVERY_ACK, encode_payload({
            "message_id": envelope.message_id, "status": "STORED", "duplicate": duplicate,
            "origin_principal_id": envelope.origin_principal_id,
            "note": "origin-signed envelope durably stored by this node; not proof of recipient delivery",
        }), request_id=frame.request_id), max_frame_size=self.config.max_frame_size)

    async def _send_error(self, writer: asyncio.StreamWriter, code: str, detail: str) -> None:
        try:
            await write_frame(writer, Frame(TYPE_ERROR, encode_payload({"code": code, "detail": detail})),
                              max_frame_size=self.config.max_frame_size)
        except (ConnectionError, FrameError):
            pass


def make_server_tls_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


def make_client_tls_context(cafile: str) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


async def send_message(host: str, port: int, ca_file: str, message: Any, *,
                       identity_keys: IdentityKeyPair | None = None,
                       expected_server_principal: str | None = None,
                       recipient: str = "test-recipient",
                       message_id: str | None = None) -> dict[str, Any]:
    if identity_keys is None:
        raise ValueError("identity_keys are required for authenticated LMP messaging")
    if not expected_server_principal:
        raise ValueError("expected_server_principal is required; do not trust an unpinned server identity")
    context = make_client_tls_context(ca_file)
    reader, writer = await asyncio.open_connection(host, port, ssl=context, server_hostname=host,
                                                   limit=DEFAULT_MAX_FRAME_SIZE + HEADER_SIZE)
    try:
        tls_object = writer.get_extra_info("ssl_object")
        if tls_object is None or tls_object.version() != "TLSv1.3":
            raise AuthenticationError("LMP requires a negotiated TLS 1.3 session")
        request_id = 1
        client_nonce = secrets.token_bytes(32)
        client_doc = identity_keys.create_initial_document()
        hello = Frame(TYPE_HELLO, encode_payload({
            "protocol": "LMP", "versions": ["0.1-draft"],
            "capabilities": ["message-basic", "delivery-ack", "identity-ed25519-v1"],
            "nonce": client_nonce,
            "identity_document": client_doc.to_bytes(),
        }), request_id=request_id)
        await write_frame(writer, hello, max_frame_size=DEFAULT_MAX_FRAME_SIZE)
        response = await asyncio.wait_for(read_frame(reader, max_frame_size=DEFAULT_MAX_FRAME_SIZE), timeout=10)
        if response.frame_type != TYPE_HELLO_ACK:
            raise RuntimeError(f"handshake rejected: {decode_payload(response.payload)!r}")
        if response.request_id != request_id:
            raise AuthenticationError("HELLO_ACK request ID does not match HELLO")
        response_data = decode_payload(response.payload)
        server_nonce = response_data.get("nonce")
        server_doc_bytes = response_data.get("identity_document")
        server_proof = response_data.get("identity_proof")
        if not isinstance(server_nonce, bytes) or len(server_nonce) != 32 or not isinstance(server_doc_bytes, bytes) or not isinstance(server_proof, bytes):
            raise AuthenticationError("server did not provide complete identity evidence")
        server_doc, server_principal = verify_document_bytes(server_doc_bytes)
        if "lmp:p:" + base64.b32encode(server_principal.value).decode("ascii").rstrip("=").lower() != expected_server_principal:
            raise AuthenticationError("server Principal ID does not match configured pin")
        transcript = HandshakeTranscript(client_nonce, server_nonce, client_doc, server_doc)
        binding = transcript.binding
        verify_peer_proof(server_doc, client_nonce, binding, server_proof)
        client_proof = identity_keys.sign_challenge(client_doc, server_nonce, binding)
        await write_frame(writer, Frame(TYPE_IDENTITY_PROOF, encode_payload({"signature": client_proof}), request_id=2),
                          max_frame_size=DEFAULT_MAX_FRAME_SIZE)
        accepted = await asyncio.wait_for(read_frame(reader, max_frame_size=DEFAULT_MAX_FRAME_SIZE), timeout=10)
        if accepted.frame_type != TYPE_IDENTITY_ACCEPT:
            raise AuthenticationError(f"identity authentication rejected: {decode_payload(accepted.payload)!r}")
        accepted_data = decode_payload(accepted.payload)
        if accepted.request_id != 2:
            raise AuthenticationError("IDENTITY_ACCEPT request ID does not match identity proof")
        if (accepted_data.get("authenticated") is not True
                or accepted_data.get("server_principal_id") != expected_server_principal
                or accepted_data.get("principal_id") != identity_keys.principal_id_text):
            raise AuthenticationError("server did not confirm the expected authenticated principals")
        msg_id = message_id or str(uuid.uuid4())
        if not isinstance(msg_id, str) or not 1 <= len(msg_id) <= 128:
            raise ValueError("message_id must contain 1..128 characters")
        if not isinstance(recipient, str) or not recipient or len(recipient) > 256:
            raise ValueError("recipient must contain 1..256 characters")
        if not isinstance(message, (str, bytes, dict, list)):
            raise ValueError("message body must be a string, bytes, map, or list")
        payload = {
            "message_id": msg_id,
            "sender": identity_keys.principal_id_text,
            "recipient": recipient,
            "body": message,
        }
        await write_frame(writer, Frame(TYPE_MESSAGE, encode_payload(payload), request_id=3),
                          max_frame_size=DEFAULT_MAX_FRAME_SIZE)
        ack = await asyncio.wait_for(read_frame(reader, max_frame_size=DEFAULT_MAX_FRAME_SIZE), timeout=10)
        if ack.frame_type != TYPE_DELIVERY_ACK or ack.request_id != 3:
            raise RuntimeError(f"message rejected or response correlation failed: {decode_payload(ack.payload)!r}")
        ack_data = decode_payload(ack.payload)
        if ack_data.get("message_id") != msg_id or ack_data.get("status") != "STORED":
            raise AuthenticationError("remote node did not confirm durable storage of this message")
        return ack_data
    finally:
        writer.close()
        await writer.wait_closed()


async def send_signed_envelope(host: str, port: int, ca_file: str, envelope: Any, *,
                               identity_keys: IdentityKeyPair,
                               expected_server_principal: str,
                               relay_trace: Any = None,
                               relay_allowed_principals: frozenset[str] | None = None,
                               max_relay_hops: int = 8,
                               trace_prepared: bool = False) -> dict[str, Any]:
    """Send an origin-signed envelope; if forwarding, append this node's relay receipt.

    The authenticated peer is always this connection's identity. The envelope's
    origin remains independently verifiable. Relay policy is explicit and defaults
    to no forwarding.
    """
    from .messaging.envelope import SignedMessageEnvelope, verify_signed_envelope
    from .messaging.relay import RelayTrace, verify_relay_trace
    if not isinstance(envelope, SignedMessageEnvelope):
        raise TypeError("envelope must be a SignedMessageEnvelope")
    verify_signed_envelope(envelope)
    if not expected_server_principal:
        raise ValueError("expected_server_principal is required")
    trace = relay_trace or RelayTrace()
    local_doc = identity_keys.create_initial_document()
    if identity_keys.principal_id_text != envelope.origin_principal_id:
        if relay_allowed_principals is None or identity_keys.principal_id_text not in relay_allowed_principals:
            raise AuthenticationError("local node is not authorized by the relay policy")
        if trace_prepared:
            verify_relay_trace(envelope, trace, allowed_relays=relay_allowed_principals,
                               max_hops=max_relay_hops)
            if not trace.receipts or trace.receipts[-1].relay_principal_id != identity_keys.principal_id_text:
                raise AuthenticationError("prepared relay trace does not end with the local relay")
        else:
            if trace.receipts:
                verify_relay_trace(envelope, trace, allowed_relays=relay_allowed_principals,
                                   max_hops=max_relay_hops)
            trace = trace.append(envelope, identity_keys, local_doc, allowed_relays=relay_allowed_principals,
                                 max_hops=max_relay_hops)
    elif trace.receipts:
        raise AuthenticationError("origin submission cannot include pre-existing relay receipts")
    elif trace_prepared:
        raise AuthenticationError("trace_prepared is only valid for a relay")

    context = make_client_tls_context(ca_file)
    reader, writer = await asyncio.open_connection(host, port, ssl=context, server_hostname=host,
                                                   limit=DEFAULT_MAX_FRAME_SIZE + HEADER_SIZE)
    try:
        tls_object = writer.get_extra_info("ssl_object")
        if tls_object is None or tls_object.version() != "TLSv1.3":
            raise AuthenticationError("LMP requires a negotiated TLS 1.3 session")
        request_id = 1
        client_nonce = secrets.token_bytes(32)
        client_doc = identity_keys.create_initial_document()
        await write_frame(writer, Frame(TYPE_HELLO, encode_payload({
            "protocol": "LMP", "versions": ["0.1-draft"], "capabilities": ["message-basic", "delivery-ack", "identity-ed25519-v1", "signed-envelope-v1"],
            "nonce": client_nonce, "identity_document": client_doc.to_bytes(),
        }), request_id=request_id), max_frame_size=DEFAULT_MAX_FRAME_SIZE)
        response = await asyncio.wait_for(read_frame(reader, max_frame_size=DEFAULT_MAX_FRAME_SIZE), timeout=10)
        if response.frame_type != TYPE_HELLO_ACK or response.request_id != request_id:
            raise AuthenticationError("server rejected or mismatched HELLO")
        response_data = decode_payload(response.payload)
        server_nonce, server_doc_bytes, server_proof = (response_data.get("nonce"), response_data.get("identity_document"), response_data.get("identity_proof"))
        if not isinstance(server_nonce, bytes) or len(server_nonce) != 32 or not isinstance(server_doc_bytes, bytes) or not isinstance(server_proof, bytes):
            raise AuthenticationError("server identity evidence is incomplete")
        server_doc, server_principal = verify_document_bytes(server_doc_bytes)
        server_text = "lmp:p:" + base64.b32encode(server_principal.value).decode("ascii").rstrip("=").lower()
        if server_text != expected_server_principal:
            raise AuthenticationError("server Principal ID does not match configured pin")
        binding = HandshakeTranscript(client_nonce, server_nonce, client_doc, server_doc).binding
        verify_peer_proof(server_doc, client_nonce, binding, server_proof)
        proof = identity_keys.sign_challenge(client_doc, server_nonce, binding)
        await write_frame(writer, Frame(TYPE_IDENTITY_PROOF, encode_payload({"signature": proof}), request_id=2), max_frame_size=DEFAULT_MAX_FRAME_SIZE)
        accepted = await asyncio.wait_for(read_frame(reader, max_frame_size=DEFAULT_MAX_FRAME_SIZE), timeout=10)
        if accepted.frame_type != TYPE_IDENTITY_ACCEPT or accepted.request_id != 2:
            raise AuthenticationError("identity authentication was not accepted")
        accepted_data = decode_payload(accepted.payload)
        if accepted_data.get("authenticated") is not True or accepted_data.get("principal_id") != identity_keys.principal_id_text or accepted_data.get("server_principal_id") != expected_server_principal:
            raise AuthenticationError("server confirmed unexpected identities")
        await write_frame(writer, Frame(TYPE_SIGNED_ENVELOPE, encode_payload({
            "envelope": envelope.to_bytes(), "relay_trace": trace.to_bytes(),
        }), request_id=3), max_frame_size=DEFAULT_MAX_FRAME_SIZE)
        ack = await asyncio.wait_for(read_frame(reader, max_frame_size=DEFAULT_MAX_FRAME_SIZE), timeout=10)
        if ack.frame_type != TYPE_DELIVERY_ACK or ack.request_id != 3:
            raise AuthenticationError("remote node did not acknowledge signed envelope storage")
        ack_data = decode_payload(ack.payload)
        if ack_data.get("message_id") != envelope.message_id or ack_data.get("status") != "STORED":
            raise AuthenticationError("remote node did not confirm storage of this envelope")
        return ack_data
    finally:
        writer.close()
        await writer.wait_closed()
