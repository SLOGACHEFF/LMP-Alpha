"""Outbound sender that connects verified route records to the durable delivery worker.

This adapter supports direct delivery to a recipient hosted by a known remote node.
It deliberately does not relay arbitrary third-party-origin messages: the current
wire protocol authenticates the sender as the local Principal ID and has no
origin-signed forwarding envelope yet.
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable, Mapping

from ..errors import AuthenticationError
from ..security.identity import IdentityDocument, IdentityKeyPair
from ..storage.message_store import StoredMessage
from .federation import RouteCache, verify_route_record

SendFunction = Callable[..., Awaitable[dict[str, Any]]]


class FederationSender:
    """Send locally-authored messages through verified routes to remote LMP nodes.

    Args:
        identity_keys: identity used to authenticate this node to the remote node.
        ca_file: CA bundle used for TLS certificate validation.
        route_cache: cache populated only after route signature validation.
        identity_documents: trusted identity documents indexed by node Principal ID.
        recipient_routes: maps a recipient Principal ID to its hosting node Principal ID.
        send_func: optional injectable send function, useful for integration tests.
    """

    def __init__(
        self,
        *,
        identity_keys: IdentityKeyPair,
        ca_file: str,
        route_cache: RouteCache,
        identity_documents: Mapping[str, IdentityDocument],
        recipient_routes: Mapping[str, str],
        send_func: SendFunction | None = None,
    ) -> None:
        if not isinstance(ca_file, str) or not ca_file:
            raise ValueError("ca_file must be a non-empty path")
        self.identity_keys = identity_keys
        self.ca_file = ca_file
        self.route_cache = route_cache
        self.identity_documents = dict(identity_documents)
        self.recipient_routes = dict(recipient_routes)
        if send_func is None:
            async def _default_send(*args: Any, **kwargs: Any) -> dict[str, Any]:
                from ..node import send_message
                return await send_message(*args, **kwargs)
            self.send_func = _default_send
        else:
            self.send_func = send_func

    async def __call__(self, message: StoredMessage) -> bool:
        """Return True only when the remote node confirms durable acceptance."""
        if message.sender != self.identity_keys.principal_id_text:
            # Forwarding requires a separately specified origin signature envelope.
            raise AuthenticationError("federation sender cannot relay messages authored by another Principal ID")
        node_principal = self.recipient_routes.get(message.recipient)
        if not node_principal:
            return False
        record = self.route_cache.get(node_principal)
        identity_document = self.identity_documents.get(node_principal)
        if record is None or identity_document is None:
            return False
        verify_route_record(record, identity_document)
        if record.principal_id != node_principal:
            raise AuthenticationError("route cache returned a route for a different node")
        ack = await self.send_func(
            record.host,
            record.port,
            self.ca_file,
            message.body,
            identity_keys=self.identity_keys,
            expected_server_principal=node_principal,
            recipient=message.recipient,
            message_id=message.message_id,
        )
        return (isinstance(ack, dict)
                and ack.get("message_id") == message.message_id
                and ack.get("status") == "STORED")
