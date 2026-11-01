"""Durable worker that sends signed federation envelopes from the outbox."""
from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping

from ..errors import AuthenticationError
from ..messaging.envelope import SignedMessageEnvelope, verify_signed_envelope
from ..messaging.relay import RelayTrace, verify_relay_trace
from ..network.federation import RouteCache, verify_route_record
from ..security.identity import IdentityDocument, IdentityKeyPair
from .outbox import FederationOutbox, FederationOutboxItem

SendEnvelope = Callable[..., Awaitable[dict[str, Any]]]
RouteFailover = Callable[[FederationOutboxItem, str], str | None]


@dataclass(frozen=True, slots=True)
class FederationBatchResult:
    claimed: int = 0
    sent: int = 0
    retried: int = 0
    failed: int = 0
    lease_lost: int = 0
    route_missing: int = 0
    expired: int = 0


class FederationOutboxWorker:
    """Claim, route, sign relay receipt, and send outbox envelopes.

    ``allowed_relays`` is an explicit policy set of relay Principal IDs accepted
    by this deployment. Route records must be signed by the configured identity
    document for the next-hop Principal ID. A remote STORED ACK means durable
    acceptance by that node, not delivery to the final recipient.
    """

    def __init__(self, *, outbox: FederationOutbox, identity_keys: IdentityKeyPair,
                 ca_file: str, route_cache: RouteCache,
                 identity_documents: Mapping[str, IdentityDocument],
                 allowed_relays: frozenset[str], max_relay_hops: int = 8,
                 worker_id: str | None = None, lease_seconds: float = 60,
                 max_attempts: int = 8, base_retry_seconds: float = 1,
                 max_retry_seconds: float = 300, send_func: SendEnvelope | None = None,
                 route_failover: RouteFailover | None = None) -> None:
        if not isinstance(ca_file, str) or not ca_file:
            raise ValueError("ca_file must be a non-empty path")
        if not 1 <= max_relay_hops <= 16:
            raise ValueError("max_relay_hops must be between 1 and 16")
        if not 1 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be between 1 and 3600")
        if not 1 <= max_attempts <= 100:
            raise ValueError("max_attempts must be between 1 and 100")
        if not 0.1 <= base_retry_seconds <= max_retry_seconds <= 604800:
            raise ValueError("invalid retry interval")
        self.outbox = outbox
        self.identity_keys = identity_keys
        self.ca_file = ca_file
        self.route_cache = route_cache
        self.identity_documents = dict(identity_documents)
        self.allowed_relays = frozenset(allowed_relays)
        self.max_relay_hops = max_relay_hops
        self.worker_id = worker_id or f"federation-{secrets.token_hex(12)}"
        if not 1 <= len(self.worker_id) <= 128:
            raise ValueError("worker_id must contain 1..128 characters")
        self.lease_seconds = float(lease_seconds)
        self.max_attempts = max_attempts
        self.base_retry_seconds = float(base_retry_seconds)
        self.max_retry_seconds = float(max_retry_seconds)
        if send_func is None:
            async def _default_send(*args: Any, **kwargs: Any) -> dict[str, Any]:
                from ..node import send_signed_envelope
                return await send_signed_envelope(*args, **kwargs)
            self.send_func = _default_send
        else:
            self.send_func = send_func
        self.route_failover = route_failover

    async def run_once(self, *, limit: int = 10, now: float | None = None) -> FederationBatchResult:
        claimed = self.outbox.claim(worker_id=self.worker_id, limit=limit,
                                    lease_seconds=self.lease_seconds, now=now)
        sent = retried = failed = lease_lost = route_missing = expired = 0
        for item in claimed:
            try:
                outcome = await self._send_one(item, now=now)
            except Exception:
                outcome = "retry"
            # Claiming is not a network attempt: a process can crash immediately
            # after claim. Use the durable send-attempt count for terminal policy.
            latest = self.outbox.get(item.origin_principal_id, item.message_id)
            send_attempts = latest.attempts if latest is not None else item.attempts
            if outcome == "expired":
                ok = self.outbox.expire(origin_principal_id=item.origin_principal_id,
                    message_id=item.message_id, worker_id=self.worker_id,
                    lease_token=item.lease_token or "", now=now)
                expired += int(ok)
                lease_lost += int(not ok)
            elif outcome == "route_changed":
                # Release the lease and retry promptly with the newly persisted hop.
                ok = self._retry(item, now=now, force_delay=0)
                retried += int(ok)
                lease_lost += int(not ok)
            elif outcome == "sent":
                ok = self.outbox.acknowledge(origin_principal_id=item.origin_principal_id,
                    message_id=item.message_id, worker_id=self.worker_id, lease_token=item.lease_token or "")
                if ok:
                    sent += 1
                else:
                    lease_lost += 1
            elif send_attempts >= self.max_attempts:
                ok = self._fail(item)
                failed += int(ok)
                lease_lost += int(not ok)
            elif outcome == "route_missing":
                ok = self._retry(item, now=now, force_delay=self.base_retry_seconds)
                route_missing += 1
                retried += int(ok)
                lease_lost += int(not ok)
            else:
                delay = min(self.max_retry_seconds,
                    self.base_retry_seconds * (2 ** min(max(send_attempts - 1, 0), 20)))
                delay *= 0.8 + secrets.randbelow(401) / 1000
                ok = self._retry(item, now=now, force_delay=min(delay, self.max_retry_seconds))
                retried += int(ok)
                lease_lost += int(not ok)
        return FederationBatchResult(len(claimed), sent, retried, failed, lease_lost, route_missing, expired)

    async def _send_one(self, item: FederationOutboxItem, *, now: float | None = None) -> str:
        envelope = SignedMessageEnvelope.from_bytes(item.envelope_bytes)
        current = int(time.time() if now is None else now)
        # Expiry is a terminal delivery state, not a transient network failure.
        # The immutable envelope was signature-checked at enqueue; verify again
        # when it remains within its signed validity window.
        if envelope.expires_at <= current:
            return "expired"
        verify_signed_envelope(envelope, now=current)
        if envelope.origin_principal_id != item.origin_principal_id or envelope.message_id != item.message_id:
            raise AuthenticationError("outbox index does not match signed envelope")
        trace = RelayTrace.from_bytes(item.relay_trace_bytes)
        record = self.route_cache.get(item.next_hop)
        document = self.identity_documents.get(item.next_hop)
        if record is None or document is None:
            # A missing route is a routing condition, not a message failure. An
            # application may provide an ordered policy-aware alternate selector.
            # The candidate is persisted under the current fencing token before retry.
            if self.route_failover is not None:
                candidate = self.route_failover(item, item.next_hop)
                if candidate is not None:
                    if not isinstance(candidate, str) or not candidate or len(candidate) > 256:
                        raise ValueError("route_failover returned an invalid Principal ID")
                    trace_ids = {receipt.relay_principal_id for receipt in trace.receipts}
                    if candidate == item.next_hop:
                        return "route_missing"
                    # A relay must never route a message to itself. A valid signed
                    # route record for the local identity is not a usable next hop.
                    if candidate == self.identity_keys.principal_id_text:
                        return "route_missing"
                    if candidate == envelope.origin_principal_id or candidate in trace_ids:
                        raise AuthenticationError("alternate route would create a federation loop")
                    if self.outbox.route_was_tried(origin_principal_id=item.origin_principal_id,
                            message_id=item.message_id, next_hop=candidate):
                        return "route_missing"
                    candidate_record = self.route_cache.get(candidate)
                    candidate_document = self.identity_documents.get(candidate)
                    if candidate_record is None or candidate_document is None:
                        return "route_missing"
                    verify_route_record(candidate_record, candidate_document)
                    if candidate_record.principal_id != candidate:
                        raise AuthenticationError("alternate route record identity mismatch")
                    if not self.outbox.update_next_hop(origin_principal_id=item.origin_principal_id,
                            message_id=item.message_id, worker_id=self.worker_id,
                            lease_token=item.lease_token or "", next_hop=candidate, now=now):
                        raise RuntimeError("lost outbox lease while updating next hop")
                    return "route_changed"
            return "route_missing"
        verify_route_record(record, document)
        if record.principal_id != item.next_hop:
            raise AuthenticationError("route cache returned a different Principal ID")
        if self.identity_keys.principal_id_text != envelope.origin_principal_id:
            # Validate existing history before extending it. If this worker has
            # already persisted its receipt during a previous attempt, reuse it.
            if trace.receipts and trace.receipts[-1].relay_principal_id == self.identity_keys.principal_id_text:
                verify_relay_trace(envelope, trace, allowed_relays=self.allowed_relays,
                                   max_hops=self.max_relay_hops)
            else:
                if trace.receipts:
                    verify_relay_trace(envelope, trace, allowed_relays=self.allowed_relays,
                                       max_hops=self.max_relay_hops)
                trace = trace.append(envelope, self.identity_keys,
                    self.identity_keys.create_initial_document(), allowed_relays=self.allowed_relays,
                    max_hops=self.max_relay_hops)
                if not self.outbox.update_trace(origin_principal_id=item.origin_principal_id,
                        message_id=item.message_id, worker_id=self.worker_id, lease_token=item.lease_token or "", relay_trace_bytes=trace.to_bytes()):
                    raise RuntimeError("lost outbox lease while persisting relay receipt")
        if not self.outbox.record_attempt(origin_principal_id=item.origin_principal_id,
                message_id=item.message_id, worker_id=self.worker_id,
                lease_token=item.lease_token or "", now=now):
            raise RuntimeError("lost outbox lease before network send")
        ack = await asyncio.wait_for(self.send_func(record.host, record.port, self.ca_file, envelope,
            identity_keys=self.identity_keys, expected_server_principal=item.next_hop,
            relay_trace=trace, relay_allowed_principals=self.allowed_relays,
            max_relay_hops=self.max_relay_hops, trace_prepared=(self.identity_keys.principal_id_text != envelope.origin_principal_id)),
            timeout=self.lease_seconds * 0.8)
        if not isinstance(ack, dict) or ack.get("status") != "STORED" or ack.get("message_id") != item.message_id:
            raise AuthenticationError("next hop did not confirm durable acceptance")
        return "sent"

    def _retry(self, item: FederationOutboxItem, *, now: float | None, force_delay: float) -> bool:
        return self.outbox.retry(origin_principal_id=item.origin_principal_id,
            message_id=item.message_id, worker_id=self.worker_id, lease_token=item.lease_token or "", delay_seconds=force_delay, now=now)

    def _fail(self, item: FederationOutboxItem) -> bool:
        return self.outbox.fail(origin_principal_id=item.origin_principal_id,
            message_id=item.message_id, worker_id=self.worker_id, lease_token=item.lease_token or "")
