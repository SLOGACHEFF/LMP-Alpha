from __future__ import annotations

import asyncio
import time

from lmp_core.federation import FederationOutbox, FederationOutboxWorker
from lmp_core.messaging.envelope import create_signed_envelope
from lmp_core.messaging.relay import RelayTrace
from lmp_core.network import RouteCache, create_route_record
from lmp_core.security.identity import IdentityKeyPair



def _worker_crash_after_receipt_child(db_path, envelope_bytes, relay_key_path,
                                      target_key_path, key_password, now):
    """Run the real worker, then hard-exit when it reaches record_attempt."""
    import os
    from lmp_core.federation import FederationOutbox, FederationOutboxWorker
    from lmp_core.messaging.envelope import SignedMessageEnvelope
    from lmp_core.network import RouteCache, create_route_record
    from lmp_core.security.identity import IdentityKeyPair

    relay = IdentityKeyPair.load_encrypted(relay_key_path, key_password)
    target = IdentityKeyPair.load_encrypted(target_key_path, key_password)
    target_doc = target.create_initial_document(created_at=now)
    envelope = SignedMessageEnvelope.from_bytes(envelope_bytes)
    cache = RouteCache()
    route = create_route_record(target, target_doc, "127.0.0.1", 7443,
                                ttl_seconds=300, now=now)
    cache.add(route, target_doc, now=now)
    outbox = FederationOutbox(db_path)

    original_update_trace = outbox.update_trace

    def persist_then_crash(**kwargs):
        # Perform the real transactional write, then die before _send_one proceeds.
        persisted = original_update_trace(**kwargs)
        if not persisted:
            os._exit(87)
        os._exit(86)

    outbox.update_trace = persist_then_crash
    async def send_func(*args, **kwargs):
        raise AssertionError("network send must not happen before attempt record")
    worker = FederationOutboxWorker(
        outbox=outbox, identity_keys=relay, ca_file="unused-ca.pem",
        route_cache=cache, identity_documents={target.principal_id_text: target_doc},
        allowed_relays=frozenset({relay.principal_id_text}),
        send_func=send_func, worker_id="crash-after-receipt", lease_seconds=60,
    )
    asyncio.run(worker.run_once(now=now))

def test_worker_persists_relay_receipt_before_sending_and_acknowledges():
    now = int(time.time())
    origin = IdentityKeyPair.generate()
    relay = IdentityKeyPair.generate()
    target = IdentityKeyPair.generate()
    origin_doc = origin.create_initial_document(created_at=now)
    relay_doc = relay.create_initial_document(created_at=now)
    target_doc = target.create_initial_document(created_at=now)
    envelope = create_signed_envelope(origin, origin_doc, message_id="federation-worker-1",
        recipient="lmp:p:recipient", body={"hello": "federation"}, ttl_seconds=600, now=now)

    cache = RouteCache()
    route = create_route_record(target, target_doc, "127.0.0.1", 7443, ttl_seconds=300, now=now)
    cache.add(route, target_doc, now=now)
    outbox = FederationOutbox()
    outbox.enqueue(envelope_bytes=envelope.to_bytes(), next_hop=target.principal_id_text, now=now)
    calls = []

    async def send_func(host, port, ca_file, sent_envelope, **kwargs):
        calls.append((host, port, sent_envelope.to_bytes(), kwargs))
        return {"status": "STORED", "message_id": sent_envelope.message_id}

    worker = FederationOutboxWorker(outbox=outbox, identity_keys=relay, ca_file="unused-ca.pem",
        route_cache=cache, identity_documents={target.principal_id_text: target_doc},
        allowed_relays=frozenset({relay.principal_id_text}), send_func=send_func,
        worker_id="worker-test")
    result = asyncio.run(worker.run_once(now=now))

    assert result.claimed == 1 and result.sent == 1 and result.retried == 0
    assert calls[0][0:2] == ("127.0.0.1", 7443)
    assert calls[0][2] == envelope.to_bytes()  # origin-signed bytes unchanged
    assert calls[0][3]["trace_prepared"] is True
    sent_trace = calls[0][3]["relay_trace"]
    assert sent_trace.receipts[-1].relay_principal_id == relay.principal_id_text
    stored = outbox.get(envelope.origin_principal_id, envelope.message_id)
    assert stored is not None and stored.status == "SENT"
    assert RelayTrace.from_bytes(stored.relay_trace_bytes) == sent_trace
    outbox.close()


def test_worker_retries_when_route_is_missing():
    now = int(time.time())
    origin = IdentityKeyPair.generate()
    relay = IdentityKeyPair.generate()
    doc = origin.create_initial_document(created_at=now)
    envelope = create_signed_envelope(origin, doc, message_id="federation-no-route",
        recipient="lmp:p:recipient", body="hello", ttl_seconds=600, now=now)
    outbox = FederationOutbox()
    outbox.enqueue(envelope_bytes=envelope.to_bytes(), next_hop="lmp:p:missing", now=now)
    worker = FederationOutboxWorker(outbox=outbox, identity_keys=relay, ca_file="unused-ca.pem",
        route_cache=RouteCache(), identity_documents={}, allowed_relays=frozenset({relay.principal_id_text}),
        worker_id="worker-no-route", base_retry_seconds=1)
    result = asyncio.run(worker.run_once(now=now))
    assert result.claimed == 1 and result.route_missing == 1 and result.retried == 1
    stored = outbox.get(envelope.origin_principal_id, envelope.message_id)
    assert stored is not None and stored.status == "PENDING" and stored.lease_owner is None
    outbox.close()


def test_worker_marks_expired_envelope_terminal_instead_of_retrying():
    created = 1_800_000_000
    origin = IdentityKeyPair.generate()
    relay = IdentityKeyPair.generate()
    doc = origin.create_initial_document(created_at=created)
    envelope = create_signed_envelope(origin, doc, message_id="federation-expired",
        recipient="lmp:p:recipient", body="short lived", ttl_seconds=1, now=created)
    outbox = FederationOutbox()
    outbox.enqueue(envelope_bytes=envelope.to_bytes(), next_hop="lmp:p:missing", now=created)
    worker = FederationOutboxWorker(outbox=outbox, identity_keys=relay, ca_file="unused-ca.pem",
        route_cache=RouteCache(), identity_documents={}, allowed_relays=frozenset({relay.principal_id_text}),
        worker_id="worker-expired")

    result = asyncio.run(worker.run_once(now=created + 2))

    assert result.claimed == 1 and result.expired == 1
    assert result.retried == 0 and result.route_missing == 0
    stored = outbox.get(envelope.origin_principal_id, envelope.message_id)
    assert stored is not None and stored.status == "EXPIRED"
    assert stored.lease_token is None and stored.lease_owner is None
    outbox.close()


def test_worker_switches_to_verified_alternate_when_route_missing():
    now = int(time.time())
    origin = IdentityKeyPair.generate()
    relay = IdentityKeyPair.generate()
    alternate = IdentityKeyPair.generate()
    origin_doc = origin.create_initial_document(created_at=now)
    alternate_doc = alternate.create_initial_document(created_at=now)
    envelope = create_signed_envelope(origin, origin_doc, message_id="federation-route-failover",
        recipient="lmp:p:recipient", body="route around outage", ttl_seconds=600, now=now)

    cache = RouteCache()
    route = create_route_record(alternate, alternate_doc, "127.0.0.1", 7444, ttl_seconds=300, now=now)
    cache.add(route, alternate_doc, now=now)
    outbox = FederationOutbox()
    outbox.enqueue(envelope_bytes=envelope.to_bytes(), next_hop="lmp:p:offline", now=now)
    calls = []

    async def send_func(host, port, ca_file, sent_envelope, **kwargs):
        calls.append((host, port, sent_envelope.to_bytes()))
        return {"status": "STORED", "message_id": sent_envelope.message_id}

    worker = FederationOutboxWorker(outbox=outbox, identity_keys=relay, ca_file="unused-ca.pem",
        route_cache=cache, identity_documents={alternate.principal_id_text: alternate_doc},
        allowed_relays=frozenset({relay.principal_id_text}), send_func=send_func,
        route_failover=lambda item, failed_hop: alternate.principal_id_text,
        worker_id="worker-failover", base_retry_seconds=1)

    first = asyncio.run(worker.run_once(now=now))
    stored = outbox.get(envelope.origin_principal_id, envelope.message_id)
    assert first.claimed == 1 and first.retried == 1 and first.route_missing == 0
    assert stored is not None and stored.next_hop == alternate.principal_id_text
    assert stored.status == "PENDING" and stored.lease_owner is None

    second = asyncio.run(worker.run_once(now=now + 0.01))
    stored = outbox.get(envelope.origin_principal_id, envelope.message_id)
    assert second.claimed == 1 and second.sent == 1
    assert calls == [("127.0.0.1", 7444, envelope.to_bytes())]
    assert stored is not None and stored.status == "SENT"
    outbox.close()


def test_outbox_next_hop_update_requires_current_lease_token():
    now = int(time.time())
    origin = IdentityKeyPair.generate()
    doc = origin.create_initial_document(created_at=now)
    envelope = create_signed_envelope(origin, doc, message_id="federation-route-fencing",
        recipient="lmp:p:recipient", body="hello", ttl_seconds=600, now=now)
    outbox = FederationOutbox()
    outbox.enqueue(envelope_bytes=envelope.to_bytes(), next_hop="lmp:p:first", now=now)
    item = outbox.claim(worker_id="worker-one", now=now, lease_seconds=10)[0]
    assert item.lease_token is not None
    assert not outbox.update_next_hop(origin_principal_id=item.origin_principal_id,
        message_id=item.message_id, worker_id="worker-one", lease_token="stale-token",
        next_hop="lmp:p:alternate", now=now)
    assert outbox.update_next_hop(origin_principal_id=item.origin_principal_id,
        message_id=item.message_id, worker_id="worker-one", lease_token=item.lease_token,
        next_hop="lmp:p:alternate", now=now)
    stored = outbox.get(envelope.origin_principal_id, envelope.message_id)
    assert stored is not None and stored.next_hop == "lmp:p:alternate"
    outbox.close()


def test_route_attempt_history_prevents_failover_oscillation():
    now = int(time.time())
    origin = IdentityKeyPair.generate()
    doc = origin.create_initial_document(created_at=now)
    envelope = create_signed_envelope(origin, doc, message_id="federation-route-loop-guard",
        recipient="lmp:p:recipient", body="no route oscillation", ttl_seconds=600, now=now)
    outbox = FederationOutbox()
    outbox.enqueue(envelope_bytes=envelope.to_bytes(), next_hop="lmp:p:first", now=now)
    item = outbox.claim(worker_id="route-loop-test", now=now, lease_seconds=10)[0]
    assert item.lease_token is not None
    assert outbox.update_next_hop(origin_principal_id=item.origin_principal_id,
        message_id=item.message_id, worker_id="route-loop-test", lease_token=item.lease_token,
        next_hop="lmp:p:second", now=now)
    assert not outbox.update_next_hop(origin_principal_id=item.origin_principal_id,
        message_id=item.message_id, worker_id="route-loop-test", lease_token=item.lease_token,
        next_hop="lmp:p:first", now=now)
    assert outbox.route_was_tried(origin_principal_id=item.origin_principal_id,
        message_id=item.message_id, next_hop="lmp:p:first")
    outbox.close()


def test_worker_refuses_local_identity_as_alternate_next_hop():
    now = int(time.time())
    origin = IdentityKeyPair.generate()
    relay = IdentityKeyPair.generate()
    envelope = create_signed_envelope(
        origin, origin.create_initial_document(created_at=now),
        message_id="federation-no-self-route", recipient="lmp:p:recipient",
        body="must not route to self", ttl_seconds=600, now=now,
    )
    outbox = FederationOutbox()
    original_hop = "lmp:p:offline"
    outbox.enqueue(envelope_bytes=envelope.to_bytes(), next_hop=original_hop, now=now)
    calls = []

    async def send_func(*args, **kwargs):
        calls.append((args, kwargs))
        return {"status": "STORED", "message_id": envelope.message_id}

    worker = FederationOutboxWorker(
        outbox=outbox, identity_keys=relay, ca_file="unused-ca.pem",
        route_cache=RouteCache(), identity_documents={},
        allowed_relays=frozenset({relay.principal_id_text}), send_func=send_func,
        route_failover=lambda item, failed_hop: relay.principal_id_text,
        worker_id="worker-no-self-route", base_retry_seconds=1,
    )

    result = asyncio.run(worker.run_once(now=now))
    stored = outbox.get(envelope.origin_principal_id, envelope.message_id)
    assert result.claimed == 1 and result.route_missing == 1
    assert result.sent == 0 and result.failed == 0
    assert calls == []
    assert stored is not None and stored.next_hop == original_hop
    assert stored.status == "PENDING"
    outbox.close()


def test_crashed_claims_do_not_exhaust_network_send_attempt_limit(tmp_path):
    """Repeated crashes before send must not consume max_attempts."""
    now = int(time.time())
    origin = IdentityKeyPair.generate()
    relay = IdentityKeyPair.generate()
    target = IdentityKeyPair.generate()
    origin_doc = origin.create_initial_document(created_at=now)
    target_doc = target.create_initial_document(created_at=now)
    envelope = create_signed_envelope(origin, origin_doc,
        message_id="federation-crash-before-send", recipient="lmp:p:recipient",
        body="must still get a send attempt", ttl_seconds=600, now=now)
    path = str(tmp_path / "crash-before-send.sqlite3")

    outbox = FederationOutbox(path)
    outbox.enqueue(envelope_bytes=envelope.to_bytes(), next_hop=target.principal_id_text, now=now)
    abandoned_tokens = []
    for index in range(3):
        claim = outbox.claim(worker_id=f"crashed-worker-{index}", now=now + index,
                             lease_seconds=1)[0]
        abandoned_tokens.append(claim.lease_token)
        assert claim.attempts == 0
        outbox.close()
        outbox = FederationOutbox(path)

    cache = RouteCache()
    cache.add(create_route_record(target, target_doc, "127.0.0.1", 7443,
        ttl_seconds=300, now=now), target_doc, now=now)
    calls = []

    async def send_func(host, port, ca_file, sent_envelope, **kwargs):
        calls.append(sent_envelope.message_id)
        return {"status": "STORED", "message_id": sent_envelope.message_id}

    worker = FederationOutboxWorker(outbox=outbox, identity_keys=relay, ca_file="unused-ca.pem",
        route_cache=cache, identity_documents={target.principal_id_text: target_doc},
        allowed_relays=frozenset({relay.principal_id_text}), send_func=send_func,
        worker_id="recovery-worker", lease_seconds=10, max_attempts=1)
    result = asyncio.run(worker.run_once(now=now + 3))
    stored = outbox.get(envelope.origin_principal_id, envelope.message_id)
    assert result.claimed == 1 and result.sent == 1 and result.failed == 0
    assert calls == [envelope.message_id]
    assert stored is not None and stored.status == "SENT"
    assert stored.claims == 4 and stored.attempts == 1
    outbox.close()



def test_crash_after_receipt_persisted_before_send_reuses_single_receipt(tmp_path):
    """A durable relay receipt survives restart and is not appended twice."""
    now = int(time.time())
    origin = IdentityKeyPair.generate()
    relay = IdentityKeyPair.generate()
    target = IdentityKeyPair.generate()
    origin_doc = origin.create_initial_document(created_at=now)
    target_doc = target.create_initial_document(created_at=now)
    envelope = create_signed_envelope(origin, origin_doc,
        message_id="federation-crash-after-receipt", recipient="lmp:p:recipient",
        body="persist receipt then crash", ttl_seconds=600, now=now)
    db_path = str(tmp_path / "receipt-crash.sqlite3")
    outbox = FederationOutbox(db_path)
    outbox.enqueue(envelope_bytes=envelope.to_bytes(),
                    next_hop=target.principal_id_text, now=now)
    cache = RouteCache()
    cache.add(create_route_record(target, target_doc, "127.0.0.1", 7443,
        ttl_seconds=300, now=now), target_doc, now=now)
    calls = []

    async def send_func(*args, **kwargs):
        calls.append(kwargs["relay_trace"])
        return {"status": "STORED", "message_id": envelope.message_id}

    worker = FederationOutboxWorker(outbox=outbox, identity_keys=relay,
        ca_file="unused-ca.pem", route_cache=cache,
        identity_documents={target.principal_id_text: target_doc},
        allowed_relays=frozenset({relay.principal_id_text}),
        send_func=send_func, worker_id="worker-crash-receipt",
        base_retry_seconds=1)

    original_record_attempt = outbox.record_attempt
    def fail_once(**kwargs):
        outbox.record_attempt = original_record_attempt
        raise OSError("injected crash boundary after durable receipt")
    outbox.record_attempt = fail_once

    first = asyncio.run(worker.run_once(now=now))
    saved = outbox.get(envelope.origin_principal_id, envelope.message_id)
    assert first.claimed == 1 and first.retried == 1 and first.sent == 0
    assert calls == []
    assert saved is not None and saved.status == "PENDING"
    first_trace = RelayTrace.from_bytes(saved.relay_trace_bytes)
    assert len(first_trace.receipts) == 1
    outbox.close()

    # Simulate a process restart by reopening the same SQLite file.
    outbox = FederationOutbox(db_path)
    worker.outbox = outbox
    second = asyncio.run(worker.run_once(now=now + 3))
    saved = outbox.get(envelope.origin_principal_id, envelope.message_id)
    assert second.claimed == 1 and second.sent == 1
    assert len(calls) == 1
    assert calls[0] == first_trace
    assert saved is not None and saved.status == "SENT"
    assert RelayTrace.from_bytes(saved.relay_trace_bytes) == first_trace
    assert len(RelayTrace.from_bytes(saved.relay_trace_bytes).receipts) == 1
    outbox.close()


def test_remote_store_then_lost_ack_retries_idempotently(tmp_path):
    """If remote durable storage succeeds but ACK is lost, retry reuses same trace."""
    now = int(time.time())
    origin = IdentityKeyPair.generate()
    relay = IdentityKeyPair.generate()
    target = IdentityKeyPair.generate()
    origin_doc = origin.create_initial_document(created_at=now)
    target_doc = target.create_initial_document(created_at=now)
    envelope = create_signed_envelope(origin, origin_doc,
        message_id="federation-lost-ack", recipient="lmp:p:recipient",
        body="receiver stores, ack is lost", ttl_seconds=600, now=now)
    db_path = str(tmp_path / "lost-ack.sqlite3")
    outbox = FederationOutbox(db_path)
    outbox.enqueue(envelope_bytes=envelope.to_bytes(),
                    next_hop=target.principal_id_text, now=now)
    cache = RouteCache()
    cache.add(create_route_record(target, target_doc, "127.0.0.1", 7443,
        ttl_seconds=300, now=now), target_doc, now=now)
    remote_durable_store = {}
    received_traces = []
    calls = 0

    async def send_func(host, port, ca_file, sent_envelope, **kwargs):
        nonlocal calls
        calls += 1
        received_traces.append(kwargs["relay_trace"])
        # Model the receiver's idempotent durable store keyed by origin + message id.
        key = (sent_envelope.origin_principal_id, sent_envelope.message_id)
        remote_durable_store.setdefault(key, sent_envelope.to_bytes())
        if calls == 1:
            raise asyncio.TimeoutError("receiver stored message but ACK was lost")
        return {"status": "STORED", "message_id": sent_envelope.message_id}

    worker = FederationOutboxWorker(outbox=outbox, identity_keys=relay,
        ca_file="unused-ca.pem", route_cache=cache,
        identity_documents={target.principal_id_text: target_doc},
        allowed_relays=frozenset({relay.principal_id_text}),
        send_func=send_func, worker_id="worker-lost-ack",
        base_retry_seconds=1)

    first = asyncio.run(worker.run_once(now=now))
    pending = outbox.get(envelope.origin_principal_id, envelope.message_id)
    assert first.claimed == 1 and first.retried == 1 and first.sent == 0
    assert len(remote_durable_store) == 1
    assert pending is not None and pending.status == "PENDING"
    outbox.close()

    outbox = FederationOutbox(db_path)
    worker.outbox = outbox
    second = asyncio.run(worker.run_once(now=now + 3))
    sent = outbox.get(envelope.origin_principal_id, envelope.message_id)
    assert second.claimed == 1 and second.sent == 1
    assert calls == 2
    assert len(remote_durable_store) == 1
    assert remote_durable_store[(envelope.origin_principal_id, envelope.message_id)] == envelope.to_bytes()
    assert received_traces[0] == received_traces[1]
    assert len(received_traces[0].receipts) == 1
    assert sent is not None and sent.status == "SENT" and sent.attempts == 2
    outbox.close()


def test_worker_crash_after_receipt_persist_reuses_receipt_after_restart(tmp_path):
    """Hard process death after trace persistence must not duplicate the receipt."""
    import multiprocessing
    from lmp_core.messaging.relay import RelayTrace

    now = int(time.time())
    origin = IdentityKeyPair.generate()
    relay = IdentityKeyPair.generate()
    target = IdentityKeyPair.generate()
    origin_doc = origin.create_initial_document(created_at=now)
    target_doc = target.create_initial_document(created_at=now)
    envelope = create_signed_envelope(
        origin, origin_doc, message_id="federation-crash-after-receipt",
        recipient="lmp:p:recipient", body="receipt must survive process death",
        ttl_seconds=600, now=now,
    )
    db_path = str(tmp_path / "crash-after-receipt.sqlite3")
    relay_key_path = str(tmp_path / "relay-key.json")
    target_key_path = str(tmp_path / "target-key.json")
    password = "test-only-password"
    relay.save_encrypted(relay_key_path, password)
    target.save_encrypted(target_key_path, password)

    outbox = FederationOutbox(db_path)
    outbox.enqueue(envelope_bytes=envelope.to_bytes(),
                   next_hop=target.principal_id_text, now=now)
    outbox.close()

    ctx = multiprocessing.get_context("spawn")
    child = ctx.Process(
        target=_worker_crash_after_receipt_child,
        args=(db_path, envelope.to_bytes(), relay_key_path, target_key_path, password, now),
    )
    child.start()
    child.join(timeout=20)
    if child.is_alive():
        child.terminate()
        child.join(timeout=5)
        raise AssertionError("crash-injection child did not exit")
    assert child.exitcode == 86, f"unexpected child exit code: {child.exitcode}"

    # The receipt must already be durable although no send attempt was recorded.
    reopened = FederationOutbox(db_path)
    stored = reopened.get(envelope.origin_principal_id, envelope.message_id)
    assert stored is not None and stored.status == "PENDING"
    assert stored.attempts == 0
    persisted_trace = RelayTrace.from_bytes(stored.relay_trace_bytes)
    assert len(persisted_trace.receipts) == 1
    assert persisted_trace.receipts[0].relay_principal_id == relay.principal_id_text
    persisted_trace_bytes = stored.relay_trace_bytes
    reopened.close()

    # Restart the worker after lease expiry. It must reuse the saved trace,
    # not append a second receipt, and only then perform a network send.
    cache = RouteCache()
    route = create_route_record(target, target_doc, "127.0.0.1", 7443,
                                ttl_seconds=300, now=now)
    cache.add(route, target_doc, now=now)
    sent_traces = []

    async def send_func(host, port, ca_file, sent_envelope, **kwargs):
        sent_traces.append(kwargs["relay_trace"])
        return {"status": "STORED", "message_id": sent_envelope.message_id}

    recovered_outbox = FederationOutbox(db_path)
    worker = FederationOutboxWorker(
        outbox=recovered_outbox, identity_keys=relay, ca_file="unused-ca.pem",
        route_cache=cache, identity_documents={target.principal_id_text: target_doc},
        allowed_relays=frozenset({relay.principal_id_text}),
        send_func=send_func, worker_id="recovered-worker", lease_seconds=10,
    )
    result = asyncio.run(worker.run_once(now=now + 61))
    final = recovered_outbox.get(envelope.origin_principal_id, envelope.message_id)
    assert result.claimed == 1 and result.sent == 1 and result.retried == 0
    assert len(sent_traces) == 1
    assert len(sent_traces[0].receipts) == 1
    assert sent_traces[0].to_bytes() == persisted_trace_bytes
    assert final is not None and final.status == "SENT"
    assert final.attempts == 1
    assert final.relay_trace_bytes == persisted_trace_bytes
    recovered_outbox.close()
