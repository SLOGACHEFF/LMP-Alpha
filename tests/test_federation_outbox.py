from __future__ import annotations

import pytest

from lmp_core.federation.outbox import FederationOutbox
from lmp_core.messaging.envelope import create_signed_envelope
from lmp_core.messaging.relay import RelayTrace
from lmp_core.security.identity import IdentityKeyPair

NOW = 1_800_000_000


def make_envelope(message_id="msg-outbox-1"):
    keys = IdentityKeyPair.generate()
    document = keys.create_initial_document()
    envelope = create_signed_envelope(keys, document, message_id=message_id,
        recipient="lmp:p:recipient", body={"text": "keep original signature"},
        ttl_seconds=600, now=NOW)
    return envelope


def test_outbox_preserves_exact_signed_bytes_across_restart(tmp_path):
    path = str(tmp_path / "outbox.sqlite3")
    envelope = make_envelope()
    original = envelope.to_bytes()
    store = FederationOutbox(path)
    item, duplicate = store.enqueue(envelope_bytes=original, next_hop="lmp:p:node-b",
                                    now=NOW)
    assert duplicate is False
    assert item.envelope_bytes == original
    store.close()

    reopened = FederationOutbox(path)
    recovered = reopened.get(envelope.origin_principal_id, envelope.message_id)
    assert recovered is not None
    assert recovered.envelope_bytes == original
    assert recovered.relay_trace_bytes == RelayTrace().to_bytes()
    reopened.close()


def test_outbox_duplicate_enqueue_is_idempotent_and_conflicts_are_rejected():
    store = FederationOutbox()
    envelope = make_envelope()
    first, duplicate = store.enqueue(envelope_bytes=envelope.to_bytes(), next_hop="lmp:p:b", now=NOW)
    second, duplicate_again = store.enqueue(envelope_bytes=envelope.to_bytes(), next_hop="lmp:p:c", now=NOW + 1)
    assert not duplicate and duplicate_again
    # Existing queue target is not silently rewritten by duplicate enqueue.
    assert second.next_hop == "lmp:p:b"
    # A modified envelope is rejected before it can enter the queue.
    from dataclasses import replace
    altered = replace(envelope, recipient="lmp:p:attacker")
    with pytest.raises(Exception):
        store.enqueue(envelope_bytes=altered.to_bytes(), next_hop="lmp:p:b", now=NOW)
    store.close()


def test_claim_lease_retry_and_ack_are_worker_scoped():
    store = FederationOutbox()
    envelope = make_envelope()
    store.enqueue(envelope_bytes=envelope.to_bytes(), next_hop="lmp:p:b", now=NOW)
    claimed = store.claim(worker_id="worker-a", now=NOW, lease_seconds=10)
    assert len(claimed) == 1
    assert claimed[0].attempts == 0
    assert claimed[0].claims == 1
    assert store.claim(worker_id="worker-b", now=NOW + 5) == []
    assert not store.acknowledge(origin_principal_id=envelope.origin_principal_id,
                                 message_id=envelope.message_id, worker_id="worker-b", lease_token="wrong-token")
    assert store.retry(origin_principal_id=envelope.origin_principal_id,
                       message_id=envelope.message_id, worker_id="worker-a", lease_token=claimed[0].lease_token,
                       delay_seconds=5, now=NOW)
    assert store.claim(worker_id="worker-b", now=NOW + 4) == []
    reclaimed = store.claim(worker_id="worker-b", now=NOW + 6)
    assert len(reclaimed) == 1
    assert reclaimed[0].attempts == 0
    assert reclaimed[0].claims == 2
    assert store.acknowledge(origin_principal_id=envelope.origin_principal_id,
                             message_id=envelope.message_id, worker_id="worker-b", lease_token=reclaimed[0].lease_token)
    assert store.get(envelope.origin_principal_id, envelope.message_id).status == "SENT"
    store.close()


def test_outbox_rejects_noncanonical_envelope_and_trace():
    store = FederationOutbox()
    envelope = make_envelope()
    with pytest.raises(Exception):
        store.enqueue(envelope_bytes=envelope.to_bytes() + b" ", next_hop="lmp:p:b", now=NOW)
    with pytest.raises(Exception):
        store.enqueue(envelope_bytes=envelope.to_bytes(), next_hop="lmp:p:b",
                      relay_trace_bytes=b"{}", now=NOW)
    store.close()


def test_stale_lease_token_cannot_ack_after_reclaim_even_with_same_worker_id():
    store = FederationOutbox()
    envelope = make_envelope("msg-fencing-token")
    store.enqueue(envelope_bytes=envelope.to_bytes(), next_hop="lmp:p:b", now=NOW)
    old = store.claim(worker_id="worker-same", now=NOW, lease_seconds=10)[0]
    new = store.claim(worker_id="worker-same", now=NOW + 11, lease_seconds=10)[0]
    assert old.lease_token and new.lease_token and old.lease_token != new.lease_token
    assert not store.acknowledge(origin_principal_id=envelope.origin_principal_id,
        message_id=envelope.message_id, worker_id="worker-same", lease_token=old.lease_token)
    assert store.acknowledge(origin_principal_id=envelope.origin_principal_id,
        message_id=envelope.message_id, worker_id="worker-same", lease_token=new.lease_token)
    store.close()


def test_claim_does_not_duplicate_rows_when_same_worker_claims_twice():
    store = FederationOutbox()
    one = make_envelope("msg-claim-one")
    two = make_envelope("msg-claim-two")
    store.enqueue(envelope_bytes=one.to_bytes(), next_hop="lmp:p:b", now=NOW)
    store.enqueue(envelope_bytes=two.to_bytes(), next_hop="lmp:p:b", now=NOW)
    first = store.claim(worker_id="worker-repeat", now=NOW, lease_seconds=30, limit=1)
    second = store.claim(worker_id="worker-repeat", now=NOW, lease_seconds=30, limit=1)
    assert len(first) == len(second) == 1
    assert first[0].message_id != second[0].message_id
    store.close()


def test_legacy_outbox_schema_is_migrated_with_lease_token(tmp_path):
    import sqlite3
    path = str(tmp_path / "legacy-outbox.sqlite3")
    db = sqlite3.connect(path)
    db.execute("""CREATE TABLE lmp_federation_outbox (
        origin_principal_id TEXT NOT NULL, message_id TEXT NOT NULL,
        recipient TEXT NOT NULL, next_hop TEXT NOT NULL, envelope_bytes BLOB NOT NULL,
        relay_trace_bytes BLOB NOT NULL, created_at REAL NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0, available_at REAL NOT NULL,
        status TEXT NOT NULL, lease_owner TEXT, lease_until REAL,
        PRIMARY KEY(origin_principal_id, message_id))""")
    db.commit()
    db.close()
    store = FederationOutbox(path)
    columns = {row[1] for row in store._db.execute("PRAGMA table_info(lmp_federation_outbox)")}
    assert "lease_token" in columns
    store.close()


def test_two_outbox_instances_cannot_claim_same_item_concurrently(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    path = str(tmp_path / "shared-outbox.sqlite3")
    store_a = FederationOutbox(path)
    envelope = make_envelope("msg-concurrent-claim")
    store_a.enqueue(envelope_bytes=envelope.to_bytes(), next_hop="lmp:p:b", now=NOW)
    store_b = FederationOutbox(path)
    with ThreadPoolExecutor(max_workers=2) as pool:
        future_a = pool.submit(store_a.claim, worker_id="worker-a", now=NOW, lease_seconds=20)
        future_b = pool.submit(store_b.claim, worker_id="worker-b", now=NOW, lease_seconds=20)
        claimed_a = future_a.result()
        claimed_b = future_b.result()
    assert len(claimed_a) + len(claimed_b) == 1
    store_a.close()
    store_b.close()


def test_claimed_item_recovers_after_process_restart_and_lease_expiry(tmp_path):
    """A worker crash must not lose a durable item; stale ownership must be fenced."""
    path = str(tmp_path / "crash-recovery.sqlite3")
    envelope = make_envelope("msg-crash-recovery")
    original_bytes = envelope.to_bytes()

    first_process = FederationOutbox(path)
    first_process.enqueue(envelope_bytes=original_bytes, next_hop="lmp:p:node-b", now=NOW)
    abandoned = first_process.claim(worker_id="worker-before-crash", now=NOW, lease_seconds=10)[0]
    assert abandoned.lease_token is not None
    first_process.close()  # Simulate process termination without retry/ack.

    second_process = FederationOutbox(path)
    # The lease remains in durable storage until it expires; no early double claim.
    assert second_process.claim(worker_id="worker-after-restart", now=NOW + 9,
                                lease_seconds=10) == []
    recovered = second_process.claim(worker_id="worker-after-restart", now=NOW + 10,
                                     lease_seconds=10)
    assert len(recovered) == 1
    current = recovered[0]
    assert current.envelope_bytes == original_bytes
    assert current.attempts == 0
    assert current.claims == 2
    assert current.lease_token and current.lease_token != abandoned.lease_token

    # A late completion from the crashed worker cannot mark the item as sent.
    assert not second_process.acknowledge(
        origin_principal_id=envelope.origin_principal_id,
        message_id=envelope.message_id,
        worker_id="worker-before-crash",
        lease_token=abandoned.lease_token,
    )
    assert second_process.get(envelope.origin_principal_id, envelope.message_id).status == "PENDING"

    assert second_process.acknowledge(
        origin_principal_id=envelope.origin_principal_id,
        message_id=envelope.message_id,
        worker_id="worker-after-restart",
        lease_token=current.lease_token,
    )
    assert second_process.get(envelope.origin_principal_id, envelope.message_id).status == "SENT"
    second_process.close()


def test_enqueue_rolls_back_completely_if_route_history_write_fails(tmp_path):
    """An injected SQLite failure must not leave an outbox row without its route history."""
    import sqlite3

    path = str(tmp_path / "enqueue-atomicity.sqlite3")
    store = FederationOutbox(path)
    envelope = make_envelope("msg-enqueue-atomicity")
    store._db.execute("""
        CREATE TRIGGER fail_route_history_insert
        BEFORE INSERT ON lmp_federation_route_attempts
        BEGIN
            SELECT RAISE(ABORT, 'injected route-history storage failure');
        END
    """)
    store._db.commit()

    with pytest.raises(sqlite3.IntegrityError, match="injected route-history storage failure"):
        store.enqueue(envelope_bytes=envelope.to_bytes(), next_hop="lmp:p:node-b", now=NOW)

    assert store.get(envelope.origin_principal_id, envelope.message_id) is None
    assert not store.route_was_tried(
        origin_principal_id=envelope.origin_principal_id,
        message_id=envelope.message_id,
        next_hop="lmp:p:node-b",
    )
    store.close()



def _claim_in_child_process(db_path, worker_id, ready_event, result_queue):
    """Child-process helper for SQLite cross-process claim fencing."""
    store = FederationOutbox(db_path)
    ready_event.wait(timeout=10)
    try:
        claimed = store.claim(worker_id=worker_id, now=NOW, lease_seconds=30)
        result_queue.put((worker_id, [item.message_id for item in claimed], None))
    except Exception as exc:
        result_queue.put((worker_id, [], repr(exc)))
    finally:
        store.close()


def test_independent_processes_cannot_claim_same_item(tmp_path):
    """SQLite BEGIN IMMEDIATE must fence claims across OS processes, not just threads."""
    import multiprocessing

    path = str(tmp_path / "multiprocess-outbox.sqlite3")
    envelope = make_envelope("msg-multiprocess-claim")
    store = FederationOutbox(path)
    store.enqueue(envelope_bytes=envelope.to_bytes(), next_hop="lmp:p:node-b", now=NOW)
    store.close()

    ctx = multiprocessing.get_context("spawn")
    ready = ctx.Event()
    results = ctx.Queue()
    processes = [
        ctx.Process(target=_claim_in_child_process,
                    args=(path, "process-worker-a", ready, results)),
        ctx.Process(target=_claim_in_child_process,
                    args=(path, "process-worker-b", ready, results)),
    ]
    for process in processes:
        process.start()
    ready.set()
    observations = [results.get(timeout=15) for _ in processes]
    for process in processes:
        process.join(timeout=15)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
        assert process.exitcode == 0

    assert all(error is None for _, _, error in observations), observations
    claimed_ids = [message_id for _, ids, _ in observations for message_id in ids]
    assert claimed_ids == [envelope.message_id]
    reopened = FederationOutbox(path)
    stored = reopened.get(envelope.origin_principal_id, envelope.message_id)
    assert stored is not None and stored.claims == 1
    reopened.close()



def _claim_then_block_in_child_process(db_path, worker_id, claimed_queue, hold_event):
    """Claim a durable outbox lease, report it, then block until the parent kills us."""
    store = FederationOutbox(db_path)
    try:
        claimed = store.claim(worker_id=worker_id, now=NOW, lease_seconds=5)
        claimed_queue.put([
            {
                "origin_principal_id": item.origin_principal_id,
                "message_id": item.message_id,
                "envelope_bytes": item.envelope_bytes.hex(),
                "lease_token": item.lease_token,
                "claims": item.claims,
            }
            for item in claimed
        ])
        # Deliberately do not close the SQLite connection gracefully. The parent
        # terminates this process after observing the committed claim.
        hold_event.wait(timeout=60)
    finally:
        # On the tested crash path this finally block is not run: terminate()
        # simulates abrupt process death rather than a clean worker shutdown.
        store.close()


def test_hard_process_kill_recovers_durable_claim_after_lease_expiry(tmp_path):
    """A real OS process kill must leave a durable, reclaimable and fenced lease."""
    import multiprocessing

    path = str(tmp_path / "hard-process-kill.sqlite3")
    envelope = make_envelope("msg-hard-process-kill")
    original_bytes = envelope.to_bytes()

    seed = FederationOutbox(path)
    seed.enqueue(envelope_bytes=original_bytes, next_hop="lmp:p:node-b", now=NOW)
    seed.close()

    ctx = multiprocessing.get_context("spawn")
    claimed_queue = ctx.Queue()
    hold_event = ctx.Event()
    child = ctx.Process(
        target=_claim_then_block_in_child_process,
        args=(path, "worker-killed-by-os", claimed_queue, hold_event),
    )
    child.start()
    try:
        claimed_rows = claimed_queue.get(timeout=20)
        assert len(claimed_rows) == 1, claimed_rows
        crashed_claim = claimed_rows[0]
        assert crashed_claim["message_id"] == envelope.message_id
        assert crashed_claim["envelope_bytes"] == original_bytes.hex()
        assert crashed_claim["lease_token"]
        assert child.is_alive()
        child.terminate()
        child.join(timeout=10)
        assert not child.is_alive()
        assert child.exitcode is not None and child.exitcode != 0
    finally:
        if child.is_alive():
            child.terminate()
            child.join(timeout=5)
        claimed_queue.close()
        claimed_queue.join_thread()

    reopened = FederationOutbox(path)
    try:
        durable = reopened.get(envelope.origin_principal_id, envelope.message_id)
        assert durable is not None
        assert durable.envelope_bytes == original_bytes
        assert durable.status == "PENDING"
        assert durable.claims == 1
        assert durable.lease_token == crashed_claim["lease_token"]

        # The committed lease prevents immediate duplicate work.
        assert reopened.claim(
            worker_id="worker-recovery", now=NOW + 4, lease_seconds=5
        ) == []

        recovered = reopened.claim(
            worker_id="worker-recovery", now=NOW + 5, lease_seconds=5
        )
        assert len(recovered) == 1
        current = recovered[0]
        assert current.envelope_bytes == original_bytes
        assert current.claims == 2
        assert current.lease_token
        assert current.lease_token != crashed_claim["lease_token"]

        # The dead process's lease token cannot complete the recovered row.
        assert not reopened.acknowledge(
            origin_principal_id=envelope.origin_principal_id,
            message_id=envelope.message_id,
            worker_id="worker-killed-by-os",
            lease_token=crashed_claim["lease_token"],
        )
        still_pending = reopened.get(envelope.origin_principal_id, envelope.message_id)
        assert still_pending is not None and still_pending.status == "PENDING"

        assert reopened.acknowledge(
            origin_principal_id=envelope.origin_principal_id,
            message_id=envelope.message_id,
            worker_id="worker-recovery",
            lease_token=current.lease_token,
        )
        completed = reopened.get(envelope.origin_principal_id, envelope.message_id)
        assert completed is not None and completed.status == "SENT"
    finally:
        reopened.close()

def test_ack_storage_failure_does_not_mark_message_sent(tmp_path):
    """An injected SQLite failure leaves the durable item pending and recoverable."""
    import sqlite3

    path = str(tmp_path / "ack-failure.sqlite3")
    envelope = make_envelope("msg-ack-storage-failure")
    store = FederationOutbox(path)
    store.enqueue(envelope_bytes=envelope.to_bytes(), next_hop="lmp:p:node-b", now=NOW)
    claim = store.claim(worker_id="ack-worker", now=NOW, lease_seconds=30)[0]

    store._db.execute("""
        CREATE TRIGGER fail_sent_update
        BEFORE UPDATE OF status ON lmp_federation_outbox
        WHEN NEW.status = 'SENT'
        BEGIN
            SELECT RAISE(ABORT, 'injected ack storage failure');
        END
    """)
    store._db.commit()
    with pytest.raises(sqlite3.IntegrityError, match="injected ack storage failure"):
        store.acknowledge(
            origin_principal_id=envelope.origin_principal_id,
            message_id=envelope.message_id,
            worker_id="ack-worker",
            lease_token=claim.lease_token,
        )

    still_pending = store.get(envelope.origin_principal_id, envelope.message_id)
    assert still_pending is not None and still_pending.status == "PENDING"
    assert still_pending.lease_token == claim.lease_token

    store._db.execute("DROP TRIGGER fail_sent_update")
    store._db.commit()
    assert store.acknowledge(
        origin_principal_id=envelope.origin_principal_id,
        message_id=envelope.message_id,
        worker_id="ack-worker",
        lease_token=claim.lease_token,
    )
    assert store.get(envelope.origin_principal_id, envelope.message_id).status == "SENT"
    store.close()
