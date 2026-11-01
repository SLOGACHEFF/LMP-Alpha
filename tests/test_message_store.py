from __future__ import annotations

import time
import pytest

from lmp_core.storage.message_store import MessageConflictError, SQLiteMessageStore


def test_store_persists_across_reopen(tmp_path):
    path = str(tmp_path / "messages.sqlite3")
    store = SQLiteMessageStore(path)
    record, duplicate = store.store(
        sender="lmp:p:sender", message_id="m-1", recipient="lmp:p:recipient",
        body={"text": "hello", "n": 1},
    )
    assert record.status == "STORED"
    assert duplicate is False
    store.close()

    reopened = SQLiteMessageStore(path)
    pending = reopened.pending_for("lmp:p:recipient")
    assert len(pending) == 1
    assert pending[0].message_id == "m-1"
    assert pending[0].body == {"text": "hello", "n": 1}
    assert pending[0].status == "STORED"
    reopened.close()


def test_exact_duplicate_is_idempotent(tmp_path):
    store = SQLiteMessageStore(str(tmp_path / "messages.sqlite3"))
    kwargs = dict(sender="sender", message_id="m-1", recipient="recipient", body="hello")
    first, duplicate1 = store.store(**kwargs)
    second, duplicate2 = store.store(**kwargs)
    assert duplicate1 is False
    assert duplicate2 is True
    assert first.created_at == second.created_at
    assert len(store.pending_for("recipient")) == 1
    store.close()


def test_reusing_message_id_for_different_content_is_rejected(tmp_path):
    store = SQLiteMessageStore(str(tmp_path / "messages.sqlite3"))
    store.store(sender="sender", message_id="m-1", recipient="recipient", body="hello")
    with pytest.raises(MessageConflictError):
        store.store(sender="sender", message_id="m-1", recipient="other", body="different")
    store.close()


def test_mark_delivered_removes_message_from_pending(tmp_path):
    store = SQLiteMessageStore(str(tmp_path / "messages.sqlite3"))
    store.store(sender="sender", message_id="m-1", recipient="recipient", body=b"binary")
    assert store.mark_delivered(sender="sender", message_id="m-1", recipient="recipient") is True
    assert store.mark_delivered(sender="sender", message_id="m-1", recipient="recipient") is False
    assert store.pending_for("recipient") == []
    store.close()


def test_pending_limit_is_bounded():
    store = SQLiteMessageStore()
    with pytest.raises(ValueError):
        store.pending_for("recipient", limit=1001)
    store.close()


def test_delivery_claim_is_exclusive_and_retryable():
    store = SQLiteMessageStore()
    store.store(sender="s", message_id="m", recipient="r", body="hello")
    now = time.time()
    first = store.claim_pending("r", worker_id="worker-a", now=now, lease_seconds=10)
    assert len(first) == 1
    assert first[0].message.attempts == 1
    assert store.claim_pending("r", worker_id="worker-b", now=now + 5) == []
    assert store.release_claim(sender="s", message_id="m", worker_id="worker-a", retry_after=5, now=now + 6)
    assert store.claim_pending("r", worker_id="worker-b", now=now + 10) == []
    second = store.claim_pending("r", worker_id="worker-b", now=now + 11)
    assert len(second) == 1
    assert second[0].message.attempts == 2
    assert store.mark_delivered(sender="s", message_id="m", recipient="r", worker_id="worker-a") is False
    assert store.mark_delivered(sender="s", message_id="m", recipient="r", worker_id="worker-b") is True
    store.close()


def test_expired_messages_are_not_claimed_and_can_be_marked_expired():
    store = SQLiteMessageStore()
    store.store(sender="s", message_id="m", recipient="r", body="short-lived", ttl_seconds=10)
    row = store.pending_for("r")[0]
    assert row.expires_at is not None
    assert store.claim_pending("r", worker_id="worker", now=row.expires_at + 1) == []
    assert store.expire_messages(now=row.expires_at + 1) == 1
    assert store.pending_for("r") == []
    store.close()


def test_delivery_lease_can_be_reclaimed_after_timeout():
    store = SQLiteMessageStore()
    store.store(sender="s", message_id="m", recipient="r", body="hello")
    now = time.time()
    first = store.claim_pending("r", worker_id="worker-a", now=now, lease_seconds=5)
    assert len(first) == 1
    second = store.claim_pending("r", worker_id="worker-b", now=now + 6, lease_seconds=5)
    assert len(second) == 1
    assert second[0].worker_id == "worker-b"
    assert store.release_claim(sender="s", message_id="m", worker_id="worker-a", now=now + 7) is False
    store.close()


def test_legacy_database_schema_is_migrated(tmp_path):
    import sqlite3

    path = str(tmp_path / "legacy.sqlite3")
    db = sqlite3.connect(path)
    db.execute("""CREATE TABLE lmp_messages (
        sender TEXT NOT NULL, message_id TEXT NOT NULL, recipient TEXT NOT NULL,
        body BLOB NOT NULL, created_at REAL NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('STORED','DELIVERED','FAILED')),
        PRIMARY KEY(sender,message_id))""")
    db.commit()
    db.close()

    store = SQLiteMessageStore(path)
    store.store(sender="s", message_id="m", recipient="r", body="works", ttl_seconds=5)
    assert store.expire_messages(now=time.time() + 10) == 1
    store.close()


def test_store_preserves_authoritative_absolute_expiry():
    store = SQLiteMessageStore()
    expiry = time.time() + 120.25
    message, duplicate = store.store(
        sender="signed-origin", message_id="absolute-expiry", recipient="r",
        body={"signed": True}, expires_at=expiry,
    )
    assert duplicate is False
    assert message.expires_at == expiry
    assert store.pending_for("r")[0].expires_at == expiry
    store.close()


def test_store_rejects_expiry_that_is_already_past_or_conflicts_with_ttl():
    store = SQLiteMessageStore()
    with pytest.raises(ValueError):
        store.store(sender="s", message_id="past-expiry", recipient="r", body="x",
                    expires_at=time.time() - 1)
    with pytest.raises(ValueError):
        store.store(sender="s", message_id="conflicting-expiry", recipient="r", body="x",
                    ttl_seconds=10, expires_at=time.time() + 10)
    store.close()
