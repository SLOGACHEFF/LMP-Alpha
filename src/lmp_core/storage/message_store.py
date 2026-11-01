"""SQLite-backed durable inbox/outbox primitives for LMP messages.

This store persists accepted messages and suppresses duplicate submissions across
process restarts when a filesystem database path is configured. It does not
claim end-to-end delivery or exactly-once processing by a recipient.
"""
from __future__ import annotations

import base64
import json
import math
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any



class MessageConflictError(ValueError):
    """A sender reused a message ID for different content."""


@dataclass(frozen=True, slots=True)
class StoredMessage:
    message_id: str
    sender: str
    recipient: str
    body: Any
    created_at: float
    status: str
    attempts: int = 0
    available_at: float = 0.0
    expires_at: float | None = None


@dataclass(frozen=True, slots=True)
class DeliveryLease:
    """A time-limited claim on one message for a delivery worker."""
    message: StoredMessage
    worker_id: str
    lease_until: float


class SQLiteMessageStore:
    """Small transactional store with a stable duplicate key.

    Use a filesystem path for persistence across process restarts. ``:memory:``
    is useful for tests and ephemeral nodes. A single instance is thread-safe;
    SQLite transactions serialize writes from concurrent asyncio handlers.
    """

    def __init__(self, path: str = ":memory:") -> None:
        if not isinstance(path, str) or not path:
            raise ValueError("storage path must be a non-empty string")
        if path != ":memory:":
            expanded_path = str(Path(path).expanduser())
            Path(expanded_path).resolve().parent.mkdir(parents=True, exist_ok=True)
            path = expanded_path
        self.path = path
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, timeout=10, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.execute("PRAGMA foreign_keys = ON")
            self._db.execute("PRAGMA busy_timeout = 10000")
            if path != ":memory:":
                self._db.execute("PRAGMA journal_mode = WAL")
                self._db.execute("PRAGMA synchronous = FULL")
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS lmp_messages (
                    sender TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    body BLOB NOT NULL,
                    created_at REAL NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('STORED','DELIVERED','FAILED','EXPIRED')),
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                    available_at REAL NOT NULL DEFAULT 0,
                    expires_at REAL,
                    lease_owner TEXT,
                    lease_until REAL,
                    PRIMARY KEY(sender, message_id)
                );
                CREATE INDEX IF NOT EXISTS lmp_messages_recipient_status_time
                    ON lmp_messages(recipient, status, created_at);
            """)
            # Forward-compatible migration for databases created by alpha9 and earlier.
            columns = {row[1] for row in self._db.execute("PRAGMA table_info(lmp_messages)")}
            migrations = {
                "attempts": "ALTER TABLE lmp_messages ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0",
                "available_at": "ALTER TABLE lmp_messages ADD COLUMN available_at REAL NOT NULL DEFAULT 0",
                "expires_at": "ALTER TABLE lmp_messages ADD COLUMN expires_at REAL",
                "lease_owner": "ALTER TABLE lmp_messages ADD COLUMN lease_owner TEXT",
                "lease_until": "ALTER TABLE lmp_messages ADD COLUMN lease_until REAL",
            }
            for column, statement in migrations.items():
                if column not in columns:
                    self._db.execute(statement)
            schema_row = self._db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='lmp_messages'"
            ).fetchone()
            if schema_row and "'EXPIRED'" not in schema_row["sql"]:
                # Rebuild the old CHECK constraint so expiry state works on alpha9 DBs too.
                self._db.execute("DROP INDEX IF EXISTS lmp_messages_recipient_status_time")
                self._db.execute("DROP INDEX IF EXISTS lmp_messages_delivery_ready")
                self._db.execute("ALTER TABLE lmp_messages RENAME TO lmp_messages_legacy")
                self._db.execute("""CREATE TABLE lmp_messages (
                    sender TEXT NOT NULL, message_id TEXT NOT NULL, recipient TEXT NOT NULL,
                    body BLOB NOT NULL, created_at REAL NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('STORED','DELIVERED','FAILED','EXPIRED')),
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                    available_at REAL NOT NULL DEFAULT 0, expires_at REAL,
                    lease_owner TEXT, lease_until REAL, PRIMARY KEY(sender,message_id))""")
                self._db.execute("""INSERT INTO lmp_messages
                    (sender,message_id,recipient,body,created_at,status,attempts,available_at,expires_at,lease_owner,lease_until)
                    SELECT sender,message_id,recipient,body,created_at,status,attempts,available_at,expires_at,lease_owner,lease_until
                    FROM lmp_messages_legacy""")
                self._db.execute("DROP TABLE lmp_messages_legacy")
            self._db.execute("CREATE INDEX IF NOT EXISTS lmp_messages_recipient_status_time ON lmp_messages(recipient,status,created_at)")
            self._db.execute("CREATE INDEX IF NOT EXISTS lmp_messages_delivery_ready ON lmp_messages(recipient,status,available_at,lease_until)")
            self._db.commit()

    def store(self, *, sender: str, message_id: str, recipient: str, body: Any,
              ttl_seconds: float | None = None,
              expires_at: float | None = None) -> tuple[StoredMessage, bool]:
        """Persist a message atomically; return (record, was_duplicate).

        ``expires_at`` preserves an authoritative absolute expiry (for example,
        one covered by a signed envelope). Legacy callers may continue using
        ``ttl_seconds``; the two forms are mutually exclusive.
        """
        body_bytes = _encode_body(body)
        now = time.time()
        if ttl_seconds is not None and expires_at is not None:
            raise ValueError("ttl_seconds and expires_at are mutually exclusive")
        if ttl_seconds is not None and (isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)) or not math.isfinite(ttl_seconds) or ttl_seconds <= 0 or ttl_seconds > 365 * 24 * 3600):
            raise ValueError("ttl_seconds must be > 0 and <= 365 days")
        if expires_at is not None:
            if (isinstance(expires_at, bool) or not isinstance(expires_at, (int, float))
                    or not math.isfinite(expires_at) or expires_at <= now
                    or expires_at > now + 365 * 24 * 3600):
                raise ValueError("expires_at must be in the future and no more than 365 days away")
            expires_at = float(expires_at)
        else:
            expires_at = now + float(ttl_seconds) if ttl_seconds is not None else None
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                row = self._db.execute(
                    "SELECT sender, message_id, recipient, body, created_at, status, attempts, available_at, expires_at "
                    "FROM lmp_messages WHERE sender=? AND message_id=?",
                    (sender, message_id),
                ).fetchone()
                if row is not None:
                    if row["recipient"] != recipient or bytes(row["body"]) != body_bytes:
                        raise MessageConflictError("message ID already exists with different content")
                    self._db.commit()
                    return self._row_to_message(row), True
                self._db.execute(
                    "INSERT INTO lmp_messages(sender,message_id,recipient,body,created_at,status,available_at,expires_at) "
                    "VALUES(?,?,?,?,?,'STORED',?,?)",
                    (sender, message_id, recipient, body_bytes, now, now, expires_at),
                )
                self._db.commit()
                return StoredMessage(message_id, sender, recipient, body, now, "STORED", 0, now, expires_at), False
            except Exception:
                self._db.rollback()
                raise

    def pending_for(self, recipient: str, *, limit: int = 100) -> list[StoredMessage]:
        if not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._lock:
            rows = self._db.execute(
                "SELECT sender, message_id, recipient, body, created_at, status, attempts, available_at, expires_at "
                "FROM lmp_messages WHERE recipient=? AND status='STORED' AND (expires_at IS NULL OR expires_at>?) "
                "ORDER BY created_at, sender, message_id LIMIT ?",
                (recipient, time.time(), limit),
            ).fetchall()
        return [self._row_to_message(row) for row in rows]

    def claim_pending(self, recipient: str, *, worker_id: str, limit: int = 10,
                      lease_seconds: float = 30.0, now: float | None = None) -> list[DeliveryLease]:
        """Atomically lease ready messages to a worker; expired leases can be reclaimed.

        A lease is not proof of delivery. Workers must call ``mark_delivered`` after
        the recipient has acknowledged durable acceptance, or ``release_claim`` to
        schedule a retry.
        """
        if not isinstance(worker_id, str) or not 1 <= len(worker_id) <= 128:
            raise ValueError("worker_id must contain 1..128 characters")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, (int, float)) or not 1 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be between 1 and 3600")
        current = time.time() if now is None else float(now)
        lease_until = current + float(lease_seconds)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                rows = self._db.execute(
                    "SELECT sender,message_id,recipient,body,created_at,status,attempts,available_at,expires_at "
                    "FROM lmp_messages WHERE recipient=? AND status='STORED' AND available_at<=? "
                    "AND (expires_at IS NULL OR expires_at>?) AND (lease_until IS NULL OR lease_until<=?) "
                    "ORDER BY created_at,sender,message_id LIMIT ?",
                    (recipient, current, current, current, limit),
                ).fetchall()
                leases: list[DeliveryLease] = []
                for row in rows:
                    cursor = self._db.execute(
                        "UPDATE lmp_messages SET lease_owner=?,lease_until=?,attempts=attempts+1 "
                        "WHERE sender=? AND message_id=? AND status='STORED' "
                        "AND (lease_until IS NULL OR lease_until<=?)",
                        (worker_id, lease_until, row["sender"], row["message_id"], current),
                    )
                    if cursor.rowcount == 1:
                        message = self._row_to_message(row)
                        leases.append(DeliveryLease(
                            StoredMessage(message.message_id, message.sender, message.recipient,
                                          message.body, message.created_at, message.status,
                                          message.attempts + 1, message.available_at, message.expires_at),
                            worker_id, lease_until,
                        ))
                self._db.commit()
                return leases
            except Exception:
                self._db.rollback()
                raise

    def release_claim(self, *, sender: str, message_id: str, worker_id: str,
                      retry_after: float = 0.0, now: float | None = None) -> bool:
        """Release a worker's claim and schedule a retry after a bounded delay."""
        if isinstance(retry_after, bool) or not isinstance(retry_after, (int, float)) or not 0 <= retry_after <= 7 * 24 * 3600:
            raise ValueError("retry_after must be between 0 and 7 days")
        current = time.time() if now is None else float(now)
        with self._lock:
            cursor = self._db.execute(
                "UPDATE lmp_messages SET lease_owner=NULL,lease_until=NULL,available_at=? "
                "WHERE sender=? AND message_id=? AND status='STORED' AND lease_owner=? AND lease_until>?",
                (current + float(retry_after), sender, message_id, worker_id, current),
            )
            self._db.commit()
            return cursor.rowcount == 1

    def expire_messages(self, *, now: float | None = None, limit: int = 1000) -> int:
        """Mark expired stored messages as EXPIRED and clear any active leases."""
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 10000:
            raise ValueError("limit must be between 1 and 10000")
        current = time.time() if now is None else float(now)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                rows = self._db.execute(
                    "SELECT sender,message_id FROM lmp_messages WHERE status='STORED' "
                    "AND expires_at IS NOT NULL AND expires_at<=? LIMIT ?", (current, limit)
                ).fetchall()
                for row in rows:
                    self._db.execute(
                        "UPDATE lmp_messages SET status='EXPIRED',lease_owner=NULL,lease_until=NULL "
                        "WHERE sender=? AND message_id=? AND status='STORED'",
                        (row["sender"], row["message_id"]),
                    )
                self._db.commit()
                return len(rows)
            except Exception:
                self._db.rollback()
                raise

    def mark_delivered(self, *, sender: str, message_id: str, recipient: str,
                       worker_id: str | None = None) -> bool:
        """Mark a stored message delivered; return False if no eligible row exists."""
        with self._lock:
            if worker_id is None:
                cursor = self._db.execute(
                    "UPDATE lmp_messages SET status='DELIVERED',lease_owner=NULL,lease_until=NULL "
                    "WHERE sender=? AND message_id=? AND recipient=? AND status='STORED'",
                    (sender, message_id, recipient),
                )
            else:
                cursor = self._db.execute(
                    "UPDATE lmp_messages SET status='DELIVERED',lease_owner=NULL,lease_until=NULL "
                    "WHERE sender=? AND message_id=? AND recipient=? AND status='STORED' AND lease_owner=? AND lease_until>?",
                    (sender, message_id, recipient, worker_id, time.time()),
                )
            self._db.commit()
            return cursor.rowcount == 1

    def mark_failed(self, *, sender: str, message_id: str, recipient: str,
                    worker_id: str | None = None) -> bool:
        """Mark a message terminally failed, optionally requiring the active lease owner."""
        with self._lock:
            if worker_id is None:
                cursor = self._db.execute(
                    "UPDATE lmp_messages SET status='FAILED',lease_owner=NULL,lease_until=NULL "
                    "WHERE sender=? AND message_id=? AND recipient=? AND status='STORED'",
                    (sender, message_id, recipient),
                )
            else:
                cursor = self._db.execute(
                    "UPDATE lmp_messages SET status='FAILED',lease_owner=NULL,lease_until=NULL "
                    "WHERE sender=? AND message_id=? AND recipient=? AND status='STORED' "
                    "AND lease_owner=? AND lease_until>?",
                    (sender, message_id, recipient, worker_id, time.time()),
                )
            self._db.commit()
            return cursor.rowcount == 1

    def close(self) -> None:
        with self._lock:
            self._db.close()

    @staticmethod
    def _row_to_message(row: sqlite3.Row) -> StoredMessage:
        return StoredMessage(
            message_id=row["message_id"], sender=row["sender"],
            recipient=row["recipient"], body=_decode_body(bytes(row["body"])),
            created_at=float(row["created_at"]), status=row["status"],
            attempts=int(row["attempts"]), available_at=float(row["available_at"]),
            expires_at=float(row["expires_at"]) if row["expires_at"] is not None else None,
        )


def _pack(value: Any) -> Any:
    """Encode supported CBOR-like values into collision-free JSON tags."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return {"t": "v", "v": value}
    if isinstance(value, bytes):
        return {"t": "b", "v": base64.b64encode(value).decode("ascii")}
    if isinstance(value, list):
        return {"t": "l", "v": [_pack(item) for item in value]}
    if isinstance(value, dict):
        return {"t": "m", "v": [[_pack(key), _pack(item)] for key, item in value.items()]}
    raise TypeError(f"unsupported stored message body type: {type(value).__name__}")


def _unpack(value: Any) -> Any:
    if not isinstance(value, dict) or set(value) != {"t", "v"}:
        raise ValueError("invalid stored body encoding")
    tag, payload = value["t"], value["v"]
    if tag == "v" and (payload is None or isinstance(payload, (bool, int, float, str))):
        return payload
    if tag == "b" and isinstance(payload, str):
        return base64.b64decode(payload.encode("ascii"), validate=True)
    if tag == "l" and isinstance(payload, list):
        return [_unpack(item) for item in payload]
    if tag == "m" and isinstance(payload, list):
        result = {}
        for pair in payload:
            if not isinstance(pair, list) or len(pair) != 2:
                raise ValueError("invalid stored map entry")
            key, item = _unpack(pair[0]), _unpack(pair[1])
            if key in result:
                raise ValueError("duplicate key in stored map")
            result[key] = item
        return result
    raise ValueError("invalid stored body type tag")


def _encode_body(body: Any) -> bytes:
    return json.dumps(_pack(body), ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def _decode_body(data: bytes) -> Any:
    return _unpack(json.loads(data.decode("utf-8")))
