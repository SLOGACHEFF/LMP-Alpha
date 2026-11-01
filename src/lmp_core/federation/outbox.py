"""Durable outbox for immutable origin-signed federation envelopes.

The outbox stores the exact signed envelope bytes separately from the mutable
relay trace. It deliberately does not perform routing or network I/O.
"""
from __future__ import annotations

import sqlite3
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from ..messaging.envelope import SignedMessageEnvelope, verify_signed_envelope
from ..messaging.relay import RelayTrace


@dataclass(frozen=True, slots=True)
class FederationOutboxItem:
    origin_principal_id: str
    message_id: str
    recipient: str
    next_hop: str
    envelope_bytes: bytes
    relay_trace_bytes: bytes
    created_at: float
    attempts: int
    available_at: float
    status: str
    lease_owner: str | None = None
    lease_until: float | None = None
    lease_token: str | None = None
    claims: int = 0


class FederationOutbox:
    """SQLite-backed, restart-safe queue for forwarding signed envelopes."""

    def __init__(self, path: str = ":memory:") -> None:
        if not isinstance(path, str) or not path:
            raise ValueError("storage path must be a non-empty string")
        if path != ":memory:":
            path = str(Path(path).expanduser())
            Path(path).resolve().parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, timeout=10, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.execute("PRAGMA busy_timeout=10000")
            if path != ":memory:":
                self._db.execute("PRAGMA journal_mode=WAL")
                self._db.execute("PRAGMA synchronous=FULL")
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS lmp_federation_outbox (
                    origin_principal_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    next_hop TEXT NOT NULL,
                    envelope_bytes BLOB NOT NULL,
                    relay_trace_bytes BLOB NOT NULL,
                    created_at REAL NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                    claims INTEGER NOT NULL DEFAULT 0 CHECK(claims >= 0),
                    available_at REAL NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('PENDING','SENT','FAILED','EXPIRED')),
                    lease_owner TEXT,
                    lease_until REAL,
                    lease_token TEXT,
                    PRIMARY KEY(origin_principal_id, message_id)
                );
                CREATE INDEX IF NOT EXISTS lmp_federation_outbox_ready
                    ON lmp_federation_outbox(status, available_at, lease_until);
                CREATE TABLE IF NOT EXISTS lmp_federation_route_attempts (
                    origin_principal_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    next_hop TEXT NOT NULL,
                    attempted_at REAL NOT NULL,
                    PRIMARY KEY(origin_principal_id, message_id, next_hop),
                    FOREIGN KEY(origin_principal_id, message_id)
                      REFERENCES lmp_federation_outbox(origin_principal_id, message_id)
                      ON DELETE CASCADE
                );
            """)
            # Forward-compatible migration for databases created by alpha17-alpha19.
            columns = {row[1] for row in self._db.execute("PRAGMA table_info(lmp_federation_outbox)")}
            if "lease_token" not in columns:
                self._db.execute("ALTER TABLE lmp_federation_outbox ADD COLUMN lease_token TEXT")
            if "claims" not in columns:
                self._db.execute("ALTER TABLE lmp_federation_outbox ADD COLUMN claims INTEGER NOT NULL DEFAULT 0 CHECK(claims >= 0)")
            # Seed the currently configured hop for rows created before route-history
            # tracking existed, so failover cannot immediately cycle back to it.
            self._db.execute("""INSERT OR IGNORE INTO lmp_federation_route_attempts
                (origin_principal_id,message_id,next_hop,attempted_at)
                SELECT origin_principal_id,message_id,next_hop,created_at FROM lmp_federation_outbox""")
            self._db.commit()

    def enqueue(self, *, envelope_bytes: bytes, next_hop: str,
                relay_trace_bytes: bytes | None = None, now: float | None = None) -> tuple[FederationOutboxItem, bool]:
        """Validate and persist the exact origin-signed bytes; duplicate inserts are idempotent."""
        if not isinstance(envelope_bytes, bytes) or not envelope_bytes:
            raise ValueError("envelope_bytes must be non-empty bytes")
        if not isinstance(next_hop, str) or not next_hop:
            raise ValueError("next_hop must be a non-empty string")
        envelope = SignedMessageEnvelope.from_bytes(envelope_bytes)
        verify_signed_envelope(envelope, now=int(time.time() if now is None else now))
        trace_raw = RelayTrace().to_bytes() if relay_trace_bytes is None else relay_trace_bytes
        trace = RelayTrace.from_bytes(trace_raw)
        if not isinstance(relay_trace_bytes, (bytes, type(None))):
            raise ValueError("relay_trace_bytes must be bytes")
        if trace.to_bytes() != trace_raw:
            raise ValueError("relay trace must be canonical")
        current = time.time() if now is None else float(now)
        item = FederationOutboxItem(envelope.origin_principal_id, envelope.message_id,
            envelope.recipient, next_hop, envelope_bytes, trace_raw, current, 0, current, "PENDING")
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                row = self._db.execute("SELECT * FROM lmp_federation_outbox WHERE origin_principal_id=? AND message_id=?",
                    (item.origin_principal_id, item.message_id)).fetchone()
                if row is not None:
                    if (bytes(row['envelope_bytes']) != envelope_bytes or row['recipient'] != envelope.recipient):
                        raise ValueError("message ID conflicts with previously queued envelope")
                    self._db.commit()
                    return self._row(row), True
                self._db.execute("""INSERT INTO lmp_federation_outbox
                    (origin_principal_id,message_id,recipient,next_hop,envelope_bytes,relay_trace_bytes,created_at,available_at,status)
                    VALUES(?,?,?,?,?,?,?,?, 'PENDING')""", (item.origin_principal_id,item.message_id,item.recipient,
                    next_hop,envelope_bytes,trace_raw,current,current))
                self._db.execute("""INSERT INTO lmp_federation_route_attempts
                    (origin_principal_id,message_id,next_hop,attempted_at) VALUES(?,?,?,?)""",
                    (item.origin_principal_id, item.message_id, next_hop, current))
                self._db.commit()
                return item, False
            except Exception:
                self._db.rollback()
                raise

    def claim(self, *, worker_id: str, limit: int = 10, lease_seconds: float = 60,
              now: float | None = None) -> list[FederationOutboxItem]:
        if not isinstance(worker_id, str) or not 1 <= len(worker_id) <= 128:
            raise ValueError("worker_id must contain 1..128 characters")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, (int,float)) or not 1 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be between 1 and 3600")
        current = time.time() if now is None else float(now)
        claimed: list[FederationOutboxItem] = []
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                rows = self._db.execute("""SELECT * FROM lmp_federation_outbox WHERE status='PENDING'
                    AND available_at<=? AND (lease_until IS NULL OR lease_until<=?)
                    ORDER BY created_at,origin_principal_id,message_id LIMIT ?""", (current,current,limit)).fetchall()
                for row in rows:
                    token = secrets.token_urlsafe(24)
                    cur = self._db.execute("""UPDATE lmp_federation_outbox
                        SET lease_owner=?,lease_until=?,lease_token=?,claims=claims+1
                        WHERE origin_principal_id=? AND message_id=? AND status='PENDING'
                          AND (lease_until IS NULL OR lease_until<=?)""",
                        (worker_id,current+lease_seconds,token,row['origin_principal_id'],row['message_id'],current))
                    if cur.rowcount == 1:
                        updated = self._db.execute("SELECT * FROM lmp_federation_outbox WHERE origin_principal_id=? AND message_id=?",
                            (row['origin_principal_id'],row['message_id'])).fetchone()
                        claimed.append(self._row(updated))
                self._db.commit()
                return claimed
            except Exception:
                self._db.rollback()
                raise

    def record_attempt(self, *, origin_principal_id: str, message_id: str, worker_id: str,
                       lease_token: str, now: float | None = None) -> bool:
        """Count a network-send attempt only while this worker owns a live lease."""
        current = time.time() if now is None else float(now)
        with self._lock:
            cur = self._db.execute("""UPDATE lmp_federation_outbox SET attempts=attempts+1
                WHERE origin_principal_id=? AND message_id=? AND status='PENDING'
                  AND lease_owner=? AND lease_token=? AND lease_until>?""",
                (origin_principal_id, message_id, worker_id, lease_token, current))
            self._db.commit()
            return cur.rowcount == 1

    def update_next_hop(self, *, origin_principal_id: str, message_id: str, worker_id: str,
                        lease_token: str, next_hop: str, now: float | None = None) -> bool:
        """Change next hop once per message, fenced by the current lease.

        A next hop already tried for this message is rejected to prevent route
        selector oscillation (A -> B -> A -> B) across retry cycles.
        """
        if not isinstance(next_hop, str) or not next_hop or len(next_hop) > 256:
            raise ValueError("next_hop must contain 1..256 characters")
        current = time.time() if now is None else float(now)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                owned = self._db.execute("""SELECT 1 FROM lmp_federation_outbox
                    WHERE origin_principal_id=? AND message_id=? AND status='PENDING'
                      AND lease_owner=? AND lease_token=? AND lease_until>?""",
                    (origin_principal_id, message_id, worker_id, lease_token, current)).fetchone()
                if owned is None:
                    self._db.rollback()
                    return False
                tried = self._db.execute("""SELECT 1 FROM lmp_federation_route_attempts
                    WHERE origin_principal_id=? AND message_id=? AND next_hop=?""",
                    (origin_principal_id, message_id, next_hop)).fetchone()
                if tried is not None:
                    self._db.rollback()
                    return False
                cur = self._db.execute("""UPDATE lmp_federation_outbox SET next_hop=?
                    WHERE origin_principal_id=? AND message_id=? AND status='PENDING'
                      AND lease_owner=? AND lease_token=? AND lease_until>?""",
                    (next_hop, origin_principal_id, message_id, worker_id, lease_token, current))
                if cur.rowcount != 1:
                    self._db.rollback()
                    return False
                self._db.execute("""INSERT INTO lmp_federation_route_attempts
                    (origin_principal_id,message_id,next_hop,attempted_at) VALUES(?,?,?,?)""",
                    (origin_principal_id, message_id, next_hop, current))
                self._db.commit()
                return True
            except Exception:
                self._db.rollback()
                raise

    def route_was_tried(self, *, origin_principal_id: str, message_id: str, next_hop: str) -> bool:
        """Return whether a next hop has already been selected for this message."""
        with self._lock:
            row = self._db.execute("""SELECT 1 FROM lmp_federation_route_attempts
                WHERE origin_principal_id=? AND message_id=? AND next_hop=?""",
                (origin_principal_id, message_id, next_hop)).fetchone()
            return row is not None

    def update_trace(self, *, origin_principal_id: str, message_id: str, worker_id: str,
                     lease_token: str, relay_trace_bytes: bytes) -> bool:
        trace = RelayTrace.from_bytes(relay_trace_bytes)
        if trace.to_bytes() != relay_trace_bytes:
            raise ValueError("relay trace must be canonical")
        with self._lock:
            cur = self._db.execute("""UPDATE lmp_federation_outbox SET relay_trace_bytes=?
                WHERE origin_principal_id=? AND message_id=? AND status='PENDING'
                  AND lease_owner=? AND lease_token=? AND lease_until>?""",
                (relay_trace_bytes,origin_principal_id,message_id,worker_id,lease_token,time.time()))
            self._db.commit()
            return cur.rowcount == 1

    def acknowledge(self, *, origin_principal_id: str, message_id: str, worker_id: str,
                    lease_token: str) -> bool:
        with self._lock:
            cur = self._db.execute("""UPDATE lmp_federation_outbox
                SET status='SENT',lease_owner=NULL,lease_until=NULL,lease_token=NULL
                WHERE origin_principal_id=? AND message_id=? AND status='PENDING'
                  AND lease_owner=? AND lease_token=? AND lease_until>?""",
                (origin_principal_id,message_id,worker_id,lease_token,time.time()))
            self._db.commit()
            return cur.rowcount == 1

    def retry(self, *, origin_principal_id: str, message_id: str, worker_id: str,
              lease_token: str, delay_seconds: float, now: float | None = None) -> bool:
        if isinstance(delay_seconds, bool) or not isinstance(delay_seconds, (int,float)) or not 0 <= delay_seconds <= 604800:
            raise ValueError("delay_seconds must be between 0 and 7 days")
        current = time.time() if now is None else float(now)
        with self._lock:
            cur = self._db.execute("""UPDATE lmp_federation_outbox
                SET available_at=?,lease_owner=NULL,lease_until=NULL,lease_token=NULL
                WHERE origin_principal_id=? AND message_id=? AND status='PENDING'
                  AND lease_owner=? AND lease_token=? AND lease_until>?""",
                (current+delay_seconds,origin_principal_id,message_id,worker_id,lease_token,current))
            self._db.commit()
            return cur.rowcount == 1

    def expire(self, *, origin_principal_id: str, message_id: str, worker_id: str,
               lease_token: str, now: float | None = None) -> bool:
        """Mark an expired envelope EXPIRED while the caller still owns its lease."""
        current = time.time() if now is None else float(now)
        with self._lock:
            cur = self._db.execute("""UPDATE lmp_federation_outbox
                SET status='EXPIRED',lease_owner=NULL,lease_until=NULL,lease_token=NULL
                WHERE origin_principal_id=? AND message_id=? AND status='PENDING'
                  AND lease_owner=? AND lease_token=? AND lease_until>?""",
                (origin_principal_id,message_id,worker_id,lease_token,current))
            self._db.commit()
            return cur.rowcount == 1

    def fail(self, *, origin_principal_id: str, message_id: str, worker_id: str,
             lease_token: str) -> bool:
        """Move a claimed item to FAILED only while its fencing token is current."""
        with self._lock:
            cur = self._db.execute("""UPDATE lmp_federation_outbox
                SET status='FAILED',lease_owner=NULL,lease_until=NULL,lease_token=NULL
                WHERE origin_principal_id=? AND message_id=? AND status='PENDING'
                  AND lease_owner=? AND lease_token=? AND lease_until>?""",
                (origin_principal_id,message_id,worker_id,lease_token,time.time()))
            self._db.commit()
            return cur.rowcount == 1

    def get(self, origin_principal_id: str, message_id: str) -> FederationOutboxItem | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM lmp_federation_outbox WHERE origin_principal_id=? AND message_id=?",
                (origin_principal_id,message_id)).fetchone()
            return None if row is None else self._row(row)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    @staticmethod
    def _row(row: sqlite3.Row) -> FederationOutboxItem:
        return FederationOutboxItem(row['origin_principal_id'],row['message_id'],row['recipient'],row['next_hop'],
            bytes(row['envelope_bytes']),bytes(row['relay_trace_bytes']),row['created_at'],row['attempts'],
            row['available_at'],row['status'],row['lease_owner'],row['lease_until'],row['lease_token'],row['claims'])
