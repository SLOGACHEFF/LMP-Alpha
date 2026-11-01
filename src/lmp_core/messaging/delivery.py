"""Async delivery worker for the durable LMP message queue.

The sender callback must return True only after the remote LMP node has
acknowledged durable acceptance. This module does not implement network routing.
"""
from __future__ import annotations

import asyncio
import inspect
import math
import secrets
from dataclasses import dataclass
from typing import Awaitable, Callable

from ..storage.message_store import SQLiteMessageStore, StoredMessage

DeliveryCallback = Callable[[StoredMessage], bool | Awaitable[bool]]


@dataclass(frozen=True, slots=True)
class DeliveryBatchResult:
    claimed: int = 0
    delivered: int = 0
    retried: int = 0
    failed: int = 0
    lease_lost: int = 0


class DeliveryWorker:
    """Claim and deliver pending messages with bounded exponential backoff."""

    def __init__(
        self,
        store: SQLiteMessageStore,
        sender: DeliveryCallback,
        *,
        worker_id: str | None = None,
        lease_seconds: float = 60.0,
        max_attempts: int = 8,
        base_retry_seconds: float = 1.0,
        max_retry_seconds: float = 300.0,
        batch_size: int = 10,
    ) -> None:
        if not 1 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be between 1 and 3600")
        if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or not 1 <= max_attempts <= 100:
            raise ValueError("max_attempts must be between 1 and 100")
        if not math.isfinite(base_retry_seconds) or not 0.1 <= base_retry_seconds <= 86400:
            raise ValueError("base_retry_seconds must be between 0.1 and 86400")
        if not math.isfinite(max_retry_seconds) or not base_retry_seconds <= max_retry_seconds <= 604800:
            raise ValueError("max_retry_seconds must be >= base_retry_seconds and <= 7 days")
        if not isinstance(batch_size, int) or isinstance(batch_size, bool) or not 1 <= batch_size <= 100:
            raise ValueError("batch_size must be between 1 and 100")
        self.store = store
        self.sender = sender
        self.worker_id = worker_id or f"delivery-{secrets.token_hex(12)}"
        if not isinstance(self.worker_id, str) or not 1 <= len(self.worker_id) <= 128:
            raise ValueError("worker_id must contain 1..128 characters")
        self.lease_seconds = float(lease_seconds)
        self.max_attempts = max_attempts
        self.base_retry_seconds = float(base_retry_seconds)
        self.max_retry_seconds = float(max_retry_seconds)
        self.batch_size = batch_size

    async def run_once(self, recipient: str) -> DeliveryBatchResult:
        """Process one bounded batch for a recipient; safe to call repeatedly."""
        leases = self.store.claim_pending(
            recipient, worker_id=self.worker_id, limit=self.batch_size,
            lease_seconds=self.lease_seconds,
        )
        delivered = retried = failed = lease_lost = 0
        for lease in leases:
            message = lease.message
            try:
                outcome = self.sender(message)
                if inspect.isawaitable(outcome):
                    outcome = await asyncio.wait_for(outcome, timeout=self.lease_seconds * 0.8)
                accepted = outcome is True
            except Exception:
                accepted = False
            if accepted:
                ok = self.store.mark_delivered(
                    sender=message.sender, message_id=message.message_id,
                    recipient=message.recipient, worker_id=self.worker_id,
                )
                if ok:
                    delivered += 1
                else:
                    lease_lost += 1
                continue

            if message.attempts >= self.max_attempts:
                ok = self.store.mark_failed(
                    sender=message.sender, message_id=message.message_id,
                    recipient=message.recipient, worker_id=self.worker_id,
                )
                if ok:
                    failed += 1
                else:
                    lease_lost += 1
                continue

            delay = min(self.max_retry_seconds,
                        self.base_retry_seconds * (2 ** min(message.attempts - 1, 20)))
            # Small positive jitter prevents many failed messages retrying in lockstep.
            delay *= 0.8 + secrets.randbelow(401) / 1000.0
            ok = self.store.release_claim(
                sender=message.sender, message_id=message.message_id,
                worker_id=self.worker_id, retry_after=min(delay, self.max_retry_seconds),
            )
            if ok:
                retried += 1
            else:
                lease_lost += 1
        return DeliveryBatchResult(len(leases), delivered, retried, failed, lease_lost)
