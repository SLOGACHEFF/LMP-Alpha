"""Bounded in-memory duplicate suppression for the prototype."""
from __future__ import annotations
import time
from collections import OrderedDict


class DedupCache:
    """Bounded cache; volatile and not a durable exactly-once guarantee."""
    def __init__(self, capacity: int = 10_000, ttl_seconds: float = 24 * 3600) -> None:
        if capacity < 1:
            raise ValueError("dedup capacity must be positive")
        if ttl_seconds <= 0:
            raise ValueError("dedup TTL must be positive")
        self.capacity = capacity
        self.ttl_seconds = ttl_seconds
        self._items: OrderedDict[str, float] = OrderedDict()

    def seen_or_add(self, message_id: str) -> bool:
        now = time.monotonic()
        while self._items and next(iter(self._items.values())) < now - self.ttl_seconds:
            self._items.popitem(last=False)
        if message_id in self._items:
            self._items[message_id] = now
            self._items.move_to_end(message_id)
            return True
        self._items[message_id] = now
        while len(self._items) > self.capacity:
            self._items.popitem(last=False)
        return False
