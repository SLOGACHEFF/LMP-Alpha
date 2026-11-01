"""Shared message and delivery state models."""
from __future__ import annotations
from enum import Enum
from ..api import Message


class DeliveryStatus(str, Enum):
    CREATED = "CREATED"
    SUBMITTED = "SUBMITTED"
    ACCEPTED = "ACCEPTED"
    STORED = "STORED"
    DELIVERED = "DELIVERED"
    READ = "READ"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


__all__ = ["Message", "DeliveryStatus"]
