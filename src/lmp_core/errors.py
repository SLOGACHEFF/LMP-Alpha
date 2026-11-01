"""Common error taxonomy for the LMP Core prototype."""
from __future__ import annotations
from enum import Enum


class ErrorCode(str, Enum):
    INVALID_FRAME = "INVALID_FRAME"
    INVALID_PAYLOAD = "INVALID_PAYLOAD"
    PROTOCOL_MISMATCH = "PROTOCOL_MISMATCH"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    ROUTE_UNAVAILABLE = "ROUTE_UNAVAILABLE"
    DELIVERY_FAILED = "DELIVERY_FAILED"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class LMPError(Exception):
    """Base class for protocol-level errors safe to classify in callers."""
    code = ErrorCode.INTERNAL_ERROR


class AuthenticationError(LMPError):
    code = ErrorCode.AUTHENTICATION_FAILED


class AuthorizationError(LMPError):
    code = ErrorCode.AUTHORIZATION_DENIED


class ResourceLimitError(LMPError):
    code = ErrorCode.RESOURCE_LIMIT
