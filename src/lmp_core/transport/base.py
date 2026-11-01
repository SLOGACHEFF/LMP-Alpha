"""Transport contracts. Concrete adapters must preserve framing boundaries logically."""
from __future__ import annotations
from typing import Protocol, runtime_checkable


@runtime_checkable
class ByteConnection(Protocol):
    async def readexactly(self, n: int) -> bytes: ...
    async def write(self, data: bytes) -> None: ...
    async def close(self) -> None: ...


@runtime_checkable
class Listener(Protocol):
    async def close(self) -> None: ...
