"""Platform-neutral primitives for the Windows broker named-pipe transport.

This module deliberately does not load Win32 APIs. The native adapter must own
OVERLAPPED/event lifetime and cancel/drain semantics; these helpers provide
bounded, deterministic byte-stream operations for that adapter.
"""
from __future__ import annotations

import math
import re
import secrets
import time
from collections.abc import Callable

PIPE_PREFIX = "\\\\.\\pipe\\"
_PIPE_BASENAME = re.compile(r"^broker-[0-9a-f]{64}$")
MAX_PIPE_NAME_LENGTH = 256


class PipeTransportError(OSError):
    """Base class for named-pipe transport failures."""


class PipeDeadlineExceeded(PipeTransportError, TimeoutError):
    """An absolute monotonic I/O deadline expired."""


class PipePeerClosed(PipeTransportError, EOFError):
    """The peer closed the byte stream before the requested bytes arrived."""


class PipeNoProgress(PipeTransportError):
    """An I/O callback completed without making forward progress."""


class Deadline:
    """An absolute deadline measured against a monotonic clock."""

    __slots__ = ("_expires_at", "_clock")

    def __init__(
        self,
        timeout: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise TypeError("timeout must be a finite non-negative number")
        if not math.isfinite(timeout) or timeout < 0:
            raise ValueError("timeout must be a finite non-negative number")
        self._clock = clock
        self._expires_at = clock() + float(timeout)

    @property
    def remaining(self) -> float:
        """Return remaining seconds, clamped to zero."""
        return max(0.0, self._expires_at - self._clock())

    @property
    def expired(self) -> bool:
        return self.remaining <= 0.0


def new_pipe_name(token_bytes: Callable[[int], bytes] = secrets.token_bytes) -> str:
    """Create a per-launch pipe name with 256 bits of cryptographic randomness."""
    token = token_bytes(32)
    if not isinstance(token, bytes) or len(token) != 32:
        raise ValueError("token source must return exactly 32 bytes")
    return PIPE_PREFIX + "broker-" + token.hex()


def validate_pipe_name(name: str) -> str:
    """Accept only this transport's canonical local named-pipe namespace."""
    if not isinstance(name, str):
        raise TypeError("pipe name must be a string")
    if len(name) > MAX_PIPE_NAME_LENGTH or not name.startswith(PIPE_PREFIX):
        raise ValueError("pipe name is outside the permitted local namespace")
    basename = name[len(PIPE_PREFIX):]
    if not _PIPE_BASENAME.fullmatch(basename):
        raise ValueError("pipe name must contain a canonical 256-bit broker token")
    return name


def read_exact(
    read_chunk: Callable[[int, float], bytes],
    length: int,
    deadline: Deadline,
) -> bytes:
    """Read exactly length bytes; callbacks receive size and remaining timeout."""
    if type(length) is not int or length < 0:
        raise ValueError("length must be a non-negative integer")
    chunks = bytearray()
    while len(chunks) < length:
        remaining = deadline.remaining
        if remaining <= 0.0:
            raise PipeDeadlineExceeded("named-pipe read deadline expired")
        try:
            chunk = read_chunk(length - len(chunks), remaining)
        except TimeoutError as exc:
            raise PipeDeadlineExceeded("named-pipe read deadline expired") from exc
        if not isinstance(chunk, bytes):
            raise TypeError("read callback must return bytes")
        if not chunk:
            raise PipePeerClosed(
                f"peer closed after {len(chunks)} of {length} requested bytes"
            )
        if len(chunk) > length - len(chunks):
            raise PipeTransportError("read callback returned more bytes than requested")
        chunks.extend(chunk)
    return bytes(chunks)


def write_all(
    write_chunk: Callable[[memoryview, float], int],
    data: bytes,
    deadline: Deadline,
) -> None:
    """Write all bytes, correctly handling short writes under one deadline."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        remaining = deadline.remaining
        if remaining <= 0.0:
            raise PipeDeadlineExceeded("named-pipe write deadline expired")
        try:
            written = write_chunk(view[offset:], remaining)
        except TimeoutError as exc:
            raise PipeDeadlineExceeded("named-pipe write deadline expired") from exc
        if type(written) is not int:
            raise TypeError("write callback must return an integer byte count")
        if written <= 0:
            raise PipeNoProgress("named-pipe write made no progress")
        if written > len(view) - offset:
            raise PipeTransportError("write callback reported more bytes than supplied")
        offset += written
