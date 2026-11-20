"""Bounded byte-stream adapter for the Windows broker named-pipe transport.

This module deliberately contains no Win32 bindings. A small backend owns the
native HANDLE/OVERLAPPED/event details; this layer enforces deadlines, partial
I/O semantics, cancellation draining, and Python stream behavior on every OS.
"""
from __future__ import annotations

import math
import threading
import time
from typing import Any, Protocol

MAX_PIPE_IO_BYTES = 1024 * 1024 + 4


class TransportError(OSError):
    """The broker transport could not complete an operation."""


class TransportTimeout(TimeoutError):
    """A bounded broker transport operation exceeded its deadline."""


class TransportCancelled(TransportError):
    """A broker transport operation was cancelled by its owner."""


class TransportCleanupError(TransportError):
    """A pending native operation could not be proven complete and released."""


class OverlappedBackend(Protocol):
    """Native adapter contract.

    start returns (token, count). count is an integer for an operation
    completed inline, or None when it is pending. The backend must keep the
    OVERLAPPED structure, event, and buffer alive through close. wait returns
    true only when the event is signaled. complete obtains the final result
    after a signaled event. cancel requests cancellation for this exact token.
    drain must not return until the operation is no longer pending (including
    an aborted completion); only then may close release native storage.

    The Win32 implementation must translate ERROR_PIPE_CONNECTED for connect
    into an inline successful completion, and treat ERROR_IO_PENDING as
    pending rather than as failure.
    """

    def start(self, operation: str, handle: Any, buffer: bytearray | bytes) -> tuple[Any, int | None]:
        ...

    def wait(
        self, token: Any, timeout_ms: int, cancel_event: threading.Event | None
    ) -> bool:
        ...

    def complete(self, token: Any) -> int:
        ...

    def cancel(self, token: Any) -> None:
        ...

    def drain(self, token: Any) -> None:
        ...

    def close(self, token: Any) -> None:
        ...


def _deadline(timeout: float, clock: Any) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("timeout must be a finite positive number of seconds")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be a finite positive number of seconds")
    return clock() + float(timeout)


def _remaining_ms(deadline: float, clock: Any) -> int:
    remaining = deadline - clock()
    if remaining <= 0:
        return 0
    return max(1, math.ceil(remaining * 1000))


class OverlappedIO:
    """Run bounded native operations and drain every cancelled OVERLAPPED."""

    def __init__(self, backend: OverlappedBackend, *, clock: Any = time.monotonic):
        self._backend = backend
        self._clock = clock

    def perform(
        self,
        operation: str,
        handle: Any,
        buffer: bytearray | bytes,
        *,
        timeout: float,
        cancel_event: threading.Event | None = None,
    ) -> int:
        if operation not in {"connect", "read", "write"}:
            raise ValueError("operation must be connect, read, or write")
        if operation == "read" and not isinstance(buffer, bytearray):
            raise TypeError("read operations require a mutable bytearray")
        if operation == "write" and not isinstance(buffer, bytes):
            raise TypeError("write operations require immutable bytes")
        deadline = _deadline(timeout, self._clock)
        token, count = self._backend.start(operation, handle, buffer)
        if count is not None:
            try:
                return self._validate_count(count, len(buffer), operation)
            finally:
                self._backend.close(token)

        safe_to_close = False
        cancellation_attempted = False
        try:
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    cancellation_attempted = True
                    self._cancel_and_drain(token)
                    safe_to_close = True
                    raise TransportCancelled(f"{operation} operation was cancelled")
                remaining = _remaining_ms(deadline, self._clock)
                if remaining == 0:
                    cancellation_attempted = True
                    self._cancel_and_drain(token)
                    safe_to_close = True
                    raise TransportTimeout(f"{operation} operation timed out")
                if self._backend.wait(token, remaining, cancel_event):
                    safe_to_close = True
                    return self._validate_count(
                        self._backend.complete(token), len(buffer), operation
                    )
                # A false wait can mean either the deadline elapsed or the
                # cancellation event won the native wait race. Re-check both
                # conditions at the top of the loop before deciding.
        except (TransportCancelled, TransportTimeout):
            raise
        except BaseException:
            if not safe_to_close and not cancellation_attempted:
                cancellation_attempted = True
                self._cancel_and_drain(token)
                safe_to_close = True
            raise
        finally:
            if safe_to_close:
                self._backend.close(token)

    def connect(
        self,
        handle: Any,
        *,
        timeout: float,
        cancel_event: threading.Event | None = None,
    ) -> None:
        """Wait for ConnectNamedPipe; the backend handles ERROR_PIPE_CONNECTED."""
        self.perform(
            "connect", handle, b"", timeout=timeout, cancel_event=cancel_event
        )

    def _cancel_and_drain(self, token: Any) -> None:
        try:
            self._backend.cancel(token)
        except BaseException:
            # Cancellation can race with natural completion (for example,
            # ERROR_NOT_FOUND). A successful drain is the authoritative proof
            # that native storage is no longer in use.
            pass
        try:
            self._backend.drain(token)
        except BaseException as exc:
            raise TransportCleanupError(
                "could not drain cancelled overlapped operation; native storage retained"
            ) from exc

    @staticmethod
    def _validate_count(count: Any, capacity: int, operation: str) -> int:
        if type(count) is not int or count < 0 or count > capacity:
            raise TransportError(
                f"backend returned invalid {operation} byte count {count!r}"
            )
        if operation in {"read", "write"} and capacity and count == 0:
            raise TransportError(f"{operation} completed without making progress")
        return count


class NamedPipeByteStream:
    """File-like byte stream over one authenticated named-pipe handle.

    The caller must authenticate the peer PID before constructing this object.
    Each individual native operation has its own finite timeout. Higher-level
    framing code remains responsible for exact reads and complete writes.
    """

    def __init__(
        self,
        io: OverlappedIO,
        handle: Any,
        *,
        timeout: float = 5.0,
        cancel_event: threading.Event | None = None,
        close_handle: Any | None = None,
    ):
        _deadline(timeout, time.monotonic)
        if handle is None:
            raise ValueError("pipe handle must not be None")
        self._io = io
        self._handle = handle
        self._timeout = float(timeout)
        self._cancel_event = cancel_event
        self._close_handle = close_handle
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def _ensure_open(self) -> None:
        if self._closed:
            raise ValueError("I/O operation on closed named-pipe stream")

    def read(self, size: int = -1) -> bytes:
        self._ensure_open()
        if type(size) is not int or size < 0:
            raise ValueError("read size must be a non-negative integer")
        if size > MAX_PIPE_IO_BYTES:
            raise ValueError("read size exceeds the bounded pipe I/O limit")
        if size == 0:
            return b""
        buffer = bytearray(size)
        count = self._io.perform(
            "read", self._handle, buffer,
            timeout=self._timeout, cancel_event=self._cancel_event,
        )
        return bytes(buffer[:count])

    def write(self, data: bytes | bytearray | memoryview) -> int:
        self._ensure_open()
        raw = bytes(data)
        if len(raw) > MAX_PIPE_IO_BYTES:
            raise ValueError("write size exceeds the bounded pipe I/O limit")
        if not raw:
            return 0
        return self._io.perform(
            "write", self._handle, raw,
            timeout=self._timeout, cancel_event=self._cancel_event,
        )

    def flush(self) -> None:
        self._ensure_open()

    def close(self) -> None:
        if self._closed:
            return
        if self._close_handle is not None:
            self._close_handle(self._handle)
        self._closed = True

    def __enter__(self) -> "NamedPipeByteStream":
        self._ensure_open()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()
