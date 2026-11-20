"""Lazy ctypes bindings and guarded overlapped-operation lifetimes.

Importing this module is safe on non-Windows hosts. Native DLL loading is
explicit; the lifecycle object is callback-driven so its state machine can be
tested without pretending that mocked tests exercise the Windows kernel.
"""
from __future__ import annotations

import ctypes
import os
import threading
from dataclasses import dataclass
from typing import Any, Callable


# Fixed-width Win32 scalar types (POSIX c_ulong is commonly 64-bit).
DWORD = ctypes.c_uint32
BOOL = ctypes.c_int32
HANDLE = ctypes.c_void_p
ULONG_PTR = ctypes.c_size_t
LPVOID = ctypes.c_void_p
LPCWSTR = ctypes.c_wchar_p

ERROR_IO_PENDING = 997
ERROR_IO_INCOMPLETE = 996
ERROR_NOT_FOUND = 1168
ERROR_OPERATION_ABORTED = 995
ERROR_PIPE_CONNECTED = 535
MAX_DWORD = 0xFFFFFFFF
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
INFINITE = 0xFFFFFFFF


class _OffsetUnion(ctypes.Union):
    _fields_ = [("_offset", DWORD * 2), ("_pointer", LPVOID)]


class OVERLAPPED(ctypes.Structure):
    """Native OVERLAPPED layout with pointer-sized internal fields."""

    _anonymous_ = ("_offset_union",)
    _fields_ = [
        ("Internal", ULONG_PTR),
        ("InternalHigh", ULONG_PTR),
        ("_offset_union", _OffsetUnion),
        ("hEvent", HANDLE),
    ]


class Win32ApiUnavailable(RuntimeError):
    """Raised when native Windows APIs cannot be loaded."""


class OverlappedLifecycleError(RuntimeError):
    """Raised when an operation is used outside its valid lifecycle."""


class OverlappedStillPending(OverlappedLifecycleError):
    """Raised when a drain attempt has not established completion."""


@dataclass(frozen=True)
class OverlappedResult:
    succeeded: bool
    bytes_transferred: int
    error_code: int
    cancel_error: int | None


@dataclass(frozen=True)
class Kernel32Bindings:
    """Typed function references from kernel32.dll."""

    library: Any
    CreateEventW: Any
    CloseHandle: Any
    WaitForSingleObject: Any
    CancelIoEx: Any
    GetOverlappedResult: Any
    GetOverlappedResultEx: Any
    ReadFile: Any
    WriteFile: Any
    ConnectNamedPipe: Any
    SetEvent: Any


def _set_signature(function: Any, argtypes: list[Any], restype: Any) -> Any:
    function.argtypes = argtypes
    function.restype = restype
    return function


def load_kernel32(*, loader: Any = None) -> Kernel32Bindings:
    """Load and type-check required APIs; callable injection is for unit tests."""
    if os.name != "nt":
        raise Win32ApiUnavailable("the Windows broker transport requires Windows")
    load_library = loader or ctypes.WinDLL
    try:
        library = load_library("kernel32", use_last_error=True)
        create_event = _set_signature(
            library.CreateEventW, [LPVOID, BOOL, BOOL, LPCWSTR], HANDLE
        )
        close_handle = _set_signature(library.CloseHandle, [HANDLE], BOOL)
        wait = _set_signature(library.WaitForSingleObject, [HANDLE, DWORD], DWORD)
        cancel = _set_signature(
            library.CancelIoEx, [HANDLE, ctypes.POINTER(OVERLAPPED)], BOOL
        )
        get_result = _set_signature(
            library.GetOverlappedResult,
            [HANDLE, ctypes.POINTER(OVERLAPPED), ctypes.POINTER(DWORD), BOOL],
            BOOL,
        )
        read_file = _set_signature(library.ReadFile, [HANDLE, LPVOID, DWORD, ctypes.POINTER(DWORD), ctypes.POINTER(OVERLAPPED)], BOOL)
        write_file = _set_signature(library.WriteFile, [HANDLE, LPVOID, DWORD, ctypes.POINTER(DWORD), ctypes.POINTER(OVERLAPPED)], BOOL)
        connect_named_pipe = _set_signature(library.ConnectNamedPipe, [HANDLE, ctypes.POINTER(OVERLAPPED)], BOOL)
        set_event = _set_signature(library.SetEvent, [HANDLE], BOOL)
        get_result_ex = _set_signature(
            library.GetOverlappedResultEx,
            [
                HANDLE,
                ctypes.POINTER(OVERLAPPED),
                ctypes.POINTER(DWORD),
                DWORD,
                BOOL,
            ],
            BOOL,
        )
    except (AttributeError, OSError) as exc:
        raise Win32ApiUnavailable(
            "kernel32 is missing a required overlapped-I/O API"
        ) from exc
    return Kernel32Bindings(
        library, create_event, close_handle, wait, cancel, get_result, get_result_ex, read_file, write_file, connect_named_pipe, set_event
    )


def last_error() -> int:
    """Return the calling thread's Win32 last-error value."""
    getter = getattr(ctypes, "get_last_error", None)
    if getter is None:
        raise Win32ApiUnavailable("Win32 last-error state is unavailable")
    return int(getter())


def create_manual_reset_event(
    bindings: Kernel32Bindings, *, get_last_error: Callable[[], int] = last_error
) -> tuple[Any, int | None]:
    """Create a non-inheritable, initially nonsignaled manual-reset event."""
    handle = bindings.CreateEventW(None, BOOL(1), BOOL(0), None)
    if not handle:
        return None, int(get_last_error())
    return handle, None


def close_kernel_handle(
    bindings: Kernel32Bindings, handle: Any,
    *, get_last_error: Callable[[], int] = last_error,
) -> tuple[bool, int | None]:
    """Close a kernel handle and capture GetLastError immediately on failure."""
    succeeded = bool(bindings.CloseHandle(handle))
    return (True, None) if succeeded else (False, int(get_last_error()))


def cancel_exact_io(
    bindings: Kernel32Bindings, file_handle: Any, overlapped: OVERLAPPED,
    *, get_last_error: Callable[[], int] = last_error,
) -> tuple[bool, int | None]:
    """Request cancellation for exactly one OVERLAPPED operation."""
    succeeded = bool(bindings.CancelIoEx(file_handle, ctypes.byref(overlapped)))
    return (True, None) if succeeded else (False, int(get_last_error()))


def get_overlapped_result_wait(
    bindings: Kernel32Bindings, file_handle: Any, overlapped: OVERLAPPED,
    wait: bool = True, *, get_last_error: Callable[[], int] = last_error,
) -> tuple[bool, int, int | None]:
    """Read completion status; optionally block until the I/O is terminal."""
    transferred = DWORD(0)
    succeeded = bool(bindings.GetOverlappedResult(
        file_handle, ctypes.byref(overlapped), ctypes.byref(transferred),
        BOOL(1 if wait else 0),
    ))
    error = None if succeeded else int(get_last_error())
    return succeeded, int(transferred.value), error


def start_overlapped_connect(bindings: Kernel32Bindings, operation: "OverlappedOperation", *, get_last_error: Callable[[], int] = last_error) -> tuple[str, int | None]:
    """Start ConnectNamedPipe and normalize the already-connected race."""
    if operation.state != operation.CREATED:
        raise OverlappedLifecycleError(f"cannot start connect in state {operation.state}")
    if not operation.event_handle:
        raise ValueError("overlapped connect requires an event handle")
    operation.overlapped.hEvent = operation.event_handle
    succeeded = bool(bindings.ConnectNamedPipe(operation.file_handle, ctypes.byref(operation.overlapped)))
    if succeeded:
        operation.mark_completed()
        return "connected", None
    error = int(get_last_error())
    if error == ERROR_IO_PENDING:
        operation.mark_pending()
        return "pending", None
    if error == ERROR_PIPE_CONNECTED:
        # A client connected after pipe creation but before this call.
        signaled = bool(bindings.SetEvent(operation.event_handle))
        signal_error = None if signaled else int(get_last_error())
        operation.mark_completed()
        return "connected", signal_error
    operation.mark_completed()
    return "failed", error


def start_overlapped_io(bindings: Kernel32Bindings, operation: "OverlappedOperation", *, buffer: Any, length: int, write: bool = False, get_last_error: Callable[[], int] = last_error) -> tuple[str, int, int | None]:
    """Start one overlapped ReadFile/WriteFile using operation-owned memory."""
    if operation.state != operation.CREATED:
        raise OverlappedLifecycleError(f"cannot start operation in state {operation.state}")
    if length < 0 or length > MAX_DWORD:
        raise ValueError("I/O length must fit an unsigned Win32 DWORD")
    if buffer is not operation.buffer:
        raise ValueError("I/O buffer must be owned by the operation")
    if length and buffer is None:
        raise ValueError("non-empty I/O requires a live buffer")
    try:
        pointer = ctypes.cast(buffer, LPVOID) if buffer is not None else None
    except (TypeError, ctypes.ArgumentError) as exc:
        raise TypeError("buffer must expose a ctypes-compatible address") from exc
    transferred = DWORD(0)
    function = bindings.WriteFile if write else bindings.ReadFile
    succeeded = bool(function(operation.file_handle, pointer, DWORD(length), ctypes.byref(transferred), ctypes.byref(operation.overlapped)))
    if succeeded:
        operation.mark_completed()
        return "completed", int(transferred.value), None
    error = int(get_last_error())
    if error == ERROR_IO_PENDING:
        operation.mark_pending()
        return "pending", int(transferred.value), error
    operation.mark_completed()
    return "failed", int(transferred.value), error


class OverlappedOperation:
    """Own one event, OVERLAPPED object and buffer until I/O is truly complete.

    Callbacks return (success, error_code) for CancelIoEx and
    (success, bytes_transferred, error_code) for GetOverlappedResult. The latter
    must be invoked with wait=True so a terminal result is obtained before the
    operation releases any memory. ERROR_NOT_FOUND from cancellation is treated
    as a completion race, never as proof that the OVERLAPPED can be freed.
    """

    CREATED = "created"
    PENDING = "pending"
    COMPLETED = "completed"
    CLOSED = "closed"

    def __init__(
        self,
        *,
        file_handle: Any,
        overlapped: OVERLAPPED,
        event_handle: Any,
        buffer: Any,
        close_handle: Callable[[Any], bool],
    ) -> None:
        if not callable(close_handle):
            raise TypeError("close_handle must be callable")
        self.file_handle = file_handle
        self.overlapped = overlapped
        self.event_handle = event_handle
        self.buffer = buffer
        self._close_handle = close_handle
        self._state = self.CREATED
        self._lock = threading.RLock()

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    def mark_pending(self) -> None:
        with self._lock:
            if self._state != self.CREATED:
                raise OverlappedLifecycleError(
                    f"cannot start operation in state {self._state}"
                )
            self._state = self.PENDING

    def mark_completed(self) -> None:
        """Record completion observed by the normal (non-cancellation) path."""
        with self._lock:
            if self._state != self.PENDING:
                raise OverlappedLifecycleError(
                    f"cannot complete operation in state {self._state}"
                )
            self._state = self.COMPLETED

    def cancel_and_drain(
        self,
        *,
        cancel_io_ex: Callable[[Any, OVERLAPPED], tuple[bool, int]],
        get_overlapped_result: Callable[
            [Any, OVERLAPPED, bool], tuple[bool, int, int]
        ],
    ) -> OverlappedResult:
        """Request targeted cancellation, then wait for a terminal I/O result."""
        with self._lock:
            if self._state != self.PENDING:
                raise OverlappedLifecycleError(
                    f"cannot cancel operation in state {self._state}"
                )

            cancel_ok, cancel_error = cancel_io_ex(
                self.file_handle, self.overlapped
            )
            # Always drain, including ERROR_NOT_FOUND: completion may have won
            # the race with cancellation. The callbacks must capture last-error
            # immediately on the calling thread.
            result_ok, transferred, result_error = get_overlapped_result(
                self.file_handle, self.overlapped, True
            )
            if not result_ok and result_error in (
                ERROR_IO_INCOMPLETE,
                ERROR_IO_PENDING,
            ):
                raise OverlappedStillPending(
                    "GetOverlappedResult did not establish terminal completion"
                )

            self._state = self.COMPLETED
            return OverlappedResult(
                succeeded=bool(result_ok),
                bytes_transferred=int(transferred),
                error_code=int(result_error),
                cancel_error=None if cancel_ok else int(cancel_error),
            )

    def close(self) -> None:
        """Close the event exactly once, but only after I/O is no longer pending."""
        with self._lock:
            if self._state == self.CLOSED:
                return
            if self._state == self.PENDING:
                raise OverlappedLifecycleError(
                    "cannot release OVERLAPPED resources while I/O is pending"
                )
            if self.event_handle:
                if not self._close_handle(self.event_handle):
                    raise OSError("CloseHandle failed for overlapped event")
            self.event_handle = None
            self.buffer = None
            self.overlapped = None
            self.file_handle = None
            self._state = self.CLOSED
