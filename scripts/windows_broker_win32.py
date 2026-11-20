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
    ReadFile: Any = None
    WriteFile: Any = None
    ConnectNamedPipe: Any = None
    SetEvent: Any = None
    DisconnectNamedPipe: Any = None


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
        disconnect_named_pipe = _set_signature(library.DisconnectNamedPipe, [HANDLE], BOOL)
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
        library, create_event, close_handle, wait, cancel, get_result, get_result_ex, read_file, write_file, connect_named_pipe, set_event, disconnect_named_pipe
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


def get_overlapped_result_ex_wait(
    bindings: Kernel32Bindings, file_handle: Any, overlapped: OVERLAPPED,
    timeout_ms: int, *, get_last_error: Callable[[], int] = last_error,
) -> tuple[bool, int, int | None]:
    """Read completion status with a finite timeout and no alertable wait."""
    if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool):
        raise TypeError("timeout_ms must be an integer")
    if timeout_ms < 0 or timeout_ms >= INFINITE:
        raise ValueError("timeout_ms must be a finite unsigned Win32 timeout")
    transferred = DWORD(0)
    succeeded = bool(bindings.GetOverlappedResultEx(
        file_handle, ctypes.byref(overlapped), ctypes.byref(transferred),
        DWORD(timeout_ms), BOOL(0),
    ))
    error = None if succeeded else int(get_last_error())
    return succeeded, int(transferred.value), error


class NamedPipeConnection:
    """Track server-side connection state independently from one I/O operation."""

    CONNECTED = "connected"
    CONNECTING = "connecting"
    DISCONNECTED = "disconnected"
    CLOSING = "closing"
    CLOSED = "closed"

    def __init__(self, file_handle: Any) -> None:
        if not file_handle:
            raise ValueError("a live named-pipe handle is required")
        self.file_handle = file_handle
        self._state = self.CONNECTED
        self._lock = threading.RLock()
        self._operations: set[Any] = set()
        self._connect_operation: Any | None = None

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    def register_operation(self, operation: "OverlappedOperation") -> None:
        """Register every I/O operation issued against this pipe instance."""
        # Lock order is connection -> operation throughout this class.
        # Keep the state check and registry insertion atomic with respect to
        # operation.close(), which takes only the operation lock.
        with self._lock, operation._lock:
            if self._state != self.CONNECTED:
                raise OverlappedLifecycleError(
                    "cannot register I/O on a disconnected pipe"
                )
            if self._connect_operation is not None:
                raise OverlappedLifecycleError(
                    "connect operation resources must be closed and unregistered before I/O"
                )
            if operation.file_handle != self.file_handle:
                raise OverlappedLifecycleError(
                    "operation handle does not belong to this pipe connection"
                )
            if operation._state == operation.CLOSED:
                raise OverlappedLifecycleError(
                    "cannot register a closed I/O operation"
                )
            self._operations.add(operation)

    def start_operation(
        self,
        bindings: "Kernel32Bindings",
        operation: "OverlappedOperation",
        *,
        buffer: Any,
        length: int,
        write: bool = False,
        get_last_error: Callable[[], int] = last_error,
    ) -> tuple[str, int, int | None]:
        """Submit registered I/O while excluding concurrent disconnect/reuse.

        The connection lock remains held through the native ReadFile/WriteFile
        submission. This makes registration, submission, and disconnect one
        serialized lifecycle; callers must not submit registered operations
        through the low-level start_overlapped_io helper directly.
        """
        with self._lock:
            if self._state != self.CONNECTED:
                raise OverlappedLifecycleError(
                    "cannot submit I/O on a disconnected pipe"
                )
            if self._connect_operation is not None:
                raise OverlappedLifecycleError(
                    "connect operation resources must be closed and unregistered before I/O"
                )
            if operation not in self._operations:
                raise OverlappedLifecycleError(
                    "operation must be registered before I/O submission"
                )
            if operation.file_handle != self.file_handle:
                raise OverlappedLifecycleError(
                    "operation handle does not belong to this pipe connection"
                )
            if operation.state != operation.CREATED:
                raise OverlappedLifecycleError(
                    f"cannot submit operation in state {operation.state}"
                )
            return start_overlapped_io(
                bindings,
                operation,
                buffer=buffer,
                length=length,
                write=write,
                get_last_error=get_last_error,
            )

    def unregister_operation(self, operation: "OverlappedOperation") -> None:
        """Forget an operation only after its OVERLAPPED resources are closed."""
        with self._lock:
            if operation not in self._operations:
                raise OverlappedLifecycleError("operation is not registered")
            if operation.state != operation.CLOSED:
                raise OverlappedLifecycleError(
                    "operation resources must be closed before unregistering"
                )
            self._operations.remove(operation)
            if operation is self._connect_operation:
                self._connect_operation = None

    def start_connect(
        self,
        bindings: "Kernel32Bindings",
        operation: "OverlappedOperation",
        *,
        get_last_error: Callable[[], int] = last_error,
    ) -> tuple[str, int | None]:
        """Start a new overlapped connection as one serialized lifecycle step.

        The connect operation is registered before the native call and remains
        registered until its event/buffer/OVERLAPPED resources are closed.
        A pending connect must be finalized with complete_connect after its
        operation reaches COMPLETED.
        """
        with self._lock, operation._lock:
            if self._state != self.DISCONNECTED:
                raise OverlappedLifecycleError(
                    f"cannot start pipe connect in state {self._state}"
                )
            if self._operations:
                raise OverlappedLifecycleError(
                    "cannot connect while previous operation resources remain registered"
                )
            if operation.file_handle != self.file_handle:
                raise OverlappedLifecycleError(
                    "connect operation handle does not belong to this pipe"
                )
            if operation.state != operation.CREATED:
                raise OverlappedLifecycleError(
                    f"cannot start connect in operation state {operation.state}"
                )
            self._operations.add(operation)
            self._connect_operation = operation
            self._state = self.CONNECTING
            try:
                result, error = start_overlapped_connect(
                    bindings, operation, get_last_error=get_last_error
                )
            except BaseException:
                # Validation failures before STARTING cannot have reached the
                # kernel, so roll back registration and permit a safe retry.
                # Once submission starts, retain both state and resources until
                # the uncertain kernel operation has been drained.
                if operation.state == operation.CREATED:
                    self._operations.discard(operation)
                    self._connect_operation = None
                    self._state = self.DISCONNECTED
                raise
            if result == "connected":
                self._state = self.CONNECTED
            elif result == "failed":
                self._state = self.DISCONNECTED
            return result, error

    def complete_connect(
        self, operation: "OverlappedOperation", *, connected: bool
    ) -> None:
        """Commit a pending ConnectNamedPipe result after I/O completion."""
        if type(connected) is not bool:
            raise TypeError("connected must be a bool")
        with self._lock:
            if self._state != self.CONNECTING:
                raise OverlappedLifecycleError(
                    f"cannot complete pipe connect in state {self._state}"
                )
            if operation not in self._operations:
                raise OverlappedLifecycleError(
                    "connect operation is not registered with this pipe"
                )
            if operation.file_handle != self.file_handle:
                raise OverlappedLifecycleError(
                    "connect operation handle does not belong to this pipe"
                )
            if operation.state != operation.COMPLETED:
                raise OverlappedLifecycleError(
                    "connect operation must be completed before committing its result"
                )
            self._state = self.CONNECTED if connected else self.DISCONNECTED

    def mark_connected(self) -> None:
        """Reject state-only reconnects; use start_connect/complete_connect."""
        raise OverlappedLifecycleError(
            "connection state must be established by the ConnectNamedPipe lifecycle"
        )


def disconnect_named_pipe(
    bindings: Kernel32Bindings,
    connection: NamedPipeConnection,
    operation: "OverlappedOperation",
    *,
    get_last_error: Callable[[], int] = last_error,
) -> tuple[bool, int | None]:
    """Disconnect once, only after the supplied pipe I/O has completed.

    Every operation issued against the pipe must first be registered with
    its NamedPipeConnection. All registered operations must be terminal
    (not pending) before disconnect. The registry remains until each operation
    closes its event/buffer/OVERLAPPED resources and is explicitly unregistered.
    """
    with connection._lock:
        if connection._state != connection.CONNECTED:
            raise OverlappedLifecycleError(
                f"cannot disconnect pipe in state {connection._state}"
            )
        if operation.state == operation.PENDING:
            raise OverlappedLifecycleError(
                "cannot disconnect a pipe while overlapped I/O is pending"
            )
        if operation.state != operation.COMPLETED:
            raise OverlappedLifecycleError(
                "disconnect requires a completed operation"
            )
        if operation.file_handle != connection.file_handle:
            raise OverlappedLifecycleError(
                "operation handle does not belong to this pipe connection"
            )
        if operation not in connection._operations:
            raise OverlappedLifecycleError(
                "operation must be registered with its pipe connection"
            )
        unfinished = [
            item for item in connection._operations
            if item.state not in (item.COMPLETED, item.CLOSED)
        ]
        if unfinished:
            raise OverlappedLifecycleError(
                "cannot disconnect while registered pipe I/O is not completed"
            )
        succeeded = bool(bindings.DisconnectNamedPipe(connection.file_handle))
        if not succeeded:
            return False, int(get_last_error())
        connection._state = connection.DISCONNECTED
        return True, None


def close_named_pipe(
    bindings: Kernel32Bindings,
    connection: NamedPipeConnection,
    *,
    get_last_error: Callable[[], int] = last_error,
) -> tuple[bool, int | None]:
    """Close the server pipe handle after disconnect and operation cleanup."""
    with connection._lock:
        if connection._state not in (connection.DISCONNECTED, connection.CLOSING):
            raise OverlappedLifecycleError(
                f"cannot close pipe handle in state {connection._state}"
            )
        if connection._operations:
            raise OverlappedLifecycleError(
                "cannot close pipe handle while registered operation resources remain"
            )
        # A Python/API exception leaves the close outcome uncertain. Keep the
        # handle for a retry, but block reconnect until that retry resolves it.
        connection._state = connection.CLOSING
        succeeded = bool(bindings.CloseHandle(connection.file_handle))
        if not succeeded:
            connection._state = connection.DISCONNECTED
            return False, int(get_last_error())
        connection.file_handle = None
        connection._state = connection.CLOSED
        return True, None


def start_overlapped_connect(bindings: Kernel32Bindings, operation: "OverlappedOperation", *, get_last_error: Callable[[], int] = last_error) -> tuple[str, int | None]:
    """Low-level ConnectNamedPipe primitive; prefer NamedPipeConnection.start_connect.

    This helper owns only the operation state transition. It cannot serialize
    against pipe disconnect/reuse and must not be used as a connection API.
    """
    if operation.state != operation.CREATED:
        raise OverlappedLifecycleError(f"cannot start connect in state {operation.state}")
    if not operation.event_handle:
        raise ValueError("overlapped connect requires an event handle")
    operation.mark_starting()
    operation.overlapped.hEvent = operation.event_handle
    try:
        succeeded = bool(bindings.ConnectNamedPipe(operation.file_handle, ctypes.byref(operation.overlapped)))
        if succeeded:
            operation.mark_completed()
            return "connected", None
        error = int(get_last_error())
        if error == ERROR_IO_PENDING:
            operation.mark_pending()
            return "pending", None
        if error == ERROR_PIPE_CONNECTED:
            # The connection exists even if signaling the event fails.
            operation.mark_completed()
            signaled = bool(bindings.SetEvent(operation.event_handle))
            signal_error = None if signaled else int(get_last_error())
            return "connected", signal_error
        operation.mark_completed()
        return "failed", error
    except BaseException:
        # Any exception before a terminal state leaves submission outcome uncertain.
        if operation.state == operation.STARTING:
            operation.mark_pending()
        raise


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
    if not operation.event_handle:
        raise ValueError("overlapped I/O requires an event handle")
    operation.mark_starting()
    operation.overlapped.hEvent = operation.event_handle
    transferred = DWORD(0)
    function = bindings.WriteFile if write else bindings.ReadFile
    try:
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
    except BaseException:
        # Any exception before a terminal state leaves submission outcome uncertain.
        if operation.state == operation.STARTING:
            operation.mark_pending()
        raise


class OverlappedOperation:
    """Own one event, OVERLAPPED object and buffer until I/O is truly complete.

    Callbacks return (success, error_code) for CancelIoEx and
    (success, bytes_transferred, error_code) for GetOverlappedResultEx. The latter
    must be invoked with wait=True so a terminal result is obtained before the
    operation releases any memory. ERROR_NOT_FOUND from cancellation is treated
    as a completion race, never as proof that the OVERLAPPED can be freed.
    """

    CREATED = "created"
    STARTING = "starting"
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

    def mark_starting(self) -> None:
        """Reserve the operation before entering a Win32 submission call."""
        with self._lock:
            if self._state != self.CREATED:
                raise OverlappedLifecycleError(
                    f"cannot start operation in state {self._state}"
                )
            self._state = self.STARTING

    def mark_pending(self) -> None:
        with self._lock:
            if self._state not in (self.CREATED, self.STARTING):
                raise OverlappedLifecycleError(
                    f"cannot mark operation pending in state {self._state}"
                )
            self._state = self.PENDING

    def mark_completed(self) -> None:
        """Record immediate or drained completion of an overlapped operation."""
        with self._lock:
            if self._state not in (self.CREATED, self.STARTING, self.PENDING):
                raise OverlappedLifecycleError(
                    f"cannot complete operation in state {self._state}"
                )
            self._state = self.COMPLETED

    def cancel_and_drain(
        self,
        *,
        cancel_io_ex: Callable[[Any, OVERLAPPED], tuple[bool, int]],
        get_overlapped_result_ex: Callable[
            [Any, OVERLAPPED, int], tuple[bool, int, int]
        ],
        timeout_ms: int = 5000,
    ) -> OverlappedResult:
        """Request targeted cancellation and drain for at most timeout_ms.

        A timeout leaves the operation PENDING and retains every resource so
        the caller can retry draining without reusing the OVERLAPPED or buffer.
        """
        if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool):
            raise TypeError("timeout_ms must be an integer")
        if timeout_ms < 0 or timeout_ms > MAX_DWORD:
            raise ValueError("timeout_ms must fit an unsigned Win32 DWORD")
        with self._lock:
            if self._state != self.PENDING:
                raise OverlappedLifecycleError(
                    f"cannot cancel operation in state {self._state}"
                )

            cancel_ok, cancel_error = cancel_io_ex(
                self.file_handle, self.overlapped
            )
            # Always drain, including ERROR_NOT_FOUND: completion may have won
            # the race with cancellation. CancelIoEx itself does not wait.
            result_ok, transferred, result_error = get_overlapped_result_ex(
                self.file_handle, self.overlapped, timeout_ms
            )
            if not result_ok and result_error in (
                ERROR_IO_INCOMPLETE,
                ERROR_IO_PENDING,
                WAIT_TIMEOUT,
            ):
                raise OverlappedStillPending(
                    "bounded GetOverlappedResultEx did not establish terminal completion"
                )

            self._state = self.COMPLETED
            return OverlappedResult(
                succeeded=bool(result_ok),
                bytes_transferred=int(transferred),
                error_code=0 if result_ok else int(result_error),
                cancel_error=None if cancel_ok else int(cancel_error),
            )

    def close(self) -> None:
        """Close the event exactly once, but only after I/O is no longer pending."""
        with self._lock:
            if self._state == self.CLOSED:
                return
            if self._state in (self.STARTING, self.PENDING):
                raise OverlappedLifecycleError(
                    "cannot release OVERLAPPED resources while I/O submission or completion is in progress"
                )
            if self.event_handle:
                if not self._close_handle(self.event_handle):
                    raise OSError("CloseHandle failed for overlapped event")
            self.event_handle = None
            self.buffer = None
            self.overlapped = None
            self.file_handle = None
            self._state = self.CLOSED
