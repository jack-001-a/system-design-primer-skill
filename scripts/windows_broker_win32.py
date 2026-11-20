"""Lazy ctypes bindings for the Windows broker's overlapped-I/O primitives.

Importing this module is safe on non-Windows hosts. No DLL is loaded until
load_kernel32() is explicitly called. This module binds APIs only; it does not
claim to implement a complete, production-ready pipe transport.
"""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any


DWORD = wintypes.DWORD
BOOL = wintypes.BOOL
HANDLE = wintypes.HANDLE
ULONG_PTR = ctypes.c_size_t
LPVOID = wintypes.LPVOID

ERROR_IO_PENDING = 997
ERROR_IO_INCOMPLETE = 996
ERROR_NOT_FOUND = 1168
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
INFINITE = 0xFFFFFFFF


class _OffsetUnion(ctypes.Union):
    _fields_ = [
        ("_offset", wintypes.DWORD * 2),
        ("_pointer", LPVOID),
    ]


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
            library.CreateEventW,
            [LPVOID, BOOL, BOOL, wintypes.LPCWSTR],
            HANDLE,
        )
        close_handle = _set_signature(library.CloseHandle, [HANDLE], BOOL)
        wait = _set_signature(
            library.WaitForSingleObject,
            [HANDLE, DWORD],
            DWORD,
        )
        cancel = _set_signature(
            library.CancelIoEx,
            [HANDLE, ctypes.POINTER(OVERLAPPED)],
            BOOL,
        )
        get_result = _set_signature(
            library.GetOverlappedResult,
            [HANDLE, ctypes.POINTER(OVERLAPPED), ctypes.POINTER(DWORD), BOOL],
            BOOL,
        )
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
        library=library,
        CreateEventW=create_event,
        CloseHandle=close_handle,
        WaitForSingleObject=wait,
        CancelIoEx=cancel,
        GetOverlappedResult=get_result,
        GetOverlappedResultEx=get_result_ex,
    )


def last_error() -> int:
    """Return the calling thread's Win32 last-error value."""
    getter = getattr(ctypes, "get_last_error", None)
    if getter is None:
        raise Win32ApiUnavailable("Win32 last-error state is unavailable")
    return int(getter())
