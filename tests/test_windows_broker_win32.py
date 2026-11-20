"""Tests for lazy Win32 API bindings and native structure layout."""
from __future__ import annotations

import ctypes
import unittest
from unittest.mock import patch

from scripts import windows_broker_win32 as win32


class FakeFunction:
    def __call__(self, *args):
        return 1


class FakeKernel32:
    def __init__(self):
        for name in (
            "CreateEventW",
            "CloseHandle",
            "WaitForSingleObject",
            "CancelIoEx",
            "GetOverlappedResult",
            "GetOverlappedResultEx",
        ):
            setattr(self, name, FakeFunction())


class WindowsBrokerWin32Tests(unittest.TestCase):
    def test_win32_scalar_types_have_windows_widths(self):
        self.assertEqual(ctypes.sizeof(win32.DWORD), 4)
        self.assertEqual(ctypes.sizeof(win32.BOOL), 4)
        self.assertEqual(ctypes.sizeof(win32.ULONG_PTR), ctypes.sizeof(ctypes.c_void_p))

    def test_module_import_and_structure_layout_are_platform_neutral(self):
        pointer_size = ctypes.sizeof(ctypes.c_void_p)
        self.assertEqual(ctypes.sizeof(win32.OVERLAPPED), 2 * pointer_size + 8)
        self.assertEqual(win32.OVERLAPPED.Internal.offset, 0)
        self.assertEqual(win32.OVERLAPPED.InternalHigh.offset, pointer_size)
        self.assertEqual(win32.OVERLAPPED.hEvent.offset, 2 * pointer_size + 8)

    def test_loader_rejects_non_windows_without_loading_dll(self):
        with patch.object(win32.os, "name", "posix"):
            with self.assertRaises(win32.Win32ApiUnavailable):
                win32.load_kernel32(loader=lambda *args, **kwargs: self.fail("must not load"))

    def test_loader_binds_required_api_signatures(self):
        fake = FakeKernel32()
        with patch.object(win32.os, "name", "nt"):
            bindings = win32.load_kernel32(loader=lambda *args, **kwargs: fake)
        self.assertIs(bindings.library, fake)
        self.assertEqual(fake.CancelIoEx.argtypes[1], ctypes.POINTER(win32.OVERLAPPED))
        self.assertEqual(fake.GetOverlappedResultEx.argtypes[-2], win32.DWORD)
        self.assertIs(fake.GetOverlappedResult.restype, win32.BOOL)

    def test_loader_fails_closed_when_required_api_is_missing(self):
        class IncompleteKernel32:
            pass

        with patch.object(win32.os, "name", "nt"):
            with self.assertRaises(win32.Win32ApiUnavailable):
                win32.load_kernel32(loader=lambda *args, **kwargs: IncompleteKernel32())


if __name__ == "__main__":
    unittest.main()
