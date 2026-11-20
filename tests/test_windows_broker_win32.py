"""Tests for Win32 bindings and overlapped-operation ownership rules."""
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
            "CreateEventW", "CloseHandle", "WaitForSingleObject",
            "CancelIoEx", "GetOverlappedResult", "GetOverlappedResultEx",
            "ReadFile", "WriteFile", "ConnectNamedPipe", "SetEvent", "DisconnectNamedPipe",
        ):
            setattr(self, name, FakeFunction())


class WindowsBrokerWin32Tests(unittest.TestCase):
    def make_operation(self, close=None):
        closed = []
        operation = win32.OverlappedOperation(
            file_handle=10,
            overlapped=win32.OVERLAPPED(),
            event_handle=20,
            buffer=bytearray(b"payload"),
            close_handle=close or (lambda handle: closed.append(handle) or True),
        )
        return operation, closed

    def test_win32_scalar_types_have_windows_widths(self):
        self.assertEqual(ctypes.sizeof(win32.DWORD), 4)
        self.assertEqual(ctypes.sizeof(win32.BOOL), 4)
        self.assertEqual(ctypes.sizeof(win32.ULONG_PTR), ctypes.sizeof(ctypes.c_void_p))

    def test_overlapped_structure_layout_is_platform_neutral(self):
        pointer_size = ctypes.sizeof(ctypes.c_void_p)
        union_size = max(pointer_size, 8)
        self.assertEqual(ctypes.sizeof(win32.OVERLAPPED), 3 * pointer_size + union_size)
        self.assertEqual(win32.OVERLAPPED.Internal.offset, 0)
        self.assertEqual(win32.OVERLAPPED.InternalHigh.offset, pointer_size)
        self.assertEqual(win32.OVERLAPPED.hEvent.offset, 2 * pointer_size + union_size)

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

    def test_create_event_uses_manual_reset_and_captures_failure(self):
        fake = FakeKernel32()
        calls = []
        fake.CreateEventW = lambda *args: calls.append(args) or None
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile, fake.ConnectNamedPipe, fake.SetEvent, fake.DisconnectNamedPipe)
        handle, error = win32.create_manual_reset_event(bindings, get_last_error=lambda: 123)
        self.assertIsNone(handle)
        self.assertEqual(error, 123)
        self.assertIsNone(calls[0][0])
        self.assertEqual(tuple(int(x.value) for x in calls[0][1:3]), (1, 0))

    def test_cancel_wrapper_targets_exact_overlapped_and_captures_error(self):
        fake = FakeKernel32()
        seen = []
        fake.CancelIoEx = lambda handle, pointer: seen.append((handle, pointer)) or 0
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile, fake.ConnectNamedPipe, fake.SetEvent)
        operation = win32.OVERLAPPED()
        ok, error = win32.cancel_exact_io(bindings, 44, operation, get_last_error=lambda: 1168)
        self.assertFalse(ok)
        self.assertEqual(error, 1168)
        self.assertEqual(seen[0][0], 44)
        self.assertIs(seen[0][1]._obj, operation)

    def test_result_wrapper_captures_error_and_transferred_bytes(self):
        fake = FakeKernel32()
        def failed(handle, overlapped, transferred, wait):
            transferred._obj.value = 9
            return 0
        fake.GetOverlappedResult = failed
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile, fake.ConnectNamedPipe, fake.SetEvent)
        ok, count, error = win32.get_overlapped_result_wait(
            bindings, 44, win32.OVERLAPPED(), True, get_last_error=lambda: 996
        )
        self.assertFalse(ok)
        self.assertEqual((count, error), (9, 996))

    def test_loader_binds_disconnect_named_pipe_signature(self):
        fake = FakeKernel32()
        with patch.object(win32.os, "name", "nt"):
            win32.load_kernel32(loader=lambda *args, **kwargs: fake)
        self.assertEqual(fake.DisconnectNamedPipe.argtypes, [win32.HANDLE])

    def test_disconnect_rejects_pending_operation(self):
        fake = FakeKernel32()
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile,
            fake.ConnectNamedPipe, fake.SetEvent, fake.DisconnectNamedPipe)
        operation, _ = self.make_operation()
        operation.mark_pending()
        connection = win32.NamedPipeConnection(10)
        with self.assertRaises(win32.OverlappedLifecycleError):
            win32.disconnect_named_pipe(bindings, connection, operation)

    def test_disconnect_captures_api_failure(self):
        fake = FakeKernel32()
        seen = []
        fake.DisconnectNamedPipe = lambda handle: seen.append(handle) or 0
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile,
            fake.ConnectNamedPipe, fake.SetEvent, fake.DisconnectNamedPipe)
        operation, _ = self.make_operation()
        operation.mark_pending()
        operation.mark_completed()
        connection = win32.NamedPipeConnection(10)
        self.assertEqual(win32.disconnect_named_pipe(bindings, connection, operation,
            get_last_error=lambda: 109), (False, 109))
        self.assertEqual(connection.state, connection.CONNECTED)
        self.assertEqual(seen, [10])

    def test_disconnect_transitions_connection_and_rejects_duplicate(self):
        fake = FakeKernel32()
        calls = []
        fake.DisconnectNamedPipe = lambda handle: calls.append(handle) or 1
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile,
            fake.ConnectNamedPipe, fake.SetEvent, fake.DisconnectNamedPipe)
        operation, _ = self.make_operation()
        operation.mark_pending()
        operation.mark_completed()
        connection = win32.NamedPipeConnection(10)
        self.assertEqual(win32.disconnect_named_pipe(bindings, connection, operation), (True, None))
        self.assertEqual(connection.state, connection.DISCONNECTED)
        with self.assertRaises(win32.OverlappedLifecycleError):
            win32.disconnect_named_pipe(bindings, connection, operation)
        self.assertEqual(calls, [10])

    def test_reconnect_requires_disconnected_state(self):
        connection = win32.NamedPipeConnection(10)
        with self.assertRaises(win32.OverlappedLifecycleError):
            connection.mark_connected()
        # A successful ConnectNamedPipe completion is recorded explicitly.
        connection._state = connection.DISCONNECTED
        connection.mark_connected()
        self.assertEqual(connection.state, connection.CONNECTED)

    def test_disconnect_rejects_operation_for_another_pipe(self):
        fake = FakeKernel32()
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile,
            fake.ConnectNamedPipe, fake.SetEvent, fake.DisconnectNamedPipe)
        operation, _ = self.make_operation()
        operation.mark_pending()
        operation.mark_completed()
        connection = win32.NamedPipeConnection(99)
        with self.assertRaises(win32.OverlappedLifecycleError):
            win32.disconnect_named_pipe(bindings, connection, operation)

    def test_loader_binds_connect_named_pipe_signature(self):
        fake = FakeKernel32()
        with patch.object(win32.os, "name", "nt"):
            win32.load_kernel32(loader=lambda *args, **kwargs: fake)
        self.assertEqual(fake.ConnectNamedPipe.argtypes[-1], ctypes.POINTER(win32.OVERLAPPED))

    def test_connect_named_pipe_pending(self):
        fake = FakeKernel32()
        fake.ConnectNamedPipe = lambda *_: 0
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle, fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult, fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile, fake.ConnectNamedPipe, fake.SetEvent)
        operation = win32.OverlappedOperation(file_handle=10, overlapped=win32.OVERLAPPED(), event_handle=20, buffer=None, close_handle=lambda _: True)
        self.assertEqual(win32.start_overlapped_connect(bindings, operation, get_last_error=lambda: win32.ERROR_IO_PENDING), ("pending", None))
        self.assertEqual(operation.state, operation.PENDING)
        self.assertEqual(operation.overlapped.hEvent, 20)

    def test_connect_named_pipe_already_connected_signals_event(self):
        fake = FakeKernel32()
        fake.ConnectNamedPipe = lambda *_: 0
        events = []
        fake.SetEvent = lambda handle: events.append(handle) or 1
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle, fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult, fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile, fake.ConnectNamedPipe, fake.SetEvent)
        operation = win32.OverlappedOperation(file_handle=10, overlapped=win32.OVERLAPPED(), event_handle=20, buffer=None, close_handle=lambda _: True)
        self.assertEqual(win32.start_overlapped_connect(bindings, operation, get_last_error=lambda: win32.ERROR_PIPE_CONNECTED), ("connected", None))
        self.assertEqual(events, [20])
        self.assertEqual(operation.state, operation.COMPLETED)

    def test_connect_named_pipe_failure_preserves_error(self):
        fake = FakeKernel32()
        fake.ConnectNamedPipe = lambda *_: 0
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle, fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult, fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile, fake.ConnectNamedPipe, fake.SetEvent)
        operation = win32.OverlappedOperation(file_handle=10, overlapped=win32.OVERLAPPED(), event_handle=20, buffer=None, close_handle=lambda _: True)
        self.assertEqual(win32.start_overlapped_connect(bindings, operation, get_last_error=lambda: 5), ("failed", 5))
        self.assertEqual(operation.state, operation.COMPLETED)

    def test_loader_binds_read_write_overlapped_signatures(self):
        fake = FakeKernel32()
        with patch.object(win32.os, "name", "nt"):
            bindings = win32.load_kernel32(loader=lambda *args, **kwargs: fake)
        self.assertIs(bindings.ReadFile, fake.ReadFile)
        self.assertEqual(fake.ReadFile.argtypes[-1], ctypes.POINTER(win32.OVERLAPPED))

    def test_start_overlapped_read_pending(self):
        fake = FakeKernel32()
        seen = []
        fake.ReadFile = lambda *args: seen.append(args) or 0
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle, fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult, fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile, fake.ConnectNamedPipe, fake.SetEvent)
        buffer = (ctypes.c_ubyte * 4)()
        operation = win32.OverlappedOperation(file_handle=10, overlapped=win32.OVERLAPPED(), event_handle=20, buffer=buffer, close_handle=lambda _: True)
        result = win32.start_overlapped_io(bindings, operation, buffer=buffer, length=4, get_last_error=lambda: win32.ERROR_IO_PENDING)
        self.assertEqual(result, ("pending", 0, win32.ERROR_IO_PENDING))
        self.assertEqual(operation.state, operation.PENDING)
        self.assertIs(seen[0][-1]._obj, operation.overlapped)
        self.assertEqual(operation.overlapped.hEvent, 20)

    def test_start_overlapped_write_immediate_completion(self):
        fake = FakeKernel32()
        def completed(handle, pointer, length, transferred, overlapped):
            transferred._obj.value = 3
            return 1
        fake.WriteFile = completed
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle, fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult, fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile, fake.ConnectNamedPipe, fake.SetEvent)
        buffer = (ctypes.c_ubyte * 4)()
        operation = win32.OverlappedOperation(file_handle=10, overlapped=win32.OVERLAPPED(), event_handle=20, buffer=buffer, close_handle=lambda _: True)
        self.assertEqual(win32.start_overlapped_io(bindings, operation, buffer=buffer, length=4, write=True), ("completed", 3, None))
        self.assertEqual(operation.state, operation.COMPLETED)

    def test_close_is_forbidden_while_pending_then_idempotent(self):
        operation, closed = self.make_operation()
        operation.mark_pending()
        with self.assertRaises(win32.OverlappedLifecycleError):
            operation.close()
        self.assertEqual(closed, [])
        operation.mark_completed()
        operation.close()
        operation.close()
        self.assertEqual(closed, [20])
        self.assertEqual(operation.state, win32.OverlappedOperation.CLOSED)
        self.assertIsNone(operation.buffer)
        self.assertIsNone(operation.overlapped)

    def test_error_not_found_still_drains_before_resources_can_be_released(self):
        operation, closed = self.make_operation()
        operation.mark_pending()
        calls = []
        def cancel(handle, overlapped):
            calls.append(("cancel", handle, overlapped))
            return False, win32.ERROR_NOT_FOUND
        def drain(handle, overlapped, wait):
            calls.append(("drain", handle, overlapped, wait))
            self.assertIsNotNone(operation.buffer)
            return True, 7, 0
        result = operation.cancel_and_drain(
            cancel_io_ex=cancel, get_overlapped_result=drain
        )
        self.assertEqual([call[0] for call in calls], ["cancel", "drain"])
        self.assertTrue(calls[1][3])
        self.assertEqual(result.bytes_transferred, 7)
        self.assertEqual(result.cancel_error, win32.ERROR_NOT_FOUND)
        self.assertEqual(operation.state, win32.OverlappedOperation.COMPLETED)
        operation.close()
        self.assertEqual(closed, [20])

    def test_cancel_error_still_requires_and_performs_drain(self):
        operation, _ = self.make_operation()
        operation.mark_pending()
        result = operation.cancel_and_drain(
            cancel_io_ex=lambda *_: (False, 5),
            get_overlapped_result=lambda *_: (False, 0, win32.ERROR_OPERATION_ABORTED),
        )
        self.assertEqual(result.error_code, win32.ERROR_OPERATION_ABORTED)
        self.assertEqual(result.cancel_error, 5)
        self.assertEqual(operation.state, win32.OverlappedOperation.COMPLETED)

    def test_incomplete_drain_keeps_all_resources_alive(self):
        operation, closed = self.make_operation()
        operation.mark_pending()
        with self.assertRaises(win32.OverlappedStillPending):
            operation.cancel_and_drain(
                cancel_io_ex=lambda *_: (False, win32.ERROR_NOT_FOUND),
                get_overlapped_result=lambda *_: (False, 0, win32.ERROR_IO_INCOMPLETE),
            )
        self.assertEqual(operation.state, win32.OverlappedOperation.PENDING)
        self.assertIsNotNone(operation.buffer)
        self.assertIsNotNone(operation.overlapped)
        self.assertEqual(closed, [])

    def test_event_close_failure_is_retryable(self):
        outcomes = iter((False, True))
        operation, _ = self.make_operation(close=lambda _: next(outcomes))
        with self.assertRaises(OSError):
            operation.close()
        self.assertEqual(operation.state, win32.OverlappedOperation.CREATED)
        operation.close()
        self.assertEqual(operation.state, win32.OverlappedOperation.CLOSED)


if __name__ == "__main__":
    unittest.main()
