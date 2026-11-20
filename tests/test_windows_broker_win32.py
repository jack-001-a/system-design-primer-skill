"""Tests for Win32 bindings and overlapped-operation ownership rules."""
from __future__ import annotations

import ctypes
import threading
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
        connection.register_operation(operation)
        with self.assertRaises(win32.OverlappedLifecycleError):
            win32.disconnect_named_pipe(bindings, connection, operation)

    def test_concurrent_disconnect_invokes_win32_once(self):
        entered = threading.Event()
        release = threading.Event()
        calls = []
        fake = FakeKernel32()

        def blocking_disconnect(handle):
            calls.append(handle)
            entered.set()
            if not release.wait(2):
                raise AssertionError("disconnect was not released")
            return 1

        fake.DisconnectNamedPipe = blocking_disconnect
        bindings = win32.Kernel32Bindings(
            fake, fake.CreateEventW, fake.CloseHandle, fake.WaitForSingleObject,
            fake.CancelIoEx, fake.GetOverlappedResult, fake.GetOverlappedResultEx,
            fake.ReadFile, fake.WriteFile, fake.ConnectNamedPipe, fake.SetEvent,
            fake.DisconnectNamedPipe,
        )
        operation, _ = self.make_operation()
        operation.mark_completed()
        connection = win32.NamedPipeConnection(10)
        connection.register_operation(operation)

        results = []
        errors = []
        def disconnect():
            try:
                results.append(win32.disconnect_named_pipe(bindings, connection, operation))
            except win32.OverlappedLifecycleError as exc:
                errors.append(str(exc))

        first = threading.Thread(target=disconnect)
        second = threading.Thread(target=disconnect)
        first.start()
        self.assertTrue(entered.wait(2))
        second.start()
        release.set()
        first.join(2)
        second.join(2)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(calls, [10])
        self.assertEqual(results, [(True, None)])
        self.assertEqual(len(errors), 1)
        self.assertEqual(connection.state, connection.DISCONNECTED)
        self.assertIn(operation, connection._operations)

    def test_disconnect_error_lookup_exception_preserves_connected_state(self):
        fake = FakeKernel32()
        calls = []
        fake.DisconnectNamedPipe = lambda handle: calls.append(handle) or 0
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile,
            fake.ConnectNamedPipe, fake.SetEvent, fake.DisconnectNamedPipe)
        operation, _ = self.make_operation()
        operation.mark_completed()
        connection = win32.NamedPipeConnection(10)
        connection.register_operation(operation)
        with self.assertRaisesRegex(RuntimeError, "last-error"):
            win32.disconnect_named_pipe(
                bindings, connection, operation,
                get_last_error=lambda: (_ for _ in ()).throw(RuntimeError("last-error"))
            )
        self.assertEqual(connection.state, connection.CONNECTED)
        self.assertEqual(calls, [10])
        self.assertEqual(win32.disconnect_named_pipe(
            bindings, connection, operation, get_last_error=lambda: 109
        ), (False, 109))
        self.assertEqual(connection.state, connection.CONNECTED)

    def test_pipe_close_error_lookup_exception_preserves_handle_for_retry(self):
        fake = FakeKernel32()
        calls = []
        fake.CloseHandle = lambda handle: calls.append(handle) or 0
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile,
            fake.ConnectNamedPipe, fake.SetEvent, fake.DisconnectNamedPipe)
        connection = win32.NamedPipeConnection(10)
        connection._state = connection.DISCONNECTED
        with self.assertRaisesRegex(RuntimeError, "last-error"):
            win32.close_named_pipe(
                bindings, connection,
                get_last_error=lambda: (_ for _ in ()).throw(RuntimeError("last-error"))
            )
        self.assertEqual(connection.state, connection.DISCONNECTED)
        self.assertEqual(connection.file_handle, 10)
        fake.CloseHandle = lambda handle: calls.append(handle) or 1
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile,
            fake.ConnectNamedPipe, fake.SetEvent, fake.DisconnectNamedPipe)
        self.assertEqual(win32.close_named_pipe(bindings, connection), (True, None))
        self.assertEqual(calls, [10, 10])
        self.assertEqual(connection.state, connection.CLOSED)
        self.assertIsNone(connection.file_handle)

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
        connection.register_operation(operation)
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
        connection.register_operation(operation)
        self.assertEqual(win32.disconnect_named_pipe(bindings, connection, operation), (True, None))
        self.assertEqual(connection.state, connection.DISCONNECTED)
        with self.assertRaises(win32.OverlappedLifecycleError):
            win32.disconnect_named_pipe(bindings, connection, operation)
        self.assertEqual(calls, [10])

    def test_reconnect_requires_disconnected_state(self):
        fake = FakeKernel32()
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile,
            fake.ConnectNamedPipe, fake.SetEvent, fake.DisconnectNamedPipe)
        operation, _ = self.make_operation()
        operation.mark_pending()
        operation.mark_completed()
        connection = win32.NamedPipeConnection(10)
        connection.register_operation(operation)
        with self.assertRaises(win32.OverlappedLifecycleError):
            connection.mark_connected()
        self.assertEqual(win32.disconnect_named_pipe(bindings, connection, operation), (True, None))
        operation.close()
        connection.unregister_operation(operation)
        connection.mark_connected()
        self.assertEqual(connection.state, connection.CONNECTED)

    def test_reconnected_pipe_uses_fresh_operation_resources(self):
        fake = FakeKernel32()
        disconnect_calls = []
        fake.DisconnectNamedPipe = lambda handle: disconnect_calls.append(handle) or 1
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile,
            fake.ConnectNamedPipe, fake.SetEvent, fake.DisconnectNamedPipe)

        first, _ = self.make_operation()
        first.mark_completed()
        connection = win32.NamedPipeConnection(10)
        connection.register_operation(first)
        self.assertEqual(
            win32.disconnect_named_pipe(bindings, connection, first),
            (True, None),
        )
        first.close()
        connection.unregister_operation(first)
        self.assertEqual(connection.state, connection.DISCONNECTED)

        connection.mark_connected()
        second, _ = self.make_operation()
        self.assertIsNot(first.overlapped, second.overlapped)
        self.assertIsNot(first.event_handle, second.event_handle)
        with self.assertRaises(win32.OverlappedLifecycleError):
            connection.register_operation(first)
        connection.register_operation(second)
        second.mark_completed()
        self.assertEqual(
            win32.disconnect_named_pipe(bindings, connection, second),
            (True, None),
        )
        self.assertEqual(disconnect_calls, [10, 10])
        self.assertEqual(connection._operations, {second})

    def test_disconnect_checks_all_registered_operations(self):
        fake = FakeKernel32()
        calls = []
        fake.DisconnectNamedPipe = lambda handle: calls.append(handle) or 1
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile,
            fake.ConnectNamedPipe, fake.SetEvent, fake.DisconnectNamedPipe)
        completed, _ = self.make_operation()
        completed.mark_pending()
        completed.mark_completed()
        pending, _ = self.make_operation()
        pending.mark_pending()
        connection = win32.NamedPipeConnection(10)
        connection.register_operation(completed)
        connection.register_operation(pending)
        with self.assertRaises(win32.OverlappedLifecycleError):
            win32.disconnect_named_pipe(bindings, connection, completed)
        self.assertEqual(calls, [])
        pending.mark_completed()
        self.assertEqual(win32.disconnect_named_pipe(bindings, connection, completed), (True, None))
        self.assertEqual(connection._operations, {completed, pending})

    def test_disconnect_rejects_registered_operation_not_yet_started(self):
        fake = FakeKernel32()
        calls = []
        fake.DisconnectNamedPipe = lambda handle: calls.append(handle) or 1
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile,
            fake.ConnectNamedPipe, fake.SetEvent, fake.DisconnectNamedPipe)
        completed, _ = self.make_operation()
        completed.mark_completed()
        not_started, _ = self.make_operation()
        connection = win32.NamedPipeConnection(10)
        connection.register_operation(completed)
        connection.register_operation(not_started)
        with self.assertRaisesRegex(
            win32.OverlappedLifecycleError, "not completed"
        ):
            win32.disconnect_named_pipe(bindings, connection, completed)
        self.assertEqual(calls, [])
        self.assertEqual(connection.state, connection.CONNECTED)

    def test_register_and_close_are_serialized(self):
        entered_add = threading.Event()
        release_add = threading.Event()
        close_started = threading.Event()
        close_finished = threading.Event()

        class BlockingSet(set):
            def add(self, item):
                entered_add.set()
                if not release_add.wait(2):
                    raise AssertionError("registration did not get released")
                super().add(item)

        operation, _ = self.make_operation()
        connection = win32.NamedPipeConnection(10)
        connection._operations = BlockingSet()

        def register():
            connection.register_operation(operation)

        def close():
            close_started.set()
            operation.close()
            close_finished.set()

        register_thread = threading.Thread(target=register)
        close_thread = threading.Thread(target=close)
        register_thread.start()
        self.assertTrue(entered_add.wait(2))
        close_thread.start()
        self.assertTrue(close_started.wait(2))
        self.assertFalse(close_finished.wait(0.05))
        release_add.set()
        register_thread.join(2)
        close_thread.join(2)
        self.assertFalse(register_thread.is_alive())
        self.assertFalse(close_thread.is_alive())
        self.assertTrue(close_finished.is_set())
        self.assertEqual(operation.state, operation.CLOSED)
        self.assertIn(operation, connection._operations)

    def test_disconnect_waits_for_operation_close_and_rejects_closed_operation(self):
        entered_close = threading.Event()
        release_close = threading.Event()
        disconnect_started = threading.Event()
        disconnect_errors = []
        disconnect_calls = []

        def blocking_close(handle):
            entered_close.set()
            if not release_close.wait(2):
                raise AssertionError("event close was not released")
            return True

        operation, _ = self.make_operation(close=blocking_close)
        operation.mark_completed()
        connection = win32.NamedPipeConnection(10)
        connection.register_operation(operation)

        fake = FakeKernel32()
        fake.DisconnectNamedPipe = lambda handle: disconnect_calls.append(handle) or 1
        bindings = win32.Kernel32Bindings(
            fake, fake.CreateEventW, fake.CloseHandle, fake.WaitForSingleObject,
            fake.CancelIoEx, fake.GetOverlappedResult, fake.GetOverlappedResultEx,
            fake.ReadFile, fake.WriteFile, fake.ConnectNamedPipe, fake.SetEvent,
            fake.DisconnectNamedPipe,
        )

        closer = threading.Thread(target=operation.close)

        def disconnect():
            disconnect_started.set()
            try:
                win32.disconnect_named_pipe(bindings, connection, operation)
            except win32.OverlappedLifecycleError as exc:
                disconnect_errors.append(str(exc))

        closer.start()
        self.assertTrue(entered_close.wait(2))
        disconnector = threading.Thread(target=disconnect)
        disconnector.start()
        self.assertTrue(disconnect_started.wait(2))
        self.assertEqual(disconnect_calls, [])
        release_close.set()

        closer.join(2)
        disconnector.join(2)
        self.assertFalse(closer.is_alive())
        self.assertFalse(disconnector.is_alive())
        self.assertTrue(disconnect_errors)
        self.assertEqual(disconnect_calls, [])
        self.assertEqual(connection.state, connection.CONNECTED)
        self.assertEqual(operation.state, operation.CLOSED)
        self.assertIn(operation, connection._operations)

        connection.unregister_operation(operation)
        self.assertNotIn(operation, connection._operations)

    def test_unregister_waits_for_close_and_removes_only_closed_operation(self):
        entered_close = threading.Event()
        release_close = threading.Event()
        unregister_started = threading.Event()
        close_errors = []
        unregister_errors = []

        def blocking_close(handle):
            entered_close.set()
            if not release_close.wait(2):
                raise AssertionError("event close was not released")
            return True

        operation, _ = self.make_operation(close=blocking_close)
        operation.mark_completed()
        connection = win32.NamedPipeConnection(10)
        connection.register_operation(operation)

        def close_operation():
            try:
                operation.close()
            except Exception as exc:
                close_errors.append(exc)

        def unregister_operation():
            unregister_started.set()
            try:
                connection.unregister_operation(operation)
            except Exception as exc:
                unregister_errors.append(exc)

        closer = threading.Thread(target=close_operation)
        unregister = threading.Thread(target=unregister_operation)
        closer.start()
        self.assertTrue(entered_close.wait(2))
        unregister.start()
        self.assertTrue(unregister_started.wait(2))

        # The registry must retain the operation while its event handle is
        # still being closed; unregister waits for the operation lock.
        self.assertIn(operation, connection._operations)
        release_close.set()

        closer.join(2)
        unregister.join(2)
        self.assertFalse(closer.is_alive())
        self.assertFalse(unregister.is_alive())
        self.assertEqual(close_errors, [])
        self.assertEqual(unregister_errors, [])
        self.assertEqual(operation.state, operation.CLOSED)
        self.assertNotIn(operation, connection._operations)

    def test_register_rejects_wrong_handle_and_disconnected_pipe(self):
        connection = win32.NamedPipeConnection(10)
        wrong, _ = self.make_operation()
        wrong.file_handle = 11
        with self.assertRaises(win32.OverlappedLifecycleError):
            connection.register_operation(wrong)
        connection._state = connection.DISCONNECTED
        right, _ = self.make_operation()
        with self.assertRaises(win32.OverlappedLifecycleError):
            connection.register_operation(right)

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


    def test_pipe_handle_close_requires_disconnect_and_operation_cleanup(self):
        fake = FakeKernel32()
        closed = []
        fake.CloseHandle = lambda handle: closed.append(handle) or 1
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile,
            fake.ConnectNamedPipe, fake.SetEvent, fake.DisconnectNamedPipe)
        operation, event_closed = self.make_operation()
        connection = win32.NamedPipeConnection(10)
        connection.register_operation(operation)
        with self.assertRaises(win32.OverlappedLifecycleError):
            win32.close_named_pipe(bindings, connection)
        operation.mark_completed()
        self.assertEqual(win32.disconnect_named_pipe(bindings, connection, operation), (True, None))
        with self.assertRaises(win32.OverlappedLifecycleError):
            win32.close_named_pipe(bindings, connection)
        operation.close()
        connection.unregister_operation(operation)
        self.assertEqual(win32.close_named_pipe(bindings, connection), (True, None))
        self.assertEqual(closed, [10])
        self.assertEqual(event_closed, [20])
        self.assertEqual(connection.state, connection.CLOSED)
        self.assertIsNone(connection.file_handle)
        with self.assertRaises(win32.OverlappedLifecycleError):
            connection.mark_connected()

    def test_pipe_close_is_serialized_against_reconnect_and_registration(self):
        entered_close = threading.Event()
        release_close = threading.Event()
        reconnect_started = threading.Event()
        register_started = threading.Event()
        reconnect_errors = []
        register_errors = []

        fake = FakeKernel32()
        def blocking_close(handle):
            self.assertEqual(handle, 10)
            entered_close.set()
            if not release_close.wait(2):
                raise AssertionError("pipe close was not released")
            return 1

        fake.CloseHandle = blocking_close
        bindings = win32.Kernel32Bindings(
            fake, fake.CreateEventW, fake.CloseHandle, fake.WaitForSingleObject,
            fake.CancelIoEx, fake.GetOverlappedResult, fake.GetOverlappedResultEx,
            fake.ReadFile, fake.WriteFile, fake.ConnectNamedPipe, fake.SetEvent,
            fake.DisconnectNamedPipe,
        )
        connection = win32.NamedPipeConnection(10)
        connection._state = connection.DISCONNECTED
        operation, _ = self.make_operation()

        close_result = []
        closer = threading.Thread(
            target=lambda: close_result.append(win32.close_named_pipe(bindings, connection))
        )
        def reconnect():
            reconnect_started.set()
            try:
                connection.mark_connected()
            except win32.OverlappedLifecycleError as exc:
                reconnect_errors.append(str(exc))

        def register():
            register_started.set()
            try:
                connection.register_operation(operation)
            except win32.OverlappedLifecycleError as exc:
                register_errors.append(str(exc))

        closer.start()
        self.assertTrue(entered_close.wait(2))
        reconnecter = threading.Thread(target=reconnect)
        registrar = threading.Thread(target=register)
        reconnecter.start()
        registrar.start()
        self.assertTrue(reconnect_started.wait(2))
        self.assertTrue(register_started.wait(2))
        self.assertFalse(reconnect_errors)
        self.assertFalse(register_errors)
        release_close.set()

        closer.join(2)
        reconnecter.join(2)
        registrar.join(2)
        self.assertFalse(closer.is_alive())
        self.assertFalse(reconnecter.is_alive())
        self.assertFalse(registrar.is_alive())
        self.assertEqual(close_result, [(True, None)])
        self.assertTrue(reconnect_errors)
        self.assertTrue(register_errors)
        self.assertEqual(connection.state, connection.CLOSED)
        self.assertIsNone(connection.file_handle)
        self.assertNotIn(operation, connection._operations)

    def test_pipe_close_failure_serializes_reconnect_after_state_preservation(self):
        entered_close = threading.Event()
        release_close = threading.Event()
        reconnect_started = threading.Event()
        close_results = []
        reconnect_errors = []

        fake = FakeKernel32()
        def blocking_close(handle):
            self.assertEqual(handle, 10)
            entered_close.set()
            if not release_close.wait(2):
                raise AssertionError("pipe close failure was not released")
            return 0

        fake.CloseHandle = blocking_close
        bindings = win32.Kernel32Bindings(
            fake, fake.CreateEventW, fake.CloseHandle, fake.WaitForSingleObject,
            fake.CancelIoEx, fake.GetOverlappedResult, fake.GetOverlappedResultEx,
            fake.ReadFile, fake.WriteFile, fake.ConnectNamedPipe, fake.SetEvent,
            fake.DisconnectNamedPipe,
        )
        connection = win32.NamedPipeConnection(10)
        connection._state = connection.DISCONNECTED

        def close_pipe():
            close_results.append(
                win32.close_named_pipe(bindings, connection, get_last_error=lambda: 6)
            )

        def reconnect():
            reconnect_started.set()
            try:
                connection.mark_connected()
            except win32.OverlappedLifecycleError as exc:
                reconnect_errors.append(str(exc))

        closer = threading.Thread(target=close_pipe)
        closer.start()
        self.assertTrue(entered_close.wait(2))
        reconnecter = threading.Thread(target=reconnect)
        reconnecter.start()
        self.assertTrue(reconnect_started.wait(2))
        self.assertEqual(connection.state, connection.DISCONNECTED)
        self.assertFalse(reconnect_errors)

        release_close.set()
        closer.join(2)
        reconnecter.join(2)
        self.assertFalse(closer.is_alive())
        self.assertFalse(reconnecter.is_alive())
        self.assertEqual(close_results, [(False, 6)])
        self.assertEqual(reconnect_errors, [])
        self.assertEqual(connection.state, connection.CONNECTED)
        self.assertEqual(connection.file_handle, 10)

    def test_pipe_handle_close_failure_preserves_disconnected_handle(self):
        fake = FakeKernel32()
        fake.CloseHandle = lambda handle: 0
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile,
            fake.ConnectNamedPipe, fake.SetEvent, fake.DisconnectNamedPipe)
        connection = win32.NamedPipeConnection(10)
        connection._state = connection.DISCONNECTED
        self.assertEqual(win32.close_named_pipe(bindings, connection, get_last_error=lambda: 6), (False, 6))
        self.assertEqual(connection.state, connection.DISCONNECTED)
        self.assertEqual(connection.file_handle, 10)

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

    def test_last_error_exception_keeps_io_resources_recoverable(self):
        operation, closed = self.make_operation()
        fake = FakeKernel32()
        fake.ReadFile = lambda *args: 0
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile,
            fake.ConnectNamedPipe, fake.SetEvent)
        buffer = (ctypes.c_ubyte * 4)()
        operation.buffer = buffer
        with self.assertRaisesRegex(RuntimeError, "last-error"):
            win32.start_overlapped_io(
                bindings, operation, buffer=buffer, length=4,
                get_last_error=lambda: (_ for _ in ()).throw(RuntimeError("last-error"))
            )
        self.assertEqual(operation.state, operation.PENDING)
        result = operation.cancel_and_drain(
            cancel_io_ex=lambda *_: (False, win32.ERROR_NOT_FOUND),
            get_overlapped_result=lambda *_: (False, 0, win32.ERROR_OPERATION_ABORTED),
        )
        self.assertEqual(result.error_code, win32.ERROR_OPERATION_ABORTED)
        operation.close()
        self.assertEqual(closed, [20])

    def test_connect_last_error_exception_keeps_resources_recoverable(self):
        operation, closed = self.make_operation()
        fake = FakeKernel32()
        fake.ConnectNamedPipe = lambda *args: 0
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile,
            fake.ConnectNamedPipe, fake.SetEvent)
        with self.assertRaisesRegex(RuntimeError, "last-error"):
            win32.start_overlapped_connect(
                bindings, operation,
                get_last_error=lambda: (_ for _ in ()).throw(RuntimeError("last-error"))
            )
        self.assertEqual(operation.state, operation.PENDING)
        operation.cancel_and_drain(
            cancel_io_ex=lambda *_: (False, win32.ERROR_NOT_FOUND),
            get_overlapped_result=lambda *_: (False, 0, win32.ERROR_OPERATION_ABORTED),
        )
        operation.close()
        self.assertEqual(closed, [20])

    def test_close_is_rejected_while_win32_submission_is_in_progress(self):
        operation, closed = self.make_operation()
        entered = threading.Event()
        release = threading.Event()
        fake = FakeKernel32()
        def blocked_read(*args):
            entered.set()
            self.assertTrue(release.wait(2))
            return 0
        fake.ReadFile = blocked_read
        bindings = win32.Kernel32Bindings(fake, fake.CreateEventW, fake.CloseHandle,
            fake.WaitForSingleObject, fake.CancelIoEx, fake.GetOverlappedResult,
            fake.GetOverlappedResultEx, fake.ReadFile, fake.WriteFile,
            fake.ConnectNamedPipe, fake.SetEvent)
        buffer = (ctypes.c_ubyte * 4)()
        operation.buffer = buffer
        result = []
        worker = threading.Thread(target=lambda: result.append(
            win32.start_overlapped_io(
                bindings, operation, buffer=buffer, length=4,
                get_last_error=lambda: win32.ERROR_IO_PENDING
            )
        ))
        worker.start()
        self.assertTrue(entered.wait(2))
        self.assertEqual(operation.state, operation.STARTING)
        with self.assertRaises(win32.OverlappedLifecycleError):
            operation.close()
        self.assertEqual(closed, [])
        release.set()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result[0][0], "pending")
        operation.mark_completed()
        operation.close()
        self.assertEqual(closed, [20])

    def test_concurrent_close_releases_event_only_once(self):
        entered = threading.Event()
        release = threading.Event()
        calls = []
        def blocking_close(handle):
            calls.append(handle)
            entered.set()
            self.assertTrue(release.wait(2))
            return True
        operation, _ = self.make_operation(close=blocking_close)
        operation.mark_completed()
        first = threading.Thread(target=operation.close)
        second = threading.Thread(target=operation.close)
        first.start()
        self.assertTrue(entered.wait(2))
        second.start()
        release.set()
        first.join(2)
        second.join(2)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(calls, [20])
        self.assertEqual(operation.state, operation.CLOSED)

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
