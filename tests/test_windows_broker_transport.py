from __future__ import annotations

import threading
import unittest

from scripts.windows_broker_transport import (
    NamedPipeByteStream,
    OverlappedIO,
    TransportCancelled,
    TransportCleanupError,
    TransportTimeout,
)


class FakeBackend:
    def __init__(self, *, immediate=None, result=0, waits=None, fail_wait=None):
        self.immediate = immediate
        self.result = result
        self.waits = list(waits or [True])
        self.fail_wait = fail_wait
        self.events = []
        self.read_data = b""

    def start(self, operation, handle, buffer):
        self.events.append("start")
        if operation == "read" and isinstance(buffer, bytearray):
            buffer[:min(len(buffer), len(self.read_data))] = self.read_data[:len(buffer)]
        return {"operation": operation, "buffer": buffer}, self.immediate

    def wait(self, token, timeout_ms, cancel_event):
        self.events.append(("wait", timeout_ms))
        if self.fail_wait is not None:
            raise self.fail_wait
        return self.waits.pop(0) if self.waits else True

    def complete(self, token):
        self.events.append("complete")
        return self.result

    def cancel(self, token):
        self.events.append("cancel")

    def drain(self, token):
        self.events.append("drain")

    def close(self, token):
        self.events.append("close")


class WindowsBrokerTransportTests(unittest.TestCase):
    def test_pending_operation_completes_and_closes_after_result(self):
        backend = FakeBackend(result=4)
        count = OverlappedIO(backend).perform("write", 12, b"data", timeout=2)
        self.assertEqual(count, 4)
        self.assertEqual(backend.events, ["start", ("wait", 2000), "complete", "close"])

    def test_connect_accepts_inline_pipe_connected_translation(self):
        backend = FakeBackend(immediate=0)
        OverlappedIO(backend).connect(12, timeout=2)
        self.assertEqual(backend.events, ["start", "close"])

    def test_cancel_event_that_wins_native_wait_is_drained(self):
        backend = FakeBackend(waits=[False])
        cancel = threading.Event()

        def set_cancel():
            cancel.set()

        backend.wait = lambda token, timeout_ms, cancel_event: (set_cancel() or False)
        with self.assertRaises(TransportCancelled):
            OverlappedIO(backend).perform(
                "read", 12, bytearray(4), timeout=2, cancel_event=cancel
            )
        self.assertEqual(backend.events, ["start", "cancel", "drain", "close"])

    def test_invalid_completion_count_is_rejected_after_native_completion(self):
        backend = FakeBackend(result=5)
        with self.assertRaisesRegex(OSError, "invalid write byte count"):
            OverlappedIO(backend).perform("write", 12, b"data", timeout=2)
        self.assertEqual(backend.events[-2:], ["complete", "close"])

    def test_close_handle_failure_does_not_mark_stream_closed(self):
        attempts = []

        def close_handle(handle):
            attempts.append(handle)
            if len(attempts) == 1:
                raise OSError("close failed")

        stream = NamedPipeByteStream(
            OverlappedIO(FakeBackend()), 12, close_handle=close_handle
        )
        with self.assertRaisesRegex(OSError, "close failed"):
            stream.close()
        self.assertFalse(stream.closed)
        stream.close()
        self.assertTrue(stream.closed)
        self.assertEqual(attempts, [12, 12])

    def test_inline_completion_does_not_wait(self):
        backend = FakeBackend(immediate=3)
        count = OverlappedIO(backend).perform("write", 12, b"abc", timeout=2)
        self.assertEqual(count, 3)
        self.assertEqual(backend.events, ["start", "close"])

    def test_timeout_cancels_drains_then_closes(self):
        backend = FakeBackend(waits=[False])
        with self.assertRaises(TransportTimeout):
            OverlappedIO(backend).perform("read", 12, bytearray(8), timeout=0.001)
        self.assertEqual(
            [event if isinstance(event, str) else event[0] for event in backend.events],
            ["start", "wait", "cancel", "drain", "close"],
        )

    def test_cancellation_drains_before_close(self):
        backend = FakeBackend()
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(TransportCancelled):
            OverlappedIO(backend).perform(
                "read", 12, bytearray(8), timeout=2, cancel_event=cancel
            )
        self.assertEqual(backend.events, ["start", "cancel", "drain", "close"])

    def test_wait_failure_still_cancels_and_drains(self):
        backend = FakeBackend(fail_wait=RuntimeError("wait failed"))
        with self.assertRaisesRegex(RuntimeError, "wait failed"):
            OverlappedIO(backend).perform("read", 12, bytearray(8), timeout=2)
        self.assertEqual(backend.events, ["start", ("wait", 2000), "cancel", "drain", "close"])

    def test_drain_failure_is_reported_and_storage_is_not_closed(self):
        class BrokenDrain(FakeBackend):
            def drain(self, token):
                self.events.append("drain")
                raise RuntimeError("still pending")

        backend = BrokenDrain(waits=[False])
        with self.assertRaises(TransportCleanupError):
            OverlappedIO(backend).perform("read", 12, bytearray(8), timeout=0.001)
        self.assertNotIn("close", backend.events)

    def test_stream_handles_partial_reads_and_writes(self):
        backend = FakeBackend(immediate=2)
        backend.read_data = b"ab"
        stream = NamedPipeByteStream(OverlappedIO(backend), 12)
        self.assertEqual(stream.read(4), b"ab")
        self.assertEqual(stream.write(b"wxyz"), 2)
        self.assertEqual(stream.read(0), b"")
        self.assertEqual(len([event for event in backend.events if event == "start"]), 2)

    def test_stream_rejects_unbounded_reads_and_closes_idempotently(self):
        closed = []
        stream = NamedPipeByteStream(
            OverlappedIO(FakeBackend(immediate=1)), 12, close_handle=closed.append
        )
        with self.assertRaises(ValueError):
            stream.read()
        with self.assertRaises(ValueError):
            stream.read(1024 * 1024 + 5)
        stream.close()
        stream.close()
        self.assertTrue(stream.closed)
        self.assertEqual(closed, [12])
        with self.assertRaises(ValueError):
            stream.read(1)

    def test_stream_requires_finite_positive_timeout(self):
        for timeout in (0, -1, float("inf"), float("nan"), True):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                NamedPipeByteStream(OverlappedIO(FakeBackend()), 12, timeout=timeout)


if __name__ == "__main__":
    unittest.main()
