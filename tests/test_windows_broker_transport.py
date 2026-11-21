"""Tests for platform-neutral Windows broker transport primitives."""
from __future__ import annotations

import unittest

from scripts.windows_broker_transport import (
    Deadline,
    PIPE_PREFIX,
    PipeDeadlineExceeded,
    PipeNoProgress,
    PipePeerClosed,
    new_pipe_name,
    read_exact,
    validate_pipe_name,
    write_all,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now

    def advance(self, amount: float) -> None:
        self.now += amount


class WindowsBrokerTransportTests(unittest.TestCase):
    def test_pipe_name_uses_exactly_256_bits_and_canonical_namespace(self):
        name = new_pipe_name(lambda count: b"\xab" * count)
        self.assertEqual(PIPE_PREFIX, "\\\\.\\pipe\\")
        self.assertEqual(name, "\\\\.\\pipe\\broker-" + "ab" * 32)
        self.assertEqual(validate_pipe_name(name), name)

    def test_pipe_name_rejects_noncanonical_or_remote_names(self):
        for name in (
            r"\\server\pipe\broker-" + "ab" * 32,
            PIPE_PREFIX + "broker-" + "AB" * 32,
            PIPE_PREFIX + "broker-" + "ab" * 31,
            PIPE_PREFIX + "other-" + "ab" * 32,
            PIPE_PREFIX + "broker-" + "ab" * 32 + r"\child",
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_pipe_name(name)

    def test_pipe_name_rejects_weak_token_source(self):
        with self.assertRaises(ValueError):
            new_pipe_name(lambda count: b"short")

    def test_read_exact_handles_short_reads_with_one_absolute_deadline(self):
        clock = FakeClock()
        calls = []
        chunks = iter((b"ab", b"c", b"de"))

        def read_chunk(size, timeout):
            calls.append((size, timeout))
            clock.advance(0.1)
            return next(chunks)

        self.assertEqual(read_exact(read_chunk, 5, Deadline(1.0, clock=clock)), b"abcde")
        self.assertEqual([call[0] for call in calls], [5, 3, 2])
        self.assertAlmostEqual(calls[-1][1], 0.8)

    def test_read_exact_fails_closed_on_eof_and_deadline(self):
        with self.assertRaises(PipePeerClosed):
            read_exact(lambda size, timeout: b"", 1, Deadline(1))
        clock = FakeClock()

        def slow_read(size, timeout):
            clock.advance(1.1)
            return b"x"

        with self.assertRaises(PipeDeadlineExceeded):
            read_exact(slow_read, 2, Deadline(1, clock=clock))
        with self.assertRaises(PipeDeadlineExceeded):
            write_all(
                lambda data, timeout: (clock.advance(1.1) or len(data)),
                b"x",
                Deadline(1, clock=clock),
            )

    def test_write_all_handles_short_writes_and_zero_progress(self):
        chunks = []

        def write_chunk(data, timeout):
            amount = min(2, len(data))
            chunks.append(bytes(data[:amount]))
            return amount

        write_all(write_chunk, b"abcde", Deadline(1))
        self.assertEqual(chunks, [b"ab", b"cd", b"e"])
        with self.assertRaises(PipeNoProgress):
            write_all(lambda data, timeout: 0, b"x", Deadline(1))

    def test_write_all_maps_timeout_to_transport_deadline(self):
        def timed_out(data, timeout):
            raise TimeoutError("native wait timed out")

        with self.assertRaises(PipeDeadlineExceeded):
            write_all(timed_out, b"x", Deadline(1))


if __name__ == "__main__":
    unittest.main()
