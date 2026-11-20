from __future__ import annotations

import io
import struct
import unittest

from scripts.windows_broker_protocol import (
    MAX_FRAME_BYTES,
    PROTOCOL_VERSION,
    ProtocolError,
    encode_message,
    read_message,
    validate_message,
    write_message,
    BrokerProtocolState,
)


def message(payload=None):
    return {
        "version": PROTOCOL_VERSION,
        "type": "launch",
        "request_id": "launch-001",
        "payload": {} if payload is None else payload,
    }


class ShortReadStream(io.BytesIO):
    def read(self, size=-1):
        return super().read(min(size, 2))


class ShortWriteStream:
    def __init__(self):
        self.data = bytearray()
        self.flush_count = 0

    def write(self, data):
        count = min(len(data), 3)
        self.data.extend(data[:count])
        return count

    def flush(self):
        self.flush_count += 1


class WindowsBrokerProtocolTests(unittest.TestCase):
    def test_round_trip_unicode_payload(self):
        original = message({
            "application": "C:\\工具\\worker.exe",
            "argv": ["worker.exe", "", "路径", "a b"],
            "cwd": "C:\\工作",
            "environment": {"LANG": "zh_CN.UTF-8"},
            "stdin_handle": 10, "stdout_handle": 11, "stderr_handle": 12,
        })
        self.assertEqual(read_message(io.BytesIO(encode_message(original))), original)

    def test_reader_handles_short_reads(self):
        original = message({
            "application": "worker.exe", "argv": ["worker.exe", "x" * 100],
            "cwd": None, "environment": {},
            "stdin_handle": 10, "stdout_handle": 11, "stderr_handle": 12,
        })
        self.assertEqual(read_message(ShortReadStream(encode_message(original))), original)

    def test_writer_handles_short_writes_and_flushes(self):
        stream = ShortWriteStream()
        original = message({
            "application": "worker.exe", "argv": ["worker.exe", "short writes"],
            "cwd": None, "environment": {},
            "stdin_handle": 10, "stdout_handle": 11, "stderr_handle": 12,
        })
        write_message(stream, original)
        self.assertEqual(read_message(io.BytesIO(stream.data)), original)
        self.assertEqual(stream.flush_count, 1)

    def test_rejects_unknown_or_missing_envelope_fields(self):
        for invalid in (
            {**message(), "extra": True},
            {key: value for key, value in message().items() if key != "payload"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ProtocolError):
                encode_message(invalid)

    def test_rejects_unsupported_version_and_message_type(self):
        for changes in ({"version": PROTOCOL_VERSION + 1}, {"type": "arbitrary_shell"}):
            invalid = {**message(), **changes}
            with self.subTest(changes=changes), self.assertRaises(ProtocolError):
                encode_message(invalid)

    def test_rejects_unsafe_request_ids_and_non_object_payloads(self):
        for request_id in ("", "../escape", "space id", "x" * 129, "ümlaut"):
            with self.subTest(request_id=request_id), self.assertRaises(ProtocolError):
                encode_message({**message(), "request_id": request_id})
        with self.assertRaises(ProtocolError):
            encode_message({**message(), "payload": []})

    def test_rejects_duplicate_json_keys(self):
        body = (
            b'{"version":1,"type":"launch","request_id":"first",'
            b'"request_id":"second","payload":{}}'
        )
        frame = struct.pack("!I", len(body)) + body
        with self.assertRaisesRegex(ProtocolError, "duplicate JSON object key"):
            read_message(io.BytesIO(frame))

    def test_rejects_invalid_utf8_and_malformed_json(self):
        for body in (b"\xff", b"{"):
            frame = struct.pack("!I", len(body)) + body
            with self.subTest(body=body), self.assertRaises(ProtocolError):
                read_message(io.BytesIO(frame))

    def test_rejects_non_finite_json_numbers(self):
        body = b'{"version":1,"type":"launch","request_id":"x","payload":{"n":NaN}}'
        frame = struct.pack("!I", len(body)) + body
        with self.assertRaisesRegex(ProtocolError, "non-finite"):
            read_message(io.BytesIO(frame))

    def test_rejects_zero_and_oversized_frame_lengths_before_body_read(self):
        for length in (0, MAX_FRAME_BYTES + 1, 0xFFFFFFFF):
            with self.subTest(length=length), self.assertRaises(ProtocolError):
                read_message(io.BytesIO(struct.pack("!I", length)))

    def test_rejects_truncated_header_and_body(self):
        for raw in (b"\x00\x00", struct.pack("!I", 5) + b"{}"):
            with self.subTest(raw=raw), self.assertRaisesRegex(ProtocolError, "truncated"):
                read_message(io.BytesIO(raw))

    def test_validate_message_returns_original_mapping(self):
        candidate = message({
            "application": "worker.exe", "argv": ["worker.exe"], "cwd": None,
            "environment": {}, "stdin_handle": 10, "stdout_handle": 11, "stderr_handle": 12,
        })
        self.assertIs(validate_message(candidate), candidate)

    def _launch_payload(self):
        return {
            "application": "worker.exe", "argv": ["worker.exe"], "cwd": None,
            "environment": {}, "stdin_handle": 10, "stdout_handle": 11, "stderr_handle": 12,
        }

    def test_message_payload_schemas_are_strict(self):
        valid = self._launch_payload()
        validate_message({**message({"broker_pid": 42}), "type": "broker_ready"})
        validate_message({**message({"accepted": True}), "type": "handles_ack"})
        validate_message({**message({}), "type": "cancel"})
        validate_message({**message({"code": "CREATE", "message": "failed"}), "type": "broker_error"})
        for invalid in (
            {**valid, "extra": True},
            {**valid, "stdout_handle": True},
            {**valid, "stderr_handle": 0},
            {**valid, "argv": []},
            {**valid, "application": "bad\x00path"},
            {**valid, "environment": {"=C:": "bad"}},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ProtocolError):
                validate_message(message(invalid))

    def test_launch_result_payload_variants(self):
        for payload in (
            {"status": "created", "pid": 123, "process_handle": 44, "job_handle": 45},
            {"status": "failed", "error_code": 5, "message": "denied"},
        ):
            validate_message({**message(payload), "type": "launch_result"})
        for payload in (
            {"status": "created", "pid": True, "process_handle": 44, "job_handle": 45},
            {"status": "created", "pid": 123, "process_handle": 0, "job_handle": 45},
            {"status": "failed", "error_code": -1, "message": "bad"},
            {"status": "unknown"},
        ):
            with self.subTest(payload=payload), self.assertRaises(ProtocolError):
                validate_message({**message(payload), "type": "launch_result"})

    def test_host_state_machine_requires_ordered_handshake_and_ack(self):
        state = BrokerProtocolState("host", "launch-001")
        self.assertEqual(state.advance("receive", {**message({"broker_pid": 99}), "type": "broker_ready"}), "ready")
        self.assertEqual(state.advance("send", message(self._launch_payload())), "waiting_result")
        self.assertEqual(state.advance("receive", {**message({
            "status": "created", "pid": 123, "process_handle": 44, "job_handle": 45,
        }), "type": "launch_result"}), "result_received")
        self.assertEqual(state.advance("send", {**message({"accepted": True}), "type": "handles_ack"}), "complete")
        with self.assertRaises(ProtocolError):
            state.advance("receive", {**message({}), "type": "cancel"})

    def test_broker_state_machine_rejects_wrong_request_and_out_of_order_events(self):
        state = BrokerProtocolState("broker", "launch-001")
        with self.assertRaises(ProtocolError):
            state.advance("receive", message(self._launch_payload()))
        state.advance("send", {**message({"broker_pid": 99}), "type": "broker_ready"})
        with self.assertRaises(ProtocolError):
            state.advance("receive", {**message(self._launch_payload()), "request_id": "other"})
        state.advance("receive", message(self._launch_payload()))
        state.advance("send", {**message({
            "status": "created", "pid": 123, "process_handle": 44, "job_handle": 45,
        }), "type": "launch_result"})
        self.assertEqual(state.advance("receive", {**message({"accepted": True}), "type": "handles_ack"}), "complete")

    def test_cancel_and_failed_launch_are_terminal(self):
        host = BrokerProtocolState("host", "launch-001")
        host.advance("receive", {**message({"broker_pid": 99}), "type": "broker_ready"})
        host.advance("send", message(self._launch_payload()))
        self.assertEqual(host.advance("send", {**message({}), "type": "cancel"}), "cancelled")
        broker = BrokerProtocolState("broker", "launch-001")
        broker.advance("send", {**message({"broker_pid": 99}), "type": "broker_ready"})
        broker.advance("receive", message(self._launch_payload()))
        self.assertEqual(broker.advance("send", {**message({
            "status": "failed", "error_code": 5, "message": "denied",
        }), "type": "launch_result"}), "failed")


if __name__ == "__main__":
    unittest.main()
