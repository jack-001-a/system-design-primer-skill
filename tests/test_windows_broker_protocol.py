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
        original = message({"argv": ["tool.exe", "", "路径", "a b"], "cwd": "C:\\工作"})
        self.assertEqual(read_message(io.BytesIO(encode_message(original))), original)

    def test_reader_handles_short_reads(self):
        original = message({"value": "x" * 100})
        self.assertEqual(read_message(ShortReadStream(encode_message(original))), original)

    def test_writer_handles_short_writes_and_flushes(self):
        stream = ShortWriteStream()
        original = message({"value": "short writes"})
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
        candidate = message()
        self.assertIs(validate_message(candidate), candidate)


if __name__ == "__main__":
    unittest.main()
