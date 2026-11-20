"""Bounded, versioned framing for the Windows process broker IPC.

This module is intentionally platform-neutral: importing and testing the wire
protocol must not load Win32 libraries or create operating-system resources.
"""
from __future__ import annotations

import json
import re
import struct
from typing import BinaryIO, Any

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 1024 * 1024
_HEADER = struct.Struct("!I")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MESSAGE_TYPES = frozenset({
    "broker_ready",
    "launch",
    "launch_result",
    "handles_ack",
    "cancel",
    "broker_error",
})


class ProtocolError(ValueError):
    """Raised when an IPC frame is malformed or violates protocol limits."""


def _reject_constant(value: str) -> None:
    raise ProtocolError(f"non-finite JSON number is not permitted: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def validate_message(message: Any) -> dict[str, Any]:
    """Validate the stable envelope while leaving payload schemas to handlers."""
    if not isinstance(message, dict):
        raise ProtocolError("message must be a JSON object")
    expected = {"version", "type", "request_id", "payload"}
    if set(message) != expected:
        missing = sorted(expected - set(message))
        extra = sorted(set(message) - expected)
        raise ProtocolError(f"invalid message fields (missing={missing}, extra={extra})")
    if type(message["version"]) is not int or message["version"] != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported protocol version: {message['version']!r}")
    message_type = message["type"]
    if not isinstance(message_type, str) or message_type not in _MESSAGE_TYPES:
        raise ProtocolError(f"unsupported message type: {message_type!r}")
    request_id = message["request_id"]
    if not isinstance(request_id, str) or not _REQUEST_ID_RE.fullmatch(request_id):
        raise ProtocolError("request_id must be 1-128 safe ASCII characters")
    if not isinstance(message["payload"], dict):
        raise ProtocolError("payload must be a JSON object")
    return message


def encode_message(message: Any) -> bytes:
    """Encode one message as a 4-byte network-order length plus UTF-8 JSON."""
    validated = validate_message(message)
    try:
        body = json.dumps(
            validated,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ProtocolError(f"message is not JSON-serializable: {exc}") from exc
    if not body or len(body) > MAX_FRAME_BYTES:
        raise ProtocolError(
            f"encoded frame length {len(body)} exceeds limit {MAX_FRAME_BYTES}"
        )
    return _HEADER.pack(len(body)) + body


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = stream.read(length - len(chunks))
        if not chunk:
            raise ProtocolError(
                f"truncated IPC frame: expected {length} bytes, received {len(chunks)}"
            )
        chunks.extend(chunk)
    return bytes(chunks)


def read_message(stream: BinaryIO) -> dict[str, Any]:
    """Read exactly one bounded frame from a blocking binary stream."""
    header = _read_exact(stream, _HEADER.size)
    (length,) = _HEADER.unpack(header)
    if length == 0 or length > MAX_FRAME_BYTES:
        raise ProtocolError(
            f"invalid IPC frame length {length}; maximum is {MAX_FRAME_BYTES}"
        )
    body = _read_exact(stream, length)
    try:
        decoded = body.decode("utf-8", errors="strict")
        message = json.loads(
            decoded,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except ProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"invalid IPC JSON: {exc}") from exc
    return validate_message(message)


def write_message(stream: BinaryIO, message: Any) -> None:
    """Write a complete frame, handling streams that perform short writes."""
    frame = encode_message(message)
    offset = 0
    while offset < len(frame):
        written = stream.write(frame[offset:])
        if written is None or written <= 0:
            raise ProtocolError("IPC stream made no progress while writing")
        offset += written
    flush = getattr(stream, "flush", None)
    if flush is not None:
        flush()
