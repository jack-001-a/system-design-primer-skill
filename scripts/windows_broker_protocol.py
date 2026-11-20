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
    _validate_payload(message_type, message["payload"])
    return message


def _require_fields(payload: dict[str, Any], expected: set[str], label: str) -> None:
    if set(payload) != expected:
        missing = sorted(expected - set(payload))
        extra = sorted(set(payload) - expected)
        raise ProtocolError(f"{label} payload fields invalid (missing={missing}, extra={extra})")


def _require_text(value: Any, label: str, *, allow_empty: bool = False, maximum: int = 32767) -> None:
    if not isinstance(value, str) or (not allow_empty and not value) or len(value) > maximum or "\x00" in value:
        raise ProtocolError(f"{label} must be a NUL-free string of at most {maximum} characters")


def _require_handle(value: Any, label: str) -> None:
    if type(value) is not int or value <= 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise ProtocolError(f"{label} must be a positive unsigned 64-bit handle value")


def _validate_payload(message_type: str, payload: dict[str, Any]) -> None:
    if message_type == "broker_ready":
        _require_fields(payload, {"broker_pid"}, message_type)
        if type(payload["broker_pid"]) is not int or payload["broker_pid"] <= 0:
            raise ProtocolError("broker_pid must be a positive integer")
    elif message_type == "launch":
        _require_fields(payload, {"application", "argv", "cwd", "environment", "stdin_handle", "stdout_handle", "stderr_handle"}, message_type)
        _require_text(payload["application"], "application")
        argv = payload["argv"]
        if not isinstance(argv, list) or not argv or len(argv) > 4096:
            raise ProtocolError("argv must be a non-empty list of at most 4096 strings")
        for index, argument in enumerate(argv):
            _require_text(argument, f"argv[{index}]", allow_empty=True)
        cwd = payload["cwd"]
        if cwd is not None:
            _require_text(cwd, "cwd")
        environment = payload["environment"]
        if not isinstance(environment, dict) or len(environment) > 32767:
            raise ProtocolError("environment must be an object with at most 32767 entries")
        for key, value in environment.items():
            _require_text(key, "environment key")
            if "=" in key:
                raise ProtocolError("environment keys must not contain '='")
            _require_text(value, f"environment[{key!r}]", allow_empty=True)
        for name in ("stdin_handle", "stdout_handle", "stderr_handle"):
            _require_handle(payload[name], name)
    elif message_type == "launch_result":
        status = payload.get("status")
        if status == "created":
            _require_fields(payload, {"status", "pid", "process_handle", "job_handle"}, message_type)
            if type(payload["pid"]) is not int or payload["pid"] <= 0:
                raise ProtocolError("pid must be a positive integer")
            _require_handle(payload["process_handle"], "process_handle")
            _require_handle(payload["job_handle"], "job_handle")
        elif status == "failed":
            _require_fields(payload, {"status", "error_code", "message"}, message_type)
            if type(payload["error_code"]) is not int or payload["error_code"] < 0:
                raise ProtocolError("error_code must be a non-negative integer")
            _require_text(payload["message"], "message", allow_empty=True, maximum=4096)
        else:
            raise ProtocolError("launch_result status must be 'created' or 'failed'")
    elif message_type == "handles_ack":
        _require_fields(payload, {"accepted"}, message_type)
        if type(payload["accepted"]) is not bool or not payload["accepted"]:
            raise ProtocolError("handles_ack accepted must be true")
    elif message_type == "cancel":
        _require_fields(payload, set(), message_type)
    elif message_type == "broker_error":
        _require_fields(payload, {"code", "message"}, message_type)
        _require_text(payload["code"], "code", maximum=128)
        _require_text(payload["message"], "message", allow_empty=True, maximum=4096)


class BrokerProtocolState:
    """Enforce one launch request's directional message ordering."""

    _TERMINAL = frozenset({"complete", "failed", "cancelled"})

    def __init__(self, role: str, request_id: str):
        if role not in {"host", "broker"}:
            raise ValueError("role must be 'host' or 'broker'")
        if not isinstance(request_id, str) or not _REQUEST_ID_RE.fullmatch(request_id):
            raise ValueError("request_id must be 1-128 safe ASCII characters")
        self.role = role
        self.request_id = request_id
        self.state = "start"

    def advance(self, direction: str, message: Any) -> str:
        """Apply one sent/received message and return the new state."""
        validated = validate_message(message)
        if direction not in {"send", "receive"}:
            raise ValueError("direction must be 'send' or 'receive'")
        if validated["request_id"] != self.request_id:
            raise ProtocolError("message request_id does not match active request")
        kind = validated["type"]
        payload = validated["payload"]
        if self.state in self._TERMINAL:
            raise ProtocolError(f"message {kind!r} is invalid after terminal state {self.state!r}")
        if kind == "broker_error" and ((self.role == "host" and direction == "receive") or (self.role == "broker" and direction == "send")):
            self.state = "failed"
            return self.state
        if self.role == "host":
            transitions = {
                ("start", "receive", "broker_ready"): "ready",
                ("ready", "send", "launch"): "waiting_result",
                ("waiting_result", "receive", "launch_result"): "result_received" if payload["status"] == "created" else "failed",
                ("result_received", "send", "handles_ack"): "complete",
                ("waiting_result", "send", "cancel"): "cancelled",
            }
        else:
            transitions = {
                ("start", "send", "broker_ready"): "ready",
                ("ready", "receive", "launch"): "launched",
                ("ready", "receive", "cancel"): "cancelled",
                ("launched", "send", "launch_result"): "awaiting_ack" if payload["status"] == "created" else "failed",
                ("launched", "receive", "cancel"): "cancelled",
                ("awaiting_ack", "receive", "handles_ack"): "complete",
                ("awaiting_ack", "receive", "cancel"): "cancelled",
            }
        next_state = transitions.get((self.state, direction, kind))
        if next_state is None:
            raise ProtocolError(f"unexpected {direction} {kind!r} in state {self.state!r}")
        self.state = next_state
        return self.state


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
