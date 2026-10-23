"""Original bounded Cursor fixture protocol, independent of Claude framing.

This deliberately narrow synthetic subset does not qualify a vendor CLI,
model route, permissions, continuation or process cessation.
"""
from dataclasses import dataclass
import hashlib
from uuid import UUID

from ..errors import TaskAlongError
from ..validation import canonical_bytes, loads, validate_versioned


@dataclass(frozen=True, slots=True)
class DecodedCursorTurn:
    session_id: str
    reported_model: str
    worker_result_json: bytes
    wire_sha256: str
    wire_bytes: int
    frames: int
    protocol_version: int = 1

    def observation(self):
        """A fresh value describing this stream, never continuation authority."""
        return {"kind": "cursor_fixture_stream_observation", "schema_version": "1.0",
                "session_policy": "fresh", "observed_session_id": self.session_id,
                "reported_model": self.reported_model, "stdout_sha256": self.wire_sha256,
                "stdout_bytes": self.wire_bytes, "frame_count": self.frames}


def _depth(value, level=0):
    if level > 32:
        raise ValueError("nesting bound")
    if type(value) is dict:
        for item in value.values():
            _depth(item, level + 1)
    elif type(value) is list:
        for item in value:
            _depth(item, level + 1)


class CursorStreamDecoder:
    """Observe one fresh session and parse a whole terminal JSON object.

    Success is untrusted worker data. The caller must separately establish
    owned-process cessation, capture association and independent acceptance.
    """
    def __init__(self, packet: dict, *, expected_model: str,
                 max_output_bytes: int = 8 * 1024 * 1024,
                 max_line_bytes: int | None = None, max_frames: int = 4096):
        line_limit = min(max_output_bytes, 1024 * 1024) if type(max_output_bytes) is int else 0
        if max_line_bytes is not None:
            line_limit = max_line_bytes
        if (type(max_output_bytes) is not int or not 1 <= max_output_bytes <= 8 * 1024 * 1024
                or type(line_limit) is not int or not 1 <= line_limit <= min(max_output_bytes, 1024 * 1024)
                or type(max_frames) is not int or not 1 <= max_frames <= 4096):
            raise TaskAlongError("cursor_decoder_limits_invalid", "Wire limits must be bounded integers.")
        if type(expected_model) is not str or not 1 <= len(expected_model) <= 256:
            raise TaskAlongError("cursor_decoder_binding_invalid", "An exact model-report expectation is required.")
        admitted = validate_versioned("worker-packet", packet, expected_version="2.5")
        self._packet = loads(canonical_bytes(admitted))
        self._model = expected_model
        self._line_limit, self._byte_limit, self._frame_limit = line_limit, max_output_bytes, max_frames
        self._pending = bytearray()
        self._hash = hashlib.sha256()
        self._bytes = self._frames = 0
        self._session = None
        self._terminal = self._error = self._finished = None
        self._seen_calls = set()
        self._pending_tools = {}

    def _fail(self, code):
        if self._error is None:
            self._error = TaskAlongError(code, "The Cursor stream did not satisfy its bounded fixture contract.",
                                        exit_code=3, effect_outcome="uncertain")
        raise self._error from None

    def feed(self, chunk: bytes) -> None:
        if self._error is not None:
            raise self._error
        if type(chunk) is not bytes:
            self._fail("cursor_frame_invalid")
        if not chunk:
            return
        if self._finished is not None:
            self._fail("cursor_decoder_closed")
        if len(chunk) + self._bytes > self._byte_limit:
            self._fail("cursor_output_limit")
        self._bytes += len(chunk)
        self._hash.update(chunk)
        offset = 0
        while offset < len(chunk):
            newline = chunk.find(b"\n", offset)
            end = len(chunk) if newline < 0 else newline
            if len(self._pending) + end - offset > self._line_limit:
                self._fail("cursor_line_limit")
            self._pending.extend(chunk[offset:end])
            if newline < 0:
                break
            line = bytes(self._pending)
            self._pending.clear()
            self._frames += 1
            if self._frames > self._frame_limit:
                self._fail("cursor_frame_limit")
            self._consume(line)
            offset = end + 1

    def _consume(self, line):
        if self._terminal is not None:
            self._fail("cursor_event_after_terminal")
        try:
            event = loads(line, max_bytes=self._line_limit)
            _depth(event)
        except (TaskAlongError, ValueError, RecursionError):
            self._fail("cursor_frame_invalid")
        kind = event.get("type")
        if type(kind) is not str:
            self._fail("cursor_frame_invalid")
        if kind == "system":
            if self._session is not None:
                self._fail("cursor_duplicate_init")
            if set(event) != {"type", "subtype", "session_id", "model"} or event["subtype"] != "init":
                self._fail("cursor_init_invalid")
            try:
                valid = type(event["session_id"]) is str and str(UUID(event["session_id"])) == event["session_id"]
            except (ValueError, AttributeError):
                valid = False
            if not valid:
                self._fail("cursor_session_invalid")
            if event["session_id"] in {self._packet[key] for key in ("run_id", "attempt_id", "packet_id")}:
                self._fail("cursor_session_conflict")
            if event["model"] != self._model:
                self._fail("cursor_model_mismatch")
            self._session = event["session_id"]
            return
        if self._session is None:
            self._fail("cursor_init_required")
        if event.get("session_id") != self._session:
            self._fail("cursor_session_mismatch")
        if kind in {"assistant", "user"}:
            self._message(event)
            return
        if kind == "tool_call":
            self._tool(event)
            return
        if kind != "result":
            self._fail("cursor_event_unsupported")
        if set(event) != {"type", "subtype", "is_error", "session_id", "result"}:
            self._fail("cursor_result_invalid")
        if event["subtype"] != "success" or event["is_error"] is not False:
            self._fail("cursor_result_failed")
        if self._pending_tools:
            self._fail("cursor_tool_pending")
        if type(event["result"]) is not str:
            self._fail("cursor_result_invalid")
        try:
            worker = loads(event["result"].encode("utf-8", errors="strict"), max_bytes=self._line_limit)
            _depth(worker)
            worker = validate_versioned("worker-result", worker, expected_version="2.5")
        except (TaskAlongError, ValueError, UnicodeError, RecursionError):
            self._fail("cursor_result_invalid")
        expected = {key: self._packet[key] for key in ("packet_id", "run_id", "attempt_id", "spec_digest", "qualification")}
        expected.update(packet_digest=self._packet["digest"],
            driver_config_digest=self._packet["bindings"]["driver_config_digest"],
            provider_profile_digest=self._packet["bindings"]["provider_profile_digest"])
        if any(worker[key] != value for key, value in expected.items()):
            self._fail("cursor_result_binding_mismatch")
        if worker["status"] != "completed" or worker["blockers"] or worker["deviations"]:
            self._fail("cursor_result_failed")
        self._terminal = canonical_bytes(worker)

    def _message(self, event):
        if set(event) != {"type", "session_id", "message"} or type(event["message"]) is not dict:
            self._fail("cursor_message_invalid")
        message = event["message"]
        if not {"content"} <= set(message) <= {"content", "model"} or type(message["content"]) is not list:
            self._fail("cursor_message_invalid")
        if "model" in message and message["model"] != self._model:
            self._fail("cursor_model_mismatch")
        for content in message["content"]:
            if (type(content) is not dict or set(content) != {"type", "text"}
                    or content["type"] != "text" or type(content["text"]) is not str):
                self._fail("cursor_message_invalid")

    def _tool(self, event):
        required = {"type", "subtype", "session_id", "call_id", "tool", "path"}
        phase = event.get("subtype")
        if type(phase) is not str or phase not in {"started", "completed"}:
            self._fail("cursor_tool_invalid")
        if set(event) != required | ({"is_error"} if phase == "completed" else set()):
            self._fail("cursor_tool_invalid")
        call = event["call_id"]
        if (type(call) is not str or not 1 <= len(call.encode("utf-8")) <= 128
                or any(ord(char) < 32 or ord(char) == 127 for char in call)):
            self._fail("cursor_tool_invalid")
        if event["tool"] != "Edit":
            self._fail("cursor_tool_unsupported")
        if type(event["path"]) is not str or event["path"] not in self._packet["scope"]["files"]:
            self._fail("cursor_tool_scope_mismatch")
        identity = (event["tool"], event["path"])
        if phase == "started":
            if call in self._seen_calls:
                self._fail("cursor_tool_duplicate")
            self._seen_calls.add(call)
            self._pending_tools[call] = identity
            return
        if call not in self._pending_tools:
            self._fail("cursor_tool_order_invalid")
        if self._pending_tools[call] != identity:
            self._fail("cursor_tool_mismatch")
        if event["is_error"] is not False:
            self._fail("cursor_tool_failed")
        del self._pending_tools[call]

    def finish(self, *, exit_code: int) -> DecodedCursorTurn:
        if self._error is not None:
            raise self._error
        if type(exit_code) is not int or exit_code != 0:
            self._fail("cursor_exit_failed")
        if self._pending:
            self._fail("cursor_truncated_frame")
        if self._session is None or self._terminal is None:
            self._fail("cursor_stream_incomplete")
        if self._finished is None:
            self._finished = DecodedCursorTurn(self._session, self._model, self._terminal,
                self._hash.hexdigest(), self._bytes, self._frames)
        return self._finished
