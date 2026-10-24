"""Original bounded Antigravity fixture dialect; no vendor transcript or authority."""
from dataclasses import dataclass
import hashlib
from uuid import UUID

from ..errors import TaskAlongError
from ..validation import canonical_bytes, loads, schema, validate_versioned


def _wire_depth(value, level=0):
    if level > 32:
        raise ValueError("fixture nesting bound")
    if type(value) is dict:
        for item in value.values():
            _wire_depth(item, level + 1)
    elif type(value) is list:
        for item in value:
            _wire_depth(item, level + 1)


@dataclass(frozen=True, slots=True)
class DecodedAntigravityTurn:
    session_id: str
    reported_model: str
    worker_result_json: bytes
    reported_usage_json: bytes
    wire_sha256: str
    wire_bytes: int
    frames: int

    def observation(self):
        return {"kind": "antigravity_fixture_stream_observation", "schema_version": "1.0",
                "session_policy": "fresh", "native_session_kind": "conversation",
                "observed_session_id": self.session_id, "reported_model": self.reported_model,
                "stdout_sha256": self.wire_sha256, "stdout_bytes": self.wire_bytes, "frame_count": self.frames,
                "reported_usage": loads(self.reported_usage_json)}


class AntigravityStreamDecoder:
    """One init/conversation/turn, strict step transitions, then one whole result.

    Parsing is independent of process cessation, policy qualification and core
    acceptance. Even a valid terminal document grants none of those powers.
    """
    def __init__(self, packet, *, expected_model, expected_cwd,
                 max_output_bytes=8 * 1024 * 1024, max_line_bytes=None, max_frames=4096):
        line_limit = min(max_output_bytes, 1024 * 1024) if type(max_output_bytes) is int else 0
        if max_line_bytes is not None:
            line_limit = max_line_bytes
        if (type(max_output_bytes) is not int or not 1 <= max_output_bytes <= 8 * 1024 * 1024
                or type(line_limit) is not int or not 1 <= line_limit <= min(max_output_bytes, 1024 * 1024)
                or type(max_frames) is not int or not 1 <= max_frames <= 4096):
            raise TaskAlongError("agy_decoder_limits_invalid", "Wire limits must be bounded integers.")
        if (type(expected_model) is not str or not 1 <= len(expected_model) <= 256
                or type(expected_cwd) is not str or not 1 <= len(expected_cwd) <= 4096):
            raise TaskAlongError("agy_decoder_binding_invalid", "Exact model and working-directory observations are required.")
        self._packet = validate_versioned("worker-packet", packet, expected_version="2.6")
        self._model, self._cwd = expected_model, expected_cwd
        self._schema = schema("worker-result", version="2.5")
        self._line_limit, self._byte_limit, self._frame_limit = line_limit, max_output_bytes, max_frames
        self._pending, self._hash = bytearray(), hashlib.sha256()
        self._bytes = self._frames = 0
        self._session = self._terminal = self._error = self._finished = None
        self._steps, self._user_step = {}, None
        self._usage = self._read_usage(None)

    def _fail(self, code):
        if self._error is None:
            self._error = TaskAlongError(code, "The Antigravity stream did not satisfy its original fixture contract.",
                                        exit_code=3, effect_outcome="uncertain")
        raise self._error from None

    def feed(self, chunk):
        if self._error is not None:
            raise self._error
        if type(chunk) is not bytes:
            self._fail("agy_frame_invalid")
        if not chunk:
            return
        if self._finished is not None:
            self._fail("agy_decoder_closed")
        if self._bytes + len(chunk) > self._byte_limit:
            self._fail("agy_output_limit")
        self._bytes += len(chunk)
        self._hash.update(chunk)
        offset = 0
        while offset < len(chunk):
            newline = chunk.find(b"\n", offset)
            end = len(chunk) if newline < 0 else newline
            if len(self._pending) + end - offset > self._line_limit:
                self._fail("agy_line_limit")
            self._pending.extend(chunk[offset:end])
            if newline < 0:
                break
            raw = bytes(self._pending)
            self._pending.clear()
            self._frames += 1
            if self._frames > self._frame_limit:
                self._fail("agy_frame_limit")
            self._consume(raw)
            offset = end + 1

    def _consume(self, raw):
        if self._terminal is not None:
            self._fail("agy_event_after_terminal")
        try:
            event = loads(raw, max_bytes=self._line_limit)
            _wire_depth(event)
        except (TaskAlongError, ValueError, RecursionError):
            self._fail("agy_frame_invalid")
        kind = event.get("type")
        if type(kind) is not str:
            self._fail("agy_frame_invalid")
        if kind == "init":
            if self._session is not None:
                self._fail("agy_duplicate_init")
            expected = {"type": "init", "model": self._model, "tools": ["write_file"],
                        "permission_mode": "request-review", "cwd": self._cwd,
                        "json_schema": self._schema, "agent": "fixture-agent"}
            if (set(event) != set(expected) | {"conversation_id"}
                    or any(canonical_bytes(event[k]) != canonical_bytes(v) for k, v in expected.items())):
                self._fail("agy_init_mismatch")
            session = event["conversation_id"]
            try:
                valid = type(session) is str and str(UUID(session)) == session
            except (ValueError, AttributeError):
                valid = False
            if not valid:
                self._fail("agy_conversation_invalid")
            if session in {self._packet[k] for k in ("run_id", "attempt_id", "packet_id")}:
                self._fail("agy_conversation_conflict")
            self._session = session
            return
        if self._session is None:
            self._fail("agy_init_required")
        if event.get("conversation_id") != self._session:
            self._fail("agy_conversation_mismatch")
        if kind == "step_update":
            self._step(event)
            return
        if kind != "result":
            self._fail("agy_event_unsupported")
        required = {"type", "conversation_id", "status", "num_turns", "structured_output"}
        if not required <= set(event) <= required | {"response", "json_schema", "error", "usage"}:
            self._fail("agy_result_invalid")
        if (event["status"] != "SUCCESS" or type(event["num_turns"]) is not int or event["num_turns"] != 1
                or event.get("error") is not None):
            self._fail("agy_result_failed")
        if ("response" in event and type(event["response"]) is not str
                or "json_schema" in event and canonical_bytes(event["json_schema"]) != canonical_bytes(self._schema)):
            self._fail("agy_result_invalid")
        if any(status != "DONE" for _, status in self._steps.values()):
            self._fail("agy_step_pending")
        try:
            worker = validate_versioned("worker-result", event["structured_output"], expected_version="2.5")
        except TaskAlongError:
            self._fail("agy_result_invalid")
        expected = {key: self._packet[key] for key in ("packet_id", "run_id", "attempt_id", "spec_digest", "qualification")}
        expected.update(packet_digest=self._packet["digest"],
                        driver_config_digest=self._packet["bindings"]["driver_config_digest"],
                        provider_profile_digest=self._packet["bindings"]["provider_profile_digest"])
        if any(worker[key] != value for key, value in expected.items()):
            self._fail("agy_result_binding_mismatch")
        if worker["status"] != "completed" or worker["blockers"] or worker["deviations"]:
            self._fail("agy_result_failed")
        self._usage = self._read_usage(event.get("usage"))
        self._terminal = canonical_bytes(worker)

    def _read_usage(self, value):
        result = {"input_tokens": None, "output_tokens": None, "total_tokens": None}
        if value is None:
            return result
        if type(value) is not dict or not set(value) <= set(result):
            self._fail("agy_usage_invalid")
        for key, count in value.items():
            if type(count) is not int or not 0 <= count <= 2**53 - 1:
                self._fail("agy_usage_invalid")
            result[key] = count
        return result

    def _step(self, event):
        if set(event) != {"type", "conversation_id", "step"} or type(event["step"]) is not dict:
            self._fail("agy_step_invalid")
        step = event["step"]
        index, kind, status = (step.get(key) for key in ("index", "kind", "status"))
        if (type(index) is not int or not 0 <= index <= 65535 or type(kind) is not str
                or kind not in {"tool", "text", "user_input"} or type(status) is not str
                or status not in {"ACTIVE", "DONE"}):
            self._fail("agy_step_invalid")
        required = {"index", "kind", "status"}
        if kind == "tool":
            required |= {"tool", "tool_info"}
            info = step.get("tool_info")
            if (step.get("tool") != "write_file" or type(info) is not dict
                    or set(info) != {"name", "parameters", "error", "permission_denied"}
                    or info["name"] != step["tool"] or type(info["parameters"]) is not dict
                    or set(info["parameters"]) != {"path"}
                    or type(info["parameters"]["path"]) is not str
                    or info["parameters"]["path"] not in self._packet["scope"]["files"]):
                self._fail("agy_tool_invalid")
            if info["error"] is not None or info["permission_denied"] is not False:
                self._fail("agy_tool_failed")
            identity = canonical_bytes({"kind": kind, "tool": step["tool"], "parameters": info["parameters"]})
        else:
            required |= {"content"}
            if type(step.get("content")) is not str:
                self._fail("agy_step_invalid")
            if kind == "user_input":
                if (step["content"] != canonical_bytes(self._packet).decode()
                        or self._user_step is not None and self._user_step != index):
                    self._fail("agy_extra_turn")
                self._user_step = index
            identity = canonical_bytes({"kind": kind})
        if set(step) != required and set(step) != required | {"usage"}:
            self._fail("agy_step_invalid")
        if "usage" in step:
            self._read_usage(step["usage"])
        previous = self._steps.get(index)
        if previous is not None and (previous[0] != identity or previous[1] == "DONE"):
            self._fail("agy_step_transition_invalid")
        self._steps[index] = (identity, status)

    def finish(self, *, exit_code):
        if self._error is not None:
            raise self._error
        if type(exit_code) is not int or exit_code != 0:
            self._fail("agy_exit_failed")
        if self._pending:
            self._fail("agy_truncated_frame")
        if self._session is None or self._terminal is None:
            self._fail("agy_stream_incomplete")
        if self._finished is None:
            self._finished = DecodedAntigravityTurn(self._session, self._model, self._terminal,
                canonical_bytes(self._usage), self._hash.hexdigest(), self._bytes, self._frames)
        return self._finished
