"""Bounded observations of the documented native agy stream; no process effects.

Wire examples in tests are original offline examples of the public protocol at
https://antigravity.google/docs/cli/headless/, not captured vendor executions.
This decoder never supplies admission, tool authority, acceptance or cessation
evidence. Raw response/output bytes belong in private core-owned captures.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError
from referencing.exceptions import Unresolvable

from ..errors import TaskAlongError


_TOKEN_FIELDS = {"input_tokens", "output_tokens", "thinking_tokens", "cache_read_tokens", "total_tokens"}
_STATUSES = {"SUCCESS", "ERROR", "CANCELED", "INTERRUPTED", "INVALID", "WAITING", "RUNNING"}
_MAX_BYTES = 64 * 1024 * 1024


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _walk(value, depth=0):
    if depth > 32:
        raise ValueError("native JSON depth")
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("native JSON key")
            key.encode("utf-8")
            _walk(item, depth + 1)
    elif type(value) is list:
        for item in value:
            _walk(item, depth + 1)
    elif type(value) is float:
        if not math.isfinite(value):
            raise ValueError("native JSON number")
    elif type(value) is str:
        value.encode("utf-8")
    elif type(value) not in {str, int, bool, type(None)}:
        raise ValueError("native JSON value")
    elif type(value) is int and abs(value) > 2**53 - 1:
        raise ValueError("native JSON integer")


def checked_native_schema(value):
    """Copy a bounded local schema; never resolve a network or file reference."""
    try:
        if type(value) is not dict:
            raise ValueError("object schema required")
        _walk(value)
        raw = _json_bytes(value)
        if len(raw) > 1024 * 1024:
            raise ValueError("schema size")
        copied = json.loads(raw)
        pending = [copied]
        while pending:
            item = pending.pop()
            if type(item) is dict:
                for key, target in item.items():
                    if key in {"$ref", "$dynamicRef", "$recursiveRef"} and (
                            type(target) is not str or not target.startswith("#")):
                        raise ValueError("nonlocal schema reference")
                    # A nested resource changes the base URI of fragment refs.
                    if item is not copied and "$id" in item:
                        raise ValueError("nested schema resource")
                    pending.append(target)
            elif type(item) is list:
                pending.extend(item)
        Draft202012Validator.check_schema(copied)
        return copied
    except (ValueError, TypeError, OverflowError, UnicodeError, RecursionError, SchemaError):
        raise TaskAlongError("agy_native_schema_invalid", "Native Antigravity requires a bounded self-contained result schema.",
                             exit_code=3, effect_outcome="not_sent") from None


def encode_native_input(prompt):
    """One documented user event followed by EOF, with no slash expansion."""
    try:
        if type(prompt) is not str or not prompt or len(prompt.encode()) > 8 * 1024 * 1024:
            raise ValueError("prompt size")
        return _json_bytes({"event": "user", "message": {"content": prompt}}) + b"\n"
    except (ValueError, UnicodeError):
        raise TaskAlongError("agy_native_input_invalid", "Native Antigravity requires one bounded UTF-8 prompt.",
                             exit_code=3, effect_outcome="not_sent") from None


@dataclass(frozen=True, slots=True)
class NativeAntigravityTurn:
    conversation_id: str
    reported_model: str
    available_tools: tuple[str, ...]
    provider_status: str
    structured_output_json: bytes | None
    response: str
    reported_usage_json: bytes
    successful: bool
    error_code: str | None
    stdout_sha256: str
    stdout_bytes: int
    frame_count: int

    def observation(self):
        """Safe metadata, excluding provider prose, tool output and task data."""
        return {"kind": "antigravity_native_stream_observation", "version": 1,
                "conversation_id": self.conversation_id, "reported_model": self.reported_model,
                "effective_effort": None, "provider_status": self.provider_status,
                "successful": self.successful, "error_code": self.error_code,
                "reported_usage": json.loads(self.reported_usage_json),
                "usage_scope": "provider_reported_cumulative_session_snapshot",
                "stdout_sha256": self.stdout_sha256, "stdout_bytes": self.stdout_bytes,
                "frame_count": self.frame_count, "production_dispatch_allowed": False}


class NativeAntigravityDecoder:
    """Decode one fresh turn. Unknown/malformed wire stays a sticky failure.

    Native durations may be finite decimals. Canonical TaskAlong documents keep
    their separate integer-only contract. Usage remains a terminal cumulative
    snapshot; per-step counters are validated but never added to terminal totals.
    """

    def __init__(self, *, expected_model, expected_cwd, result_schema,
                 max_output_bytes=8 * 1024 * 1024, max_line_bytes=None, max_frames=65536):
        if (type(max_output_bytes) is not int or not 1 <= max_output_bytes <= _MAX_BYTES
                or type(max_frames) is not int or not 1 <= max_frames <= 262144):
            self._invalid_configuration()
        line_limit = min(max_output_bytes, 8 * 1024 * 1024) if max_line_bytes is None else max_line_bytes
        if type(line_limit) is not int or not 1 <= line_limit <= min(max_output_bytes, 8 * 1024 * 1024):
            self._invalid_configuration()
        if (type(expected_model) is not str or not 1 <= len(expected_model) <= 256
                or type(expected_cwd) is not str or not 1 <= len(expected_cwd) <= 4096):
            self._invalid_configuration()
        self._schema = checked_native_schema(result_schema)
        self._validator = Draft202012Validator(self._schema)
        self._model, self._cwd = expected_model, expected_cwd
        self._byte_limit, self._line_limit, self._frame_limit = max_output_bytes, line_limit, max_frames
        self._pending, self._hash = bytearray(), hashlib.sha256()
        self._bytes = self._frames = 0
        self._session = self._tools = self._terminal = self._finished = self._error = None
        self._finish_signature = None
        self._steps = {}
        self._user_step = None
        self._tool_failed = False

    @property
    def conversation_id(self):
        """Observed after a valid init, for the shared owner's durable receipt."""
        return self._session

    @staticmethod
    def _invalid_configuration():
        raise TaskAlongError("agy_native_decoder_invalid", "Native Antigravity decoding requires exact identities and finite limits.",
                             exit_code=3, effect_outcome="not_sent")

    def _fail(self, code):
        if self._error is None:
            self._error = TaskAlongError(code, "The native Antigravity stream could not be validated; retain private captures.",
                                        exit_code=3, effect_outcome="uncertain")
        raise self._error from None

    def feed(self, chunk):
        if self._error is not None:
            raise self._error
        if type(chunk) is not bytes:
            self._fail("agy_native_frame_invalid")
        if not chunk:
            return
        if self._finished is not None:
            self._fail("agy_native_decoder_closed")
        if self._bytes + len(chunk) > self._byte_limit:
            self._fail("agy_native_output_limit")
        self._bytes += len(chunk)
        self._hash.update(chunk)
        offset = 0
        while offset < len(chunk):
            newline = chunk.find(b"\n", offset)
            end = len(chunk) if newline < 0 else newline
            if len(self._pending) + end - offset > self._line_limit:
                self._fail("agy_native_line_limit")
            self._pending.extend(chunk[offset:end])
            if newline < 0:
                break
            raw = bytes(self._pending)
            self._pending.clear()
            self._frames += 1
            if self._frames > self._frame_limit:
                self._fail("agy_native_frame_limit")
            self._consume(raw)
            offset = end + 1

    @staticmethod
    def _pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate native JSON key")
            result[key] = value
        return result

    def _consume(self, raw):
        if self._terminal is not None:
            self._fail("agy_native_event_after_terminal")
        try:
            event = json.loads(raw.decode("utf-8"), object_pairs_hook=self._pairs)
            _walk(event)
        except (ValueError, UnicodeError, RecursionError):
            self._fail("agy_native_frame_invalid")
        if type(event) is not dict:
            self._fail("agy_native_frame_invalid")
        kind = event.get("event")
        if kind == "init":
            self._init(event)
        elif self._session is None:
            self._fail("agy_native_init_required")
        elif kind == "step_update":
            if set(event) != {"event", "step_update"}:
                self._fail("agy_native_frame_invalid")
            self._step(event["step_update"])
        elif kind == "result":
            if set(event) != {"event", "result"}:
                self._fail("agy_native_frame_invalid")
            self._result(event["result"])
        else:
            self._fail("agy_native_event_unsupported")

    def _init(self, event):
        if self._session is not None:
            self._fail("agy_native_duplicate_init")
        if set(event) != {"event", "conversation_id", "init"} or type(event["init"]) is not dict:
            self._fail("agy_native_init_invalid")
        session, data = event["conversation_id"], event["init"]
        if (type(session) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,255}", session)
                or not {"cwd", "tools", "permission_mode", "model", "json_schema"} <= set(data)
                or not set(data) <= {"cwd", "tools", "permission_mode", "model", "json_schema", "agent"}
                or data["cwd"] != self._cwd or data["model"] != self._model
                or data["permission_mode"] != "request-review"
                or _json_bytes(data["json_schema"]) != _json_bytes(self._schema)
                or "agent" in data and (type(data["agent"]) is not str or not 1 <= len(data["agent"]) <= 256)):
            self._fail("agy_native_init_mismatch")
        tools = data["tools"]
        if (type(tools) is not list or len(tools) > 256
                or any(type(tool) is not str or not 1 <= len(tool) <= 256 for tool in tools)
                or len(set(tools)) != len(tools)):
            self._fail("agy_native_tools_invalid")
        self._session, self._tools = session, tuple(tools)

    def _usage(self, value):
        result = dict.fromkeys(sorted(_TOKEN_FIELDS))
        if value is None:
            return result
        if type(value) is not dict or not set(value) <= _TOKEN_FIELDS:
            self._fail("agy_native_usage_invalid")
        for key, count in value.items():
            if type(count) is not int or not 0 <= count <= 2**53 - 1:
                self._fail("agy_native_usage_invalid")
            result[key] = count
        return result

    def _duration(self, value):
        if type(value) not in {int, float} or not math.isfinite(value) or value < 0:
            self._fail("agy_native_duration_invalid")

    def _step(self, step):
        if type(step) is not dict:
            self._fail("agy_native_step_invalid")
        required = {"conversation_id", "step_index", "state", "step_type"}
        allowed = required | {"tool_name", "text_delta", "duration_seconds", "usage", "tool_info", "subagent_info"}
        if not required <= set(step) or not set(step) <= allowed or step["conversation_id"] != self._session:
            self._fail("agy_native_step_invalid")
        if "subagent_info" in step:
            self._fail("agy_native_subagent_unsupported")
        index, state, kind = step["step_index"], step["state"], step["step_type"]
        if (type(index) is not int or not 0 <= index <= 2**31 - 1
                or type(state) is not str or state not in {"ACTIVE", "DONE"}
                or type(kind) is not str or kind not in {"user_input", "agent_response", "tool", "checkpoint"}):
            self._fail("agy_native_step_invalid")
        if "duration_seconds" in step:
            self._duration(step["duration_seconds"])
        if "usage" in step:
            self._usage(step["usage"])
        if "text_delta" in step and (type(step["text_delta"]) is not str or kind != "agent_response"):
            self._fail("agy_native_step_invalid")
        tool, parameters = None, None
        if kind == "tool":
            tool = step.get("tool_name")
            if type(tool) is not str or tool not in self._tools:
                self._fail("agy_native_tool_invalid")
            info = step.get("tool_info")
            if info is not None:
                if (type(info) is not dict or info.get("name") != tool
                        or not {"name", "parameters"} <= set(info)
                        or not set(info) <= {"name", "parameters", "output", "error", "permission_denied"}
                        or type(info["parameters"]) is not dict):
                    self._fail("agy_native_tool_invalid")
                parameters = _json_bytes(info["parameters"])
                error = info.get("error")
                if error is not None:
                    if (type(error) is not dict or set(error) != {"type", "message"}
                            or type(error["type"]) is not str or type(error["message"]) is not str):
                        self._fail("agy_native_tool_invalid")
                    self._tool_failed = True
                if "permission_denied" in info:
                    if type(info["permission_denied"]) is not bool:
                        self._fail("agy_native_tool_invalid")
                    self._tool_failed |= info["permission_denied"]
            if state == "DONE" and info is None:
                self._fail("agy_native_tool_result_missing")
        elif "tool_name" in step or "tool_info" in step:
            self._fail("agy_native_step_invalid")
        previous = self._steps.get(index)
        if previous is not None:
            previous_kind, previous_tool, previous_parameters, previous_state = previous
            if (previous_state == "DONE" or previous_kind != kind or previous_tool != tool
                    or previous_parameters is not None and parameters is not None and previous_parameters != parameters):
                self._fail("agy_native_step_transition_invalid")
            if parameters is None:
                parameters = previous_parameters
        elif len(self._steps) >= 65536:
            self._fail("agy_native_step_limit")
        if kind == "user_input":
            if self._user_step is not None and self._user_step != index:
                self._fail("agy_native_extra_turn")
            self._user_step = index
        self._steps[index] = (kind, tool, parameters, state)

    def _result(self, result):
        required = {"conversation_id", "status", "response", "num_turns"}
        if (type(result) is not dict or not required <= set(result)
                or not set(result) <= required | {"duration_seconds", "usage", "structured_output", "json_schema", "error"}
                or result["conversation_id"] != self._session
                or type(result["status"]) is not str or result["status"] not in _STATUSES
                or type(result["response"]) is not str or type(result["num_turns"]) is not int
                or not 0 <= result["num_turns"] <= 1
                or result.get("error") is not None and type(result["error"]) is not str):
            self._fail("agy_native_result_invalid")
        if "duration_seconds" in result:
            self._duration(result["duration_seconds"])
        if "json_schema" in result and _json_bytes(result["json_schema"]) != _json_bytes(self._schema):
            self._fail("agy_native_schema_mismatch")
        usage = self._usage(result.get("usage"))
        if result["status"] == "SUCCESS":
            if result["num_turns"] != 1 or result.get("error") or "structured_output" not in result:
                self._fail("agy_native_result_inconsistent")
            if any(step[3] != "DONE" for step in self._steps.values()):
                self._fail("agy_native_step_pending")
            try:
                self._validator.validate(result["structured_output"])
            except (ValidationError, Unresolvable, ValueError, RecursionError):
                self._fail("agy_native_structured_output_invalid")
        self._terminal = (result, usage)

    def finish(self, *, exit_code, stderr=b""):
        """Return a protocol observation after EOF, never a cessation claim.

        Even a valid SUCCESS is unsuccessful if stderr is unclassified, a tool
        failed, or the process exited nonzero. Failed provider statuses retain
        their observed identity and usage instead of manufacturing a result.
        """
        if self._error is not None:
            raise self._error
        if type(exit_code) is not int or type(stderr) is not bytes:
            self._fail("agy_native_exit_invalid")
        signature = (exit_code, hashlib.sha256(stderr).digest(), len(stderr))
        if self._finished is not None:
            if self._finish_signature != signature:
                self._fail("agy_native_finish_conflict")
            return self._finished
        if self._pending:
            self._fail("agy_native_truncated_frame")
        if self._terminal is None:
            self._fail("agy_native_stream_incomplete")
        if self._bytes + len(stderr) > self._byte_limit:
            self._fail("agy_native_output_limit")
        result, usage = self._terminal
        status = result["status"]
        error = None
        if status != "SUCCESS":
            error = "agy_native_turn_incomplete" if status in {"WAITING", "RUNNING"} else "agy_native_provider_failed"
        elif exit_code != 0:
            error = "agy_native_exit_failed"
        elif stderr:
            error = "agy_native_diagnostics_unqualified"
        elif self._tool_failed:
            error = "agy_native_tool_failed"
        self._finished = NativeAntigravityTurn(self._session, self._model, self._tools, status,
            _json_bytes(result["structured_output"]) if "structured_output" in result else None,
            result["response"], _json_bytes(usage), error is None, error,
            self._hash.hexdigest(), self._bytes, self._frames)
        self._finish_signature = signature
        return self._finished
