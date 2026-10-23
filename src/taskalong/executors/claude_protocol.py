"""Experimental, offline Claude stream contract. No launcher or admission path.

Synthetic tests establish decoding only, not compatibility with an installed CLI,
actual model routing, permissions, cancellation, resume or process cessation.
"""
from dataclasses import dataclass, replace
import hashlib
import json
from decimal import Decimal, DecimalException
from uuid import UUID

from ..errors import TaskAlongError
from ..validation import canonical_bytes, loads, validate, validate_versioned


_MAX_INT = 2**53 - 1


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _integer(text):
    if len(text) > 32:
        raise ValueError("integer bound")
    value = int(text)
    if abs(value) > _MAX_INT:
        raise ValueError("integer bound")
    return value


def _decimal(text):
    if len(text) > 128:
        raise ValueError("decimal bound")
    value = Decimal(text)
    if not value.is_finite() or abs(value.adjusted()) > 1024 or value.copy_abs() > _MAX_INT:
        raise ValueError("decimal bound")
    return value


def _constant(text):
    raise ValueError("nonfinite number")


def _shape(value, depth=0):
    if depth > 32:
        raise ValueError("nesting bound")
    if type(value) is dict:
        if len(value) > 4096:
            raise ValueError("object bound")
        for key, item in value.items():
            _shape(key, depth+1)
            _shape(item, depth+1)
    elif type(value) is list:
        if len(value) > 4096:
            raise ValueError("array bound")
        for item in value:
            _shape(item, depth+1)
    elif type(value) is str:
        value.encode("utf-8", errors="strict")


def _wire_frame(line):
    event = json.loads(line.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                       parse_int=_integer, parse_float=_decimal, parse_constant=_constant)
    if type(event) is not dict:
        raise ValueError("object root required")
    _shape(event)
    return event


@dataclass(frozen=True, slots=True)
class DecodedClaudeTurn:
    session_id: str
    reported_model: str
    reported_tools: tuple[str, ...]
    worker_result_json: bytes
    reported_usage_json: bytes
    wire_sha256: str
    wire_bytes: int
    frames: int
    protocol_version: int = 1


class ClaudeStreamDecoder:
    """One init and one terminal result; caller must retain owned process proof.

    Even a valid turn is untrusted worker data. No acceptance, provider identity,
    native-resume or cessation receipt is produced. Errors remain uncertain as
    this decoder cannot establish what a process or remote provider has done.
    """
    def __init__(self, packet: dict, *, expected_session_id: str, expected_model: str,
                 max_output_bytes: int = 8 * 1024 * 1024,
                 max_line_bytes: int | None = None, max_frames: int = 4096):
        line_limit = min(max_output_bytes, 1024 * 1024) if type(max_output_bytes) is int else 0
        if max_line_bytes is not None:
            line_limit = max_line_bytes
        if (type(max_output_bytes) is not int or not 1 <= max_output_bytes <= 8 * 1024 * 1024
                or type(line_limit) is not int or not 1 <= line_limit <= min(max_output_bytes, 1024 * 1024)
                or type(max_frames) is not int or not 1 <= max_frames <= 4096):
            raise TaskAlongError("claude_decoder_limits_invalid", "Wire limits must be explicit bounded integers.")
        try:
            valid_session = type(expected_session_id) is str and str(UUID(expected_session_id)) == expected_session_id
        except (ValueError, AttributeError):
            valid_session = False
        if not valid_session or type(expected_model) is not str or not 1 <= len(expected_model) <= 256:
            raise TaskAlongError("claude_decoder_binding_invalid", "An exact session and reported-model expectation are required.")
        self._packet = self._admit_packet(packet)
        self._session = expected_session_id
        self._model = expected_model
        self._line_limit, self._byte_limit, self._frame_limit = line_limit, max_output_bytes, max_frames
        self._pending = bytearray()
        self._hash = hashlib.sha256()
        self._bytes = self._frames = 0
        self._initialized = False
        self._tools = ()
        self._terminal = None
        self._terminal_usage = None
        self._error = None
        self._finished = None

    @staticmethod
    def _admit_packet(packet):
        return loads(canonical_bytes(validate("worker-packet", packet)))

    def _admit_worker_result(self, worker):
        validate("worker-result", worker)

    def _fail(self, code):
        if self._error is None:
            self._error = TaskAlongError(code, "The Claude wire stream did not satisfy its bounded contract.",
                                       exit_code=3, effect_outcome="uncertain")
        raise self._error from None

    def _model_matches(self, model):
        if model != self._model:
            self._fail("claude_model_mismatch")

    def feed(self, chunk: bytes) -> None:
        if self._error is not None:
            raise self._error
        if type(chunk) is not bytes:
            self._fail("claude_frame_invalid")
        if not chunk:
            return
        if self._finished is not None:
            self._fail("claude_decoder_closed")
        if len(chunk) + self._bytes > self._byte_limit:
            self._fail("claude_output_limit")
        self._bytes += len(chunk)
        self._hash.update(chunk)
        position = 0
        while position < len(chunk):
            newline = chunk.find(b"\n", position)
            end = len(chunk) if newline == -1 else newline
            if len(self._pending) + end - position > self._line_limit:
                self._fail("claude_line_limit")
            self._pending.extend(chunk[position:end])
            if newline == -1:
                break
            line = bytes(self._pending)
            self._pending.clear()
            self._frames += 1
            if self._frames > self._frame_limit:
                self._fail("claude_frame_limit")
            self._consume(line)
            position = end + 1

    def _consume(self, line):
        if self._terminal is not None:
            self._fail("claude_event_after_terminal")
        try:
            event = _wire_frame(line)
        except (ValueError, UnicodeError, RecursionError, DecimalException):
            self._fail("claude_frame_invalid")
        if event.get("session_id") != self._session:
            self._fail("claude_session_mismatch")
        if event.get("parent_tool_use_id") is not None:
            self._fail("claude_child_session_unsupported")
        kind = event.get("type")
        if event.get("error") is not None or event.get("api_error_status") is not None:
            self._fail("claude_provider_error")
        if event.get("origin") is not None:
            origin = event["origin"]
            if type(origin) is not dict or origin.get("kind") != "human":
                self._fail("claude_unsolicited_turn")
        if not self._initialized:
            if kind != "system" or event.get("subtype") != "init":
                self._fail("claude_init_missing")
            self._model_matches(event.get("model"))
            tools = event.get("tools")
            if (type(tools) is not list or len(tools) > 256
                    or any(type(t) is not str or not 1 <= len(t) <= 128 for t in tools)
                    or len(set(tools)) != len(tools)):
                self._fail("claude_init_invalid")
            self._tools = tuple(tools)
            self._initialized = True
            return
        if kind == "result":
            if (event.get("subtype") != "success" or event.get("is_error") is not False
                    or event.get("errors") not in (None, [])
                    or event.get("deferred_tool_use") is not None
                    or event.get("terminal_reason") not in (None, "completed")):
                self._fail("claude_result_failed")
            if type(event.get("permission_denials")) is not list:
                self._fail("claude_permission_status_unknown")
            if event["permission_denials"]:
                self._fail("claude_permission_denied")
            models = event.get("modelUsage")
            if models is not None:
                if type(models) is not dict:
                    self._fail("claude_usage_invalid")
                for model in models:
                    self._model_matches(model)
            worker = event.get("structured_output")
            try:
                self._admit_worker_result(worker)
                encoded = canonical_bytes(worker)
            except (TaskAlongError, TypeError):
                self._fail("claude_result_invalid")
            for key in ("packet_id", "run_id", "attempt_id", "spec_digest", "qualification"):
                if worker[key] != self._packet[key]:
                    self._fail("claude_result_binding_mismatch")
            if (worker["packet_digest"] != self._packet["digest"] or worker["status"] != "completed"
                    or worker["blockers"] or worker["deviations"]):
                self._fail("claude_result_binding_mismatch")
            self._terminal_usage = self._reported_usage(event)
            self._terminal = encoded
        elif kind == "system":
            if event.get("subtype") == "permission_denied":
                self._fail("claude_permission_denied")
            if event.get("subtype") not in {"status", "compact_boundary"}:
                self._fail("claude_event_unsupported")
        elif kind in {"assistant", "user"}:
            message = event.get("message")
            if type(message) is not dict:
                self._fail("claude_frame_invalid")
            if kind == "assistant":
                self._model_matches(message.get("model"))
            content = message.get("content")
            if type(content) is list:
                for block in content:
                    if type(block) is not dict or type(block.get("type")) is not str:
                        self._fail("claude_frame_invalid")
                    if "is_error" in block and type(block["is_error"]) is not bool:
                        self._fail("claude_tool_status_invalid")
                    if block.get("is_error") is True:
                        self._fail("claude_tool_error")
            elif kind == "assistant" or type(content) is not str:
                self._fail("claude_frame_invalid")
        elif kind == "stream_event":
            inner = event.get("event")
            if type(inner) is not dict or type(inner.get("type")) is not str:
                self._fail("claude_frame_invalid")
            if inner["type"] == "error":
                self._fail("claude_provider_error")
            if inner["type"] == "message_start":
                message = inner.get("message")
                if type(message) is not dict:
                    self._fail("claude_frame_invalid")
                self._model_matches(message.get("model"))
        elif kind == "rate_limit_event":
            info = event.get("rate_limit_info")
            if type(info) is not dict or info.get("status") not in {"allowed", "allowed_warning"}:
                self._fail("claude_provider_error")
        else:
            self._fail("claude_event_unsupported")

    def _reported_usage(self, event):
        # Terminal metadata only: no stream-delta summation or billing proof.
        # Its per-turn versus cumulative scope remains unknown until qualified.
        usage = event.get("usage")
        if usage is None:
            usage = {}
        if type(usage) is not dict:
            self._fail("claude_usage_invalid")
        normalized = {"counter_scope": "terminal_reported_scope_unknown"}
        for name in ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"):
            value = usage.get(name)
            if value is not None and (type(value) is not int or not 0 <= value <= _MAX_INT):
                self._fail("claude_usage_invalid")
            normalized[name] = value
        cost = event.get("total_cost_usd")
        if cost is None:
            normalized["cost_micro_usd"] = None
        else:
            if (type(cost) not in (int, Decimal)
                    or isinstance(cost, Decimal) and not cost.is_finite() or cost < 0):
                self._fail("claude_usage_invalid")
            numerator, denominator = Decimal(cost).as_integer_ratio()
            micros = (numerator * 1_000_000 + denominator - 1) // denominator
            if micros > _MAX_INT:
                self._fail("claude_usage_invalid")
            normalized["cost_micro_usd"] = micros
        return canonical_bytes(normalized)

    def finish(self, *, exit_code: int) -> DecodedClaudeTurn:
        if self._error is not None:
            raise self._error
        if type(exit_code) is not int or exit_code != 0:
            self._fail("claude_exit_failed")
        if self._finished is not None:
            return self._finished
        if self._pending:
            self._fail("claude_stream_truncated")
        if not self._initialized or self._terminal is None:
            self._fail("claude_terminal_missing")
        self._finished = DecodedClaudeTurn(self._session, self._model, self._tools, self._terminal,
                                          self._terminal_usage, self._hash.hexdigest(), self._bytes, self._frames)
        return self._finished


class ClaudeDriverStreamDecoder(ClaudeStreamDecoder):
    """Versioned 2.3 fixture envelope; the original v1 entry stays unchanged.

    This validates reported identities and tools, not actual vendor enforcement,
    provider provenance, acceptance or owned process cessation.
    """
    def __init__(self, packet, **options):
        super().__init__(packet, **options)
        if self._session != self._packet["session_id"] or self._session != self._packet["attempt_id"]:
            raise TaskAlongError("claude_decoder_binding_invalid", "The session must bind the exact fresh attempt.")

    @staticmethod
    def _admit_packet(packet):
        return validate_versioned("worker-packet", packet, expected_version="2.3")

    def _admit_worker_result(self, worker):
        validate_versioned("worker-result", worker, expected_version="2.3")
        expected = {key:self._packet["bindings"][key] for key in ("driver_config_digest", "provider_profile_digest")}
        expected["session_id"] = self._packet["session_id"]
        if any(worker[key] != value for key,value in expected.items()):
            self._fail("claude_result_binding_mismatch")

    def _consume(self, line):
        super()._consume(line)
        if self._initialized and self._tools != tuple(self._packet["allowed_tools"]):
            self._fail("claude_tools_mismatch")
        # The v1 decoder's broad message handling is retained. This explicitly
        # versioned projection also checks reported invocations, not merely the
        # initialization inventory. Reports still cannot prove enforcement.
        event = _wire_frame(line)
        if event["type"] in {"assistant", "user"}:
            content = event["message"].get("content")
            if type(content) is list:
                for block in content:
                    self._admit_block(block)
        elif event["type"] == "stream_event":
            inner = event["event"]
            if inner["type"] == "content_block_start":
                self._admit_block(inner.get("content_block"))
            elif inner["type"] == "message_start":
                content = inner["message"].get("content")
                if type(content) is not list:
                    self._fail("claude_frame_invalid")
                for block in content:
                    self._admit_block(block)
            elif inner["type"] not in {"content_block_delta", "content_block_stop",
                                       "message_delta", "message_stop", "ping"}:
                self._fail("claude_event_unsupported")

    def _admit_block(self, block):
        if type(block) is not dict or block.get("type") not in (
                "text", "thinking", "redacted_thinking", "tool_use", "tool_result"):
            self._fail("claude_tool_unsupported")
        if block["type"] == "tool_use" and block.get("name") not in self._packet["allowed_tools"]:
            self._fail("claude_tool_unsupported")

    def finish(self, *, exit_code):
        result = super().finish(exit_code=exit_code)
        if result.protocol_version != 2:
            self._finished = replace(result, protocol_version=2)
        return self._finished
