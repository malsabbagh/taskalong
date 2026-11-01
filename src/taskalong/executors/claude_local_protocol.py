"""Bounded native-shape JSONL observations for both configured Claude backends.

Synthetic tests do not qualify a vendor build. Parsing grants no lifecycle,
route-authentication, process-cessation, billing, or acceptance authority.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from decimal import Decimal, DecimalException
from uuid import UUID

from ..errors import TaskAlongError
from ..validation import canonical_bytes
from .claude_local_config import CONTEXTS, EFFORTS, PROVIDER_ID, model_name, refuse

_MAX_INTEGER = 2**53 - 1


def validate_binding(raw):
    required = {"provider_id", "backend", "run_id", "attempt_id", "bundle_digest", "requested_model",
                "expected_reported_model", "requested_effort", "context", "writable_outputs"}
    if type(raw) is not dict or not required <= set(raw) or raw["provider_id"] != PROVIDER_ID:
        refuse("claude_local_binding_invalid")
    for key in ("run_id", "attempt_id"):
        try:
            if type(raw[key]) is not str or str(UUID(raw[key])) != raw[key]:
                raise ValueError
        except (ValueError, AttributeError):
            refuse("claude_local_binding_invalid")
    if type(raw["bundle_digest"]) is not str or not re.fullmatch(r"[a-f0-9]{64}", raw["bundle_digest"]):
        refuse("claude_local_binding_invalid")
    if type(raw["backend"]) is not str or raw["backend"] not in {"anthropic", "ollama"}:
        refuse("claude_local_binding_invalid")
    context = raw["context"]
    if context == "exclude":
        refuse("claude_local_context_exclusion_unsupported")
    if type(context) is not str or context not in CONTEXTS:
        refuse("claude_local_binding_invalid")
    effort = raw["requested_effort"]
    if effort is not None and (type(effort) is not str or effort not in EFFORTS):
        refuse("claude_local_binding_invalid")
    outputs = raw["writable_outputs"]
    if type(outputs) is not list or not 1 <= len(outputs) <= 32:
        refuse("claude_local_binding_invalid")
    for path in outputs:
        if (type(path) is not str or len(path) > 1024
                or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", path)
                or any(p.casefold() in {".", "..", ".git"} for p in path.split("/"))):
            refuse("claude_local_binding_invalid")
    folded = [p.casefold() for p in outputs]
    if (len(set(folded)) != len(folded) or any(
            a.startswith(b + "/") for a in folded for b in folded if a != b)):
        refuse("claude_local_binding_invalid")
    return {**{key: raw[key] for key in required - {"writable_outputs"}},
            "requested_model": model_name(raw["requested_model"]),
            "expected_reported_model": model_name(raw["expected_reported_model"]),
            "writable_outputs": list(outputs)}


def response_schema(binding):
    binding = validate_binding(binding)
    return {"type": "object", "additionalProperties": False,
            "required": ["bundle_digest", "changes"], "properties": {
                "bundle_digest": {"type": "string", "const": binding["bundle_digest"]},
                "changes": {"type": "object", "minProperties": 1,
                    "additionalProperties": False, "properties": {
                        path: {"type": ["string", "null"]} for path in binding["writable_outputs"]}}}}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _integer(text):
    if len(text) > 32:
        raise ValueError
    value = int(text)
    if abs(value) > _MAX_INTEGER:
        raise ValueError
    return value


def _decimal(text):
    if len(text) > 128:
        raise ValueError
    value = Decimal(text)
    if not value.is_finite() or abs(value.adjusted()) > 1024 or value.copy_abs() > _MAX_INTEGER:
        raise ValueError
    return value


def _constant(_):
    raise ValueError


def _shape(value, depth=0, *, budget=None):
    if budget is not None:
        budget[0] -= 1
        if budget[0] < 0:
            raise ValueError
    if depth > 32:
        raise ValueError
    if type(value) is dict:
        if len(value) > 4096:
            raise ValueError
        for key, child in value.items():
            _shape(key, depth + 1, budget=budget)
            _shape(child, depth + 1, budget=budget)
    elif type(value) is list:
        if len(value) > 4096:
            raise ValueError
        for child in value:
            _shape(child, depth + 1, budget=budget)
    elif type(value) is str:
        value.encode("utf-8", errors="strict")


def _frame(line, *, extended=False):
    value = json.loads(line.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                       parse_int=_integer, parse_float=_decimal, parse_constant=_constant)
    if type(value) is not dict:
        raise ValueError
    _shape(value, budget=[65536] if extended else None)
    return value


class ClaudeLocalDecoder:
    """One fresh session, no tool execution, one terminal structured proposal.

    feed handles stdout/stderr separately. Stderr is counted/hashed, never parsed
    as a result or retained here. The shared owner retains and caps *all* bytes.
    finish() returns protocol observation only; optional exit_code checks an
    owner-observed exit and does not manufacture cessation evidence.
    """
    def __init__(self, task_binding, limits, *, max_content_bytes=65536, extended_wire=False):
        self._binding = validate_binding(task_binding)
        if (type(extended_wire) is not bool or type(max_content_bytes) is not int
                or not 1 <= max_content_bytes <= 1048576):
            refuse("claude_local_limits_invalid")
        self._content_limit = max_content_bytes
        self._extended = extended_wire
        names = {"max_protocol_records", "max_record_bytes", "max_proposal_bytes"}
        bounds = {"max_protocol_records": 65536, "max_record_bytes": 8 * 1024 * 1024,
                  "max_proposal_bytes": 4 * 1024 * 1024}
        if extended_wire:
            bounds.update(max_protocol_records=131072, max_record_bytes=16 * 1024 * 1024,
                          max_proposal_bytes=1048576)
        if type(limits) is not dict or not names <= set(limits):
            refuse("claude_local_limits_invalid")
        if any(type(limits[k]) is not int or not 1 <= limits[k] <= bounds[k] for k in names):
            refuse("claude_local_limits_invalid")
        self._limits = {k: limits[k] for k in names}
        self._pending = bytearray()
        self._counts = {"stdout": 0, "stderr": 0}
        self._hashes = {name: hashlib.sha256() for name in self._counts}
        self._records = 0
        self._ids = set()
        self._initialized = False
        self._terminal = None
        self._usage = None
        self._reported_effort = None
        self._error = None
        self._finished = None

    def _fail(self, code):
        if self._error is None:
            self._error = TaskAlongError(code, "The configured Claude stream did not satisfy its bounded protocol.",
                                         exit_code=3, effect_outcome="uncertain")
        raise self._error from None

    def feed(self, stream, chunk):
        if self._error is not None:
            raise self._error
        if type(stream) is not str or stream not in self._counts or type(chunk) is not bytes:
            self._fail("claude_local_stream_invalid")
        if self._finished is not None:
            self._fail("claude_local_decoder_closed")
        self._counts[stream] += len(chunk)
        self._hashes[stream].update(chunk)
        if stream == "stderr":
            return
        offset = 0
        while offset < len(chunk):
            newline = chunk.find(b"\n", offset)
            end = len(chunk) if newline == -1 else newline
            if len(self._pending) + end - offset > self._limits["max_record_bytes"]:
                self._fail("claude_local_record_limit")
            self._pending.extend(chunk[offset:end])
            if newline == -1:
                return
            line = bytes(self._pending)
            self._pending.clear()
            self._records += 1
            if self._records > self._limits["max_protocol_records"]:
                self._fail("claude_local_record_count_limit")
            self._consume(line)
            offset = end + 1

    def _model(self, model):
        if model != self._binding["expected_reported_model"]:
            self._fail("claude_local_model_mismatch")

    def _effort(self, event):
        if "effort" not in event:
            return
        effort = event["effort"]
        if type(effort) is not str or effort not in EFFORTS:
            self._fail("claude_local_effort_invalid")
        if ((self._reported_effort is not None and effort != self._reported_effort)
                or (self._binding["requested_effort"] is not None and effort != self._binding["requested_effort"])):
            self._fail("claude_local_effort_mismatch")
        self._reported_effort = effort

    def _consume(self, line):
        if self._terminal is not None:
            self._fail("claude_local_event_after_terminal")
        try:
            event = _frame(line, extended=self._extended)
        except (ValueError, UnicodeError, RecursionError, DecimalException):
            self._fail("claude_local_frame_invalid")
        if event.get("session_id") != self._binding["attempt_id"]:
            self._fail("claude_local_session_mismatch")
        if event.get("parent_tool_use_id") is not None:
            self._fail("claude_local_child_session_unsupported")
        if "origin" in event:
            origin = event["origin"]
            if type(origin) is not dict or origin.get("kind") != "human":
                self._fail("claude_local_unsolicited_turn")
        if event.get("error") is not None or event.get("api_error_status") is not None:
            self._fail("claude_local_provider_error")
        if "uuid" in event:
            identity = event["uuid"]
            if type(identity) is not str or not 1 <= len(identity) <= 256:
                self._fail("claude_local_event_identity_invalid")
            if identity in self._ids:
                self._fail("claude_local_duplicate_event")
            self._ids.add(identity)
        self._effort(event)
        kind = event.get("type")
        # Native error results can precede init (e.g. authentication failure).
        if kind == "result" and (event.get("is_error") is not False or event.get("subtype") != "success"):
            self._fail("claude_local_result_failed")
        if not self._initialized:
            if kind != "system" or event.get("subtype") != "init":
                self._fail("claude_local_init_missing")
            self._model(event.get("model"))
            if event.get("tools") != []:
                self._fail("claude_local_tools_mismatch")
            if self._binding["context"] == "native-only" and event.get("mcp_servers") not in (None, []):
                self._fail("claude_local_context_mismatch")
            self._initialized = True
            return
        if kind == "result":
            self._result(event)
        elif kind == "system":
            if event.get("subtype") == "permission_denied":
                self._fail("claude_local_permission_denied")
            if event.get("subtype") not in {"status", "compact_boundary"}:
                self._fail("claude_local_event_unsupported")
        elif kind in {"assistant", "user"}:
            message = event.get("message")
            if type(message) is not dict:
                self._fail("claude_local_frame_invalid")
            if kind == "assistant":
                self._model(message.get("model"))
            if message.get("stop_reason") == "tool_use":
                self._fail("claude_local_tool_observed")
            content = message.get("content")
            if type(content) is list:
                for block in content:
                    self._block(block)
            elif kind != "user" or type(content) is not str:
                self._fail("claude_local_frame_invalid")
        elif kind == "stream_event":
            self._stream_event(event.get("event"))
        elif kind == "rate_limit_event":
            info = event.get("rate_limit_info")
            if type(info) is not dict or info.get("status") not in {"allowed", "allowed_warning"}:
                self._fail("claude_local_provider_error")
        else:
            self._fail("claude_local_event_unsupported")

    def _stream_event(self, inner):
        if type(inner) is not dict:
            self._fail("claude_local_frame_invalid")
        kind = inner.get("type")
        if kind == "message_start":
            message = inner.get("message")
            if type(message) is not dict or type(message.get("content")) is not list:
                self._fail("claude_local_frame_invalid")
            self._model(message.get("model"))
            for block in message["content"]:
                self._block(block)
        elif kind == "content_block_start":
            self._block(inner.get("content_block"))
        elif kind == "content_block_delta":
            delta = inner.get("delta")
            if type(delta) is not dict or delta.get("type") not in {
                    "text_delta", "thinking_delta", "signature_delta"}:
                self._fail("claude_local_event_unsupported")
        elif kind == "message_delta":
            delta = inner.get("delta")
            if type(delta) is not dict:
                self._fail("claude_local_frame_invalid")
            if delta.get("stop_reason") == "tool_use":
                self._fail("claude_local_tool_observed")
        elif kind == "error":
            self._fail("claude_local_provider_error")
        elif kind not in {"content_block_stop", "message_stop", "ping"}:
            self._fail("claude_local_event_unsupported")

    def _block(self, block):
        if type(block) is not dict:
            self._fail("claude_local_frame_invalid")
        if block.get("type") in {"tool_use", "tool_result", "server_tool_use"}:
            self._fail("claude_local_tool_observed")
        if block.get("type") not in {"text", "thinking", "redacted_thinking"}:
            self._fail("claude_local_event_unsupported")

    def _result(self, event):
        if (event.get("errors") not in (None, []) or event.get("deferred_tool_use") is not None
                or event.get("terminal_reason") not in (None, "completed")):
            self._fail("claude_local_result_failed")
        if "model" in event:
            self._model(event["model"])
        models = event.get("modelUsage")
        if models is not None:
            if type(models) is not dict:
                self._fail("claude_local_usage_invalid")
            for model, usage in models.items():
                self._model(model)
                if type(usage) is not dict:
                    self._fail("claude_local_usage_invalid")
        if type(event.get("permission_denials")) is not list:
            self._fail("claude_local_permission_status_unknown")
        if event["permission_denials"]:
            self._fail("claude_local_permission_denied")
        proposal = event.get("structured_output")
        if (type(proposal) is not dict or set(proposal) != {"bundle_digest", "changes"}
                or proposal["bundle_digest"] != self._binding["bundle_digest"]):
            self._fail("claude_local_proposal_binding_mismatch")
        changes = proposal["changes"]
        if (type(changes) is not dict or not changes
                or not set(changes) <= set(self._binding["writable_outputs"])):
            self._fail("claude_local_proposal_scope_invalid")
        for content in changes.values():
            if content is None:
                continue
            if (type(content) is not str or len(content.encode("utf-8")) > self._content_limit
                    or any(ord(c) < 32 and c not in "\n\t" for c in content)
                    or "\x7f" in content or content and not content.endswith("\n")):
                self._fail("claude_local_proposal_text_invalid")
        encoded = canonical_bytes(proposal)
        if len(encoded) > self._limits["max_proposal_bytes"]:
            self._fail("claude_local_proposal_limit")
        self._usage = self._reported_usage(event)
        self._terminal = proposal

    def _reported_usage(self, event):
        raw = event.get("usage")
        if raw is None:
            raw = {}
        if type(raw) is not dict:
            self._fail("claude_local_usage_invalid")
        usage = {"counter_scope": "terminal_reported_scope_unknown"}
        for name in ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"):
            value = raw.get(name)
            if value is not None and (type(value) is not int or not 0 <= value <= _MAX_INTEGER):
                self._fail("claude_local_usage_invalid")
            usage[name] = value
        cost = event.get("total_cost_usd")
        usage["cost_micro_usd"] = None
        if cost is not None:
            if type(cost) not in (int, Decimal) or cost < 0:
                self._fail("claude_local_usage_invalid")
            numerator, denominator = Decimal(cost).as_integer_ratio()
            micros = (numerator * 1000000 + denominator - 1) // denominator
            if micros > _MAX_INTEGER:
                self._fail("claude_local_usage_invalid")
            usage["cost_micro_usd"] = micros
        usage["financial_settlement"] = None
        return usage

    def finish(self, *, exit_code=None):
        if self._error is not None:
            raise self._error
        if exit_code is not None and (type(exit_code) is not int or exit_code != 0):
            self._fail("claude_local_exit_failed")
        if self._pending:
            self._fail("claude_local_stream_truncated")
        if not self._initialized or self._terminal is None:
            self._fail("claude_local_terminal_missing")
        if self._finished is None:
            self._finished = {"provider_id": PROVIDER_ID, "backend": self._binding["backend"],
                "protocol_status": "complete", "native_session_id": self._binding["attempt_id"],
                "native_turn_id": None, "requested_model": self._binding["requested_model"],
                "reported_model": self._binding["expected_reported_model"],
                "requested_effort": self._binding["requested_effort"], "reported_effort": self._reported_effort,
                "effective_effort": None, "reported_usage": self._usage, "structured_response": self._terminal,
                "failure_classification": None, "tool_observation": {"reported_tools": [], "observed_invocations": []},
                "context_observation": None, "backend_route_observation": None,
                "capture": {stream: {"bytes": self._counts[stream], "sha256": self._hashes[stream].hexdigest()}
                            for stream in self._counts}, "protocol_records": self._records,
                "qualification": "native_unqualified"}
        return copy.deepcopy(self._finished)
