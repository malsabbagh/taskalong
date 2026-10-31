"""Bounded Codex event observations, independent of lifecycle and acceptance.

The process owner supplies complete JSONL records. This decoder retains only
allowlisted observations; the owner separately retains original private bytes.
Requested model, effort and tier are not observations of this event dialect.
"""
from __future__ import annotations

import re

from ..errors import TaskAlongError
from ..validation import loads


MAX_PROTOCOL_RECORDS = 65536
MAX_LINE_BYTES = 1024 * 1024
MAX_USAGE_TOKENS = 9007199254740991
_THREAD = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,127}")


def valid_thread_id(value) -> bool:
    """Thread observations must remain positional identities, never CLI flags."""
    return type(value) is str and _THREAD.fullmatch(value) is not None


class CodexEventDecoder:
    """Observe one invocation; a completed turn alone never establishes success.

    Errors are sticky safe codes so the process owner can request cancellation
    without exposing provider text or losing its actual cleanup observations.
    """

    def __init__(self, *, mode="start", thread_id=None,
                 max_records=MAX_PROTOCOL_RECORDS, max_line_bytes=MAX_LINE_BYTES):
        if (type(mode) is not str or mode not in {"start", "restart", "native_resume"}
                or mode == "native_resume" and not valid_thread_id(thread_id)
                or mode != "native_resume" and thread_id is not None):
            raise TaskAlongError("codex_decoder_binding_invalid", "Select an exact Codex execution mode and resume thread.")
        if (type(max_records) is not int or not 1 <= max_records <= MAX_PROTOCOL_RECORDS
                or type(max_line_bytes) is not int or not 1 <= max_line_bytes <= MAX_LINE_BYTES):
            raise TaskAlongError("codex_decoder_limits_invalid", "Codex protocol limits must be finite bounded integers.")
        self._mode, self._expected_thread = mode, thread_id
        self._max_records, self._max_line_bytes = max_records, max_line_bytes
        self._records = self._unknown_events = 0
        self._thread = self._terminal = self._error = None
        self._usage = {"input_tokens": None, "output_tokens": None, "cost_usd": None}

    @property
    def thread_id(self):
        return self._thread

    @property
    def terminal(self):
        return self._terminal

    @property
    def error_code(self):
        return self._error

    @property
    def usage(self):
        return dict(self._usage)

    @property
    def diagnostics(self):
        return {"unknown_event_count": self._unknown_events} if self._unknown_events else {}

    def consume(self, line: bytes) -> None:
        if self._error is not None:
            return
        self._records += 1
        if self._records > self._max_records:
            self._error = "runtime_protocol_record_limit"
            return
        try:
            if type(line) is not bytes or len(line) > self._max_line_bytes:
                raise ValueError("record bound")
            event = loads(line, max_bytes=self._max_line_bytes)
            pending = [(event, 0)]
            while pending:
                value, depth = pending.pop()
                if depth > 32:
                    raise ValueError("nesting bound")
                if type(value) is dict:
                    pending.extend((child, depth + 1) for child in value.values())
                elif type(value) is list:
                    pending.extend((child, depth + 1) for child in value)
            event_type = event.get("type")
            if type(event_type) is not str or not 1 <= len(event_type) <= 128:
                raise ValueError("event shape")
            if self._terminal is not None:
                raise ValueError("event after terminal")
            if event_type == "thread.started":
                value = event.get("thread_id")
                if not valid_thread_id(value):
                    raise ValueError("thread identity")
                if self._mode == "native_resume" and value != self._expected_thread:
                    self._thread = None
                    self._error = "native_resume_thread_mismatch"
                    return
                if self._thread is not None and self._thread != value:
                    raise ValueError("thread changed")
                self._thread = value
            elif event_type in {"turn.completed", "turn.failed", "error"}:
                reported = event.get("usage", {})
                if type(reported) is not dict:
                    raise ValueError("usage shape")
                usage = {"input_tokens": None, "output_tokens": None, "cost_usd": None}
                for key in ("input_tokens", "output_tokens"):
                    value = reported.get(key)
                    if value is not None and (type(value) is not int or not 0 <= value <= MAX_USAGE_TOKENS):
                        raise ValueError("usage value")
                    usage[key] = value
                self._usage, self._terminal = usage, event_type
            elif event_type not in {"turn.started", "item.started", "item.updated", "item.completed"}:
                self._unknown_events += 1
        except (ValueError, UnicodeError, RecursionError, TaskAlongError):
            self._error = "runtime_protocol_invalid"
