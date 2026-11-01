"""Passive bounded native lifecycle observations; never a native request cap.

The owner polls stop_requested and owns cleanup. Native work may already have
started before its event is observed. No observation settles paid usage, remote
cancellation, escaped descendants, or permission to submit another request.
"""
from __future__ import annotations

import hashlib
import json

_MODEL = "model.meta.response"
_EVENTS = {"proposed", "side_effect_intent", "started", "status", "completed",
           "succeeded", "timed_out", "failed", "cancelled"}
_MAX_TASKS = 256


class _Decimal(str):
    """Preserve irrelevant native decimal observations without type coercion."""


def _identifier(value):
    if (type(value) is not str or not value or not value.isprintable()
            or len(value.encode("utf-8", errors="strict")) > 256):
        raise ValueError("identifier")
    return value


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _constant(_):
    raise ValueError("nonfinite number")


def _parse(raw):
    value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                       parse_float=_Decimal, parse_constant=_constant)
    if type(value) is not dict:
        raise ValueError("root")
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > 65536 or depth > 64:
            raise ValueError("shape")
        if type(item) in (str, _Decimal):
            item.encode("utf-8", errors="strict")
        elif type(item) is int:
            if abs(item) > 2**53 - 1:
                raise ValueError("integer")
        elif item is None or type(item) is bool:
            pass
        elif type(item) in (dict, list):
            if len(item) > 4096:
                raise ValueError("container")
            if type(item) is dict:
                stack.extend((key, depth + 1) for key in item)
                stack.extend((child, depth + 1) for child in item.values())
            else:
                stack.extend((child, depth + 1) for child in item)
        else:
            raise ValueError("type")
    return value


class NativeModelTaskGuard:
    """Observe complete stdout lines without I/O or callback exceptions.

    Invalid constructor arguments raise ValueError. Counters retain only bounded
    recognized observations, including subsequent valid rows after the first stop.
    They are not an exhaustive native activity or paid-call accounting record.
    """
    def __init__(self, session_id, *, max_records=131072, max_frame_bytes=16777216):
        try:
            self._session = _identifier(session_id)
        except (ValueError, TypeError, UnicodeError):
            raise ValueError("a bounded session identifier is required") from None
        if (type(max_records) is not int or not 1 <= max_records <= 131072
                or type(max_frame_bytes) is not int or not 1 <= max_frame_bytes <= 16777216):
            raise ValueError("finite native lifecycle limits are required")
        self._maximum, self._frame = max_records, max_frame_bytes
        self._records = self._sequence = 0
        self._run = self._pending_run = None
        self._tasks = {}
        self._models = set()
        self._counts = {key: 0 for key in ("proposed", "side_effect_intent", "started", "timed_out", "failed", "cancelled")}
        self._cause = None
        self._invalid_cause = None
        self._stop_sequence = None
        self._record_limited = self._task_limited = False

    @property
    def stop_requested(self):
        return self._cause is not None

    def _stop(self, cause):
        if self._cause is None:
            self._cause = cause
            self._stop_sequence = self._sequence or None

    def _invalid(self, cause):
        if self._invalid_cause is None:
            self._invalid_cause = cause
        self._stop(cause)

    def _reference(self, value, kind):
        if type(value) is not dict or set(value) != {"kind", "id"} or value.get("kind") != kind:
            raise ValueError("reference")
        return _identifier(value["id"])

    def _bind_run(self, value):
        value = _identifier(value)
        if self._pending_run is not None and self._pending_run != value:
            raise ValueError("run changed")
        self._pending_run = value
        return value

    def _bindings(self, row, payload):
        if row.get("stream") != {"kind": "session", "id": self._session}:
            raise ValueError("session")
        run = None
        if "run_stream" in payload:
            run = self._bind_run(self._reference(payload["run_stream"], "run"))
        if "command_id" in payload:
            command = self._bind_run(payload["command_id"])
            if run is not None and command != run:
                raise ValueError("command")
            if self._pending_run is not None and command != self._pending_run:
                raise ValueError("command changed")
        if run is not None and "command_id" in payload:
            self._run = run

    def _hidden(self, row, payload, event):
        expected_task = _identifier(payload.get("task_id")) if payload.get("kind") == "task_lifecycle" else None
        if not row["payload_type"].startswith("task.lifecycle.") or payload.get("kind") != "task_lifecycle":
            event = None
        stack = [row]
        while stack:
            part = stack.pop()
            if type(part) is list:
                stack.extend(part)
            elif type(part) is dict:
                kind, payload_type = part.get("kind"), part.get("payload_type")
                if ((kind == "task_lifecycle" and part is not payload)
                        or (type(payload_type) is str and payload_type.startswith("task.lifecycle.") and part is not row)
                        or (kind in _EVENTS and "task_id" in part and part is not event)):
                    raise ValueError("hidden lifecycle")
                for key in ("task_kind", "operation"):
                    if (type(part.get(key)) is str and part[key].startswith("model.") and part is not event):
                        raise ValueError("hidden model activity")
                if "run_stream" in part:
                    self._bind_run(self._reference(part["run_stream"], "run"))
                if "run_id" in part:
                    self._bind_run(part["run_id"])
                if "session_stream" in part and self._reference(part["session_stream"], "session") != self._session:
                    raise ValueError("hidden foreign session")
                if "session_id" in part and _identifier(part["session_id"]) != self._session:
                    raise ValueError("foreign session scalar")
                if "command_id" in part:
                    self._bind_run(part["command_id"])
                if "task_stream" in part:
                    task = self._reference(part["task_stream"], "task")
                    if expected_task is not None and task != expected_task:
                        raise ValueError("hidden foreign task")
                    if "task_id" in part and _identifier(part["task_id"]) != task:
                        raise ValueError("conflicting task scalar")
                if "task_id" in part:
                    task = _identifier(part["task_id"])
                    if expected_task is not None and task != expected_task:
                        raise ValueError("foreign task scalar")
                stack.extend(part.values())

    def _model(self, task):
        if task not in self._models:
            self._models.add(task)
            if len(self._models) > 1:
                self._stop("second_model_task_observed")

    def _lifecycle(self, row, payload, event):
        kind = row["payload_type"].removeprefix("task.lifecycle.")
        if (kind not in _EVENTS or payload.get("kind") != "task_lifecycle"
                or type(event) is not dict or event.get("kind") != kind
                or "run_stream" not in payload or "command_id" not in payload or self._run is None):
            raise ValueError("lifecycle wrapper")
        task = _identifier(payload.get("task_id"))
        if (self._reference(payload.get("task_stream"), "task") != task
                or _identifier(event.get("task_id")) != task):
            raise ValueError("task binding")
        if ("task_stream" in event and self._reference(event["task_stream"], "task") != task
                or "task_kind" in event and kind != "proposed"
                or "operation" in event and kind != "side_effect_intent"):
            raise ValueError("unexpected task marker")
        info = self._tasks.get(task)
        if info is None:
            if len(self._tasks) == _MAX_TASKS:
                self._task_limited = True
                self._invalid("task_metadata_limit")
                return
            info = {"kind": None, "phase": 0, "terminal": False}
            self._tasks[task] = info
        marker = event.get("task_kind") if kind == "proposed" else event.get("operation") if kind == "side_effect_intent" else None
        if marker is not None:
            _identifier(marker)
            if marker.startswith("model.") and marker != _MODEL:
                self._invalid("unsupported_model_activity")
                return
            if marker == _MODEL:
                self._model(task)
        model = task in self._models
        if kind == "proposed":
            if info["phase"] or info["terminal"] or marker is None:
                raise ValueError("proposed order")
            info.update(kind=marker, phase=1)
        elif kind == "side_effect_intent":
            if info["phase"] != 1 or info["terminal"] or marker is None or marker != info["kind"]:
                raise ValueError("intent order")
            info["phase"] = 2
        elif kind == "started":
            if info["terminal"] or info["phase"] not in ((2,) if model else (1, 2)):
                raise ValueError("start order")
            info["phase"] = 3
        elif kind == "status":
            if not info["phase"] or info["terminal"]:
                raise ValueError("status order")
        else:
            if not info["phase"] or info["terminal"] or kind in {"completed", "succeeded"} and info["phase"] != 3:
                raise ValueError("terminal order")
            info["terminal"] = True
        if model and kind in self._counts:
            self._counts[kind] += 1
        if model and kind in {"timed_out", "failed", "cancelled"}:
            self._stop("model_task_" + kind)

    def observe(self, rawline):
        """Consume one LF-free complete line. Always return; failures are sticky."""
        try:
            if self._records > self._maximum:
                return
            self._records += 1
            if self._records > self._maximum:
                self._record_limited = True
                self._invalid("record_limit")
                return
            if type(rawline) is not bytes or not rawline or len(rawline) > self._frame or b"\n" in rawline:
                raise ValueError("frame")
            row = _parse(rawline)
            sequence = row.get("sequence")
            if (type(row.get("schema_version")) is not int or row["schema_version"] != 1
                    or type(row.get("payload_schema_version")) is not int or row["payload_schema_version"] != 1
                    or type(sequence) is not int or sequence != self._sequence + 1
                    or type(row.get("payload_type")) is not str or not row["payload_type"]
                    or len(row["payload_type"].encode("utf-8")) > 256 or type(row.get("payload")) is not dict):
                raise ValueError("row")
            payload = row["payload"]
            self._bindings(row, payload)
            event = payload.get("event")
            self._hidden(row, payload, event)
            self._sequence = sequence
            if row["payload_type"].startswith("task.lifecycle."):
                self._lifecycle(row, payload, event)
            elif payload.get("kind") == "task_lifecycle":
                raise ValueError("unrecognized lifecycle")
        except BaseException:
            # The callback must never prevent the owner from draining capture
            # and retaining its final process receipt. No exception text leaks.
            self._invalid("malformed_native_lifecycle")

    def summary(self):
        hashed = lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest() if value is not None else None
        return {"format": "muse-native-model-task-guard/1", "stop_requested": self.stop_requested,
                "first_stop_cause": self._cause, "first_stop_sequence": self._stop_sequence,
                "protocol_valid": self._invalid_cause is None, "first_protocol_failure": self._invalid_cause,
                "session_sha256": hashed(self._session), "native_run_sha256": hashed(self._run),
                "records_observed": self._records, "record_limit": self._maximum,
                "record_limited": self._record_limited, "task_metadata_limited": self._task_limited,
                "tracked_tasks": len(self._tasks), "model_tasks_observed": len(self._models),
                **{"model_tasks_" + key: count for key, count in self._counts.items()},
                "local_stop_request_only": True, "hard_native_attempt_limit_enforced": False,
                "native_activity_exhaustive": False, "paid_call_count": "unknown",
                "remote_cancellation": "unknown", "remote_usage": "unknown",
                "descendant_cessation": "unknown", "new_dispatch_authorized": False}
