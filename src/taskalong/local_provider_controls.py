"""Local configured-owner observations and durable cancellation requests.

No PID is probed or signalled. A request is an intent, never a cancellation or
remote-settlement claim. Interrupted publication is observation-only: preserve
the intent and staging evidence; recovery cannot automatically replay it.
"""
from __future__ import annotations

import ctypes
from functools import wraps
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import sys

from .artifact_io import read_regular, stage_regular
from .errors import TaskAlongError
from .local_provider_capture import _Directory, read_capture
from .store import key_check
from .validation import canonical_bytes, digest, loads

_LIMIT = 1_048_576
_ACTIVE = {"starting", "running", "interrupted"}
_STATES = _ACTIVE | {"preflight", "prepared", "not_started", "blocked", "failed",
                     "completed", "cancelled", "proposal_ready", "reserved"}


def _fail(code="provider_control_invalid", *, uncertain=False):
    raise TaskAlongError(code, "Provider control evidence is unavailable, unsafe or conflicting; preserve existing evidence.",
                         exit_code=4, effect_outcome="uncertain" if uncertain else "not_sent")


def _text(value, maximum=128):
    return type(value) is str and 1 <= len(value) <= maximum and value.isprintable()


def _sha(value):
    return type(value) is str and re.fullmatch("[a-f0-9]{64}", value) is not None


def _process_receipt(value):
    return (type(value) is dict and _text(value.get("invocation_id"))
            and _sha(value.get("executable_sha256"))
            and all(type(value.get(key)) is int and 0 < value[key] < 2**53
                    for key in ("pid", "pgid", "supervisor_pid", "started_unix_ms")))


def _safe(method):
    @wraps(method)
    def call(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            _fail()
        except sqlite3.Error:
            _fail(uncertain=True)
    return call


def _path(value):
    if (type(value) is not str or not Path(value).is_absolute() or str(Path(value)) != value
            or ".." in Path(value).parts or not value.isprintable()):
        _fail()
    return Path(value)


def _present(root, name):
    # Held descriptor and no-follow stat distinguish absence from unsafe evidence.
    with_directory = _Directory(root)
    try:
        try:
            os.stat(name, dir_fd=with_directory.fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        finally:
            with_directory.check()
        return True
    finally:
        with_directory.close()


def _read_run(store, run_id):
    if not _text(run_id):
        _fail()
    record = store.setting("provider-run:" + run_id)
    if record is None:
        return None
    if (type(record) is not dict or record.get("run_id") != run_id
            or record.get("format") not in {"configured-provider-run/1", "local-provider-run/1", "local-provider-run/2"}
            or record.get("format") != "configured-provider-run/1" and record.get("provider") != "muse"
            or not _text(record.get("provider"), 64)
            or type(record.get("revision")) is not int or not 1 <= record["revision"] <= 999999
            or type(record.get("state")) is not str or record["state"] not in _STATES
            or type(record.get("controller_submissions")) is not int or record["controller_submissions"] not in {0, 1}
            or any(record.get(key) is not False for key in ("automatic_retry_allowed", "patch_applied", "acceptance_allowed"))
            or not _sha(record.get("configuration_digest"))
            or not any(_sha(record.get(key)) for key in ("request_digest", "bundle_digest"))
            or not _text(record.get("remote_usage"), 128)
            or record.get("digest") != digest(record)
            or record.get("process_receipt") is not None and not _process_receipt(record["process_receipt"])
            or record.get("process") is not None and type(record["process"]) is not dict):
        _fail()
    for key in ("request_digest", "bundle_digest"):
        if key in record and not _sha(record[key]):
            _fail()
    root = _path(record.get("output"))
    control = _path(record.get("control_root", str(root)))
    if record["format"] != "configured-provider-run/1" and control != root:
        _fail()
    if control != root and (root not in control.parents or len(control.parts) != len(root.parts) + 1):
        _fail()
    for path in (root, control):
        directory = _Directory(path)
        directory.close()
    if read_regular(root, f"events/{record['revision']:04d}.json", max_bytes=_LIMIT,
                    private=True, expected_mode=0o400) != canonical_bytes(record):
        _fail("provider_control_history_changed")
    directory = _Directory(root / "events")
    try:
        for name in directory.names():
            if re.fullmatch(r"[0-9]{4,6}\.json", name) and int(name[:-5]) > record["revision"]:
                _fail("provider_control_history_changed")
        directory.check()
    finally:
        directory.close()
    return record, root, control


def _binding(record):
    return {key: record[key] for key in ("run_id", "provider", "revision", "configuration_digest",
            "request_digest", "bundle_digest", "process_receipt") if key in record}


def _observe(record, root, control):
    process = None
    process_status = "unknown"
    if _present(root, "process.json"):
        process = loads(read_regular(root, "process.json", max_bytes=_LIMIT, private=True, expected_mode=0o400))
        if (type(process) is not dict or type(record.get("process_receipt")) is not dict
                or process.get("receipt") != record["process_receipt"]
                or record.get("process") is not None and process != record["process"]):
            _fail("provider_control_process_conflict", uncertain=True)
        # Root cessation is separate from descendants, native completion and usage.
        if (process.get("root_exit_observed") is True and type(process.get("root_exit_code")) is int
                or process.get("termination_confirmed") is True and type(process.get("exit_code")) is int):
            process_status = "observed"
    elif record.get("process") is not None:
        _fail("provider_control_process_conflict", uncertain=True)
    capture = {"status": "unknown", "byte_closure": False}
    if _present(control, "capture"):
        capture = read_capture(control / "capture")
    return {"run_id": record["run_id"], "provider": record["provider"], "revision": record["revision"],
            "stored_state": record["state"], "local_termination": process_status,
            "group_termination_confirmed": bool(process and process.get("group_termination_confirmed") is True),
            "descendant_cessation": "unknown", "capture": capture,
            "controller_submissions": record["controller_submissions"], "remote_usage": record["remote_usage"],
            "automatic_retry_allowed": False, "patch_applied": False, "acceptance_allowed": False}


@_safe
def inspect_run(store, run_id) -> dict | None:
    """Read authenticated owner evidence without exporting private source paths."""
    selected = _read_run(store, run_id)
    return None if selected is None else _observe(*selected)


def _operation(store, run_id, operation_key, expected_revision, action):
    key_check(operation_key)
    if not _text(run_id) or type(expected_revision) is not int or expected_revision < 1:
        _fail()
    request = {"run_id": run_id, "expected_revision": expected_revision, "action": action}
    name = "provider-control:operation:" + hashlib.sha256(operation_key.encode()).hexdigest()
    previous = store.setting(name)
    if previous is not None:
        if (type(previous) is not dict or previous.get("digest") != digest(previous)
                or previous.get("request") != request):
            _fail("provider_control_key_conflict")
        receipt = store.setting(name + ":receipt")
        if receipt is not None:
            if receipt.get("digest") != digest(receipt) or receipt.get("intent_digest") != previous["digest"]:
                _fail()
            return name, request, receipt
        return name, request, {"run_id": run_id, "operation": action, "status": "publication_unknown",
                               "intent_digest": previous["digest"], "automatic_retry_allowed": False,
                               "recovery": "observe_existing_evidence_only"}
    return name, request, None


def _insert(db, name, value):
    db.execute("INSERT INTO settings VALUES (?,?)", (name, canonical_bytes(value).decode()))


def _seal(value):
    return {**value, "digest": digest(value)}


def _receipt(intent, status, observation=None):
    value = {"format": "configured-provider-control-receipt/1", "run_id": intent["request"]["run_id"],
             "operation": intent["request"]["action"], "status": status,
             "intent_digest": intent["digest"], "automatic_retry_allowed": False,
             "remote_settlement": "unknown", "recovery": "observe_existing_evidence_only"}
    if observation is not None:
        value["observation"] = observation
    return _seal(value)


def _publish(control, stage):
    """Atomic no-replace rename through a held owner directory descriptor."""
    directory = _Directory(control)
    try:
        directory.check()
        libc = ctypes.CDLL(None, use_errno=True)
        if sys.platform == "darwin" and hasattr(libc, "renameatx_np"):
            rename = libc.renameatx_np
            flag = 4  # RENAME_EXCL
        elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
            rename = libc.renameat2
            flag = 1  # RENAME_NOREPLACE
        else:
            _fail("provider_control_publication_unsupported", uncertain=True)
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        if rename(directory.fd, stage.encode(), directory.fd, b"cancel-request.json", flag) != 0:
            raise OSError(ctypes.get_errno(), "Atomic control publication failed")
        os.fsync(directory.fd)
        directory.check()
    finally:
        directory.close()


@_safe
def request_cancel(store, run_id, *, operation_key, expected_revision) -> dict:
    """Reserve durable intent before publishing one local cancellation marker."""
    name, request, previous = _operation(store, run_id, operation_key, expected_revision, "cancel")
    if previous is not None:
        return previous
    selected = _read_run(store, run_id)
    if selected is None:
        _fail("provider_run_missing")
    record, root, control = selected
    if record["revision"] != expected_revision:
        _fail("revision_conflict")
    observation = _observe(*selected)
    active = record["state"] in _ACTIVE and record["controller_submissions"] == 1
    intent = _seal({"format": "configured-provider-control-intent/1", "request": request,
                    "binding": _binding(record), "owner_digest": record["digest"]})
    marker = _seal({"format": "configured-provider-cancel/1", "intent_digest": intent["digest"],
                    "binding": intent["binding"], "automatic_retry_allowed": False})
    # The transaction contains no filesystem effect. A committed intent prevents
    # a lost receipt from becoming permission to repeat publication.
    with store.transaction() as db:
        if store.setting("provider-run:" + run_id) != record:
            _fail("revision_conflict")
        if store.setting(name) is not None:
            _fail("provider_control_key_conflict")
        if active and store.setting("provider-control:cancel:" + run_id) is not None:
            _fail("provider_control_already_requested", uncertain=True)
        _insert(db, name, intent)
        if active:
            _insert(db, "provider-control:cancel:" + run_id, {"operation": name, "intent_digest": intent["digest"]})
        else:
            receipt = _receipt(intent, "observation_only", observation)
            _insert(db, name + ":receipt", receipt)
            return receipt
    try:
        # Never recreate a missing root, overwrite a marker, or replay a partial stage.
        stage = ".cancel-stage-" + intent["digest"] + ".json"
        raw = canonical_bytes(marker)
        stage_regular(control, stage, raw, expected_sha256=hashlib.sha256(raw).hexdigest())
        _publish(control, stage)
        if read_regular(control, "cancel-request.json", max_bytes=_LIMIT, private=True, expected_mode=0o400) != raw:
            _fail(uncertain=True)
        receipt = _receipt(intent, "requested", observation)
        with store.transaction() as db:
            _insert(db, name + ":receipt", receipt)
        return receipt
    except (TaskAlongError, OSError, sqlite3.Error):
        # The owner might already have consumed a fully published marker. The
        # durable intent survives even when recording this receipt also fails.
        receipt = _receipt(intent, "publication_unknown", observation)
        try:
            with store.transaction() as db:
                _insert(db, name + ":receipt", receipt)
        except (TaskAlongError, OSError, sqlite3.Error):
            pass
        return receipt


@_safe
def reconcile(store, run_id, *, operation_key, expected_revision) -> dict:
    """Observe retained evidence; never replay a request or change owner history."""
    name, request, previous = _operation(store, run_id, operation_key, expected_revision, "reconcile")
    if previous is not None:
        return previous
    selected = _read_run(store, run_id)
    if selected is None:
        _fail("provider_run_missing")
    record, root, control = selected
    if record["revision"] != expected_revision:
        _fail("revision_conflict")
    observation = _observe(*selected)
    slot = store.setting("provider-control:cancel:" + run_id)
    observation["cancel_request"] = "unknown"
    if slot is not None:
        intent = store.setting(slot.get("operation", ""))
        if (type(intent) is not dict or intent.get("digest") != digest(intent)
                or intent["digest"] != slot.get("intent_digest") or intent["request"]["run_id"] != run_id):
            _fail()
        observation["cancel_request"] = "intent_retained_publication_unknown"
        if _present(control, "cancel-request.json"):
            marker = loads(read_regular(control, "cancel-request.json", max_bytes=_LIMIT, private=True, expected_mode=0o400))
            expected = _seal({"format": "configured-provider-cancel/1", "intent_digest": intent["digest"],
                              "binding": intent["binding"], "automatic_retry_allowed": False})
            if marker != expected:
                _fail("provider_control_marker_conflict", uncertain=True)
            observation["cancel_request"] = "published"
    elif _present(control, "cancel-request.json"):
        _fail("provider_control_marker_conflict", uncertain=True)
    intent = _seal({"format": "configured-provider-control-intent/1", "request": request,
                    "binding": _binding(record), "owner_digest": record["digest"]})
    receipt = _receipt(intent, "observed", observation)
    with store.transaction() as db:
        if store.setting("provider-run:" + run_id) != record:
            _fail("revision_conflict")
        _insert(db, name, intent)
        _insert(db, name + ":receipt", receipt)
    return receipt
