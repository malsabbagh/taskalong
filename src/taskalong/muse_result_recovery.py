"""Explicit model-free reconciliation of one complete, committed Muse result.

Journal completion is local native evidence, not acceptance, account provenance,
remote settlement or descendant cessation. Original failed history is immutable.
"""
from __future__ import annotations

import datetime
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

from . import muse_experimental as muse, muse_capture_recovery as capture_proof
from . import muse_successor as successor, supervised_pilot as pilot
from .artifact_io import read_regular, _file_state, _parent, _regular, _unchanged_directories
from .errors import TaskAlongError
from .local_provider_capture import read_capture, _Directory
from .provider_wire import loads_wire
from .store import identifier, key_check
from .validation import canonical_bytes, digest, loads, screen_sensitive


def _fail(code="provider_result_recovery_evidence_invalid", *, uncertain=False):
    raise TaskAlongError(code, "Complete-result recovery evidence is unavailable, conflicting or changed; preserve existing evidence without dispatch or replay.",
                         exit_code=4 if uncertain else 3, effect_outcome="uncertain" if uncertain else "not_sent")


def _seal(value):
    return {**value, "digest": digest(value)}


def _scope(store):
    return hashlib.sha256(str(store.root).encode()).hexdigest()


def _profile(value, expected):
    """Validate the historical profile without probing an installed client."""
    if (type(value) is not dict or value.get("format") != "local-muse-provider/5" or value.get("provider") != "muse"
            or value.get("digest") != expected or digest(value) != expected or value.get("capture_profile") != "large-task"
            or type(value.get("binary")) is not dict or type(value["binary"].get("sha256")) is not str
            or re.fullmatch(r"[a-f0-9]{64}", value["binary"]["sha256"]) is None
            or type(value.get("model")) is not str or not 1 <= len(value["model"].encode()) <= 256):
        _fail()
    for key, low, high in (("attempt_seconds", 1, 1440), ("max_output_bytes", 1024, 4194304),
                           ("max_protocol_records", 2, 8192), ("max_proposal_bytes", 1024, 65536)):
        if type(value.get(key)) is not int or not low <= value[key] <= high:
            _fail()
    return value


def _original(store, run_id):
    record, root = successor._read_run(store, run_id)
    if record.get("format") == "local-provider-run/2":
        from .muse_high_result_recovery import original
        return original(store, record, root)
    process = record.get("process")
    config = _profile(store.setting("provider-config:" + record["configuration_digest"]), record["configuration_digest"])
    if (record.get("format") != "local-provider-run/1" or record.get("manual_successor") is not None
            or record.get("state") != "failed" or record.get("error") != "provider_local_failure"
            or type(record.get("controller_submissions")) is not int or record["controller_submissions"] != 1
            or any(record.get(key) != "unknown" for key in ("remote_usage", "descendant_cessation", "native_internal_retries"))
            or any(record.get(key) is not False for key in ("patch_applied", "acceptance_allowed", "automatic_retry_allowed", "production_dispatch_allowed"))
            or type(process) is not dict or process.get("output_limited") is not True
            or process.get("root_exit_observed") is not True or type(process.get("root_exit_code")) is not int
            or process.get("group_termination_confirmed") is not True or process.get("timed_out") is not False
            or process.get("cancelled") is not False or process.get("tracking_errors") != [] or process.get("boundary_failures") != []
            or process.get("failure_code") is not None or process.get("protocol_error") is not None
            or process.get("mode") != "darwin-foreground-experiment/1" or process.get("process_stream_complete") is not True
            or process.get("protocol_record_limited") is not False or process.get("protocol_record_limit") != config["max_protocol_records"]
            or type(process.get("protocol_records_observed")) is not int
            or not 1 <= process["protocol_records_observed"] <= config["max_protocol_records"]):
        _fail()
    receipt = process.get("receipt")
    if (type(receipt) is not dict or receipt != record.get("process_receipt")
            or receipt.get("executable_sha256") != config["binary"]["sha256"]
            or type(receipt.get("started_unix_ms")) is not int or receipt["started_unix_ms"] <= 0):
        _fail()
    bundle, manifest = pilot._bundle(record["bundle"])
    if manifest["digest"] != record["bundle_digest"]:
        _fail()
    for path in [root / name for name in ("response.json", "proposal", "proposed.patch", "review.json", "response-claim.json")] + [bundle / "response-claim.json"]:
        if path.exists() or path.is_symlink():
            _fail("provider_result_recovery_result_exists")
    artifacts = {"events": capture_proof._events(root, record)}
    def read(name, maximum=1048576):
        raw = read_regular(root, name, max_bytes=maximum, private=True, expected_mode=0o400)
        artifacts[name] = hashlib.sha256(raw).hexdigest()
        return raw
    if loads(read("process.json")) != process:
        _fail()
    invocation = loads(read("invocation.json"))
    session = successor._id(invocation.get("session_id"))
    if (invocation.get("configuration_digest") != config["digest"] or invocation.get("bundle_digest") != manifest["digest"]
            or invocation.get("argv") != muse._argv(config, provider="meta", workspace=root / "workspace", prompt=root / "prompt.txt", session=session)):
        _fail()
    prompt = read("prompt.txt")
    if prompt != pilot._prompt(manifest["request"], manifest["digest"]):
        _fail()
    diagnostics = {stream: read(stream + ".bin", config["max_output_bytes"]) for stream in ("stdout", "stderr")}
    capture = read_capture(root / "capture")
    if (capture != process.get("private_capture") or capture.get("status") != "limited"
            or capture.get("byte_closure") is not True or capture.get("output_limited") is not True
            or capture.get("metadata_limited") is not False or capture.get("observed_counts_complete") is not True):
        _fail()
    streams = capture["streams"]
    raw = {}
    for stream in ("stdout", "stderr"):
        reference = streams[stream]
        raw[stream] = read_regular(root / "capture", stream + ".bin", max_bytes=config["max_output_bytes"],
            private=True, expected_mode=0o600, expected_sha256=reference["sha256"], expected_bytes=reference["retained_bytes"])
        if diagnostics[stream] != muse.redact(raw[stream]) or type(process.get("retained_" + stream + "_bytes")) is not int or process["retained_" + stream + "_bytes"] != len(raw[stream]):
            _fail()
    retained = sum(streams[s]["retained_bytes"] for s in raw)
    observed = sum(streams[s]["observed_bytes"] for s in raw)
    if (retained != config["max_output_bytes"] or observed <= retained or type(process.get("observed_output_bytes")) is not int
            or process["observed_output_bytes"] != observed or type(process.get("retained_output_bytes")) is not int
            or process["retained_output_bytes"] != retained or streams["result"]["observed_bytes"] != 0
            or streams["result"]["retained_bytes"] != 0 or read_capture(root / "capture") != capture):
        _fail()
    if process["protocol_records_observed"] < raw["stdout"].count(b"\n") + int(not raw["stdout"].endswith(b"\n")):
        _fail()
    marker = read_regular(bundle, "provider-submission.json", max_bytes=65536, private=True, expected_mode=0o400)
    expected = {"run_id": run_id, "output": str(root), "bundle_digest": manifest["digest"]}
    if (store.setting("provider-claim:muse:" + manifest["digest"]) != expected
            or marker != canonical_bytes({"provider": "muse", "run_id": run_id, "bundle_digest": manifest["digest"]})):
        _fail()
    artifacts.update(capture=digest(capture), submission_marker=hashlib.sha256(marker).hexdigest(), config=config["digest"])
    return {"record": record, "root": root, "config": config, "manifest": manifest, "session": session,
            "stdout": raw["stdout"], "prompt": prompt, "marker": marker, "artifacts": artifacts}


def _capture_run(raw, session, maximum):
    complete = raw if raw.endswith(b"\n") else raw.rpartition(b"\n")[0] + b"\n"
    native_run = None
    for number, line in enumerate(complete.splitlines(), 1):
        if number > maximum:
            _fail()
        row = muse._native_json(line, max_bytes=16777216, _journal_numbers=True)
        payload, _, _ = capture_proof._parts(row)
        if (row.get("stream") != {"kind": "session", "id": session} or type(row.get("schema_version")) is not int
                or row["schema_version"] != 1 or type(row.get("sequence")) is not int or row["sequence"] != number
                or type(row.get("payload_type")) is not str or not 1 <= len(row["payload_type"]) <= 128
                or "payload_schema_version" in row and (type(row["payload_schema_version"]) is not int or row["payload_schema_version"] != 1)):
            _fail()
        reference = payload.get("run_stream")
        if reference is not None and native_run is None:
            if type(reference) is not dict or reference.get("kind") != "run" or type(reference.get("id")) is not str:
                _fail()
            native_run = successor._id(reference["id"])
    if native_run is None:
        _fail()
    return native_run


def _activity_markers(row):
    """Find recognized model/result discriminators even inside deceptive wrappers."""
    pending, marked = [row], []
    while pending:
        part = pending.pop()
        if type(part) is dict:
            if part.get("kind") in ("model_request_configured", "assistant_message_committed", "run_output_delta", "output", "delta"):
                marked.append(part)
            pending.extend(part.values())
        elif type(part) is list:
            pending.extend(part)
    return marked


def _session_end(row, session, native_run, config):
    """Accept only a bound durable session closure, never trailing activity."""
    payload = row.get("payload", {})
    if (row.get("payload_type") != "session.end" or payload.get("kind") != "session_end"
            or set(payload) != {"kind", "record"} or type(payload.get("record")) is not dict
            or row.get("stream") != {"kind": "session", "id": session}
            or row.get("record_type") != "event" or row.get("durability") != "durable"
            or type(row.get("schema_version")) is not int or row["schema_version"] != 1
            or type(row.get("sequence")) is not int or row["sequence"] < 1
            or type(row.get("payload_schema_version")) is not int or row["payload_schema_version"] != 1
            or len(json.dumps(payload["record"], ensure_ascii=False, separators=(",", ":")).encode()) > 65536):
        _fail()
    # Reuse the existing passive-metadata policy, while retaining the exact
    # session.end wrapper above. Closure metadata cannot replace the response.
    passive = {**row, "payload": {"kind": "metadata", "record": payload["record"]}}
    if not capture_proof._trailing_metadata(passive):
        _fail()
    pending = [row]
    active_keys = {"event", "task", "task_id", "task_stream", "task_kind", "operation",
                   "tool_call", "tool_calls", "tool_name", "toolset", "reminder_roster"}
    while pending:
        part = pending.pop()
        if type(part) is dict:
            capture_proof._bindings(part, session, native_run)
            if "stream" in part:
                reference = part["stream"]
                if (type(reference) is not dict or set(reference) != {"kind", "id"}
                        or reference.get("kind") not in ("session", "run")
                        or reference.get("id") != (session if reference["kind"] == "session" else native_run)):
                    _fail()
            if part.get("kind") in ("session", "run") and "id" in part:
                if set(part) != {"kind", "id"} or part["id"] != (session if part["kind"] == "session" else native_run):
                    _fail()
            if (active_keys.intersection(part) or part.get("kind") in {"task", "task_lifecycle", "model.meta.response"}
                    or type(part.get("payload_type")) is str and part["payload_type"].startswith(("run.", "task.", "turn.input."))
                    or "command_id" in part and part["command_id"] != native_run
                    or "provider_id" in part and part["provider_id"] != "meta"
                    or "model_id" in part and part["model_id"] != config["model"]):
                _fail()
            pending.extend(part.values())
        elif type(part) is list:
            pending.extend(part)


def _journal(material, native_run):
    """Observe one complete commit/completion in a fully fenced native journal."""
    record, config, session = material["record"], material["config"], material["session"]
    instant = datetime.datetime.fromtimestamp(record["process_receipt"]["started_unix_ms"] / 1000, datetime.timezone.utc)
    days = {day + datetime.timedelta(days=n) for day in (instant.date(), instant.astimezone().date()) for n in (-1, 0, 1)}
    home = pilot._root(config["muse_home"])
    relative, selected = muse._journal_identity_path(home, session, days)
    with _parent(home, relative, private=False) as (parent, name, links):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
        try:
            def guard():
                held, entry = os.fstat(fd), os.stat(name, dir_fd=parent, follow_symlinks=False)
                _regular(held, private=False, max_bytes=67108864)
                _regular(entry, private=False, max_bytes=67108864)
                if _file_state(held) != selected or _file_state(entry) != selected:
                    _fail()
                _unchanged_directories(links)
                return held.st_size
            size = guard()
            hashed = hashlib.sha256()
            records = total = sequence = phase = 0
            metadata = {}
            committed = None
            schema = None
            if "high_lineage" in material:
                from .muse_interrupted_recovery import _JournalSchema
                schema = _JournalSchema(session, native_run, config["model"])
                from .muse_high_result_recovery import JournalTasks
                tasks = JournalTasks(session, native_run)
            with os.fdopen(os.dup(fd), "rb", buffering=65536) as source:
                while True:
                    line = source.readline(16777218)
                    if not line:
                        break
                    total += len(line)
                    records += 1
                    if total > 67108864 or records > 131072 or not line.endswith(b"\n") or not 1 <= len(line) - 1 <= 16777216:
                        _fail()
                    hashed.update(line)
                    row = muse._native_json(line[:-1], max_bytes=16777216, _journal_numbers=True)
                    if phase == 4:
                        _fail()
                    payload, event, details = capture_proof._parts(row)
                    if "stream" in row and row["stream"] != {"kind": "session", "id": session}:
                        _fail()
                    if "schema_version" in row and (type(row["schema_version"]) is not int or row["schema_version"] != 1):
                        _fail()
                    if "sequence" in row:
                        if type(row["sequence"]) is not int or row["sequence"] <= sequence:
                            _fail()
                        sequence = row["sequence"]
                    if schema is not None:
                        from .muse_interrupted_recovery import _bindings
                        slots = schema.observe(row)
                        tasks.observe(row)
                        _bindings(row, session, native_run, command_slots=slots)
                    else:
                        for binding in (row, payload, event, details):
                            capture_proof._bindings(binding, session, native_run)
                    markers = _activity_markers(row)
                    outcome = capture_proof._terminal(row)
                    if outcome is not None:
                        if (outcome != ("journal", "completed") or phase != 2 or payload.get("run_id") != native_run
                                or event.get("reason") is not None or markers):
                            _fail()
                        phase = 3
                        continue
                    if markers and (len(markers) != 1 or markers[0] is not event
                            or event.get("kind") not in ("model_request_configured", "assistant_message_committed")):
                        _fail()
                    if row.get("payload_type") == "session.end" or payload.get("kind") == "session_end":
                        if phase != 3:
                            _fail()
                        _session_end(row, session, native_run, config)
                        phase = 4
                        continue
                    if phase == 3 and not capture_proof._trailing_metadata(row):
                        _fail()
                    if event.get("kind") == "model_request_configured":
                        if (phase != 0 or payload.get("kind") != "run" or payload.get("run_id") != native_run
                                or event.get("toolset", {}).get("active_tools") != [] or event.get("reminder_roster", {}).get("agents") != []):
                            _fail()
                        phase = 1
                    elif event.get("kind") == "assistant_message_committed":
                        if (phase != 1 or payload.get("kind") != "run" or payload.get("run_id") != native_run
                                or type(event.get("text")) is not str or len(event["text"].encode()) > 4194304):
                            _fail()
                        committed = event["text"]
                        phase = 2
                    elif phase == 2 and row.get("payload_type", "").startswith(("run.output.", "run.model.")):
                        _fail()
                    if payload.get("kind") == "metadata":
                        if len(json.dumps(details, ensure_ascii=False, separators=(",", ":")).encode()) > 65536:
                            _fail()
                        metadata = {}
                        for key in ("provider_id", "model_id", "reasoning_effort"):
                            if key in details:
                                value = details[key]
                                if not (key == "reasoning_effort" and value is None) and (type(value) is not str or not 1 <= len(value.encode()) <= 256):
                                    _fail()
                                metadata[key] = value
            if schema is not None:
                schema.finish()
                tasks.finish(material["model_task_sha256"])
            if (phase not in (3, 4) or total != size or metadata.get("provider_id") != "meta" or metadata.get("model_id") != config["model"]):
                _fail()
            guard()
            os.lseek(fd, 0, os.SEEK_SET)
            second = hashlib.sha256()
            verified = 0
            while verified <= size:
                chunk = os.read(fd, min(65536, size + 1 - verified))
                if not chunk:
                    break
                verified += len(chunk)
                second.update(chunk)
            if verified != size or second.digest() != hashed.digest():
                _fail()
            guard()
            if muse._journal_identity_path(home, session, days) != (relative, selected):
                _fail()
            guard()
            return committed, {"sha256": hashed.hexdigest(), "bytes": total, "records": records,
                               "reported_provider": metadata["provider_id"], "reported_model": metadata["model_id"],
                               "reported_effort": metadata.get("reasoning_effort")}
        finally:
            os.close(fd)


def _prefix(material, native_run, committed):
    raw, session = material["stdout"], material["session"]
    complete, tail = (raw, b"") if raw.endswith(b"\n") else (raw.rpartition(b"\n")[0] + b"\n", raw.rpartition(b"\n")[2])
    fragments = []
    terminal = False
    sequence = 0
    for line in complete.splitlines():
        sequence += 1
        row = muse._native_json(line, max_bytes=16777216, _journal_numbers=True)
        payload, event, details = capture_proof._parts(row)
        for binding in (row, payload, event, details):
            capture_proof._bindings(binding, session, native_run)
        outcome = capture_proof._terminal(row)
        if outcome is not None:
            if (terminal or outcome != ("session", "completed") or payload.get("text") != committed
                    or payload.get("run_stream") != {"kind": "run", "id": native_run}
                    or "command_id" in payload and payload["command_id"] != native_run):
                _fail()
            terminal = True
        elif terminal and not capture_proof._trailing_metadata(row):
            _fail()
        elif row.get("payload_type") == "run.output.delta":
            if (payload.get("kind") != "run_output_delta" or type(payload.get("text")) is not str
                    or payload.get("command_id") != native_run):
                _fail()
            fragments.append(payload["text"])
        elif payload.get("kind") == "run_output_delta":
            _fail()
        markers = _activity_markers(row)
        if markers and (len(markers) != 1 or markers[0] is not payload or row.get("payload_type") != "run.output.delta"):
            _fail()
    if not fragments or "".join(fragments).encode() != committed.encode():
        _fail()
    if not tail:
        if not terminal:
            _fail()
        return
    if terminal or sequence + 1 > material["config"]["max_protocol_records"]:
        _fail()
    uuid = rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    pattern = (re.escape(b'{"schema_version":1,"id":"') + uuid
        + re.escape(b'","stream":{"kind":"session","id":' + json.dumps(session).encode() + b'},"sequence":' + str(sequence + 1).encode() + b',"recorded_at":')
        + rb'([1-9][0-9]{0,15})' + re.escape(b',"record_type":"event","durability":"durable","causation_id":"') + uuid
        + re.escape(b'","payload_type":"run.terminal.completed","payload_schema_version":1,"payload":{"kind":"run_terminal","command_id":' + json.dumps(native_run).encode()
            + b',"run_stream":{"kind":"run","id":' + json.dumps(native_run).encode() + b'},"terminal":"completed","text":"'))
    match = re.match(pattern, tail)
    if match is None or int(match.group(1)) > 2**53 - 1:
        _fail()
    text = json.loads(b'"' + tail[match.end():] + b'"')
    if type(text) is not str or not text or not committed.encode().startswith(text.encode('utf-8', errors='strict')):
        _fail()


def _anchor(record):
    return successor._anchor(record)


def _no_activity(store, record, reservation=None):
    run_id = record["run_id"]
    if (store.setting("provider-successor:muse:" + run_id) is not None
            or store.setting("provider-successor-root:muse:" + run_id) is not None):
        _fail("provider_result_recovery_conflict")
    existing = store.setting("provider-result-recovery:muse:" + run_id)
    if reservation is None:
        if existing is not None or _anchor(record).exists() or _anchor(record).is_symlink():
            _fail("provider_result_recovery_reserved")
    elif existing != reservation:
        _fail()


def _material(store, run_id, reservation=None):
    try:
        first = _original(store, run_id)
        _no_activity(store, first["record"], reservation)
        native_run = _capture_run(first["stdout"], first["session"], first["config"]["max_protocol_records"])
        committed, journal = _journal(first, native_run)
        response = loads_wire(committed, max_bytes=4194304)
        encoded = canonical_bytes(response)
        if encoded != committed.encode() or len(encoded) > first["config"]["max_proposal_bytes"]:
            _fail("provider_result_recovery_response_limit")
        screen_sensitive(response)
        options = {"replacement_profile": "megabyte-proposal/1"} if "high_lineage" in first else {}
        patch, _ = pilot._proposal(first["manifest"], response, **options)
        _prefix(first, native_run, committed)
        second = _original(store, run_id)
        repeated, repeated_journal = _journal(second, native_run)
        _no_activity(store, first["record"], reservation)
        if first != second or repeated != committed or repeated_journal != journal:
            _fail()
        value = {"format": "muse-result-recovery-plan/1", "run_id": run_id, "original_record_digest": first["record"]["digest"],
            "configuration_digest": first["config"]["digest"], "bundle_digest": first["manifest"]["digest"], "state_scope": _scope(store),
            "requested_model": first["config"]["model"], "requested_effort": first["config"]["reasoning_effort"],
            "response_sha256": hashlib.sha256(encoded).hexdigest(), "response_bytes": len(encoded),
            "patch_sha256": hashlib.sha256(patch).hexdigest(), "patch_bytes": len(patch), "original_proposal_limit": first["config"]["max_proposal_bytes"],
            "artifact_hashes": first["artifacts"], "journal": journal, "provenance": "full_bound_native_commit_and_completed_terminal_with_capture_agreement",
            "model_free": True, "plan_authorizes_effects": False, "new_controller_submissions": 0, "original_state": "failed",
            "original_capture_status": "limited", "remote_usage": "unknown", "descendant_cessation": "unknown",
            "automatic_retry_allowed": False, "patch_applied": False, "acceptance_allowed": False, "provider_authenticity_proven": False}
        if "high_lineage" in first:
            value.update(format="muse-result-recovery-plan/2", original_capture_status="closed",
                high_lineage=first["high_lineage"], validated_native_lifecycle=first["validated_native_lifecycle"],
                model_task_sha256=first["model_task_sha256"],
                replacement_profile="megabyte-proposal/1")
        return _seal(value), first, response
    except (TaskAlongError, OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, TaskAlongError) and exc.code.startswith("provider_result_recovery_"):
            raise
        _fail()


def plan(store, *, run_id):
    return _material(store, successor._id(run_id))[0]


def _mkdir(path):
    with _parent(path.parent, path.name, private=False) as (parent, name, links):
        os.mkdir(name, mode=0o700, dir_fd=parent)
        os.fsync(parent)
        _unchanged_directories(links)


def _identity(store, record, reservation):
    return _seal({"format": "muse-result-recovery-enrollment/1", "run_id": record["run_id"],
                  "original_record_digest": record["digest"], "state_scope": _scope(store), "reservation_digest": reservation["digest"]})


def _expected_output(proof, manifest, response, reservation):
    """Derive artifact bytes from the pinned response, never bless staged bytes."""
    target = Path(reservation["output"])
    encoded = canonical_bytes(response)
    options = {"replacement_profile": "megabyte-proposal/1"} if proof.get("format") == "muse-result-recovery-plan/2" else {}
    proposal, changes = pilot._proposal(manifest, response, **options)
    if (hashlib.sha256(encoded).hexdigest() != proof["response_sha256"] or len(encoded) != proof["response_bytes"]
            or len(encoded) > proof["original_proposal_limit"] or hashlib.sha256(proposal).hexdigest() != proof["patch_sha256"]
            or len(proposal) != proof["patch_bytes"] or manifest["digest"] != proof["bundle_digest"]):
        _fail()
    claim = {"bundle_digest": manifest["digest"], "response_sha256": proof["response_sha256"], "output": str(target / "proposal")}
    report = _seal({"format": pilot.FORMAT, **claim, "response_provenance": "unverified_local_content",
        "proposed_patch_sha256": proof["patch_sha256"], "changes": changes, "validation": "text_diff_against_supplied_snapshot",
        "base_commit": manifest["request"]["base_commit"], "repository_observed": False, "tests_run": False,
        "patch_applied": False, **pilot._FLAGS})
    if options:
        report["replacement_profile"] = "megabyte-proposal/1"
        report = _seal(report)
    marker_value = {"provider": "muse", "run_id": reservation["run_id"], "bundle_digest": manifest["digest"]}
    if options:
        marker_value.update(predecessor_run_id=proof["high_lineage"]["predecessor_run_id"],
                            reservation_digest=proof["high_lineage"]["reservation_digest"])
    marker = canonical_bytes(marker_value)
    observation = _seal({"format": "muse-result-recovery-source-observation/1", "plan": proof,
        "reservation_digest": reservation["digest"], "original_state": "failed", "new_controller_submissions": 0,
        "original_submission_marker_sha256": hashlib.sha256(marker).hexdigest(),
        "response_provenance": "locally_reconciled_full_native_journal", "repository_observed": False,
        "patch_applied": False, "acceptance_allowed": False, "remote_usage": "unknown", "descendant_cessation": "unknown"})
    return {"observation.json": canonical_bytes(observation), "proposal/response.json": encoded,
        "proposal/proposed.patch": proposal, "proposal/review.json": canonical_bytes(report),
        "snapshot-bundle/provider-submission.json": marker, "snapshot-bundle/bundle.json": canonical_bytes(manifest),
        "snapshot-bundle/prompt.txt": pilot._prompt(manifest["request"], manifest["digest"]),
        "snapshot-bundle/response-claim.json": canonical_bytes(claim)}, report


def _check_output(root, expected):
    """Fence all eight artifacts together with at most three held directories."""
    with ExitStack() as cleanup:
        directories, held = {}, []
        for relative, data in expected.items():
            directory, name = relative.rsplit("/", 1) if "/" in relative else ("", relative)
            if directory not in directories:
                handle = _Directory(root / directory)
                cleanup.callback(handle.close)
                directories[directory] = handle
            handle = directories[directory]
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=handle.fd)
            cleanup.callback(os.close, fd)
            info = _file_state(os.fstat(fd))
            held.append((handle, name, fd, info, data))
        def check(item, *, content):
            handle, name, fd, before, data = item
            handle.check()
            for info in (os.fstat(fd), os.stat(name, dir_fd=handle.fd, follow_symlinks=False)):
                _regular(info, private=True, max_bytes=max(1048576, len(data)))
                if _file_state(info) != before or stat.S_IMODE(info.st_mode) != 0o400 or info.st_size != len(data):
                    _fail()
            if content:
                os.lseek(fd, 0, os.SEEK_SET)
                hashed, total = hashlib.sha256(), 0
                while total <= len(data):
                    chunk = os.read(fd, min(65536, len(data) + 1 - total))
                    if not chunk:
                        break
                    hashed.update(chunk); total += len(chunk)
                if total != len(data) or hashed.digest() != hashlib.sha256(data).digest():
                    _fail()
        for item in held:
            check(item, content=True)
        for item in reversed(held):
            check(item, content=True)
        for item in held:
            check(item, content=False)
    return {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)} for name, data in expected.items()}


def _observe(store, reservation, *, state_required=True):
    if (reservation.get("digest") != digest(reservation) or reservation.get("state_scope") != _scope(store)):
        _fail()
    record, _ = successor._read_run(store, reservation["run_id"])
    anchor = _anchor(record)
    enrollment = _identity(store, record, reservation)
    if (record["digest"] != reservation["original_record_digest"]
            or read_regular(anchor, "enrollment.json", max_bytes=65536, private=True, expected_mode=0o400) != canonical_bytes(enrollment)
            or read_regular(anchor, "recovery-slot.json", max_bytes=65536, private=True, expected_mode=0o400) != canonical_bytes(reservation)):
        _fail()
    if state_required and (store.setting("provider-result-recovery:muse:" + reservation["run_id"]) != reservation
            or store.setting("provider-result-recovery-key:muse:" + reservation["key_digest"]) != reservation
            or store.setting("provider-result-recovery-root:muse:" + reservation["run_id"]) != enrollment):
        _fail()
    receipt = store.setting("provider-result-recovery-receipt:muse:" + reservation["recovery_id"]) if state_required else None
    if receipt is None:
        return _seal({"format": "muse-result-recovery-observation/1", "state": "recovery_incomplete", "run_id": reservation["run_id"],
            "recovery_id": reservation["recovery_id"], "reservation_digest": reservation["digest"], "output": reservation["output"],
            "new_controller_submissions": 0, "original_state": "failed", "automatic_retry_allowed": False,
            "remote_usage": "unknown", "descendant_cessation": "unknown", "patch_applied": False, "acceptance_allowed": False})
    if (receipt.get("digest") != digest(receipt) or receipt.get("reservation_digest") != reservation["digest"]
            or read_regular(anchor, "receipt.json", max_bytes=65536, private=True, expected_mode=0o400) != canonical_bytes(receipt)):
        _fail()
    if receipt["state"] == "recovered_proposal_ready":
        output = pilot._root(reservation["output"])
        observation = loads(read_regular(output, "observation.json", max_bytes=65536, private=True, expected_mode=0o400))
        proof = observation["plan"]
        if (proof.get("digest") != digest(proof) or proof["digest"] != reservation["plan_digest"]
                or proof.get("run_id") != record["run_id"] or proof.get("original_record_digest") != record["digest"]
                or proof.get("configuration_digest") != record["configuration_digest"] or proof.get("bundle_digest") != record["bundle_digest"]
                or proof.get("state_scope") != _scope(store)):
            _fail()
        _, manifest = pilot._bundle(str(output / "snapshot-bundle"))
        response_limit = proof.get("original_proposal_limit")
        if type(response_limit) is not int or not 1024 <= response_limit <= (1048576 if proof.get("format") == "muse-result-recovery-plan/2" else 65536):
            _fail()
        response = loads(read_regular(output, "proposal/response.json", max_bytes=response_limit, private=True, expected_mode=0o400))
        expected, report = _expected_output(proof, manifest, response, reservation)
        if receipt["artifacts"] != _check_output(output, expected) or receipt["proposal_digest"] != report["digest"]:
            _fail()
    return receipt


def _recover(store, *, run_id, key, plan_digest, output):
    successor._id(run_id)
    key_check(key)
    screen_sensitive(key)
    if type(plan_digest) is not str or re.fullmatch(r"[a-f0-9]{64}", plan_digest) is None:
        _fail("provider_result_recovery_plan_changed")
    target = pilot._root(output)
    key_digest = hashlib.sha256(key.encode()).hexdigest()
    request = {"run_id": run_id, "key_digest": key_digest, "plan_digest": plan_digest, "output": str(target)}
    existing = store.setting("provider-result-recovery-key:muse:" + key_digest)
    if existing is not None:
        if any(existing.get(name) != value for name, value in request.items()):
            _fail("provider_result_recovery_key_conflict")
        return _observe(store, existing)
    record, original_root = successor._read_run(store, run_id)
    anchor = _anchor(record)
    if anchor.exists() or anchor.is_symlink():
        try:
            orphan = loads(read_regular(anchor, "recovery-slot.json", max_bytes=65536, private=True, expected_mode=0o400))
        except TaskAlongError:
            _fail("provider_result_recovery_reserved")
        if any(orphan.get(name) != value for name, value in request.items()):
            _fail("provider_result_recovery_key_conflict")
        return _observe(store, orphan, state_required=False)
    proof, material, response = _material(store, run_id)
    if proof["digest"] != plan_digest:
        _fail("provider_result_recovery_plan_changed")
    protected_roots = (original_root, pilot._root(record["bundle"]), anchor)
    protected_roots += tuple(pilot._root(p) for p in material.get("protected_roots", ()))
    for protected in protected_roots:
        if target.is_relative_to(protected) or protected.is_relative_to(target):
            _fail("provider_result_recovery_output_overlap")
    pilot._destination(output)
    reservation = _seal({"format": "muse-result-recovery-reservation/1", **request, "recovery_id": identifier(),
        "state_scope": _scope(store), "original_record_digest": record["digest"], "new_controller_submissions": 0})
    enrollment = _identity(store, record, reservation)
    reserved = False
    try:
        with store.transaction() as db:
            again = store.setting("provider-result-recovery-key:muse:" + key_digest)
            if again is not None:
                if any(again.get(name) != value for name, value in request.items()):
                    _fail("provider_result_recovery_key_conflict")
                return _observe(store, again)
            _no_activity(store, record)
            if store.setting("provider-run:" + run_id) != record:
                _fail()
            _mkdir(anchor)
            pilot._write(anchor, "enrollment.json", canonical_bytes(enrollment))
            pilot._write(anchor, "recovery-slot.json", canonical_bytes(reservation))
            for name, document in (("provider-result-recovery:muse:" + run_id, reservation),
                    ("provider-result-recovery-key:muse:" + key_digest, reservation),
                    ("provider-result-recovery-root:muse:" + run_id, enrollment)):
                db.execute("INSERT INTO settings VALUES (?,?)", (name, canonical_bytes(document).decode()))
        reserved = True
        fresh, _, _ = _material(store, run_id, reservation)
        if fresh != proof:
            _fail("provider_result_recovery_plan_changed")
        _observe(store, reservation)
        _mkdir(target)
        copied = target / "snapshot-bundle"
        _mkdir(copied)
        # A valid copied bundle can NEVER precede its preserved dispatch fence.
        pilot._write(copied, "provider-submission.json", material["marker"])
        pilot._write(copied, "prompt.txt", material["prompt"])
        pilot._write(copied, "bundle.json", canonical_bytes(material["manifest"]))
        options = {"replacement_profile": "megabyte-proposal/1"} if proof.get("format") == "muse-result-recovery-plan/2" else {}
        report = pilot.stage(bundle=str(copied), response=response, output=str(target / "proposal"), **options)
        expected, expected_report = _expected_output(proof, material["manifest"], response, reservation)
        if report != expected_report:
            _fail()
        pilot._write(target, "observation.json", expected["observation.json"])
        artifacts = _check_output(target, expected)
        receipt = _seal({"format": "muse-result-recovery-observation/1", "state": "recovered_proposal_ready", **request,
            "recovery_id": reservation["recovery_id"], "reservation_digest": reservation["digest"], "artifacts": artifacts,
            "proposal_digest": report["digest"], "model_free": True, "new_controller_submissions": 0, "original_state": "failed",
            "remote_usage": "unknown", "descendant_cessation": "unknown", "automatic_retry_allowed": False,
            "patch_applied": False, "acceptance_allowed": False})
        pilot._write(anchor, "receipt.json", canonical_bytes(receipt))
        with store.transaction() as db:
            db.execute("INSERT INTO settings VALUES (?,?)", ("provider-result-recovery-receipt:muse:" + reservation["recovery_id"], canonical_bytes(receipt).decode()))
        return _observe(store, reservation)
    except (TaskAlongError, OSError, sqlite3.Error):
        if reserved:
            receipt = _seal({"format": "muse-result-recovery-observation/1", "state": "recovery_incomplete", **request,
                "recovery_id": reservation["recovery_id"], "reservation_digest": reservation["digest"],
                "new_controller_submissions": 0, "original_state": "failed", "automatic_retry_allowed": False,
                "remote_usage": "unknown", "descendant_cessation": "unknown", "patch_applied": False, "acceptance_allowed": False})
            try:
                pilot._write(anchor, "receipt.json", canonical_bytes(receipt))
                with store.transaction() as db:
                    db.execute("INSERT INTO settings VALUES (?,?)", ("provider-result-recovery-receipt:muse:" + reservation["recovery_id"], canonical_bytes(receipt).decode()))
            except (TaskAlongError, OSError, sqlite3.Error):
                pass
        _fail("provider_result_recovery_incomplete", uncertain=reserved or anchor.exists())


def recover(store, *, run_id, key, plan_digest, output):
    try:
        return _recover(store, run_id=run_id, key=key, plan_digest=plan_digest, output=output)
    except TaskAlongError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, sqlite3.Error):
        _fail()
