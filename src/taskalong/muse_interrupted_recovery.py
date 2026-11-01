"""One explicit replacement of an interrupted /6 owner, never settlement.

Current recorded PID/group absence is a narrow observation. It neither closes
an incomplete capture nor proves escaped descendants or remote work ceased.
"""
from __future__ import annotations

import datetime
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os

from . import muse_experimental as muse, muse_capture_recovery as proof
from . import supervised_pilot as pilot
from .artifact_io import read_regular, _file_state, _parent, _regular, _unchanged_directories
from .errors import TaskAlongError
from .local_provider_capture import _Directory, _read_capture_fd
from .muse_native_lifecycle import NativeModelTaskGuard
from .process import receipt_is_alive
from .validation import canonical_bytes, digest, loads

POLICY = "stop-on-first-model-failure-or-second-model-task/1"
_RAW = 64 * 1048576
_FRAME = 16 * 1048576
_RECORDS = 131072


def _fail(code="provider_successor_history_changed"):
    muse._fail(code, "Interrupted-owner evidence is missing, live, changed or conflicting. Preserve the original claim and observations; no new request is authorized.")


def _bindings(row, session, native_run):
    """Recognized structured references bind recursively; text stays opaque."""
    payload, _, _ = proof._parts(row)
    def identifier(value):
        if type(value) is not str or not value or not value.isprintable() or len(value.encode()) > 256:
            _fail()
        return value
    def reference(value, kind):
        if type(value) is not dict or set(value) != {"kind", "id"} or value.get("kind") != kind:
            _fail()
        return identifier(value["id"])
    task = identifier(payload.get("task_id")) if payload.get("kind") == "task_lifecycle" else None
    pending = [row]
    while pending:
        part = pending.pop()
        if type(part) is dict:
            for key, expected in (("run_id", native_run), ("session_id", session), ("command_id", native_run)):
                if key in part and identifier(part[key]) != expected:
                    _fail()
            for key, kind, expected in (("run_stream", "run", native_run), ("session_stream", "session", session)):
                if key in part and reference(part[key], kind) != expected:
                    _fail()
            declared = identifier(part["task_id"]) if "task_id" in part else None
            streamed = reference(part["task_stream"], "task") if "task_stream" in part else None
            if ((declared is not None and streamed is not None and declared != streamed)
                    or task is not None and (declared is not None and declared != task or streamed is not None and streamed != task)):
                _fail()
            pending.extend(part.values())
        elif type(part) is list:
            pending.extend(part)


def _result(row):
    outcome = proof._terminal(row)
    if outcome is not None and (outcome[0] == "conflict" or outcome[1] == "completed"):
        _fail("provider_successor_result_exists")
    payload, event, _ = proof._parts(row)
    pending = [row]
    configured = []
    while pending:
        part = pending.pop()
        if type(part) is dict:
            if part.get("kind") == "assistant_message_committed":
                _fail("provider_successor_result_exists")
            if part.get("kind") == "model_request_configured":
                configured.append(part)
            if {"response", "structured_output", "changes", "patch"}.intersection(part):
                _fail("provider_successor_result_exists")
            pending.extend(part.values())
        elif type(part) is list:
            pending.extend(part)
    if configured and (outcome is not None or len(configured) != 1 or configured[0] is not event
                       or payload.get("kind") != "run"):
        _fail("provider_successor_result_exists")
    return outcome


def _capture(root, config, session):
    """Read at most one frame at a time; incomplete checkpoints stay incomplete."""
    directory = _Directory(root / "capture")
    fds = {}
    try:
        metadata = {}
        capture = _read_capture_fd(directory, _metadata_states=metadata)
        expected = {"kind": "private_local_provider_capture", "schema_version": "2.0",
                    "max_output_bytes": config["max_output_bytes"], "max_records": 8192}
        if (loads(read_regular(root / "capture", "capture.json", max_bytes=65536, private=True, expected_mode=0o400)) != expected
                or capture["schema_version"] != "2.0" or capture["status"] != "incomplete"
                or capture["byte_closure"] is not False or capture["observed_counts_complete"] is not False
                or capture["metadata_limited"] is not False or capture["output_limited"] is not False
                or capture["streams"]["result"]["actual_bytes"] != 0):
            _fail()
        states = {}
        for stream in ("stdout", "stderr", "result"):
            fd = os.open(stream + ".bin", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory.fd)
            fds[stream] = fd
            states[stream] = _file_state(os.fstat(fd))
        guard = NativeModelTaskGuard(session, max_records=_RECORDS, max_frame_bytes=_FRAME)
        native_run = None
        pending_command = pending_row = None
        terminal = False
        size = count = 0
        hashed = hashlib.sha256()
        with os.fdopen(os.dup(fds["stdout"]), "rb", buffering=65536) as source:
            while True:
                line = source.readline(_FRAME + 2)
                if not line:
                    break
                size += len(line); count += 1
                if count > _RECORDS or size > _RAW or not line.endswith(b"\n") or not 1 <= len(line) - 1 <= _FRAME:
                    _fail("provider_successor_capture_unrecognized")
                hashed.update(line)
                row = muse._native_json(line[:-1], max_bytes=_FRAME, _journal_numbers=True)
                payload, event, record = proof._parts(row)
                reference = payload.get("run_stream")
                if native_run is None and reference is not None:
                    from .muse_successor import _id
                    if type(reference) is not dict or reference.get("kind") != "run":
                        _fail()
                    native_run = _id(reference.get("id"))
                    if pending_command is not None:
                        if pending_command != native_run:
                            _fail()
                        _bindings(pending_row, session, native_run)
                if native_run is None:
                    if (count != 1 or row.get("payload_type") != "runtime.command.accepted"
                            or payload.get("kind") != "command_accepted"):
                        _fail()
                    from .muse_successor import _id
                    pending_command = _id(payload.get("command_id"))
                    pending_row = row
                    _bindings(row, session, pending_command)
                    _result(row)
                    guard.observe(line[:-1])
                    continue
                _bindings(row, session, native_run)
                if ((payload.get("kind") == "run_output_delta") != (row.get("payload_type") == "run.output.delta")
                        or row.get("payload_type") == "run.output.delta" and (type(payload.get("text")) is not str
                            or payload.get("command_id") != native_run)):
                    _fail("provider_successor_capture_unrecognized")
                outcome = _result(row)
                if outcome is not None:
                    if terminal:
                        _fail("provider_successor_result_exists")
                    terminal = True
                elif terminal and not proof._trailing_metadata(row):
                    _fail("provider_successor_result_exists")
                guard.observe(line[:-1])
        summary = guard.summary()
        if (native_run is None or summary.get("protocol_valid") is not True
                or size != capture["streams"]["stdout"]["actual_bytes"]
                or hashed.hexdigest() != capture["streams"]["stdout"]["sha256"]):
            _fail("provider_successor_capture_unrecognized")
        later_metadata = {}
        if _read_capture_fd(directory, _metadata_states=later_metadata) != capture or later_metadata != metadata:
            _fail()
        for stream, fd in fds.items():
            for info in (os.fstat(fd), os.stat(stream + ".bin", dir_fd=directory.fd, follow_symlinks=False)):
                _regular(info, private=True, max_bytes=_RAW)
                if _file_state(info) != states[stream]:
                    _fail()
        directory.check()
        identity = hashlib.sha256(repr((metadata, states)).encode()).hexdigest()
        return native_run, {"receipt_sha256": digest(capture), "identity_sha256": identity,
            "status": "incomplete", "byte_closure": False, "observed_counts_complete": False,
            "retained_stdout_bytes": size, "records_observed": count, "native_lifecycle": summary}
    finally:
        failure = None
        for fd in fds.values():
            try:
                os.close(fd)
            except OSError as exc:
                failure = failure or exc
        try:
            directory.close()
        except OSError as exc:
            failure = failure or exc
        if failure is not None:
            raise failure


def _journal(config, session, native_run, started):
    instant = datetime.datetime.fromtimestamp(started / 1000, datetime.timezone.utc)
    days = {day + datetime.timedelta(days=n) for day in (instant.date(), instant.astimezone().date()) for n in (-1, 0, 1)}
    home = pilot._root(config["muse_home"])
    relative, selected = muse._journal_identity_path(home, session, days)
    with _parent(home, relative, private=False) as (parent, name, links):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            def fence():
                for info in (os.fstat(fd), os.stat(name, dir_fd=parent, follow_symlinks=False)):
                    _regular(info, private=False, max_bytes=_RAW)
                    if _file_state(info) != selected:
                        _fail()
                _unchanged_directories(links)
            fence()
            hashed = hashlib.sha256()
            count = total = configured = sequence = bound = 0
            terminal = None
            metadata = {}
            with os.fdopen(os.dup(fd), "rb", buffering=65536) as source:
                while True:
                    line = source.readline(_FRAME + 2)
                    if not line:
                        break
                    count += 1; total += len(line)
                    if count > _RECORDS or total > _RAW or not line.endswith(b"\n") or not 1 <= len(line) - 1 <= _FRAME:
                        _fail()
                    hashed.update(line)
                    row = muse._native_json(line[:-1], max_bytes=_FRAME, _journal_numbers=True)
                    if "stream" in row and row["stream"] != {"kind": "session", "id": session}:
                        _fail()
                    if "schema_version" in row and (type(row["schema_version"]) is not int or row["schema_version"] != 1):
                        _fail()
                    if "payload_schema_version" in row and (type(row["payload_schema_version"]) is not int or row["payload_schema_version"] != 1):
                        _fail()
                    if "sequence" in row:
                        if type(row["sequence"]) is not int or row["sequence"] <= sequence:
                            _fail()
                        sequence = row["sequence"]
                    payload, event, record = proof._parts(row)
                    _bindings(row, session, native_run)
                    if payload.get("kind") == "run" and payload.get("run_id") == native_run:
                        bound += 1
                    outcome = _result(row)
                    if outcome is not None:
                        if terminal is not None:
                            _fail("provider_successor_result_exists")
                        terminal = outcome[1]
                        continue
                    if terminal is not None and not proof._trailing_metadata(row):
                        _fail("provider_successor_result_exists")
                    if event.get("kind") == "model_request_configured":
                        if (payload.get("kind") != "run" or payload.get("run_id") != native_run
                                or event.get("toolset", {}).get("active_tools") != []
                                or event.get("reminder_roster", {}).get("agents") != []):
                            _fail()
                        configured += 1
                    if payload.get("kind") == "metadata":
                        if len(json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode()) > 65536:
                            _fail()
                        for key in ("provider_id", "model_id", "reasoning_effort"):
                            if key in record:
                                value = record[key]
                                if not (key == "reasoning_effort" and value is None) and (type(value) is not str
                                        or not 1 <= len(value.encode()) <= 256 or not value.isprintable()):
                                    _fail()
                                if key in ("provider_id", "model_id") and value != ("meta" if key == "provider_id" else config["model"]):
                                    _fail()
                                metadata[key] = value
            if total != selected[5] or not bound or configured != 1 or metadata.get("provider_id") != "meta" or metadata.get("model_id") != config["model"]:
                _fail()
            fence()
            second = hashlib.sha256(); size = 0
            os.lseek(fd, 0, os.SEEK_SET)
            while size <= total:
                data = os.read(fd, min(65536, total + 1 - size))
                if not data:
                    break
                size += len(data); second.update(data)
            if size != total or second.digest() != hashed.digest():
                _fail()
            fence()
            if muse._journal_identity_path(home, session, days) != (relative, selected):
                _fail()
            return {"sha256": hashed.hexdigest(), "identity_sha256": hashlib.sha256(repr(selected).encode()).hexdigest(),
                "bytes": total, "records": count, "configured_model_requests_observed_lower_bound": configured,
                "reported_provider": metadata["provider_id"], "reported_model": metadata["model_id"],
                "reported_effort": metadata.get("reasoning_effort"), "native_terminal_observed": terminal}
        finally:
            os.close(fd)


def _journal_unchanged(config, session, started, expected):
    instant = datetime.datetime.fromtimestamp(started / 1000, datetime.timezone.utc)
    days = {day + datetime.timedelta(days=n) for day in (instant.date(), instant.astimezone().date()) for n in (-1, 0, 1)}
    _, selected = muse._journal_identity_path(pilot._root(config["muse_home"]), session, days)
    if hashlib.sha256(repr(selected).encode()).hexdigest() != expected["identity_sha256"]:
        _fail()


@contextmanager
def _original_observation(first):
    """Keep at most 69 owner files and three raw streams held until decision.

    Capture index metadata is bounded to the existing 8192 checkpoint ceiling;
    those immutable entries are stat-fenced without opening thousands of FDs.
    No original content or namespace is written by this observation.
    """
    parent, root, manifest, _, _, artifacts = first
    with ExitStack() as cleanup:
        directories = {}
        for label, path in (("root", root), ("events", root / "events"),
                            ("bundle", pilot._root(parent["bundle"])), ("capture", root / "capture")):
            handle = _Directory(path)
            cleanup.callback(handle.close)
            directories[label] = handle
        names = {label: handle.names() for label, handle in directories.items()}
        expected_events = {f"{number:04d}.json" for number in range(1, parent["revision"] + 1)}
        if not 1 <= parent["revision"] <= 64 or names["events"] != expected_events:
            _fail()
        selected = [("events", f"{number:04d}.json", None) for number in range(1, parent["revision"] + 1)]
        selected.extend((("root", "prompt.txt", artifacts["prompt.txt"]),
            ("root", "invocation.json", artifacts["invocation.json"]),
            ("bundle", "provider-submission.json", artifacts["submission_marker"]),
            ("bundle", "bundle.json", hashlib.sha256(canonical_bytes(manifest)).hexdigest()),
            ("bundle", "prompt.txt", hashlib.sha256(pilot._prompt(manifest["request"], manifest["digest"])).hexdigest())))
        held, events_hash = [], hashlib.sha256()
        for label, name, expected in selected:
            directory = directories[label]
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory.fd)
            cleanup.callback(os.close, fd)
            info = os.fstat(fd)
            _regular(info, private=True, max_bytes=1048576)
            if info.st_mode & 0o7777 != 0o400:
                _fail()
            before = _file_state(info)
            hashed, size = hashlib.sha256(), 0
            while size <= info.st_size:
                chunk = os.pread(fd, min(65536, info.st_size + 1 - size), size)
                if not chunk:
                    break
                size += len(chunk); hashed.update(chunk)
                if label == "events":
                    events_hash.update(chunk)
            if size != info.st_size or expected is not None and hashed.hexdigest() != expected:
                _fail()
            held.append((directory, name, fd, before))
        if events_hash.hexdigest() != artifacts["event_history"]:
            _fail()
        capture_states = {}
        capture_dir = directories["capture"]
        for name in sorted(names["capture"]):
            info = os.stat(name, dir_fd=capture_dir.fd, follow_symlinks=False)
            _regular(info, private=True, max_bytes=_RAW)
            capture_states[name] = _file_state(info)
            if name in {"stdout.bin", "stderr.bin", "result.bin"}:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=capture_dir.fd)
                cleanup.callback(os.close, fd)
                held.append((capture_dir, name, fd, _file_state(info)))
        def fence():
            for directory, name, fd, before in held:
                if (_file_state(os.fstat(fd)) != before
                        or _file_state(os.stat(name, dir_fd=directory.fd, follow_symlinks=False)) != before):
                    _fail()
            for name, before in capture_states.items():
                if _file_state(os.stat(name, dir_fd=capture_dir.fd, follow_symlinks=False)) != before:
                    _fail()
            for label, directory in directories.items():
                directory.check()
                if directory.names() != names[label]:
                    _fail()
        fence()
        identity = hashlib.sha256(repr(([(label, [(link[1], link[3]) for link in handle.links])
            for label, handle in directories.items()], [(name, before) for _, name, _, before in held], capture_states)).encode()).hexdigest()
        try:
            yield identity
        finally:
            fence()


def _original(store, predecessor, config):
    from . import muse_successor as owner
    parent, root = owner._read_run(store, predecessor)
    previous = store.setting("provider-config:" + parent["configuration_digest"])
    if (parent["format"] != "local-provider-run/1" or parent.get("manual_successor") is not None
            or parent.get("state") != "interrupted" or type(parent.get("controller_submissions")) is not int
            or parent["controller_submissions"] != 1 or type(previous) is not dict
            or previous.get("format") != "local-muse-provider/6" or previous != config
            or previous.get("digest") != digest(previous) or parent["configuration_digest"] != previous["digest"]
            or any(parent.get(key) != "unknown" for key in ("remote_usage", "descendant_cessation", "native_internal_retries"))
            or any(parent.get(key) is not False for key in ("automatic_retry_allowed", "patch_applied", "acceptance_allowed", "production_dispatch_allowed"))):
        _fail("provider_successor_configuration_mismatch")
    muse._checked_configuration(previous)
    receipt = parent.get("process_receipt")
    if (type(receipt) is not dict or set(receipt) != {"invocation_id", "pid", "pgid", "supervisor_pid", "started_unix_ms", "executable_sha256"}
            or any(type(receipt.get(key)) is not int or receipt[key] < 2 for key in ("pid", "pgid", "supervisor_pid"))
            or receipt["pid"] != receipt["pgid"] or type(receipt.get("started_unix_ms")) is not int
            or not 1 <= receipt["started_unix_ms"] <= 2**53 - 1 or receipt.get("executable_sha256") != config["binary"]["sha256"]):
        _fail()
    owner._id(receipt["invocation_id"])
    bundle, manifest = pilot._bundle(parent["bundle"])
    if manifest["digest"] != parent["bundle_digest"]:
        _fail()
    if any(path.exists() or path.is_symlink() for path in [root / name for name in
           ("proposal", "response.json", "proposed.patch", "review.json", "response-claim.json", "process.json")] + [bundle / "response-claim.json"]):
        _fail("provider_successor_result_exists")
    artifacts = {"event_history": proof._events(root, parent)}
    states = []
    for number in range(1, parent["revision"] + 1):
        event = loads(read_regular(root, f"events/{number:04d}.json", max_bytes=1048576, private=True, expected_mode=0o400))
        states.append(event.get("state"))
        if (event.get("format") != "local-provider-run/1" or event.get("configuration_digest") != config["digest"]
                or event.get("bundle_digest") != manifest["digest"] or event.get("output") != parent["output"]
                or event.get("bundle") != parent["bundle"] or event.get("manual_successor") is not None
                or event.get("controller_submissions") != (0 if number == 1 else 1)
                or number >= 3 and event.get("process_receipt") != receipt):
            _fail()
    if states != ["preflight", "starting", "running", "interrupted"]:
        _fail()
    def read(name):
        raw = read_regular(root, name, max_bytes=1048576, private=True, expected_mode=0o400)
        artifacts[name] = hashlib.sha256(raw).hexdigest()
        return raw
    invocation = loads(read("invocation.json"))
    session = owner._id(invocation.get("session_id"))
    if (invocation.get("configuration_digest") != config["digest"] or invocation.get("bundle_digest") != manifest["digest"]
            or invocation.get("argv") != muse._argv(config, provider="meta", workspace=root / "workspace", prompt=root / "prompt.txt", session=session)
            or read("prompt.txt") != pilot._prompt(manifest["request"], manifest["digest"])):
        _fail()
    marker = read_regular(bundle, "provider-submission.json", max_bytes=65536, private=True, expected_mode=0o400)
    if (store.setting("provider-claim:muse:" + manifest["digest"]) != {"run_id": predecessor, "output": str(root), "bundle_digest": manifest["digest"]}
            or marker != canonical_bytes({"provider": "muse", "run_id": predecessor, "bundle_digest": manifest["digest"]})
            or store.setting("provider-result-recovery:muse:" + predecessor) is not None):
        _fail()
    artifacts["submission_marker"] = hashlib.sha256(marker).hexdigest()
    return parent, root, manifest, session, receipt, artifacts


def _material(store, predecessor, config, first, identity):
    """Plan one linked replacement; all current absence facts are rechecked."""
    from . import muse_successor as owner
    try:
        parent, root, manifest, session, receipt, artifacts = first
        if receipt_is_alive(receipt) is not False:
            _fail("provider_successor_original_process_present")
        native_run, capture = _capture(root, config, session)
        journal = _journal(config, session, native_run, receipt["started_unix_ms"])
        if _original(store, predecessor, config) != first or _capture(root, config, session) != (native_run, capture):
            _fail()
        if _journal(config, session, native_run, receipt["started_unix_ms"]) != journal:
            _fail()
        if receipt_is_alive(receipt) is not False or _original(store, predecessor, config) != first:
            _fail("provider_successor_original_process_present")
        if (_journal(config, session, native_run, receipt["started_unix_ms"]) != journal
                or _original(store, predecessor, config) != first
                or _capture(root, config, session) != (native_run, capture)):
            _fail()
        _journal_unchanged(config, session, receipt["started_unix_ms"], journal)
        artifacts.update(capture=capture["receipt_sha256"], capture_identity=capture["identity_sha256"], native_journal=journal["sha256"], journal_identity=journal["identity_sha256"], original_identity=identity)
        enrollment = {"format": "manual-muse-ladder/4", "reason": "interrupted", "root_run_id": predecessor,
            "root_record_digest": parent["digest"], "bundle_digest": manifest["digest"],
            "state_scope": hashlib.sha256(str(store.root).encode()).hexdigest(), "deadlines_seconds": [config["attempt_seconds"]],
            "max_new_controller_submissions": 1, "native_lifecycle_policy": POLICY}
        registered = store.setting("provider-successor-root:muse:" + predecessor)
        if registered is not None and registered != enrollment:
            _fail()
        owner._anchor_view(store, parent, enrollment)
        value = {"format": "manual-muse-successor-plan/4", "reason": "interrupted", "provider": "muse", "ordinal": 1,
            "predecessor_run_id": predecessor, "predecessor_digest": parent["digest"], "root_run_id": predecessor,
            "bundle_digest": manifest["digest"], "configuration_digest": config["digest"], "attempt_seconds": config["attempt_seconds"],
            "max_output_bytes": config["max_output_bytes"], "max_protocol_records": muse._max_records(config), "max_proposal_bytes": config["max_proposal_bytes"],
            "artifact_hashes": artifacts, "enrollment": enrollment, "remaining_controller_slots_including_this": 1,
            "remaining_local_meta_seconds_including_this": config["attempt_seconds"], "native_lifecycle_policy": POLICY,
            "history": [{"run_id": predecessor, "controller_submissions": 1, "remote_usage": "unknown", "descendant_cessation": "unknown", "native_internal_retries": "unknown"}],
            "original_state": "interrupted", "original_capture": capture, "native_journal": journal,
            "native_model_task_starts_observed_lower_bound": capture["native_lifecycle"]["model_tasks_started"],
            "native_model_task_starts_source": "retained_complete_stdout_lifecycle_frames",
            "requested_model": config["model"], "requested_effort": config["reasoning_effort"],
            "current_recorded_pid_and_group_absent": True, "absence_observations": 2,
            "plan_authorizes_dispatch": False, "automatic_retry_allowed": False, "remote_usage_settled": False,
            "complete_descendant_cessation_proven": False, "hard_native_attempt_limit_enforced": False, "model_free": True}
        value["digest"] = digest(value)
        return value, parent, root, manifest
    except (TaskAlongError, OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, TaskAlongError) and exc.code.startswith("provider_successor_"):
            raise
        _fail()


def material(store, predecessor, config):
    try:
        first = _original(store, predecessor, config)
        with _original_observation(first) as identity:
            return _material(store, predecessor, config, first, identity)
    except (TaskAlongError, OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, TaskAlongError) and exc.code.startswith("provider_successor_"):
            raise
        _fail()
