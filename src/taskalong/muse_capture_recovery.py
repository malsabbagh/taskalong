"""One explicit expanded-capture successor; never fragment recovery or replay.

All evidence is retained failed-run material. A limited sink authenticates a
prefix, not a completed protocol or accepted response. Native cancellation and
local cleanup do not settle remote usage or complete descendant uncertainty.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re

from . import muse_experimental as muse
from . import supervised_pilot as pilot
from .artifact_io import read_regular, _file_state, _parent, _regular, _unchanged_directories
from .errors import TaskAlongError
from .local_provider_capture import read_capture, _Directory
from .validation import canonical_bytes, digest, loads

_MAX_OWNER_EVENTS = 64  # New /3 proof only; distinct from capture checkpoints.


def _fail(code, message):
    muse._fail(code, message)


def _terminal_prefix():
    muse._fail("provider_successor_terminal_prefix", "A retained terminal prefix may contain an existing completed result. Reconcile full sealed native completion evidence; a fresh attempt is not supported.",
        recovery=[{"action": "inspect_retained_terminal_evidence", "new_dispatch_allowed": False,
                   "existing_fragment_recovery_supported": False, "required_evidence": "full_sealed_bound_terminal_and_response"}])


def _parts(row):
    payload = row.get("payload", {})
    if (type(payload) is not dict or type(payload.get("event", {})) is not dict
            or type(payload.get("record", {})) is not dict):
        raise ValueError("native wrapper")
    event, record = payload.get("event", {}), payload.get("record", {})
    for part in (row, payload, event, record):
        if "kind" in part and type(part["kind"]) is not str:
            raise ValueError("native kind type")
        if "payload_type" in part and type(part["payload_type"]) is not str:
            raise ValueError("native payload type")
    return payload, event, record


def _terminal(row):
    """Classify every recognized terminal discriminator, never just one header."""
    payload, event, record = _parts(row)
    parts = (row, payload, event, record)
    marked = {id(part) for part in parts if (part.get("kind") in {"terminal", "run_terminal"}
              or "terminal" in part or part.get("payload_type", "").startswith("run.terminal."))}
    pending = [row]
    while pending:
        part = pending.pop()
        if type(part) is dict:
            if (part.get("kind") in ("terminal", "run_terminal")
                    or type(part.get("payload_type")) is str and part["payload_type"].startswith("run.terminal.")):
                marked.add(id(part))
            pending.extend(part.values())
        elif type(part) is list:
            pending.extend(part)
    if not marked:
        return None
    kind = row.get("payload_type", "")
    if (marked == {id(row), id(payload)} and "kind" not in row and "terminal" not in row
            and "payload_type" not in payload
            and kind in {"run.terminal.cancelled", "run.terminal.completed", "run.terminal.failed"}
            and payload.get("kind") == "run_terminal" and type(payload.get("terminal")) is str
            and payload["terminal"] == kind.rsplit(".", 1)[-1] and not event and not record):
        return "session", payload["terminal"]
    if (marked == {id(event)} and "payload_type" not in event and payload.get("kind") == "run" and event.get("kind") == "terminal"
            and type(event.get("terminal")) is str and event["terminal"] in {"cancelled", "completed", "failed"}
            and not kind.startswith(("run.output.", "run.model.", "task.", "turn.input."))):
        return "journal", event["terminal"]
    return "conflict", None


def _trailing_metadata(row):
    """Only the known metadata wrapper may follow conclusive cancellation."""
    payload, event, record = _parts(row)
    if payload.get("kind") != "metadata" or event:
        return False
    if row.get("payload_type", "").startswith(("run.output.", "run.model.", "run.lifecycle.", "task.", "turn.input.")):
        return False
    result_keys = {"text", "result", "response", "structured_output", "changes", "patch", "delta", "deltas"}
    pending = [row]
    while pending:
        part = pending.pop()
        if type(part) is dict:
            if (result_keys.intersection(part) or part.get("kind") in ("model_request_configured", "run_output_delta", "output", "delta")
                    or type(part.get("payload_type")) is str and part["payload_type"].startswith(("run.output.", "run.model.", "run.lifecycle.", "task.", "turn.input."))):
                return False
            pending.extend(part.values())
        elif type(part) is list:
            pending.extend(part)
    return True


def _delta_tail(raw, session, native_run, last_sequence):
    """Recognize only the observed ordered delta layout, cut inside text.

    Result-bearing terminal prefixes are never discarded, even if complete
    JSON was also observed in earlier nonterminal fragments. The text prefix
    is lexically checked only; it is not returned as response material.
    """
    if not raw or len(raw) > 65536:
        return False
    if (re.search(rb'"payload_type":"run\.terminal\.[A-Za-z_]+"', raw[:2048])
            or b'"kind":"run_terminal"' in raw[:2048]):
        _terminal_prefix()
    identifier = rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    pattern = (re.escape(b'{"schema_version":1,"id":"') + identifier
        + re.escape(b'","stream":{"kind":"session","id":' + json.dumps(session).encode()
            + b'},"sequence":' + str(last_sequence + 1).encode() + b',"recorded_at":')
        + rb'([1-9][0-9]{0,15})'
        + re.escape(b',"record_type":"status","durability":"ephemeral","causation_id":"') + identifier
        + re.escape(b'","payload_type":"run.output.delta","payload_schema_version":1,"payload":{"kind":"run_output_delta","command_id":'
            + json.dumps(native_run).encode() + b',"run_stream":{"kind":"run","id":' + json.dumps(native_run).encode() + b'},"text":"'))
    match = re.match(pattern, raw)
    if match is None or int(match.group(1)) > 2**53 - 1:
        return False
    try:
        text = json.loads(b'"' + raw[match.end():] + b'"')
        text.encode("utf-8", errors="strict")
        return type(text) is str
    except (ValueError, UnicodeError, RecursionError):
        return False


def inspect_prefix(stdout, session, max_records):
    """Authenticate interpretation of a limited prefix, never accept a result."""
    try:
        if type(stdout) is not bytes or not stdout or len(stdout) > 4 * 1048576:
            raise ValueError("capture bound")
        if stdout.endswith(b"\n"):
            complete, tail = stdout, b""
        else:
            complete, separator, tail = stdout.rpartition(b"\n")
            if not separator:
                raise ValueError("missing complete prefix")
            complete += b"\n"
        if tail and (re.search(rb'"payload_type":"run\.terminal\.[A-Za-z_]+"', tail[:2048])
                or b'"kind":"run_terminal"' in tail[:2048]):
            _terminal_prefix()
        sequence = 0
        native_run = None
        fragments = []
        rows = []
        for raw in complete.splitlines():
            sequence += 1
            if sequence > max_records or not raw:
                raise ValueError("record bound")
            row = muse._native_json(raw, max_bytes=16 * 1048576, _journal_numbers=True)
            if (type(row.get("schema_version")) is not int or row["schema_version"] != 1
                    or row.get("stream") != {"kind": "session", "id": session}
                    or type(row.get("sequence")) is not int or row["sequence"] != sequence
                    or type(row.get("payload_type")) is not str or not 1 <= len(row["payload_type"]) <= 128
                    or type(row.get("payload")) is not dict):
                raise ValueError("native prefix binding")
            payload = row["payload"]
            if "payload_schema_version" in row and (type(row["payload_schema_version"]) is not int or row["payload_schema_version"] != 1):
                raise ValueError("native payload version")
            reference = payload.get("run_stream")
            if native_run is None and reference is not None:
                if (type(reference) is not dict or reference.get("kind") != "run" or type(reference.get("id")) is not str):
                    raise ValueError("native run link")
                from .muse_successor import _id
                native_run = _id(reference["id"])
            rows.append(row)
        if native_run is None:
            raise ValueError("missing native run")
        terminals = 0
        for row in rows:
            payload, event, record = _parts(row)
            for binding in (row, payload, event, record):
                _bindings(binding, session, native_run)
            outcome = _terminal(row)
            if outcome is not None:
                terminals += 1
                if terminals > 1 or outcome != ("session", "cancelled"):
                    _terminal_prefix()
                if (payload.get("run_stream") != {"kind": "run", "id": native_run}
                        or "command_id" in payload and (type(payload["command_id"]) is not str or payload["command_id"] != native_run)):
                    _terminal_prefix()
                continue
            if terminals and not _trailing_metadata(row):
                raise ValueError("activity after cancellation")
            if payload.get("kind") == "run_output_delta" and row["payload_type"] != "run.output.delta":
                raise ValueError("delta wrapper conflict")
            if row["payload_type"] == "run.output.delta":
                if (payload.get("kind") != "run_output_delta" or type(payload.get("text")) is not str
                        or payload.get("command_id") != native_run or type(payload.get("command_id")) is not str):
                    raise ValueError("native delta")
                fragments.append(payload["text"])
        if tail and (terminals or sequence + 1 > max_records or not _delta_tail(tail, session, native_run, sequence)):
            raise ValueError("unsupported torn prefix")
        candidate = False
        text = "".join(fragments).strip()
        if text.startswith("```json\n") and text.endswith("\n```"):
            text = text[8:-4].strip()
        if text:
            from .provider_wire import loads_wire
            try:
                loads_wire(text, max_bytes=4 * 1048576)
            except TaskAlongError:
                pass
            else:
                candidate = True
        return native_run, candidate
    except (TaskAlongError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, TaskAlongError) and exc.code == "provider_successor_terminal_prefix":
            raise
        _fail("provider_successor_capture_prefix_unsupported", "The retained output is not a fully bound nonterminal prefix with a recognized lexical delta tail. Recovery is not supported; preserve it without dispatch.")


def _events(root, record):
    if not 1 <= record["revision"] <= _MAX_OWNER_EVENTS:
        _fail("provider_successor_history_changed", "The original event revision exceeds its finite inspection bound.")
    try:
        directory = _Directory(root / "events")
    except (TaskAlongError, OSError, ValueError):
        _fail("provider_successor_history_changed", "The original event directory could not be held safely.")
    held = {}
    try:
        names = directory.names()
        if names != {f"{n:04d}.json" for n in range(1, record["revision"] + 1)}:
            _fail("provider_successor_history_changed", "The original owner event history has missing, later or conflicting evidence.")
        hashed = hashlib.sha256()
        total = 0
        for number in range(1, record["revision"] + 1):
            name = f"{number:04d}.json"
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=directory.fd)
            held[name] = [fd, None, None]
            info = os.fstat(fd)
            _regular(info, private=True, max_bytes=1048576)
            if info.st_mode & 0o7777 != 0o400 or _file_state(info) != _file_state(os.stat(name, dir_fd=directory.fd, follow_symlinks=False)):
                raise ValueError("event identity")
            held[name][1] = _file_state(info)
            raw = read_regular(root, f"events/{number:04d}.json", max_bytes=1048576, private=True, expected_mode=0o400)
            held[name][2] = hashlib.sha256(raw).digest()
            total += len(raw)
            if total > 16 * 1048576:
                _fail("provider_successor_history_changed", "The original event evidence exceeds its finite inspection bound.")
            event = loads(raw)
            if (event.get("run_id") != record["run_id"] or event.get("revision") != number
                    or event.get("digest") != digest(event) or raw != canonical_bytes(event)):
                _fail("provider_successor_history_changed", "The original owner event binding changed.")
            hashed.update(raw)
        def guard(name, value):
            fd, before, _ = value
            if (_file_state(os.fstat(fd)) != before
                    or _file_state(os.stat(name, dir_fd=directory.fd, follow_symlinks=False)) != before):
                raise ValueError("event changed")
        for name, value in held.items():
            guard(name, value)
            fd, before, expected_hash = value
            os.lseek(fd, 0, os.SEEK_SET)
            verified = hashlib.sha256()
            count = 0
            while count <= before[5]:
                chunk = os.read(fd, min(65536, before[5] + 1 - count))
                if not chunk:
                    break
                count += len(chunk)
                verified.update(chunk)
            if count != before[5] or verified.digest() != expected_hash:
                raise ValueError("event bytes changed")
            guard(name, value)
        directory.check()
        if directory.names() != names:
            _fail("provider_successor_history_changed", "The original owner event history changed during observation.")
        for name, value in held.items():
            guard(name, value)
        if directory.names() != names:
            raise ValueError("event names changed")
        directory.check()
        return hashed.hexdigest()
    except (TaskAlongError, OSError, ValueError) as exc:
        if isinstance(exc, TaskAlongError) and exc.code == "provider_successor_history_changed":
            raise
        _fail("provider_successor_history_changed", "The original owner event files changed or could not be fenced as one retained snapshot.")
    finally:
        close_failed = False
        for fd, _, _ in held.values():
            try:
                os.close(fd)
            except OSError:
                close_failed = True
        try:
            directory.close()
        except OSError:
            close_failed = True
        if close_failed:
            _fail("provider_successor_history_changed", "The event proof descriptors could not be closed safely; no successor is admitted.")


def _bindings(binding, session, native_run):
    if "session_id" in binding and (type(binding["session_id"]) is not str or binding["session_id"] != session):
        raise ValueError("foreign session")
    if "run_id" in binding and (type(binding["run_id"]) is not str or binding["run_id"] != native_run):
        raise ValueError("foreign run")
    for key, kind, expected in (("run_stream", "run", native_run), ("session_stream", "session", session)):
        if key in binding:
            reference = binding[key]
            if (type(reference) is not dict or reference.get("kind") != kind
                    or type(reference.get("id")) is not str or reference["id"] != expected):
                raise ValueError("foreign stream")


def _journal(config, session, native_run, started_unix_ms):
    """Read a full stable journal with separate 64MiB/131072/16MiB bounds."""
    try:
        if type(started_unix_ms) is not int or started_unix_ms <= 0:
            raise ValueError("missing native timestamp")
        instant = datetime.datetime.fromtimestamp(started_unix_ms / 1000, datetime.timezone.utc)
        dates = {instant.date(), instant.astimezone().date()}
        days = {day + datetime.timedelta(days=n) for day in dates for n in (-1, 0, 1)}
        home = pilot._root(config["muse_home"])
        relative, selected = muse._journal_identity_path(home, session, days)
        with _parent(home, relative, private=False) as (parent, name, links):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
            try:
                def guard():
                    held, entry = os.fstat(fd), os.stat(name, dir_fd=parent, follow_symlinks=False)
                    _regular(held, private=False, max_bytes=64 * 1048576)
                    _regular(entry, private=False, max_bytes=64 * 1048576)
                    if _file_state(held) != selected or _file_state(entry) != selected:
                        raise ValueError("journal changed")
                    _unchanged_directories(links)
                    return held.st_size
                size = guard()
                first = hashlib.sha256()
                count = total = configured = terminals = sequence = 0
                metadata = {}
                with os.fdopen(os.dup(fd), "rb", buffering=65536) as stream:
                    while True:
                        line = stream.readline(16 * 1048576 + 2)
                        if not line:
                            break
                        count += 1
                        total += len(line)
                        if (count > 131072 or total > 64 * 1048576 or not line.endswith(b"\n")
                                or not 1 <= len(line) - 1 <= 16 * 1048576):
                            raise ValueError("journal bound")
                        first.update(line)
                        row = muse._native_json(line[:-1], max_bytes=16 * 1048576, _journal_numbers=True)
                        if "stream" in row:
                            reference = row["stream"]
                            if (type(reference) is not dict or reference != {"kind": "session", "id": session}
                                    or type(reference.get("id")) is not str or type(reference.get("kind")) is not str):
                                raise ValueError("foreign session")
                        if "sequence" in row:
                            if type(row["sequence"]) is not int or row["sequence"] <= sequence:
                                raise ValueError("journal sequence")
                            sequence = row["sequence"]
                        payload, event, record = _parts(row)
                        for binding in (row, payload, event, record):
                            _bindings(binding, session, native_run)
                        outcome = _terminal(row)
                        if outcome is not None:
                            if outcome != ("journal", "cancelled"):
                                _fail("provider_successor_result_exists", "Completed, hidden or conflicting native terminal material was observed; reconcile it instead of dispatching.")
                            terminals += 1
                            if (configured != 1 or terminals != 1 or payload.get("run_id") != native_run
                                    or event.get("reason") != "cancelled during model step"):
                                raise ValueError("cancelled native terminal order")
                            continue
                        if terminals and not _trailing_metadata(row):
                            raise ValueError("activity after cancelled native terminal")
                        if event.get("kind") == "model_request_configured":
                            configured += 1
                            if (configured != 1 or payload.get("kind") != "run" or payload.get("run_id") != native_run
                                    or event.get("toolset", {}).get("active_tools") != []
                                    or event.get("reminder_roster", {}).get("agents") != []):
                                raise ValueError("configured model evidence")
                        if payload.get("kind") == "metadata":
                            if len(json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")) > 65536:
                                raise ValueError("metadata bound")
                            metadata = {}
                            for key in ("provider_id", "model_id", "reasoning_effort"):
                                if key in record:
                                    value = record[key]
                                    if not (key == "reasoning_effort" and value is None) and (type(value) is not str
                                            or not 1 <= len(value.encode("utf-8")) <= 256 or not value.isprintable()):
                                        raise ValueError("metadata identity")
                                    metadata[key] = value
                if (total != size or configured != 1 or terminals != 1 or metadata.get("provider_id") != "meta"
                        or metadata.get("model_id") != config["model"]):
                    raise ValueError("missing cancellation proof")
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
                if verified != size or first.digest() != second.digest():
                    raise ValueError("journal hash changed")
                guard()
                if muse._journal_identity_path(home, session, days) != (relative, selected):
                    raise ValueError("journal selection changed")
                guard()
                return first.hexdigest()
            finally:
                os.close(fd)
    except (TaskAlongError, OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, TaskAlongError) and exc.code == "provider_successor_result_exists":
            raise
        _fail("provider_successor_cancellation_unconfirmed", "A full stable bound native journal with one empty-tools/reminders model request and one cancelled-during-model-step terminal is required.")


def material(store, predecessor, config):
    """Build the versioned decision; the plan itself grants no dispatch."""
    from . import muse_successor as owner
    parent, root = owner._read_run(store, predecessor)
    if parent["format"] != "local-provider-run/1" or parent.get("manual_successor") is not None:
        _fail("provider_successor_limit", "Expanded capture permits one final successor of an original failure only.")
    previous = store.setting("provider-config:" + parent["configuration_digest"])
    muse._checked_configuration(previous)
    muse._checked_configuration(config)
    if previous.get("format") != "local-muse-provider/5" or config.get("format") != "local-muse-provider/6":
        _fail("provider_successor_capture_profile", "Expanded recovery requires an original large-task /5 profile and an explicitly configured /6 profile.")
    omitted = {"format", "digest", "capture_profile", "max_output_bytes", "max_protocol_records", "max_proposal_bytes"}
    if ({k: v for k, v in config.items() if k not in omitted} != {k: v for k, v in previous.items() if k not in omitted}
            or config.get("max_proposal_bytes") != 1048576):
        _fail("provider_successor_configuration_mismatch", "Keep the original deadline, binary, task, account, context, model and effort; select the exact one-MiB /6 proposal cohort.")
    process = parent.get("process")
    if (parent.get("state") != "failed" or parent.get("error") != "provider_local_failure"
            or type(parent.get("controller_submissions")) is not int or parent["controller_submissions"] != 1
            or any(parent.get(key) != "unknown" for key in ("remote_usage", "descendant_cessation", "native_internal_retries"))
            or any(parent.get(key) is not False for key in ("automatic_retry_allowed", "patch_applied", "acceptance_allowed", "production_dispatch_allowed"))
            or type(process) is not dict or process.get("timed_out") is not False or process.get("cancelled") is not False
            or process.get("output_limited") is not True or process.get("root_exit_observed") is not True
            or type(process.get("root_exit_code")) is not int or process.get("group_termination_confirmed") is not True
            or process.get("mode") != "darwin-foreground-experiment/1" or process.get("tracking_errors") != []
            or process.get("boundary_failures") != [] or process.get("failure_code") is not None
            or process.get("protocol_error") is not None or process.get("process_stream_complete") is not True
            or process.get("protocol_record_limited") is not False or process.get("protocol_record_limit") != muse._max_records(previous)
            or type(process.get("protocol_records_observed")) is not int
            or not 1 <= process["protocol_records_observed"] <= muse._max_records(previous)):
        _fail("provider_successor_cancellation_unconfirmed", "The original limited failure requires observed root/group cessation, complete byte counts and no tracking, boundary or protocol error.")
    receipt = process.get("receipt")
    if (type(receipt) is not dict or receipt != parent.get("process_receipt")
            or receipt.get("executable_sha256") != previous["binary"]["sha256"]):
        _fail("provider_successor_history_changed", "The original process identity conflicts with its configured executable.")
    bundle_root, manifest = pilot._bundle(parent["bundle"])
    if manifest["digest"] != parent["bundle_digest"]:
        _fail("provider_successor_history_changed", "The original bundle changed.")
    result_paths = [root / name for name in ("proposal", "response.json", "proposed.patch", "review.json", "response-claim.json")]
    result_paths.append(bundle_root / "response-claim.json")
    if any(path.exists() or path.is_symlink() for path in result_paths):
        _fail("provider_successor_result_exists", "An accepted or staged response already exists; reconcile it instead of dispatching.")
    artifacts = {"event_history": _events(root, parent)}
    def read(name, maximum=1048576):
        raw = read_regular(root, name, max_bytes=maximum, private=True, expected_mode=0o400)
        artifacts[name] = hashlib.sha256(raw).hexdigest()
        return raw
    if loads(read("process.json")) != process:
        _fail("provider_successor_history_changed", "The retained process observation changed.")
    side_stdout = read("stdout.bin", previous["max_output_bytes"])
    side_stderr = read("stderr.bin", previous["max_output_bytes"])
    if read("prompt.txt") != pilot._prompt(manifest["request"], manifest["digest"]):
        _fail("provider_successor_history_changed", "The retained prompt changed.")
    invocation = loads(read("invocation.json"))
    session = owner._id(invocation.get("session_id"))
    if (invocation.get("configuration_digest") != previous["digest"] or invocation.get("bundle_digest") != manifest["digest"]
            or invocation.get("argv") != muse._argv(previous, provider="meta", workspace=root / "workspace", prompt=root / "prompt.txt", session=session)):
        _fail("provider_successor_history_changed", "The retained invocation changed.")
    capture = read_capture(root / "capture")
    if (capture != process.get("private_capture") or capture.get("status") != "limited"
            or capture.get("output_limited") is not True or capture.get("byte_closure") is not True
            or capture.get("metadata_limited") is not False or capture.get("observed_counts_complete") is not True):
        _fail("provider_successor_history_changed", "The independent limited-prefix capture proof is missing or changed.")
    streams = capture["streams"]
    retained = sum(streams[s]["retained_bytes"] for s in ("stdout", "stderr"))
    observed = sum(streams[s]["observed_bytes"] for s in ("stdout", "stderr"))
    if (any(type(process.get(key)) is not int for key in ("observed_output_bytes", "retained_output_bytes", "retained_stdout_bytes", "retained_stderr_bytes"))
            or retained != previous["max_output_bytes"] or observed <= retained or process.get("observed_output_bytes") != observed
            or process.get("retained_output_bytes") != retained or streams["result"]["observed_bytes"] != 0
            or streams["result"]["retained_bytes"] != 0
            or any(process.get("retained_" + s + "_bytes") != streams[s]["retained_bytes"] for s in ("stdout", "stderr"))):
        _fail("provider_successor_history_changed", "The limited-prefix counters conflict with the original process observation.")
    stdout = read_regular(root / "capture", "stdout.bin", max_bytes=previous["max_output_bytes"], private=True,
        expected_mode=0o600, expected_sha256=streams["stdout"]["sha256"], expected_bytes=streams["stdout"]["retained_bytes"])
    stderr = read_regular(root / "capture", "stderr.bin", max_bytes=previous["max_output_bytes"], private=True,
        expected_mode=0o600, expected_sha256=streams["stderr"]["sha256"], expected_bytes=streams["stderr"]["retained_bytes"])
    if side_stdout != muse.redact(stdout) or side_stderr != muse.redact(stderr):
        _fail("provider_successor_history_changed", "The retained diagnostics disagree with their authenticated private prefix.")
    if read_capture(root / "capture") != capture:
        _fail("provider_successor_history_changed", "The limited-prefix capture changed during inspection.")
    artifacts["limited_capture"] = digest(capture)
    native_run, candidate = inspect_prefix(stdout, session, muse._max_records(previous))
    artifacts["native_journal"] = _journal(previous, session, native_run, receipt.get("started_unix_ms"))
    claim = store.setting("provider-claim:muse:" + manifest["digest"])
    expected_claim = {"run_id": parent["run_id"], "output": parent["output"], "bundle_digest": manifest["digest"]}
    marker = read_regular(bundle_root, "provider-submission.json", max_bytes=65536, private=True, expected_mode=0o400)
    if claim != expected_claim or marker != canonical_bytes({"provider": "muse", "run_id": parent["run_id"], "bundle_digest": manifest["digest"]}):
        _fail("provider_successor_history_changed", "The original submission claim is unavailable or changed.")
    artifacts["bundle/provider-submission.json"] = hashlib.sha256(marker).hexdigest()
    if owner._read_run(store, predecessor)[0] != parent:
        _fail("provider_successor_history_changed", "The original owner changed during inspection.")
    if _events(root, parent) != artifacts["event_history"]:
        _fail("provider_successor_history_changed", "The original owner event snapshot changed during evidence inspection.")
    enrollment = {"format": "manual-muse-ladder/3", "reason": "capture", "root_run_id": parent["run_id"],
        "root_record_digest": parent["digest"], "bundle_digest": manifest["digest"],
        "state_scope": hashlib.sha256(str(store.root).encode()).hexdigest(),
        "deadlines_seconds": [config["attempt_seconds"]], "max_new_controller_submissions": 1}
    registered = store.setting("provider-successor-root:muse:" + parent["run_id"])
    if registered is not None and registered != enrollment:
        _fail("provider_successor_history_changed", "The original successor enrollment conflicts.")
    owner._anchor_view(store, parent, enrollment)
    value = {"format": "manual-muse-successor-plan/3", "reason": "capture", "provider": "muse", "ordinal": 1,
        "predecessor_run_id": predecessor, "predecessor_digest": parent["digest"], "root_run_id": parent["run_id"],
        "bundle_digest": manifest["digest"], "configuration_digest": config["digest"], "attempt_seconds": config["attempt_seconds"],
        "max_output_bytes": config["max_output_bytes"], "max_protocol_records": muse._max_records(config), "max_proposal_bytes": 1048576,
        "artifact_hashes": artifacts, "enrollment": enrollment, "remaining_controller_slots_including_this": 1,
        "remaining_local_meta_seconds_including_this": config["attempt_seconds"],
        "history": [{"run_id": parent["run_id"], "controller_submissions": 1, "remote_usage": "unknown", "descendant_cessation": "unknown",
                     "native_internal_retries": "unknown"}],
        "original_state": "failed", "original_capture_status": "limited", "unsealed_candidate_observed": candidate,
        "existing_fragment_recovery_supported": False, "plan_authorizes_dispatch": False,
        "automatic_retry_allowed": False, "remote_usage_settled": False, "complete_descendant_cessation_proven": False, "model_free": True}
    value["digest"] = digest(value)
    return value, parent, root, manifest
