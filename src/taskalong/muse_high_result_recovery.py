"""Read-only evidence admission for a completed, failed High successor.

This authenticates retained local documents, never a new provider invocation,
installed executable, live PID, paid usage, or remote cessation.
"""
from __future__ import annotations

import hashlib
import re

from . import muse_capture_recovery as capture_proof, muse_experimental as muse
from . import muse_successor as successor, supervised_pilot as pilot
from .artifact_io import read_regular
from .local_provider_capture import read_capture
from .muse_effort_amendment import derive
from .muse_native_lifecycle import NativeModelTaskGuard
from .validation import canonical_bytes, digest, loads


def original(store, record, root):
    from .muse_result_recovery import _fail
    reservation = record.get("manual_successor")
    if (record.get("format") != "local-provider-run/2" or type(reservation) is not dict
            or reservation.get("format") != "manual-muse-successor/5"
            or reservation.get("reason") != "interrupted-high"
            or reservation.get("digest") != digest(reservation)
            or reservation.get("run_id") != record["run_id"]
            or reservation.get("output") != str(root) or type(reservation.get("ordinal")) is not int or reservation["ordinal"] != 1
            or reservation.get("root_run_id") != reservation.get("predecessor_run_id")):
        _fail()
    parent, parent_root = successor._read_run(store, reservation["predecessor_run_id"])
    expected_history = [{"run_id": parent["run_id"], "controller_submissions": 1, "remote_usage": "unknown",
        "descendant_cessation": "unknown", "native_internal_retries": "unknown"}]
    if reservation.get("history") != expected_history:
        _fail()
    previous = store.setting("provider-config:" + parent["configuration_digest"])
    if (parent.get("format") != "local-provider-run/1" or parent.get("state") != "interrupted"
            or parent.get("manual_successor") is not None or type(parent.get("controller_submissions")) is not int or parent["controller_submissions"] != 1
            or parent["digest"] != reservation.get("predecessor_digest")
            or type(previous) is not dict or previous.get("digest") != parent["configuration_digest"]
            or previous.get("reasoning_effort") != "max"):
        _fail()
    _, parent_manifest = pilot._bundle(parent["bundle"])
    if (parent_manifest["digest"] != parent["bundle_digest"]
            or store.setting("provider-result-recovery:muse:" + parent["run_id"]) is not None):
        _fail()
    config, manifest, amendment = derive(previous, parent_manifest, "high")
    # Historical validation deliberately does NOT call _checked_configuration,
    # which probes the current executable. Recovery needs no installed client.
    if (config.get("format") != "local-muse-provider/6"
            or config.get("capture_profile") != "megabyte-proposal"
            or config.get("max_output_bytes") != 67108864
            or config.get("max_protocol_records") != 131072
            or type(config.get("attempt_seconds")) is not int or not 1 <= config["attempt_seconds"] <= 1440
            or type(config.get("max_proposal_bytes")) is not int or not 1024 <= config["max_proposal_bytes"] <= 1048576
            or type(config.get("binary")) is not dict
            or type(config["binary"].get("sha256")) is not str
            or re.fullmatch(r"[a-f0-9]{64}", config["binary"]["sha256"]) is None
            or reservation.get("effort_amendment") != amendment
            or reservation.get("configuration_digest") != config["digest"]
            or record.get("configuration_digest") != config["digest"]
            or reservation.get("bundle_digest") != manifest["digest"]
            or record.get("bundle_digest") != manifest["digest"]
            or reservation.get("attempt_seconds") != config["attempt_seconds"]
            or store.setting("provider-config:" + config["digest"]) != config):
        _fail()
    enrollment = store.setting("provider-successor-root:muse:" + parent["run_id"])
    expected_enrollment = {"format": "manual-muse-ladder/5", "reason": "interrupted-high",
        "root_run_id": parent["run_id"], "root_record_digest": parent["digest"],
        "bundle_digest": manifest["digest"], "state_scope": hashlib.sha256(str(store.root).encode()).hexdigest(),
        "deadlines_seconds": [config["attempt_seconds"]], "max_new_controller_submissions": 1,
        "native_lifecycle_policy": reservation.get("native_lifecycle_policy"), "effort_amendment": amendment}
    from .muse_interrupted_recovery import POLICY
    if (reservation.get("native_lifecycle_policy") != POLICY or enrollment != expected_enrollment
            or any(store.setting(key) != reservation for key in (
                "provider-successor:muse:" + parent["run_id"],
                "provider-successor-run:muse:" + record["run_id"],
                "provider-successor-key:muse:" + reservation["key_digest"]))):
        _fail()
    successor._anchor_view(store, parent, enrollment)
    bundle, observed_manifest = pilot._bundle(record["bundle"])
    if observed_manifest != manifest:
        _fail()
    for item, item_manifest in ((parent, parent_manifest), (record, manifest)):
        item_root = pilot._root(item["output"])
        expected_states = ["preflight", "starting", "running", "interrupted" if item is parent else "failed"]
        if item.get("revision") != 4:
            _fail()
        for revision, state in enumerate(expected_states, 1):
            event = loads(read_regular(item_root, f"events/{revision:04d}.json", max_bytes=1048576, private=True, expected_mode=0o400))
            if (event.get("state") != state or event.get("configuration_digest") != item["configuration_digest"]
                    or event.get("bundle_digest") != item_manifest["digest"] or event.get("output") != item["output"]
                    or event.get("bundle") != item["bundle"] or event.get("format") != item["format"]
                    or event.get("manual_successor") != item.get("manual_successor")
                    or type(event.get("controller_submissions")) is not int
                    or event["controller_submissions"] != (0 if revision == 1 else 1)):
                _fail()
        if store.setting("provider-claim:muse:" + item_manifest["digest"]) != {
                "run_id": item["run_id"], "bundle_digest": item_manifest["digest"], "output": item["output"]}:
            _fail()
    parent_marker = read_regular(pilot._root(parent["bundle"]), "provider-submission.json", max_bytes=65536, private=True, expected_mode=0o400)
    if parent_marker != canonical_bytes({"provider": "muse", "run_id": parent["run_id"], "bundle_digest": parent_manifest["digest"]}):
        _fail()
    for path in [root / name for name in ("response.json", "proposal", "proposed.patch", "review.json", "response-claim.json")] + [bundle / "response-claim.json"]:
        if path.exists() or path.is_symlink():
            _fail("provider_result_recovery_result_exists")
    if (record.get("state") != "failed" or record.get("error") != "provider_native_lifecycle_stop"
            or type(record.get("controller_submissions")) is not int or record["controller_submissions"] != 1
            or any(record.get(k) != "unknown" for k in ("remote_usage", "descendant_cessation", "native_internal_retries"))
            or any(record.get(k) is not False for k in ("patch_applied", "acceptance_allowed", "automatic_retry_allowed", "production_dispatch_allowed"))):
        _fail()
    artifacts = {"events": capture_proof._events(root, record),
        "parent_events": capture_proof._events(parent_root, parent),
        "parent_record": parent["digest"], "reservation": reservation["digest"], "enrollment": digest(enrollment)}
    def read(name):
        raw = read_regular(root, name, max_bytes=1048576, private=True, expected_mode=0o400)
        artifacts[name] = hashlib.sha256(raw).hexdigest()
        return raw
    process = record.get("process")
    if (type(process) is not dict or loads(read("process.json")) != process
            or process.get("root_exit_observed") is not True or type(process.get("root_exit_code")) is not int
            or process["root_exit_code"] != 0 or process.get("group_termination_confirmed") is not True
            or any(process.get(k) is not False for k in ("timed_out", "output_limited", "protocol_record_limited"))
            or process.get("tracking_errors") != [] or process.get("boundary_failures") != []
            or process.get("failure_code") is not None or process.get("protocol_error") is not None
            or process.get("mode") != "darwin-foreground-experiment/1" or process.get("process_stream_complete") is not True
            or type(process.get("cancelled")) is not bool
            or process.get("receipt") != record.get("process_receipt")
            or process.get("protocol_record_limit") != config["max_protocol_records"]):
        _fail()
    receipt = process["receipt"]
    if (type(receipt) is not dict or set(receipt) != {"invocation_id", "pid", "pgid", "supervisor_pid", "started_unix_ms", "executable_sha256"}
            or receipt.get("executable_sha256") != config["binary"]["sha256"]
            or any(type(receipt[k]) is not int or receipt[k] < 2 for k in ("pid", "pgid", "supervisor_pid"))
            or receipt["pid"] != receipt["pgid"] or type(receipt.get("started_unix_ms")) is not int
            or not 1 <= receipt["started_unix_ms"] <= 2**53 - 1):
        _fail()
    successor._id(receipt["invocation_id"])
    invocation = loads(read("invocation.json")); session = successor._id(invocation.get("session_id"))
    if (invocation.get("configuration_digest") != config["digest"] or invocation.get("bundle_digest") != manifest["digest"]
            or invocation.get("argv") != muse._argv(config, provider="meta", workspace=root / "workspace", prompt=root / "prompt.txt", session=session)):
        _fail()
    prompt = read("prompt.txt")
    if prompt != pilot._prompt(manifest["request"], manifest["digest"]):
        _fail()
    capture = read_capture(root / "capture")
    if (capture != process.get("private_capture") or capture.get("status") != "closed"
            or capture.get("byte_closure") is not True or capture.get("output_limited") is not False
            or capture.get("metadata_limited") is not False or capture.get("observed_counts_complete") is not True):
        _fail()
    owner = loads(read("process-owner.json"))
    retained_keys = {"retained_output_bytes", "retained_stdout_bytes", "retained_stderr_bytes"}
    if (owner.get("capture_finalized") is not False
            or any(type(owner.get(k)) is not int or owner[k] != 0 for k in retained_keys)
            or any(process.get(k) != v for k, v in owner.items() if k not in retained_keys | {"capture_finalized"})):
        _fail()
    streams = capture["streams"]; raw = {}
    for stream in ("stdout", "stderr"):
        ref = streams[stream]
        raw[stream] = read_regular(root / "capture", stream + ".bin", max_bytes=config["max_output_bytes"],
            private=True, expected_mode=0o600, expected_sha256=ref["sha256"], expected_bytes=ref["retained_bytes"])
        if ref["observed_bytes"] != len(raw[stream]) or process.get("retained_" + stream + "_bytes") != len(raw[stream]):
            _fail()
    total = sum(map(len, raw.values()))
    if (not 0 < total <= config["max_output_bytes"] or process.get("observed_output_bytes") != total
            or process.get("retained_output_bytes") != total or streams["result"]["observed_bytes"] != 0
            or streams["result"]["retained_bytes"] != 0 or read_capture(root / "capture") != capture):
        _fail()
    # Replay the ENTIRE closed stream with the corrected grammar, not just the
    # formerly rejected status. Extra starts, errors, unknown facets still veto.
    guard = NativeModelTaskGuard(session)
    lines = raw["stdout"].splitlines()
    if not raw["stdout"].endswith(b"\n"):
        _fail()
    for line in lines:
        guard.observe(line)
    checked = guard.summary()
    if (not guard.completed_single_model(full=True) or checked["stop_requested"] or not checked["protocol_valid"] or checked["model_tasks_observed"] != 1
            or checked["tracked_tasks"] != 1
            or any(checked[k] != 1 for k in ("model_tasks_proposed", "model_tasks_side_effect_intent", "model_tasks_started"))
            or process.get("protocol_records_observed") != len(lines)):
        _fail()
    old_guard = process.get("native_lifecycle")
    if (type(old_guard) is not dict or old_guard.get("first_stop_cause") != "malformed_native_lifecycle"
            or old_guard.get("first_protocol_failure") != "malformed_native_lifecycle"
            or old_guard.get("stop_requested") is not True or old_guard.get("protocol_valid") is not False
            or type(old_guard.get("first_stop_sequence")) is not int
            or not 0 <= old_guard["first_stop_sequence"] < len(lines)):
        _fail()
    stopped = muse._native_json(lines[old_guard["first_stop_sequence"]], max_bytes=16777216)
    if (stopped.get("payload_type") != "task.lifecycle.status"
            or stopped.get("payload", {}).get("event", {}).get("details", {}).get("phase") != "stream_succeeded"):
        _fail()
    marker = read_regular(bundle, "provider-submission.json", max_bytes=65536, private=True, expected_mode=0o400)
    expected_marker = {"provider": "muse", "run_id": record["run_id"], "bundle_digest": manifest["digest"],
        "predecessor_run_id": parent["run_id"], "reservation_digest": reservation["digest"]}
    if marker != canonical_bytes(expected_marker):
        _fail()
    artifacts.update(capture=digest(capture), submission_marker=hashlib.sha256(marker).hexdigest(), config=config["digest"])
    return {"record": record, "root": root, "config": config, "manifest": manifest, "session": session,
        "stdout": raw["stdout"], "prompt": prompt, "marker": marker, "artifacts": artifacts,
        "high_lineage": {"predecessor_run_id": parent["run_id"], "predecessor_digest": parent["digest"],
            "reservation_digest": reservation["digest"], "effort_amendment": amendment},
        "validated_native_lifecycle": checked,
        "model_task_sha256": guard.completed_model_task_sha256(),
        "protected_roots": [str(parent_root), parent["bundle"], str(successor._anchor(parent))]}


class JournalTasks:
    """Cross-check durable model-task events without interpreting user text."""
    def __init__(self, session, native_run):
        self.session, self.native_run = session, native_run
        self.guard = NativeModelTaskGuard(session)
        self.count = self.created = 0

    def observe(self, row):
        from .muse_result_recovery import _fail
        payload, event, _ = capture_proof._parts(row)
        lifecycle = (payload.get("kind") in {"run", "task"} and payload.get("run_id") == self.native_run
                     and event.get("kind") in {"proposed", "accepted", "scheduled", "side_effect_intent",
                         "started", "status", "completed", "succeeded", "timed_out", "failed", "cancelled"}
                     and "task_id" in event)
        stack = [row]
        while stack:
            item = stack.pop()
            if type(item) is dict:
                if any(type(item.get(k)) is str and item[k].startswith("model.") for k in ("operation", "task_kind")):
                    if not lifecycle:
                        _fail()
                if item.get("kind") == "task_lifecycle":
                    _fail()
                stack.extend(item.values())
            elif type(item) is list:
                stack.extend(item)
        if event.get("kind") == "model_response_created":
            self.created += 1
            if self.created > 1:
                _fail()
        if lifecycle:
            if payload.get("task_id", event["task_id"]) != event["task_id"]:
                _fail()
            self.count += 1
            task = event["task_id"]
            wrapper = {"schema_version": 1, "payload_schema_version": 1, "sequence": self.count,
                "stream": {"kind": "session", "id": self.session},
                "payload_type": "task.lifecycle." + event["kind"],
                "payload": {"kind": "task_lifecycle", "task_id": task, "task_stream": {"kind": "task", "id": task},
                    "command_id": self.native_run, "run_stream": {"kind": "run", "id": self.native_run}, "event": event}}
            self.guard.observe(canonical_bytes(wrapper))
            if self.guard.stop_requested:
                _fail()

    def finish(self, expected_task_sha256):
        from .muse_result_recovery import _fail
        # This new recovery dialect requires the full durable model-task chain
        # as well as the separately bound configured-request/commit/terminal.
        if (not self.guard.completed_single_model(full=True) or self.guard.summary()["tracked_tasks"] != 1
                or self.guard.completed_model_task_sha256() != expected_task_sha256):
            _fail()
