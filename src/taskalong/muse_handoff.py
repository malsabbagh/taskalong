"""Closed synthetic Muse admission and supervisor-authored handoff, version 2.9.

Plain output is private untrusted data. Only authoritative current Store records,
owned process observations and independently observed workspace bytes can issue
this handoff, which authorizes no acceptance, publication or live execution.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import ClassVar

from .contracts import JsonDocument
from .errors import TaskAlongError
from .process import ProcessBoundaryError, fingerprint
from .store import encode
from .validation import canonical_bytes, digest, loads, seal_versioned, validate, validate_versioned

VERSION = "2.9"
PROJECTION = "muse-plain-fixture/1"


@dataclass(frozen=True, slots=True)
class MuseDocument(JsonDocument):
    def __post_init__(self):
        admitted = validate_versioned(self.schema_name, loads(self._canonical), expected_version=VERSION)
        object.__setattr__(self, "_canonical", canonical_bytes(admitted))


@dataclass(frozen=True, slots=True)
class MuseConfiguration(MuseDocument):
    schema_name: ClassVar[str] = "capture-config"


@dataclass(frozen=True, slots=True)
class MuseTaskSpec(MuseDocument):
    schema_name: ClassVar[str] = "task-spec"


def _refuse(code="muse_handoff_invalid"):
    raise TaskAlongError(code, "The synthetic Muse subject or supervisor handoff is unresolved or inconsistent.", exit_code=3)


def _require(store):
    if store.format_version not in (9, 10, 11):
        _refuse("store_upgrade_required")


def _checker(store, config):
    row = store.db.execute("SELECT document FROM profiles WHERE digest=?", (config["check_profile_digest"],)).fetchone()
    if row is None:
        _refuse("check_binding_unresolved")
    profile = validate("runtime-profile", loads(row[0]))
    if profile["digest"] != config["check_profile_digest"] or profile["qualification"] != "synthetic":
        _refuse("check_binding_mismatch")
    from .executors.registry import executor_for
    executor_for(profile).preflight(qualification="synthetic", budget={})
    sandbox = store.setting("command_sandbox")
    if (not sandbox or sandbox["qualification"] != "synthetic"
            or digest(sandbox) != config["command_sandbox_digest"]):
        _refuse("sandbox_changed")
    try:
        if fingerprint(sandbox["executable"]) != sandbox["sha256"]:
            _refuse("sandbox_changed")
    except (OSError, ProcessBoundaryError):
        _refuse("sandbox_changed")
    return profile


def configure(store, document):
    """Trusted operator registration of one original fixture; never a live route."""
    _require(store)
    value = seal_versioned("capture-config", {"extensions": {}, **document}, version=VERSION)
    from .executors.muse_fixture import MuseFixtureDriver
    MuseFixtureDriver(value).preflight(qualification="synthetic", budget={})
    _checker(store, value)
    store.record_document(MuseConfiguration.from_dict(value), operation_key="muse-config:" + value["digest"])
    store.set_setting("muse-registration:" + value["digest"], {"configuration_digest": value["digest"],
        "projection": PROJECTION, "qualification": "synthetic", "enabled": True})
    return value


def configuration(store, content_digest):
    _require(store)
    row = store.db.execute("SELECT kind,document FROM document_history WHERE digest=?", (content_digest,)).fetchone()
    if row is None or row["kind"] != "capture_config":
        _refuse("execution_document_unresolved")
    value = MuseConfiguration.from_dict(loads(row["document"])).to_dict()
    if value["digest"] != content_digest:
        _refuse("store_integrity")
    return value


def resolve(store, spec, *, mode="start", authority_id=None):
    _require(store)
    spec = MuseTaskSpec.from_dict(spec).to_dict()
    if mode != "start":
        _refuse("native_resume_unsupported")
    config = configuration(store, spec["execution"]["driver_config_digest"])
    registration = store.setting("muse-registration:" + config["digest"])
    expected = {"configuration_digest": config["digest"], "projection": PROJECTION,
                "qualification": "synthetic", "enabled": True}
    if registration != expected:
        _refuse("muse_registration_unavailable")
    if (spec["qualification"] != "synthetic" or spec["publication"] is not None
            or spec["permissions"]["inference_destination_id"] != config["inference_destination_id"]
            or digest(spec["checks"]) != config["checks_digest"]
            or spec["review"]["config_digest"] != config["review_config_digest"]):
        _refuse("execution_identity_mismatch")
    from .executors.registry import contract_for
    contract = contract_for(config, task_version=VERSION, projection=PROJECTION)
    if contract.supervisor_handoff != "muse-execution-handoff/1":
        _refuse("adapter_unavailable")
    contract.factory(config, None).preflight(qualification="synthetic", budget=spec["budget"])
    check_profile = _checker(store, config)
    projection = {"projection": PROJECTION, "driver_config_digest": config["digest"],
                  "command_sandbox_digest": config["command_sandbox_digest"]}
    projection["digest"] = digest(projection)
    snapshot = {"kind": "admission_snapshot", "schema_version": VERSION, "spec_digest": spec["digest"],
        "driver_config": config, "projection": projection, "authority_id": authority_id,
        "trust_digest": digest(registration), "check_profile_digest": check_profile["digest"],
        "qualification": "synthetic", "production_dispatch_allowed": False}
    snapshot["digest"] = digest(snapshot)
    return snapshot, config, check_profile


def compile_packet(fields, admission):
    config = MuseConfiguration.from_dict(admission["driver_config"]).to_dict()
    packet = seal_versioned("worker-packet", fields | {"schema_version": VERSION,
        "admission_digest": admission["digest"], "projection": PROJECTION,
        "handoff_schema_id": "urn:taskalong:schema:v2.9:execution-handoff",
        "bindings": fields["bindings"] | {"driver_config_digest": config["digest"]}}, version=VERSION)
    mapping = seal_versioned("packet-projection", {"extensions": {}, "run_id": packet["run_id"],
        "attempt_id": packet["attempt_id"], "spec_digest": packet["spec_digest"],
        "canonical_packet_digest": packet["digest"], "wire_packet_digest": packet["digest"],
        "admission_digest": admission["digest"], "projection_digest": admission["projection"]["digest"],
        "projection": PROJECTION, "driver_config_digest": config["digest"]}, version=VERSION)
    return packet, packet, mapping


def _confirmed(process):
    return (type(process) is dict and process.get("termination_confirmed") is True
            and process.get("group_termination_confirmed") is True
            and process.get("unaccounted_descendants") is False)


def _operation(store, run_id, command, attempt_id, request):
    row = store.db.execute("SELECT request_digest FROM operations WHERE command=? AND run_id=? AND operation_key=?",
                          (command, run_id, attempt_id)).fetchone()
    if row is None or row[0] != digest(request):
        _refuse("muse_handoff_invalid")


def retain_capture(store, run_id, attempt_id, result):
    """Retain originals from the trusted in-process owner, not receipt self-claims."""
    capture = result.pop("_muse_capture", None)
    if capture is None:
        _refuse("muse_capture_missing")
    run = store.run(run_id)
    attempt = store.detail("attempts", attempt_id)
    packet = validate_versioned("worker-packet", attempt["packet"], expected_version=VERSION)
    directory = store.root / "attempts" / attempt_id / "muse-raw"
    if capture.directory != directory:
        _refuse("muse_capture_missing")
    expected = {"input.bin": canonical_bytes(packet), "receipt.json": capture.receipt_json}
    if capture.original is not None:
        expected.update({"stdout.bin": capture.original[0], "stderr.bin": capture.original[1]})
    refs = {}
    for name, raw in expected.items():
        path = directory / name
        if (path.is_symlink() or not path.is_file() or path.stat().st_size != len(raw)
                or path.read_bytes() != raw):
            _refuse("muse_capture_invalid")
        refs[name] = store.put_blob(raw, media_type=("application/octet-stream"
            if name in {"stdout.bin", "stderr.bin"} else "application/json"))
    process = result["process"]
    if capture.process is not None and process.get("receipt") != attempt.get("process_receipt"):
        _refuse("muse_process_mismatch")
    record = {"packet_digest": packet["digest"], "admission_digest": attempt["dispatch_admission"]["digest"],
        "driver_config_digest": attempt["driver_config_digest"], "refs": refs,
        "process": process, "error": result.get("error"), "capture_status": capture.status}
    record["digest"] = digest(record)
    def retained(current, db):
        item = store.detail("attempts", attempt_id)
        if current["active_attempt_id"] != attempt_id or item["lease_generation"] != current["lease_generation"]:
            _refuse("lease_fenced")
        item["muse_capture"] = record
        db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(item), attempt_id))
    store.mutate(run_id, "muse.capture", attempt_id, None, {"capture_digest": record["digest"]}, retained,
                 events=[("muse.capture.retained", {"attempt_id": attempt_id})], fence=run["lease_generation"])


def _subject(store, run, spec, attempt, manager, workspace):
    store.require_fence(run, attempt["lease_generation"])
    if (run["lease_generation"] != attempt["lease_generation"]
            or run["attempts"][-1]["attempt_id"] != attempt["attempt_id"]):
        _refuse("muse_handoff_stale")
    packet = validate_versioned("worker-packet", attempt["packet"], expected_version=VERSION)
    admission = attempt["dispatch_admission"]
    authority = store.authority(run, {"execute", "verify", "commit_candidate"}, spec["digest"], admission["authority_id"])
    fresh, config, _ = resolve(store, spec, authority_id=authority["authority_id"])
    if fresh != admission or digest(admission) != admission["digest"]:
        _refuse("admission_changed")
    expected_bindings = {"run_id": run["run_id"], "attempt_id": attempt["attempt_id"], "spec_digest": spec["digest"]}
    if (any(packet[k] != v for k, v in expected_bindings.items())
            or packet["admission_digest"] != admission["digest"]
            or packet["bindings"]["driver_config_digest"] != config["digest"]
            or packet["bindings"]["workspace_id"] != workspace["workspace_id"]
            or packet["bindings"]["lease_generation"] != run["lease_generation"]
            or attempt["workspace"] != workspace or attempt["canonical_packet"] != packet):
        _refuse("muse_handoff_stale")
    mapping = validate_versioned("packet-projection", attempt["packet_projection"], expected_version=VERSION)
    if (mapping["canonical_packet_digest"] != packet["digest"] or mapping["wire_packet_digest"] != packet["digest"]
            or mapping["projection_digest"] != admission["projection"]["digest"]
            or mapping["admission_digest"] != admission["digest"] or mapping["driver_config_digest"] != config["digest"]
            or any(mapping[k] != v for k, v in expected_bindings.items())
            or packet["bindings"]["base_commit"] != spec["repository"]["base_commit"]
            or packet["scope"] != spec["scope"] or packet["checks"] != spec["checks"]):
        _refuse("muse_handoff_invalid")
    _operation(store, run["run_id"], "executor.prepare", attempt["attempt_id"], {"packet_digest": packet["digest"]})
    _operation(store, run["run_id"], "executor.spawned", attempt["attempt_id"], {"receipt": attempt["process_receipt"]})
    for value in (packet, mapping):
        if store.get_blob(hashlib.sha256(canonical_bytes(value)).hexdigest()) != canonical_bytes(value):
            _refuse("muse_handoff_invalid")
    capture = attempt.get("muse_capture")
    if (not capture or digest(capture) != capture["digest"] or capture["error"] is not None
            or capture["capture_status"] != "local_turn_completed"
            or set(capture["refs"]) != {"input.bin", "stdout.bin", "stderr.bin", "receipt.json"}
            or capture["packet_digest"] != packet["digest"]
            or capture["admission_digest"] != admission["digest"]
            or capture["driver_config_digest"] != config["digest"]):
        _refuse("muse_capture_invalid")
    _operation(store, run["run_id"], "muse.capture", attempt["attempt_id"], {"capture_digest": capture["digest"]})
    process = capture["process"]
    if (not _confirmed(process) or process.get("exit_code") != 0
            or any(process.get(k) for k in ("timed_out", "cancelled", "output_limited", "protocol_error"))
            or process.get("receipt") != attempt["process_receipt"]
            or process["receipt"]["executable_sha256"] != config["executable"]["sha256"]):
        _refuse("muse_termination_unconfirmed")
    for ref in capture["refs"].values():
        raw = store.get_blob(ref["sha256"])
        if len(raw) != ref["bytes"]:
            _refuse("muse_capture_invalid")
    if store.get_blob(capture["refs"]["input.bin"]["sha256"]) != canonical_bytes(packet):
        _refuse("muse_capture_invalid")
    manager.validate(workspace, run["lease_generation"])
    head = run["candidate"]["commit"] if run.get("candidate") else spec["repository"]["base_commit"]
    snapshot = manager.snapshot(workspace, spec["scope"], expected_head=head)
    observed = {"head": packet["bindings"]["initial_head"], "content_digest": snapshot["content_digest"],
                "manifest_sha256": digest(snapshot["manifest"]), "changed_files": snapshot["changed_files"]}
    return {"extensions": {}, "producer_role": "supervisor", "projection": PROJECTION, **expected_bindings,
        "packet_digest": packet["digest"], "admission_digest": admission["digest"], "driver_config_digest": config["digest"],
        "authority_id": authority["authority_id"], "workspace_id": workspace["workspace_id"],
        "lease_generation": run["lease_generation"], "capture_digest": capture["digest"],
        "process_observation_digest": digest(process), "process_receipt_digest": digest(attempt["process_receipt"]),
        "workspace_snapshot": observed, "observed_model": None, "observed_session": None,
        "usage": {"input_tokens": None, "output_tokens": None, "cost_usd": None}, "outcome": "local_turn_completed"}


def create_handoff(store, run_id, attempt_id, manager, workspace):
    run = store.run(run_id)
    # Cancellation prohibits new handoffs, not validation of an already
    # committed completed handoff during cancellation reconciliation.
    if run["active_attempt_id"] != attempt_id or run["state"] != "running":
        _refuse("lease_fenced")
    spec = store.spec(run)
    attempt = store.detail("attempts", attempt_id)
    return seal_versioned("execution-handoff", _subject(store, run, spec, attempt, manager, workspace), version=VERSION)


def validate_handoff(store, run, spec, attempt, manager, workspace, *, before_finish=False, handoff=None):
    if before_finish:
        if run["state"] != "running" or run["active_attempt_id"] != attempt["attempt_id"]:
            _refuse("muse_handoff_stale")
    else:
        ref = attempt.get("execution_handoff")
        if not ref or attempt["status"] != "completed" or attempt["termination_confirmed"] is not True:
            _refuse("muse_handoff_missing")
        if attempt["process"] != attempt["muse_capture"]["process"]:
            _refuse("muse_process_mismatch")
        handoff = loads(store.get_blob(ref["sha256"]))
        row = store.db.execute("SELECT request_digest FROM operations WHERE command='executor.finish' AND run_id=? AND operation_key=?",
            (run["run_id"], attempt["attempt_id"])).fetchone()
        if row is None or row[0] != digest({"state": "completed", "artifact": None, "execution_handoff": ref}):
            _refuse("muse_handoff_invalid")
    validated = validate_versioned("execution-handoff", handoff, expected_version=VERSION)
    expected = seal_versioned("execution-handoff", _subject(store, run, spec, attempt, manager, workspace), version=VERSION)
    if validated != expected:
        _refuse("muse_handoff_stale")
    return validated


def validate_current(store, run):
    if not run["attempts"]:
        return None
    attempt = store.detail("attempts", run["attempts"][-1]["attempt_id"])
    if attempt["status"] == "completed" or run["acceptance_id"]:
        from .workflow import Workflow
        return validate_handoff(store, run, store.spec(run), attempt,
            Workflow(store)._manager(run), store.lease(run)["workspace"])
    return None


def capabilities_view(store, run, spec, mode):
    satisfied, reasons = False, []
    try:
        if mode != "start":
            _refuse("execution_mode_unsupported")
        resolve(store, spec)
        satisfied = True
    except TaskAlongError as error:
        reasons = [error.code]
    return seal_versioned("capabilities-view", {"run_id": run["run_id"], "revision": run["revision"],
        "mode": mode, "configuration_digest": spec["execution"]["driver_config_digest"],
        "requirements_satisfied": satisfied, "decision_digest": None, "reason_codes": reasons,
        "production_dispatch_allowed": False}, version=VERSION)


def result_view(store, run):
    handoff = validate_current(store, run)
    attempt = store.detail("attempts", run["attempts"][-1]["attempt_id"]) if run["attempts"] else None
    acceptance = store.detail("acceptances", run["acceptance_id"]) if run["acceptance_id"] else None
    if acceptance is not None:
        acceptance = validate("acceptance", acceptance)
        if (acceptance["run_id"] != run["run_id"] or acceptance["spec_digest"] != run["spec_digest"]
                or acceptance["candidate"] != run["candidate"]):
            _refuse("store_integrity")
    accepted = bool(acceptance and acceptance["decision"] == "accepted" and run["state"] == "accepted")
    if run["state"] == "cancelled":
        outcome = "cancelled"
    elif run["state"] == "cancel_pending":
        outcome = "pending"
    elif accepted:
        outcome = "accepted"
    elif run["active_attempt_id"] or run["pending_effect_ids"]:
        outcome = "unknown" if run["state"] == "blocked" else "pending"
    elif handoff is not None:
        outcome = "execution_handoff_ready"
    else:
        outcome = "failed" if run["state"] == "failed" else "unknown" if run["state"] == "blocked" else "pending"
    artifacts = {}
    for evidence_id in run["evidence_ids"]:
        for ref in store.detail("evidence", evidence_id)["artifacts"]:
            store.get_blob(ref["sha256"])
            artifacts[ref["sha256"]] = ref
    ref = attempt.get("execution_handoff") if attempt else None
    if ref:
        artifacts[ref["sha256"]] = ref
    return seal_versioned("result-view", {"run_id": run["run_id"], "revision": run["revision"],
        "state": run["state"], "outcome": outcome, "independently_accepted": accepted,
        "acceptance_digest": digest(acceptance) if acceptance else None,
        "execution_handoff_digest": ref["sha256"] if ref else None,
        "canonical_packet_digest": attempt["packet"]["digest"] if attempt and attempt.get("packet") else None,
        "evidence_artifacts": [artifacts[k] for k in sorted(artifacts)], "production_dispatch_allowed": False}, version=VERSION)
