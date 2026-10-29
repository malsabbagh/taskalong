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
    if store.format_version not in (9, 10, 11, 12):
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


from .opaque_handoff import OpaqueHandoff
_handoff = OpaqueHandoff(version=VERSION, projection=PROJECTION, resolve=resolve, refuse=_refuse)

def retain_capture(store, run_id, attempt_id, result):
    return _handoff.retain_capture(store, run_id, attempt_id, result)

def create_handoff(store, run_id, attempt_id, manager, workspace):
    return _handoff.create_handoff(store, run_id, attempt_id, manager, workspace)

def validate_handoff(store, run, spec, attempt, manager, workspace, *, before_finish=False, handoff=None):
    return _handoff.validate_handoff(store, run, spec, attempt, manager, workspace, before_finish=before_finish, handoff=handoff)

def validate_current(store, run):
    return _handoff.validate_current(store, run)

def capabilities_view(store, run, spec, mode):
    return _handoff.capabilities_view(store, run, spec, mode)

def result_view(store, run):
    return _handoff.result_view(store, run)
