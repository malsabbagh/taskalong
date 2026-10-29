"""Production Muse contracts through the existing lifecycle owner, version 2.12.

Registration/measurement do not grant admission. The closed runtime authenticator
currently refuses this host before any run or attempt allocation. The packet,
capture and handoff path remains separate from the original synthetic contract.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import ClassVar

from .contracts import JsonDocument
from .errors import TaskAlongError
from .muse_production import _observe_file, _profile, readiness as intent_readiness
from .muse_preparation import _inputs
from .opaque_handoff import OpaqueHandoff
from .validation import canonical_bytes, digest, loads, seal_versioned, validate, validate_versioned
from .workspace import _tree, git, inspect_repository
from . import muse_runtime

VERSION = "2.12"
PROJECTION = "muse-production-plain/1"
HANDOFF = "muse-production-execution-handoff/1"


@dataclass(frozen=True, slots=True)
class MuseProductionDocument(JsonDocument):
    def __post_init__(self):
        value = validate_versioned(self.schema_name, loads(self._canonical), expected_version=VERSION)
        object.__setattr__(self, "_canonical", canonical_bytes(value))


@dataclass(frozen=True, slots=True)
class MuseProductionConfiguration(MuseProductionDocument):
    schema_name: ClassVar[str] = "driver-config"


@dataclass(frozen=True, slots=True)
class MuseProductionTask(MuseProductionDocument):
    schema_name: ClassVar[str] = "task-spec"


def _refuse(code="muse_handoff_invalid"):
    raise TaskAlongError(code, "The exact production Muse lifecycle subject is unavailable or inconsistent.",
        exit_code=3, effect_outcome="not_sent")


def _require(store):
    if store.format_version != 12:
        _refuse("store_upgrade_required")


def _local_subject(store, value):
    profile = _profile(store, value["profile_id"])
    intent_readiness(store, profile["profile_id"], value["intent_configuration_digest"])
    if (profile["digest"] != value["profile_digest"]
            or value["executable"] != {"path": profile["executable_path"], "sha256": profile["executable_sha256"]}
            or value["build"] != profile["runtime_version"] or value["requested_model"] != profile["model"]
            or value["reasoning_effort"] != profile["reasoning_effort"]
            or value["permission_profile"] != profile["permission_policy"]["permission_profile"]
            or value["inference_destination_id"] != profile["inference_destination_id"]):
        _refuse("execution_identity_mismatch")
    inputs = _inputs(value["declared_inputs"])
    if inputs != value["declared_inputs"]:
        _refuse("muse_inputs_noncanonical")
    instruction, tools = (_observe_file(inputs[key]) for key in ("instructions_path", "tools_path"))
    if (instruction["sha256"] != profile["permission_policy"]["instructions_sha256"]
            or tools["sha256"] != profile["permission_policy"]["tools_sha256"]):
        _refuse("muse_effective_input_changed")
    dependencies, total = [], 0
    for path in inputs["dependency_paths"]:
        item = _observe_file(path, max_bytes=64*1024*1024)
        total += item["bytes"]
        if total > 128*1024*1024:
            _refuse("muse_dependency_limit")
        dependencies.append(item)
    return {"profile_digest": profile["digest"], "intent_configuration_digest": value["intent_configuration_digest"],
        "executable": _observe_file(profile["executable_path"], executable=True),
        "instructions": instruction, "tools": tools, "declared_dependencies": dependencies}


def configure(store, document):
    _require(store)
    if type(document) is not dict:
        _refuse("invalid_document")
    value = {"extensions": {}, **document}
    # The backend measures this subject; callers cannot provide qualification.
    value["declared_inputs"] = _inputs(value.get("declared_inputs"))
    supplied_subject = value.get("local_subject_digest")
    value = seal_versioned("driver-config", {"local_subject_digest": "0"*64, **value}, version=VERSION)
    subject = _local_subject(store, value)
    expected = digest(subject)
    if supplied_subject is not None and supplied_subject != expected:
        _refuse("muse_local_subject_changed")
    value.pop("digest", None)
    value["local_subject_digest"] = expected
    value = seal_versioned("driver-config", value, version=VERSION)
    store.record_document(MuseProductionConfiguration.from_dict(value), operation_key="muse-production-config:"+value["digest"])
    return value


def configuration(store, content_digest):
    _require(store)
    row = store.db.execute("SELECT kind,document FROM document_history WHERE digest=?", (content_digest,)).fetchone()
    if row is None or row["kind"] != "driver_config":
        _refuse("execution_document_unresolved")
    value = MuseProductionConfiguration.from_dict(loads(row["document"])).to_dict()
    if value["digest"] != content_digest or digest(_local_subject(store, value)) != value["local_subject_digest"]:
        _refuse("muse_local_subject_changed")
    return value


def _checker(store, config):
    row = store.db.execute("SELECT document FROM profiles WHERE digest=?", (config["check_profile_digest"],)).fetchone()
    if row is None:
        _refuse("check_binding_unresolved")
    checker = validate("runtime-profile", loads(row[0]))
    if checker["digest"] != config["check_profile_digest"] or checker["qualification"] != "production":
        _refuse("check_binding_mismatch")
    return checker


def _subject(store, spec, config):
    if (spec["permissions"]["inference_destination_id"] != config["inference_destination_id"]
            or digest(spec["checks"]) != config["checks_digest"]
            or spec["review"]["config_digest"] != config["review_config_digest"]):
        _refuse("execution_identity_mismatch")
    repository = store.repository(spec["repository"]["registration_id"])
    if inspect_repository(repository["path"])["identity"] != repository["identity"]:
        _refuse("repository_identity_changed")
    base = spec["repository"]["base_commit"]
    if git(repository["path"], "rev-parse", "--verify", base+"^{commit}") != base:
        _refuse("base_commit_mismatch")
    files = [{"path": p, "mode": m, "git_blob": oid} for p,(m,oid) in sorted(_tree(Path(repository["path"]),base).items())]
    return {"format": "muse-production-runtime-subject/1", "spec_digest": spec["digest"],
        "configuration_digest": config["digest"], "local_subject_digest": config["local_subject_digest"],
        "requested_build": config["build"], "requested_model": config["requested_model"], "requested_effort": config["reasoning_effort"],
        "repository_identity": repository["identity"], "base_commit": base, "source_files": files,
        "budget": spec["budget"], "check_profile_digest": config["check_profile_digest"],
        "command_sandbox_digest": config["command_sandbox_digest"], "review_config_digest": config["review_config_digest"],
        "review_provider": config["review_provider"], "checker_profile": _checker(store, config), "local_inputs": _local_subject(store, config),
        "requested_runtime": _profile(store, config["profile_id"]),
        "checker_setting_digest": digest(store.setting("command_sandbox")),
        "review_setting_digest": digest(store.setting("review"))}


def assess(store, document):
    spec = MuseProductionTask.from_dict(document).to_dict()
    config = configuration(store, spec["execution"]["driver_config_digest"])
    subject = _subject(store, spec, config)
    return {"valid": True, "schema_version": VERSION, "spec_digest": spec["digest"],
        "readiness": muse_runtime.observe(subject)}


def resolve(store, spec, *, mode="start", authority_id=None):
    _require(store)
    spec = MuseProductionTask.from_dict(spec).to_dict()
    if mode != "start":
        _refuse("muse_native_resume_unsupported")
    config = configuration(store, spec["execution"]["driver_config_digest"])
    subject = _subject(store, spec, config)
    # No settings flag, supplied receipt, fixture or authority can skip this
    # closed authenticator. It currently refuses before lifecycle allocation.
    muse_runtime.require(subject)
    checker = _checker(store, config)
    sandbox, review = store.setting("command_sandbox"), store.setting("review")
    if (checker["qualification"] != "production" or not sandbox or sandbox.get("qualification") != "production"
            or digest(sandbox) != config["command_sandbox_digest"] or not review or review.get("fixture_response") is not None
            or review["config_digest"] != config["review_config_digest"]):
        _refuse("muse_independent_checker_unqualified")
    projection = {"projection": PROJECTION, "driver_config_digest": config["digest"],
        "command_sandbox_digest": config["command_sandbox_digest"]}
    projection["digest"] = digest(projection)
    snapshot = {"kind": "admission_snapshot", "schema_version": VERSION, "spec_digest": spec["digest"],
        "driver_config": config, "projection": projection, "authority_id": authority_id,
        "trust_digest": digest(subject), "runtime_subject_digest": digest(subject),
        "check_profile_digest": checker["digest"], "qualification": "production", "production_dispatch_allowed": True}
    snapshot["digest"] = digest(snapshot)
    return snapshot, config, checker


def compile_packet(fields, admission):
    config = MuseProductionConfiguration.from_dict(admission["driver_config"]).to_dict()
    packet = seal_versioned("worker-packet", fields | {"schema_version": VERSION,
        "admission_digest": admission["digest"], "projection": PROJECTION,
        "runtime_subject_digest": admission["runtime_subject_digest"],
        "handoff_schema_id": "urn:taskalong:schema:v2.12:execution-handoff",
        "bindings": fields["bindings"] | {"driver_config_digest": config["digest"], "authority_id": admission["authority_id"]}}, version=VERSION)
    mapping = seal_versioned("packet-projection", {"extensions": {}, "run_id": packet["run_id"],
        "attempt_id": packet["attempt_id"], "spec_digest": packet["spec_digest"],
        "canonical_packet_digest": packet["digest"], "wire_packet_digest": packet["digest"],
        "admission_digest": admission["digest"], "projection_digest": admission["projection"]["digest"],
        "projection": PROJECTION, "driver_config_digest": config["digest"],
        "runtime_subject_digest": admission["runtime_subject_digest"],
        "prompt_sha256": hashlib.sha256(canonical_bytes(packet)).hexdigest()}, version=VERSION)
    return packet, packet, mapping


def review_options(store, spec):
    """Pure immutable reviewer routing; actual provider qualification is separate."""
    config = configuration(store, spec["execution"]["driver_config_digest"])
    return {"expected_provider": config["review_provider"]}


def _bind_subject(packet, admission, authority, mapping):
    if (packet["runtime_subject_digest"] != admission["runtime_subject_digest"]
            or packet["bindings"]["authority_id"] != authority["authority_id"]
            or mapping["runtime_subject_digest"] != admission["runtime_subject_digest"]
            or mapping["prompt_sha256"] != hashlib.sha256(canonical_bytes(packet)).hexdigest()):
        _refuse("muse_handoff_stale")
    return {"runtime_subject_digest": admission["runtime_subject_digest"]}


_handoff = OpaqueHandoff(version=VERSION, projection=PROJECTION, resolve=resolve, refuse=_refuse, bind_subject=_bind_subject)
retain_capture = _handoff.retain_capture
create_handoff = _handoff.create_handoff
validate_handoff = _handoff.validate_handoff
validate_current = _handoff.validate_current
capabilities_view = _handoff.capabilities_view
result_view = _handoff.result_view
