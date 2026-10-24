"""Pure, bounded experiment documents; no execution or trust authority.

Only the fixed installed qualification schema is read. Parsed plans cannot
select imports, commands, callbacks, evidence resolvers or production drivers.
Content digests identify data; they do not authenticate a producer.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from importlib import resources
from typing import Any, ClassVar, Self
import uuid
import hashlib
import re

from jsonschema import Draft202012Validator
from referencing import Resource

from .errors import TaskAlongError
from .validation import _FORMAT_CHECKER, canonical_bytes, digest, loads, schema_registry, screen_sensitive


SCHEMA_ID = "urn:taskalong:qualification:v1:proof-manifest"
HOST_CASES = (
    "permitted-read", "permitted-write", "bounded-capture", "predispatch-tool-denial",
    "owned-completion", "closed-gate-cancel", "running-cancel",
)
_EXECUTABLE_STAGES = {"model-free"}
_ENVIRONMENT_KEYS = {
    "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "SYSTEMROOT", "PYTHONDONTWRITEBYTECODE",
    "GIT_TERMINAL_PROMPT", "GIT_CONFIG_NOSYSTEM", "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
    "XDG_DATA_HOME", "TMPDIR", "TMP", "TEMP", "__CF_USER_TEXT_ENCODING",
}


def _invalid() -> TaskAlongError:
    return TaskAlongError("runtime_proof_invalid", "The runtime experiment document is invalid.")


def proof_schema() -> dict[str, Any]:
    """Return an independent copy of the standalone installed schema."""
    try:
        raw = resources.files("taskalong.resources").joinpath(
            "qualification", "v1", "proof-manifest.schema.json").read_bytes()
    except OSError:
        raise TaskAlongError("runtime_proof_schema_unavailable", "The runtime experiment schema is unavailable.") from None
    return loads(raw)


@lru_cache(maxsize=2)
def _validator(part: str) -> Draft202012Validator:
    document = proof_schema()
    registry = schema_registry(version="2.1").with_resource(SCHEMA_ID, Resource.from_contents(document))
    return Draft202012Validator({"$ref": SCHEMA_ID + "#/$defs/" + part},
                                registry=registry, format_checker=_FORMAT_CHECKER)


def _plan_semantics(document: dict[str, Any]) -> None:
    if str(uuid.UUID(document["campaign_id"])) != document["campaign_id"]:
        raise _invalid()
    expected = list(HOST_CASES) if document["stage"] in _EXECUTABLE_STAGES else []
    if document["case_ids"] != expected:
        raise _invalid()
    if document["stage"] == "installed-replay" and document["package_origin"] != "installed":
        raise _invalid()
    subject = document["subject"]
    if subject["kind"] == "host-experiment":
        if (subject["backend_id"] == "unsupported") != (subject["backend_digest"] is None):
            raise _invalid()
    else:
        resume = subject["mode"] == "native_resume"
        if resume != (document["stage"] == "native-resume"):
            raise _invalid()
        if resume and any(subject["qualification_subject"][key] is None for key in (
                "native_resume_compatibility_digest", "session_digest", "prior_invocation_digest")):
            raise _invalid()


def _manifest_semantics(document: dict[str, Any]) -> None:
    plan = loads(_admit("plan", canonical_bytes(document["plan"])))
    cases = document["cases"]
    if [case["id"] for case in cases] != plan["case_ids"]:
        raise _invalid()
    if any(case["campaign_id"] != plan["campaign_id"] for case in cases):
        raise _invalid()
    for case in cases:
        if case["verdict"] == "not_run" and (
                case["capability"] != "unknown" or case["dispatch"] != "not_sent"
                or case["reason"] != "not_run_after_failure"
                or any(case[key] is not None for key in ("process_ref", "capture_refs", "observation_ref"))):
            raise _invalid()
    success = all(case["verdict"] == "passed" for case in cases)
    success = success and document["first_error"] is None and not document["quarantined"] and document["inputs_rechecked"]
    if document["complete"] != success or (not document["complete"] and document["first_error"] is None):
        raise _invalid()
    start = datetime.fromisoformat(document["started_at"].replace("Z", "+00:00"))
    finish = datetime.fromisoformat(document["finished_at"].replace("Z", "+00:00"))
    if finish < start or (document["complete"] and document["execution_ms"] > plan["bounds"]["execution_ms"]):
        raise _invalid()
    if document["complete"] and plan["stage"] not in {"inventory", "model-free"}:
        raise _invalid()
    stopped = False
    first_failed = None
    for case in cases:
        if stopped and case["verdict"] != "not_run":
            raise _invalid()
        if case["verdict"] == "failed":
            first_failed = case["id"]
        stopped = stopped or case["verdict"] in {"failed", "not_run"}
    if document["first_error"] is not None and document["first_error"]["case_id"] != first_failed:
        raise _invalid()


def _admit(part: str, raw: bytes) -> bytes:
    if type(raw) is not bytes:
        raise _invalid()
    try:
        document = loads(raw)
        screen_sensitive(document)
        if next(_validator(part).iter_errors(document), None) is not None:
            raise _invalid()
        if document["digest"] != digest(document):
            raise _invalid()
        if part == "plan":
            _plan_semantics(document)
        elif part == "manifest":
            _manifest_semantics(document)
        elif document["original_passed"] and not document["original_complete"]:
            raise _invalid()
        return canonical_bytes(document)
    except (TaskAlongError, ValueError):
        raise _invalid() from None


@dataclass(frozen=True, slots=True)
class _ExperimentDocument:
    _canonical: bytes
    part: ClassVar[str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "_canonical", _admit(self.part, self._canonical))

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        return cls(raw)

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> Self:
        try:
            raw = canonical_bytes(document)
        except TaskAlongError:
            raise _invalid() from None
        return cls(raw)

    def to_dict(self) -> dict[str, Any]:
        return loads(self._canonical)

    def to_bytes(self) -> bytes:
        return self._canonical

    @property
    def digest(self) -> str:
        return self.to_dict()["digest"]


@dataclass(frozen=True, slots=True)
class ExperimentPlan(_ExperimentDocument):
    part: ClassVar[str] = "plan"

    @property
    def executable(self) -> bool:
        """A supported experiment selection, never permission to dispatch."""
        value = self.to_dict()
        return (value["stage"] in _EXECUTABLE_STAGES and value["subject"]["kind"] == "host-experiment"
                and value["subject"]["backend_id"] != "unsupported")


@dataclass(frozen=True, slots=True)
class RuntimeProofManifest(_ExperimentDocument):
    part: ClassVar[str] = "manifest"


@dataclass(frozen=True, slots=True)
class RuntimeReplayReport(_ExperimentDocument):
    part: ClassVar[str] = "replay-report"


@dataclass(frozen=True, slots=True)
class ProofEvidence:
    """Immutable bounded bytes, including empty streams; no resolver callbacks."""
    _entries: tuple[tuple[str, bytes], ...]

    def __post_init__(self) -> None:
        if type(self._entries) is not tuple or len(self._entries) > 64:
            raise _invalid()
        seen = set()
        total = 0
        for entry in self._entries:
            if type(entry) is not tuple or len(entry) != 2:
                raise _invalid()
            key, raw = entry
            if (type(key) is not str or type(raw) is not bytes or len(raw) > 65536
                    or hashlib.sha256(raw).hexdigest() != key or key in seen):
                raise _invalid()
            total += len(raw)
            seen.add(key)
        if total > 4 * 1024 * 1024:
            raise _invalid()

    @classmethod
    def from_blobs(cls, blobs: dict[str, bytes]) -> Self:
        if type(blobs) is not dict:
            raise _invalid()
        return cls(tuple(blobs.items()))

    def get(self, key: str) -> bytes | None:
        return next((raw for name, raw in self._entries if name == key), None)


@dataclass(frozen=True, slots=True)
class ProofAssessment:
    complete: bool
    passed: bool
    subject_kind: str

    @property
    def production_dispatch_allowed(self) -> bool:
        return False

    @property
    def producer_authenticated(self) -> bool:
        return False


def _shape(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise _invalid()


def _sha(value):
    return type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def _integer(value, minimum=0, maximum=2**53 - 1):
    return type(value) is int and minimum <= value <= maximum


class _ProofReader:
    def __init__(self, evidence):
        if type(evidence) is not ProofEvidence:
            raise _invalid()
        self.evidence = evidence
        self.used = set()
        self.invocations = set()

    def read(self, ref, media=None):
        _shape(ref, {"sha256", "size_bytes", "media_type", "classification"})
        if (not _sha(ref["sha256"]) or not _integer(ref["size_bytes"], maximum=65536)
                or ref["classification"] != "private"
                or ref["media_type"] not in {"application/json", "application/octet-stream"}
                or (media is not None and ref["media_type"] != media)):
            raise _invalid()
        raw = self.evidence.get(ref["sha256"])
        if raw is None or len(raw) != ref["size_bytes"] or hashlib.sha256(raw).hexdigest() != ref["sha256"]:
            raise _invalid()
        self.used.add(ref["sha256"])
        return raw

    def json(self, ref):
        return loads(self.read(ref, "application/json"), max_bytes=65536)


def _check_inventory(inventory, plan):
    _shape(inventory, {"subject", "closure_complete", "unmeasured_components", "measurements"})
    unknown = inventory["unmeasured_components"]
    if (inventory["subject"] != plan["subject"] or inventory["closure_complete"] is not False
            or type(unknown) is not list or not 1 <= len(unknown) <= 32
            or any(type(item) is not str or not 1 <= len(item) <= 512 for item in unknown)):
        raise _invalid()
    facts = inventory["measurements"]
    if facts is None:
        return None
    _shape(facts, {"host", "interpreter", "package", "backend", "runner_digest", "helper_digest",
                   "test_inventory_digest", "controller_pid"})
    _shape(facts["host"], {"system", "release", "version", "machine", "privilege"})
    if any(type(facts["host"][key]) is not str or not 1 <= len(facts["host"][key]) <= 512
           for key in ("system", "release", "version", "machine")):
        raise _invalid()
    privilege = facts["host"]["privilege"]
    _shape(privilege, {"scope", "effective_uid", "class"})
    if (privilege["scope"] != "controller" or not _integer(privilege["effective_uid"], 0, 2**32 - 1)
            or privilege["class"] != ("effective_uid_zero" if privilege["effective_uid"] == 0 else "effective_uid_nonzero")):
        raise _invalid()
    interpreter = facts["interpreter"]
    _shape(interpreter, {"invocation_path", "executable_sha256", "version", "implementation", "prefix", "base_prefix"})
    if (not _sha(interpreter["executable_sha256"])
            or any(type(interpreter[k]) is not str or not 1 <= len(interpreter[k]) <= 4096
                   for k in set(interpreter) - {"executable_sha256"})
            or not interpreter["invocation_path"].startswith("/") or not _integer(facts["controller_pid"], 2)):
        raise _invalid()
    package = facts["package"]
    _shape(package, {"origin", "artifact_digest", "source_artifact_digest", "source_artifact_kind",
                     "version", "payloads", "dependencies", "lock_sha256", "project_metadata_sha256"})
    if (package["origin"] != plan["package_origin"]
            or (package["origin"] == "source" and package["artifact_digest"] is not None)
            or (package["origin"] == "installed" and not _sha(package["artifact_digest"]))
            or (package["origin"] == "source" and (package["source_artifact_digest"] is not None or package["source_artifact_kind"] is not None))
            or (package["origin"] == "installed" and (not _sha(package["source_artifact_digest"])
                or package["source_artifact_kind"] not in {"wheel", "sdist"}))
            or type(package["version"]) is not str or not 1 <= len(package["version"]) <= 128
            or not _sha(package["lock_sha256"]) or not _sha(package["project_metadata_sha256"])):
        raise _invalid()
    payloads = package["payloads"]
    if type(payloads) is not dict or not 1 <= len(payloads) <= 512:
        raise _invalid()
    total = 0
    for name, info in payloads.items():
        if (not name.startswith("taskalong/") or len(name) > 512
                or any(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", part) is None for part in name.split("/"))):
            raise _invalid()
        _shape(info, {"sha256", "size_bytes"})
        if not _sha(info["sha256"]) or not _integer(info["size_bytes"], maximum=8388608):
            raise _invalid()
        total += info["size_bytes"]
    if total > 16 * 1048576:
        raise _invalid()
    dependencies = package["dependencies"]
    if type(dependencies) is not list or not 1 <= len(dependencies) <= 32:
        raise _invalid()
    names = set()
    for dependency in dependencies:
        _shape(dependency, {"name", "version", "metadata_sha256"})
        name = dependency["name"]
        if (type(name) is not str or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) is None
                or name.lower().replace("_", "-") in names
                or type(dependency["version"]) is not str or not 1 <= len(dependency["version"]) <= 128
                or not _sha(dependency["metadata_sha256"])):
            raise _invalid()
        names.add(name.lower().replace("_", "-"))
    backend = facts["backend"]
    _shape(backend, {"id", "implementation_digest", "components"})
    components = backend["components"]
    expected_names = {"taskalong/process.py"}
    if backend["id"] == "linux-child-subreaper":
        expected_names.add("taskalong/_linux_lifetime.py")
    if type(components) is not dict or set(components) != expected_names:
        raise _invalid()
    if any(components[name] != payloads.get(name) for name in components):
        raise _invalid()
    implementation = digest(components, exclude_digest=False) if backend["id"] != "unsupported" else None
    subject = plan["subject"]
    if (subject["interpreter_digest"] != interpreter["executable_sha256"]
            or subject["host_digest"] != digest(facts["host"], exclude_digest=False)
            or subject["package_digest"] != digest(package, exclude_digest=False)
            or subject["backend_id"] != backend["id"] or subject["backend_digest"] != implementation
            or backend["implementation_digest"] != implementation
            or any(facts[key] != plan[key] for key in ("runner_digest", "helper_digest", "test_inventory_digest"))
            or facts["test_inventory_digest"] != digest({"profile": "owned-host-canaries-v1", "oracle_version": "1.0",
                                                        "case_ids": list(HOST_CASES)}, exclude_digest=False)):
        raise _invalid()
    return facts


def _check_context(context, plan):
    _shape(context, {"campaign_id", "nonce", "payload"})
    if (context["campaign_id"] != plan["campaign_id"] or not _sha(context["nonce"])
            or type(context["payload"]) is not str or len(context["payload"].encode()) > 1024):
        raise _invalid()


def _check_process_structure(process, plan, facts, reader):
    _shape(process, {"receipt", "exit_code", "timed_out", "cancelled", "termination_confirmed", "group_termination_confirmed",
                     "output_limited", "duration_ms", "output_bytes", "lifetime_backend", "unaccounted_descendants", "protocol_error"})
    receipt = process["receipt"]
    _shape(receipt, {"invocation_id", "pid", "pgid", "supervisor_pid", "started_unix_ms", "executable_sha256"})
    if (type(receipt["invocation_id"]) is not str or str(uuid.UUID(receipt["invocation_id"])) != receipt["invocation_id"]
            or receipt["invocation_id"] in reader.invocations
            or any(not _integer(receipt[key], 2) for key in ("pid", "pgid", "supervisor_pid"))
            or not _integer(receipt["started_unix_ms"], 1)
            or receipt["supervisor_pid"] != facts["controller_pid"]
            or receipt["executable_sha256"] != plan["subject"]["interpreter_digest"]
            or (process["exit_code"] is not None and not _integer(process["exit_code"], -255, 255))
            or any(type(process[key]) is not bool for key in ("timed_out", "cancelled", "termination_confirmed",
                   "group_termination_confirmed", "output_limited", "unaccounted_descendants"))
            or not _integer(process["duration_ms"]) or not _integer(process["output_bytes"])
            or process["lifetime_backend"] != plan["subject"]["backend_id"]
            or (process["protocol_error"] is not None and (type(process["protocol_error"]) is not str
                or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", process["protocol_error"]) is None))):
        raise _invalid()
    reader.invocations.add(receipt["invocation_id"])


def _check_case(case, plan, facts, context, reader):
    name = case["id"]
    observed = reader.json(case["observation_ref"])
    _shape(observed, {"campaign_id", "case_id", "nonce", "target_invocations", "invocation_ref", "effect_ref",
                      "control_ref", "input_consumed", "policy_refused", "boundary_error", "timeout_ms"})
    if (observed["campaign_id"] != plan["campaign_id"] or observed["case_id"] != name
            or observed["nonce"] != context["nonce"] or case["reason"] != "oracle_passed"
            or not _integer(observed["target_invocations"], 0, 1)):
        raise _invalid()
    if name == "predispatch-tool-denial":
        if (case["capability"] != "unsupported" or case["dispatch"] != "not_sent"
                or case["process_ref"] is not None or case["capture_refs"] is not None
                or observed["target_invocations"] != 0 or observed["invocation_ref"] is not None
                or observed["effect_ref"] is not None or observed["input_consumed"] is not False
                or observed["policy_refused"] is not True or observed["boundary_error"] is not None
                or not _integer(observed["timeout_ms"], 0, 0)
                or reader.read(observed["control_ref"], "application/octet-stream") != ("taskalong-control-" + context["nonce"]).encode()):
            raise _invalid()
        return
    if case["capability"] != "supported" or observed["policy_refused"] is not False or observed["control_ref"] is not None:
        raise _invalid()
    if not _integer(observed["timeout_ms"], 1, plan["bounds"]["case_ms"]):
        raise _invalid()
    process = reader.json(case["process_ref"])
    _check_process_structure(process, plan, facts, reader)
    if (process["termination_confirmed"] is not True or process["group_termination_confirmed"] is not True
            or process["unaccounted_descendants"] is not False or process["timed_out"] is not False
            or process["output_limited"] is not False or process["protocol_error"] is not None
            or type(process["cancelled"]) is not bool or not _integer(process["duration_ms"])
            or not _integer(process["output_bytes"]) or process["lifetime_backend"] != plan["subject"]["backend_id"]):
        raise _invalid()
    captures = case["capture_refs"]
    _shape(captures, {"stdin", "stdout", "stderr"})
    stdin, stdout, stderr = (reader.read(captures[key], "application/octet-stream") for key in ("stdin", "stdout", "stderr"))
    expected_input = canonical_bytes({"campaign_id": plan["campaign_id"], "case_id": name,
                                      "nonce": context["nonce"], "payload": context["payload"]}) + b"\n"
    if (stdin != expected_input or len(stdout) + len(stderr) > plan["bounds"]["capture_bytes"]
            or process["output_bytes"] != len(stdout) + len(stderr)):
        raise _invalid()
    if name == "closed-gate-cancel":
        if (case["dispatch"] != "not_sent" or process["exit_code"] is not None
                or observed["boundary_error"] != {"code": "qualification_gate_cancelled", "effect_outcome": "not_sent"}
                or observed["target_invocations"] != 0 or observed["invocation_ref"] is not None
                or observed["effect_ref"] is not None or observed["input_consumed"] is not False or stdout != b""):
            raise _invalid()
        return
    if (case["dispatch"] != "sent" or observed["boundary_error"] is not None
            or observed["target_invocations"] != 1 or observed["input_consumed"] is not True
            or not _integer(process["exit_code"], 0, 255)
            or process["exit_code"] != (130 if name == "running-cancel" else 0)
            or process["cancelled"] != (name == "running-cancel")):
        raise _invalid()
    invocation = reader.json(observed["invocation_ref"])
    if invocation != {"campaign_id": plan["campaign_id"], "case_id": name,
                       "input_sha256": hashlib.sha256(stdin).hexdigest()}:
        raise _invalid()
    frame = loads(stdout, max_bytes=65536)
    _shape(frame, {"campaign_id", "case_id", "input_sha256", "nonce", "effect_sha256", "event", "environment_keys"})
    keys = frame["environment_keys"]
    if (type(keys) is not list or len(keys) > len(_ENVIRONMENT_KEYS) or any(type(k) is not str for k in keys)
            or keys != sorted(set(keys)) or not set(keys) <= _ENVIRONMENT_KEYS):
        raise _invalid()
    effect = None
    if name in {"permitted-read", "permitted-write"}:
        data = reader.read(observed["effect_ref"], "application/octet-stream")
        if data != context["payload"].encode():
            raise _invalid()
        effect = hashlib.sha256(data).hexdigest()
    elif observed["effect_ref"] is not None:
        raise _invalid()
    expected_frame = {**invocation, "nonce": context["nonce"], "effect_sha256": effect,
                      "event": "ready" if name == "running-cancel" else "completed", "environment_keys": keys}
    if frame != expected_frame or stdout != canonical_bytes(expected_frame) + b"\n":
        raise _invalid()
    expected_stderr = b"Bearer " + context["nonce"].encode() + b"\n" if name == "bounded-capture" else b""
    if stderr != expected_stderr:
        raise _invalid()


def _validate_executed_case(case, plan, facts, context, evidence):
    """Internal shared pure oracle; only supplied immutable bytes are read."""
    try:
        _check_case(case, plan, facts, context, _ProofReader(evidence))
    except (TaskAlongError, KeyError, TypeError, ValueError):
        raise _invalid() from None


def validate_proof(proof: RuntimeProofManifest, *, expected_plan: ExperimentPlan,
                   evidence: ProofEvidence) -> ProofAssessment:
    """Check supplied data only; never authenticate, discover or launch anything."""
    if type(proof) is not RuntimeProofManifest or type(expected_plan) is not ExperimentPlan or type(evidence) is not ProofEvidence:
        raise _invalid()
    document = proof.to_dict()
    plan = expected_plan.to_dict()
    if document["plan"] != plan:
        raise _invalid()
    if plan["subject"]["kind"] != "host-experiment":
        raise TaskAlongError("runtime_proof_subject_unsupported", "This experiment profile cannot validate harness execution.", exit_code=3)

    reader = _ProofReader(evidence)
    try:
        inventory = reader.json(document["inventory_ref"])
        context_raw = reader.read(document["context_ref"], "application/json")
        context = loads(context_raw)
        _check_context(context, plan)
        facts = _check_inventory(inventory, plan)
        if hashlib.sha256(context_raw).hexdigest() != plan["subject"]["context_digest"]:
            raise _invalid()
        if facts is None and (document["complete"] or any(c["verdict"] != "not_run" for c in document["cases"])):
            raise _invalid()
        for case in document["cases"]:
            if case["verdict"] == "passed":
                _check_case(case, plan, facts, context, reader)
            elif case["verdict"] == "failed":
                # Failed originals remain opaque data; no malformed output is
                # reinterpreted as a successful helper protocol.
                observed = reader.json(case["observation_ref"]) if case["observation_ref"] is not None else None
                process = None
                if case["process_ref"] is not None:
                    process = reader.json(case["process_ref"])
                    _check_process_structure(process, plan, facts, reader)
                unknown_cleanup = (case["dispatch"] == "uncertain" or (case["dispatch"] == "sent" and process is None)
                    or (process is not None and (not process["termination_confirmed"]
                        or not process["group_termination_confirmed"] or process["unaccounted_descendants"])))
                if unknown_cleanup and not document["quarantined"]:
                    raise _invalid()
                if case["capture_refs"] is not None:
                    _shape(case["capture_refs"], {"stdin", "stdout", "stderr"})
                    for ref in case["capture_refs"].values():
                        reader.read(ref, "application/octet-stream")
                if observed is not None:
                    _shape(observed, {"campaign_id", "case_id", "nonce", "target_invocations", "invocation_ref", "effect_ref",
                                      "control_ref", "input_consumed", "policy_refused", "boundary_error", "timeout_ms"})
                    if (observed["campaign_id"] != plan["campaign_id"] or observed["case_id"] != case["id"]
                            or observed["nonce"] != context["nonce"]
                            or (observed["target_invocations"] is not None and not _integer(observed["target_invocations"], 0, 32))
                            or type(observed["input_consumed"]) is not bool or type(observed["policy_refused"]) is not bool
                            or not _integer(observed["timeout_ms"], 0, plan["bounds"]["case_ms"])):
                        raise _invalid()
                    for key in ("invocation_ref", "effect_ref", "control_ref"):
                        if observed.get(key) is not None:
                            reader.read(observed[key])
        if reader.used != {key for key, _ in evidence._entries}:
            raise _invalid()
    except (TaskAlongError, KeyError, TypeError, ValueError):
        raise _invalid() from None
    return ProofAssessment(document["complete"], document["complete"], plan["subject"]["kind"])


def evidence_set_digest(evidence: ProofEvidence) -> str:
    if type(evidence) is not ProofEvidence:
        raise _invalid()
    return digest({key: len(raw) for key, raw in evidence._entries}, exclude_digest=False)


def validate_replay(report: RuntimeReplayReport, *, original_bytes: bytes, original_evidence: ProofEvidence,
                    verifier_bytes: bytes, verifier_evidence: ProofEvidence) -> ProofAssessment:
    """Keep original results separate from installed verifier measurements.

    A valid unsuccessful original remains unsuccessful. No trust decision or
    replay launch authority can be produced by this offline check.
    """
    if type(report) is not RuntimeReplayReport:
        raise _invalid()
    original = RuntimeProofManifest.from_bytes(original_bytes)
    verifier = RuntimeProofManifest.from_bytes(verifier_bytes)
    original_doc, verifier_doc = original.to_dict(), verifier.to_dict()
    original_result = validate_proof(original, expected_plan=ExperimentPlan.from_dict(original_doc["plan"]), evidence=original_evidence)
    verifier_result = validate_proof(verifier, expected_plan=ExperimentPlan.from_dict(verifier_doc["plan"]), evidence=verifier_evidence)
    value = report.to_dict()
    def reference(raw):
        return {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw),
                "media_type": "application/json", "classification": "private"}
    if (verifier_doc["plan"]["stage"] != "inventory" or verifier_doc["plan"]["package_origin"] != "installed"
            or not verifier_result.complete or not verifier_result.passed
            or value["original_manifest_ref"] != reference(original_bytes)
            or value["verifier_manifest_ref"] != reference(verifier_bytes)
            or value["original_proof_digest"] != original.digest or value["verifier_proof_digest"] != verifier.digest
            or value["original_subject"] != original_doc["plan"]["subject"]
            or value["original_evidence_set_digest"] != evidence_set_digest(original_evidence)
            or value["original_complete"] != original_result.complete or value["original_passed"] != original_result.passed):
        raise _invalid()
    return original_result
