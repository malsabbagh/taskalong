"""Pure qualification evaluation over caller-supplied trusted snapshots.

Only installed schema constants are read; no external evidence discovery,
network/process access, persistence, registration or launch.
Trusted approvals must originate outside worker/profile data. Content identity
alone is not producer authentication or proof that a measurement is truthful.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import functools
import hashlib
from typing import Any, ClassVar

from jsonschema import Draft202012Validator

from .bindings import ExecutionBinding, HarnessInstallation, ProviderProfile
from .contracts import JsonDocument
from .errors import TaskAlongError
from .validation import (_FORMAT_CHECKER, canonical_bytes, digest, loads, schema,
                         schema_registry, screen_sensitive, seal_versioned, validate_versioned)


def _invalid() -> TaskAlongError:
    return TaskAlongError("qualification_input_invalid", "The offline qualification input is invalid.")


@functools.lru_cache(maxsize=None)
def _part_validator(name: str) -> Draft202012Validator:
    selected = {"$ref": "urn:taskalong:schema:v2.1:qualification-receipt#/$defs/" + name}
    return Draft202012Validator(selected, registry=schema_registry(version="2.1"), format_checker=_FORMAT_CHECKER)


@functools.lru_cache(maxsize=None)
def _timestamp_validator() -> Draft202012Validator:
    return Draft202012Validator(schema("qualification-receipt", version="2.1")["$defs"]["timestamp"], format_checker=_FORMAT_CHECKER)


def _part(name: str, document: dict[str, Any]) -> dict[str, Any]:
    value = loads(canonical_bytes(document))
    screen_sensitive(value)
    validator = _part_validator(name)
    if next(validator.iter_errors(value), None) is not None:
        raise _invalid()
    return value


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def _semantics(document: dict[str, Any]) -> None:
    if document["kind"] == "qualification_receipt":
        if _time(document["valid_from"]) >= _time(document["valid_until"]):
            raise _invalid()
        capabilities = [item["capability"] for item in document["results"]]
    else:
        capabilities = [item["capability"] for item in document["capability_results"]]
        outcomes = [item["outcome"] for item in document["capability_results"]]
        if document["kind"] == "qualification_decision":
            if document["requirements_satisfied"] != all(value == "supported" for value in outcomes):
                raise _invalid()
        elif document["overall_outcome"] != _overall(outcomes):
            raise _invalid()
    if len(set(capabilities)) != len(capabilities):
        raise _invalid()


@dataclass(frozen=True, slots=True)
class _QualificationDocument(JsonDocument):
    def __post_init__(self) -> None:
        admitted = validate_versioned(self.schema_name, loads(self._canonical), expected_version="2.1")
        object.__setattr__(self, "_canonical", canonical_bytes(admitted))


@dataclass(frozen=True, slots=True)
class QualificationReceipt(_QualificationDocument):
    schema_name: ClassVar[str] = "qualification-receipt"


@dataclass(frozen=True, slots=True)
class QualificationDecision(_QualificationDocument):
    schema_name: ClassVar[str] = "qualification-decision"


@dataclass(frozen=True, slots=True)
class CapabilityReport(_QualificationDocument):
    schema_name: ClassVar[str] = "capability-report"


@dataclass(frozen=True, slots=True)
class TrustPolicy:
    """Explicit operator-controlled approvals; never populate from worker data.

    An approval is content-addressed after the receipt exists, so its receipt
    reference creates no cycle. The receipt contains no approval digest.
    """
    _canonical: bytes

    def __post_init__(self) -> None:
        value = _part("trust-policy", loads(self._canonical))
        producers = [p["producer_id"] for p in value["producers"]]
        if len(set(producers)) != len(producers):
            raise _invalid()
        for approval in value["approvals"]:
            if (digest(approval) != approval["digest"]
                    or _time(approval["valid_from"]) >= _time(approval["valid_until"])):
                raise _invalid()
        object.__setattr__(self, "_canonical", canonical_bytes(value))

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TrustPolicy:
        return cls(canonical_bytes(value))

    def to_dict(self) -> dict[str, Any]:
        return loads(self._canonical)

    @property
    def digest(self) -> str:
        return digest(self.to_dict(), exclude_digest=False)


@dataclass(frozen=True, slots=True)
class EvidenceStore:
    """Bounded immutable byte snapshot, not a callable or filesystem resolver."""
    _entries: tuple[tuple[str, bytes], ...]

    def __post_init__(self) -> None:
        if type(self._entries) is not tuple or len(self._entries) > 128:
            raise _invalid()
        total = 0
        seen = set()
        for entry in self._entries:
            if type(entry) is not tuple or len(entry) != 2:
                raise _invalid()
            key, data = entry
            if type(key) is not str or type(data) is not bytes or not 0 < len(data) <= 1_048_576 or hashlib.sha256(data).hexdigest() != key or key in seen:
                raise _invalid()
            total += len(data)
            seen.add(key)
        if total > 16 * 1_048_576:
            raise _invalid()

    @classmethod
    def from_blobs(cls, blobs: dict[str, bytes]) -> EvidenceStore:
        if type(blobs) is not dict:
            raise _invalid()
        return cls(tuple(blobs.items()))

    def get(self, key: str) -> bytes | None:
        return next((data for name, data in self._entries if name == key), None)


@dataclass(frozen=True, slots=True)
class Evaluation:
    decision: QualificationDecision
    report: CapabilityReport


_LEVELS = {"offline_fixture": 0, "controlled_responder": 1, "actual_provider": 2}
_MODES = {"start": "start", "observe": "observe", "cancel": "local_cessation", "result": "structured_result",
          "native_resume": "native_resume", "provider_lookup": "provider_lookup", "remote_cancel": "remote_cancellation"}


def _overall(outcomes: list[str]) -> str:
    return "unsupported" if "unsupported" in outcomes else "unknown" if "unknown" in outcomes else "supported"


class _Rejected(Exception):
    def __init__(self, code: str):
        self.code = code


def _read_evidence(ref: dict, store: EvidenceStore, policy: dict) -> bytes:
    if ref["sha256"] in policy["revoked_evidence_digests"]:
        raise _Rejected("evidence_revoked")
    data = store.get(ref["sha256"])
    if data is None:
        raise _Rejected("evidence_missing")
    if len(data) != ref["size_bytes"] or hashlib.sha256(data).hexdigest() != ref["sha256"]:
        raise _Rejected("evidence_mismatch")
    return data


def _observed(observation: dict, binding: dict) -> str:
    facts = observation["observations"]
    flags = [value for key, value in facts.items() if key != "limit"]
    if False in flags:
        return "unsupported"
    if None in flags:
        return "unknown"
    if observation["capability"] in {"hard_token_cap", "hard_cost_cap"}:
        name = "max_tokens" if observation["capability"] == "hard_token_cap" else "max_cost_micro_usd"
        expected = binding["budget"][name]
        if facts["limit"] is None or expected is None:
            return "unknown"
        if facts["limit"] != expected:
            return "unsupported"
    return "supported"


def _verify_receipt(receipt: dict, subject: dict, mode: str, policy: dict, store: EvidenceStore,
                    now: datetime, minimum_level: str, binding: dict) -> dict[str, list[str]]:
    if receipt["subject"] != subject:
        raise _Rejected("subject_mismatch")
    if receipt["mode"] != mode:
        raise _Rejected("mode_mismatch")
    if not _time(receipt["valid_from"]) <= now < _time(receipt["valid_until"]):
        raise _Rejected("receipt_not_current")
    producer = next((p for p in policy["producers"] if p["producer_id"] == receipt["producer_id"]), None)
    if producer is None:
        raise _Rejected("producer_untrusted")
    if receipt["evidence_level"] not in producer["allowed_evidence_levels"]:
        raise _Rejected("evidence_level_untrusted")
    if _LEVELS[receipt["evidence_level"]] < _LEVELS[minimum_level]:
        raise _Rejected("evidence_level_insufficient")
    if receipt["digest"] in policy["revoked_receipt_digests"]:
        raise _Rejected("receipt_revoked")
    approvals = [a for a in policy["approvals"] if a["receipt_digest"] == receipt["digest"] and a["producer_id"] == receipt["producer_id"]]
    if not approvals:
        raise _Rejected("approval_missing")
    approvals = [a for a in approvals if a["digest"] not in policy["revoked_approval_digests"]]
    if not approvals:
        raise _Rejected("approval_revoked")
    if not any(_time(a["valid_from"]) <= now < _time(a["valid_until"]) for a in approvals):
        raise _Rejected("approval_not_current")
    by_capability = {}
    for result in receipt["results"]:
        # A start or other operation cannot attest native-resume support, even
        # when that capability is required by the binding. Its own mode also
        # requires exact session and prior-invocation identities in _subject.
        if result["capability"] == "native_resume" and mode != "native_resume":
            raise _Rejected("mode_mismatch")
        observations = []
        for ref in result["evidence_refs"]:
            raw = _read_evidence(ref, store, policy)
            if ref["media_type"] != "application/json":
                raise _Rejected("evidence_invalid")
            try:
                observation = _part("observation", loads(raw))
            except TaskAlongError:
                raise _Rejected("evidence_invalid") from None
            if (observation["subject"] != subject or observation["mode"] != mode
                    or observation["producer_id"] != receipt["producer_id"]
                    or observation["evidence_level"] != receipt["evidence_level"]
                    or observation["capability"] != result["capability"]):
                raise _Rejected("evidence_subject_mismatch")
            for capture in observation["capture_refs"]:
                _read_evidence(capture, store, policy)
            observations.append(_observed(observation, binding))
        if _overall(observations) != result["outcome"]:
            raise _Rejected("evidence_outcome_mismatch")
        by_capability[result["capability"]] = [ref["sha256"] for ref in result["evidence_refs"]]
    return by_capability


def _subject(binding: ExecutionBinding, installation: HarnessInstallation, provider: ProviderProfile, context: dict[str, Any], mode: str) -> dict[str, Any]:
    if type(binding) is not ExecutionBinding or type(installation) is not HarnessInstallation or type(provider) is not ProviderProfile:
        raise _invalid()
    context = loads(canonical_bytes(context))
    if set(context) != {"artifact_digest", "host_digest", "effective_context_digest", "test_inputs_digest", "session_digest", "prior_invocation_digest"}:
        raise _invalid()
    b, i, p = binding.to_dict(), installation.to_dict(), provider.to_dict()
    if b["installation_digest"] != installation.digest or b["provider_profile_digest"] != provider.digest or i["harness"] != p["harness"]:
        raise _invalid()
    resume = b["native_resume"]
    if mode == "native_resume" and (resume is None or context["session_digest"] is None or context["prior_invocation_digest"] is None):
        raise _invalid()
    value = {key: b[key] for key in ("installation_digest", "provider_profile_digest", "instruction_bundle_digest", "tool_policy_digest", "worker_sandbox_digest", "check_binding_digest")}
    value.update(binding_digest=binding.digest, runtime_closure_digest=i["runtime_closure_digest"], backend_id=i["platform"]["backend_id"],
                 provider=p["provider"], model_digest=p["model"]["resolved_digest"], native_resume_compatibility_digest=resume["compatibility_digest"] if resume else None, **context)
    return _part("subject", value)


def evaluate(binding: ExecutionBinding, *, installation: HarnessInstallation, provider: ProviderProfile,
             context: dict[str, Any], mode: str, receipts: list[QualificationReceipt | dict] | tuple,
             trust: TrustPolicy, evidence: EvidenceStore, now: str, minimum_level: str = "actual_provider") -> Evaluation:
    """Evaluate one exact operation against explicit trusted snapshots.

    Results are offline evidence decisions. Production dispatch always remains
    false, including an actual-provider-level decision that satisfies its inputs.
    """
    if (type(trust) is not TrustPolicy or type(evidence) is not EvidenceStore or type(receipts) not in (list, tuple)
            or len(receipts) > 64 or type(mode) is not str or mode not in _MODES
            or type(minimum_level) is not str or minimum_level not in _LEVELS):
        raise _invalid()
    validator = _timestamp_validator()
    if not validator.is_valid(now):
        raise _invalid()
    subject = _subject(binding, installation, provider, context, mode)
    b, policy = binding.to_dict(), trust.to_dict()
    required = sorted(set(b["required_capabilities"]) | {_MODES[mode]})
    verified, rejected, votes = {}, [], {cap: [] for cap in required}
    for index, original in enumerate(receipts):
        try:
            try:
                if type(original) is QualificationReceipt:
                    receipt = original.to_dict()
                elif type(original) is dict:
                    receipt = QualificationReceipt.from_dict(original).to_dict()
                else:
                    raise _invalid()
            except TaskAlongError:
                raise _Rejected("receipt_invalid") from None
            refs = _verify_receipt(receipt, subject, mode, policy, evidence, _time(now), minimum_level, b)
            if receipt["digest"] in verified:
                continue
            verified[receipt["digest"]] = receipt
            for result in receipt["results"]:
                if result["capability"] in votes:
                    votes[result["capability"]].append((result["outcome"], refs[result["capability"]]))
        except _Rejected as failure:
            rejected.append({"input_index": index, "reason_code": failure.code})
    capabilities = []
    for cap in required:
        entries = votes[cap]
        outcome = _overall([value for value, _ in entries]) if entries else "unknown"
        reasons = ["evidence_verified" if outcome == "supported" else "observed_" + outcome] if entries else sorted({"no_evidence", *(r["reason_code"] for r in rejected)})
        if cap in {"hard_cost_cap", "hard_token_cap"} and outcome != "supported":
            outcome = "unsupported"
            reasons = sorted(set(reasons) | {"hard_cap_unsupported"})
        capabilities.append({"capability": cap, "outcome": outcome, "reason_codes": reasons,
                             "evidence_digests": sorted({ref for _, refs in entries for ref in refs})})
    decision = seal_versioned("qualification-decision", {"subject": subject, "mode": mode, "minimum_evidence_level": minimum_level,
        "evaluated_at": now, "trust_policy_digest": trust.digest, "verified_receipt_digests": sorted(verified), "rejected_receipts": rejected,
        "capability_results": capabilities, "requirements_satisfied": all(c["outcome"] == "supported" for c in capabilities), "production_dispatch_allowed": False}, version="2.1")
    report = seal_versioned("capability-report", {"subject": subject, "mode": mode, "decision_digest": decision["digest"],
        "overall_outcome": _overall([c["outcome"] for c in capabilities]), "capability_results": capabilities,
        "per_receipt_usage": [{"receipt_digest": key, "usage": verified[key]["usage"]} for key in sorted(verified)],
        "limitations": sorted({"Offline evaluation only; production dispatch remains disabled.", *(item for receipt in verified.values() for item in receipt["limitations"])}),
        "production_dispatch_allowed": False}, version="2.1")
    return Evaluation(QualificationDecision.from_dict(decision), CapabilityReport.from_dict(report))
