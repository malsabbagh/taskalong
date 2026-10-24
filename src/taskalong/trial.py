"""Immutable E1 intent data. No reader registers trust or constructs a launcher."""
from dataclasses import dataclass
from datetime import datetime
import hashlib
from typing import ClassVar

from .contracts import JsonDocument
from .errors import TaskAlongError
from .validation import canonical_bytes, loads, validate_versioned


@dataclass(frozen=True, slots=True)
class TrialDocument(JsonDocument):
    """Explicit additive family; document identity is not activation authority."""

    def __post_init__(self):
        admitted = validate_versioned(self.schema_name, loads(self._canonical), expected_version="2.8")
        object.__setattr__(self, "_canonical", canonical_bytes(admitted))


@dataclass(frozen=True, slots=True)
class TrialDriverConfig(TrialDocument):
    schema_name: ClassVar[str] = "driver-config"


@dataclass(frozen=True, slots=True)
class TrialTaskSpec(TrialDocument):
    schema_name: ClassVar[str] = "task-spec"


@dataclass(frozen=True, slots=True)
class TrialWorkerPacket(TrialDocument):
    schema_name: ClassVar[str] = "worker-packet"


@dataclass(frozen=True, slots=True)
class TrialWorkerResult(TrialDocument):
    schema_name: ClassVar[str] = "worker-result"


@dataclass(frozen=True, slots=True)
class TrialPacketProjection(TrialDocument):
    schema_name: ClassVar[str] = "packet-projection"


@dataclass(frozen=True, slots=True)
class TrialReviewerProfile(TrialDocument):
    schema_name: ClassVar[str] = "reviewer-profile"


@dataclass(frozen=True, slots=True)
class TrialActivation(TrialDocument):
    schema_name: ClassVar[str] = "trial-activation"


@dataclass(frozen=True, slots=True)
class TrialPublishIntent(TrialDocument):
    schema_name: ClassVar[str] = "publish-intent"


@dataclass(frozen=True, slots=True)
class TrialReviewReceipt(TrialDocument):
    schema_name: ClassVar[str] = "review-receipt"


@dataclass(frozen=True, slots=True)
class LocalReviewAssessment(TrialDocument):
    schema_name: ClassVar[str] = "local-review-assessment"


def _semantics(document, name):
    if name in {"task-spec", "publish-intent"}:
        target = document["publication"] if name == "task-spec" else document["target"]
        if target is not None:
            for branch in (target["base_branch"], target["trial_branch"]):
                if (branch.startswith(("-", "/")) or branch.endswith(("/", "."))
                        or any(value in branch for value in ("..", "@{", "\\", " ", "//", "~", "^", ":", "?", "*", "["))
                        or any(part.startswith(".") or part.endswith(".lock") for part in branch.split("/"))):
                    raise TaskAlongError("trial_target_invalid", "The exact trial branch identity is invalid.")
            if name == "task-spec" and target["base_commit"] != document["repository"]["base_commit"]:
                raise TaskAlongError("trial_target_invalid", "The exact trial target base differs from the task.")
    if name == "local-review-assessment":
        keys = [item["fingerprint"] for item in document["decisions"]]
        if len(keys) != len(set(keys)):
            raise TaskAlongError("trial_assessment_invalid", "Each finding instance requires one distinct decision.")
        if document["assessor"]["role"] == "delegated_engineering" and document["assessor"]["human_decision_observed"]:
            raise TaskAlongError("trial_assessment_invalid", "Delegated engineering assessment cannot claim a human decision.")
    if name == "review-receipt":
        keys = [item["fingerprint"] for item in document["findings"]]
        if (len(keys) != len(set(keys)) or [item["index"] for item in document["findings"]] != list(range(len(keys)))
                or document["observation_complete"] != (not document["reason_codes"])):
            raise TaskAlongError("trial_review_invalid", "The bounded review observation inventory is inconsistent.")
    if name == "trial-activation":
        start, end = (datetime.fromisoformat(document[key].replace("Z", "+00:00"))
                      for key in ("valid_from", "valid_until"))
        if start >= end:
            raise TaskAlongError("trial_activation_invalid", "Trial activation intent must expire after its valid-from time.")
    if name == "publish-intent":
        if (hashlib.sha256(document["body"].encode()).hexdigest() != document["body_sha256"]
                or document["title"] != document["target"]["title"]
                or document["authorization_ref"] != document["target"]["authorization_ref"]):
            raise TaskAlongError("trial_publish_intent_mismatch", "The exact draft payload and target intent disagree.")


def validate_publish_target(intent, task, *, observed_target):
    """Check supplied exact target facts; never discover access or publish.

    A caller-supplied snapshot cannot authenticate GitHub, grant push access or
    replace a fresh transport check. The existing private publisher is unchanged.
    """
    if type(intent) is not TrialPublishIntent or type(task) is not TrialTaskSpec:
        raise TaskAlongError("trial_target_invalid", "Select exact immutable trial intent and task documents.")
    i, s = TrialPublishIntent(intent.to_bytes()).to_dict(), TrialTaskSpec(task.to_bytes()).to_dict()
    target = s["publication"]
    fields = {"host", "repository_id", "repository_full_name", "visibility", "base_branch", "base_commit",
              "trial_branch", "archived", "disabled", "can_push", "branch_conflict", "pr_conflict"}
    if type(observed_target) is not dict or set(observed_target) != fields:
        raise TaskAlongError("trial_target_invalid", "An exact bounded target observation is required.")
    value = observed_target
    if any(type(value[key]) is not bool for key in ("archived", "disabled", "can_push", "branch_conflict", "pr_conflict")):
        raise TaskAlongError("trial_target_invalid", "Target access and conflict observations must be explicit booleans.")
    if (target is None or i["spec_digest"] != s["digest"] or i["target"] != target
            or type(value["repository_id"]) is not int
            or any(value[key] != target[key] for key in ("host", "repository_id", "repository_full_name", "base_branch", "base_commit", "trial_branch"))
            or value["visibility"] != target["expected_visibility"] or not value["can_push"]
            or any(value[key] for key in ("archived", "disabled", "branch_conflict", "pr_conflict"))):
        raise TaskAlongError("trial_target_mismatch", "The supplied target facts disagree with the exact authorized draft intent.")
    return intent


def validate_linked_result(packet, result, *, task, driver_config, provider_profile_digest,
                           run_id, attempt_id, lease_generation):
    """Check supplied immutable subjects, never authenticate execution or accept work.

    Result fields remain worker claims. Native session/model observations, real
    cessation and independent candidate acceptance are deliberately separate.
    """
    def refuse():
        raise TaskAlongError("trial_result_mismatch", "The E1 result and expected immutable subjects disagree.")

    expected = ((packet, TrialWorkerPacket), (result, TrialWorkerResult),
                (task, TrialTaskSpec), (driver_config, TrialDriverConfig))
    if any(type(value) is not kind for value, kind in expected):
        refuse()
    # Re-read each value through its exact closed reader at the linked boundary.
    packet, result, task, driver_config = tuple(kind(value.to_bytes()) for value, kind in expected)
    p, r, s, c = (value.to_dict() for value in (packet, result, task, driver_config))
    if type(lease_generation) is not int or not 1 <= lease_generation <= 2**53 - 1:
        refuse()
    if (p["run_id"] != run_id or p["attempt_id"] != attempt_id
            or p["bindings"]["lease_generation"] != lease_generation
            or p["spec_digest"] != s["digest"] or p["binding_digest"] != c["binding_digest"]
            or s["execution"]["binding_digest"] != c["binding_digest"]
            or s["execution"]["driver_config_digest"] != c["digest"]
            or p["bindings"]["driver_config_digest"] != c["digest"]
            or p["bindings"]["provider_profile_digest"] != provider_profile_digest
            or c["provider_profile_digest"] != provider_profile_digest
            or p["reviewer_profile_digest"] != s["review"]["reviewer_profile_digest"]
            or p["bindings"]["base_commit"] != s["repository"]["base_commit"]
            or any(p[key] != s[key] for key in ("goal", "non_goals", "scope", "checks"))):
        refuse()
    for key in ("max_attempts", "attempt_seconds", "total_active_seconds", "max_output_bytes"):
        if p["remaining_budget"][key] > s["budget"][key]:
            refuse()
    if any(p["remaining_budget"][key] != s["budget"][key] for key in ("hard_cost_usd", "hard_tokens")):
        refuse()
    for key, wanted in {"packet_id": p["packet_id"], "packet_digest": p["digest"],
                        "run_id": run_id, "attempt_id": attempt_id, "spec_digest": s["digest"],
                        "driver_config_digest": c["digest"],
                        "provider_profile_digest": provider_profile_digest}.items():
        if r[key] != wanted:
            refuse()
    return result


def validate_projection(projection, packet, *, wire_bytes, registration_digest,
                        run_id, attempt_id, lease_generation):
    """Validate the declared canonical-JSON mapping, without compiling a CLI.

    The packet is sealed first; wire bytes include its digest. The projection
    references those distinct identities and never appears inside the packet.
    A valid mapping grants no execution, registration or activation authority.
    """
    def refuse():
        raise TaskAlongError("trial_projection_mismatch", "The E1 packet projection and expected subjects disagree.")

    if type(projection) is not TrialPacketProjection or type(packet) is not TrialWorkerPacket:
        refuse()
    if type(wire_bytes) is not bytes or len(wire_bytes) > 1_048_576 or type(lease_generation) is not int:
        refuse()
    projection = TrialPacketProjection(projection.to_bytes())
    packet = TrialWorkerPacket(packet.to_bytes())
    p, v = packet.to_dict(), projection.to_dict()
    if (wire_bytes != packet.to_bytes() or p["run_id"] != run_id or p["attempt_id"] != attempt_id
            or p["bindings"]["lease_generation"] != lease_generation):
        refuse()
    expected = {"run_id": run_id, "attempt_id": attempt_id, "lease_generation": lease_generation,
                "canonical_packet_digest": packet.digest, "wire_packet_digest": hashlib.sha256(wire_bytes).hexdigest(),
                "registration_digest": registration_digest,
                **{key: p[key] for key in ("spec_digest", "binding_digest", "admission_digest", "activation_digest", "reviewer_profile_digest")},
                **{key: p["bindings"][key] for key in ("driver_config_digest", "provider_profile_digest")}}
    if any(v[key] != wanted for key, wanted in expected.items()):
        refuse()
    return projection
