"""Pure decoding of supplied installed-review captures, never a review launcher.

Original private bytes remain immutable. Profile selection and process records
are caller-supplied observations, not authentication of the installed producer.
This module grants neither local acceptance nor native App approval.
"""
from dataclasses import dataclass
import hashlib

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

from .errors import TaskAlongError
from .trial import TrialReviewReceipt, TrialReviewerProfile
from .validation import canonical_bytes, digest, loads, seal_versioned


def _invalid():
    return TaskAlongError("trial_review_invalid", "The selected review capture or its exact original evidence is invalid.")


@dataclass(frozen=True, slots=True)
class TrialReviewEvidence:
    """Private immutable original captures, including empty stdout/stderr.

    This separate snapshot does not change M2's nonempty evidence contract or
    M9's smaller proof limits. No path, callback or remote resolver is accepted.
    """
    _entries: tuple[tuple[str, bytes], ...]

    def __post_init__(self):
        if type(self._entries) is not tuple or len(self._entries) > 128:
            raise _invalid()
        seen, total = set(), 0
        for entry in self._entries:
            if type(entry) is not tuple or len(entry) != 2:
                raise _invalid()
            key, data = entry
            if (type(key) is not str or type(data) is not bytes or len(data) > 1_048_576
                    or hashlib.sha256(data).hexdigest() != key or key in seen):
                raise _invalid()
            seen.add(key)
            total += len(data)
        if total > 16 * 1_048_576:
            raise _invalid()

    @classmethod
    def from_blobs(cls, blobs):
        if type(blobs) is not dict:
            raise _invalid()
        return cls(tuple(blobs.items()))

    def get(self, key):
        return next((data for name, data in self._entries if name == key), None)


def _process(value):
    """Validate the existing ProcessResult serialization without executing it."""
    required = {"exit_code", "stdout", "stderr", "timed_out", "cancelled", "termination_confirmed",
                "group_termination_confirmed", "output_limited", "receipt", "duration_ms", "output_bytes",
                "lifetime_backend", "unaccounted_descendants", "protocol_error"}
    if set(value) != required:
        raise _invalid()
    for key in ("timed_out", "cancelled", "termination_confirmed", "group_termination_confirmed",
                "output_limited", "unaccounted_descendants"):
        if type(value[key]) is not bool:
            raise _invalid()
    if value["exit_code"] is not None and (type(value["exit_code"]) is not int or not -128 <= value["exit_code"] <= 255):
        raise _invalid()
    for key in ("duration_ms", "output_bytes"):
        if type(value[key]) is not int or not 0 <= value[key] <= 2**53 - 1:
            raise _invalid()
    if any(type(value[key]) is not str for key in ("stdout", "stderr", "lifetime_backend")):
        raise _invalid()
    if value["protocol_error"] is not None and type(value["protocol_error"]) is not str:
        raise _invalid()
    receipt = value["receipt"]
    if type(receipt) is not dict or set(receipt) != {"invocation_id", "pid", "pgid", "supervisor_pid", "started_unix_ms", "executable_sha256"}:
        raise _invalid()
    if any(type(receipt[key]) is not int or not 1 <= receipt[key] <= 2**53 - 1
           for key in ("pid", "pgid", "supervisor_pid", "started_unix_ms")):
        raise _invalid()
    if type(receipt["invocation_id"]) is not str or not 1 <= len(receipt["invocation_id"]) <= 256:
        raise _invalid()
    return value


def observe_review(profile, *, subject, originals, evidence, schemas):
    """Decode exact raw-schema data and report complete *text observations*.

    A complete observation still has installation_authenticated=false. Current
    producer/closure/config/authority must be checked separately by trusted
    admission; none can be inferred from JSON, a hash or healthy termination.
    Required finding classifications omitted by the upstream serialization are
    never fabricated here. Every finding instance is retained for assessment.
    """
    if (type(profile) is not TrialReviewerProfile or type(evidence) is not TrialReviewEvidence
            or type(schemas) is not dict or type(subject) is not dict):
        raise _invalid()
    profile = TrialReviewerProfile(profile.to_bytes()).to_dict()
    if set(schemas) != set(profile["schema_digests"]):
        raise _invalid()
    documents = {}
    for name, raw in schemas.items():
        if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != profile["schema_digests"][name]:
            raise _invalid()
        documents[name] = loads(raw)
    def no_remote(uri):
        raise NoSuchResource(ref=uri)
    registry = Registry(retrieve=no_remote).with_resources(
        (doc["$id"], Resource.from_contents(doc)) for doc in documents.values())
    if type(originals) is not dict or set(originals) != {"diff", "result", "outcome", "process", "stdout", "stderr"}:
        raise _invalid()
    captured = {}
    for name, ref in originals.items():
        if type(ref) is not dict or set(ref) != {"sha256", "size_bytes"} or type(ref["size_bytes"]) is not int:
            raise _invalid()
        data = evidence.get(ref["sha256"])
        if data is None or len(data) != ref["size_bytes"]:
            raise _invalid()
        captured[name] = data
    result, outcome = loads(captured["result"]), loads(captured["outcome"])
    for name, value in (("review-result", result), ("run-outcome", outcome)):
        try:
            if next(Draft202012Validator(documents[name], registry=registry).iter_errors(value), None):
                raise _invalid()
        except (ValueError, KeyError) as exc:
            raise _invalid() from exc
    process = _process(loads(captured["process"]))
    reasons = set()
    from .process import redact
    if any(redact(captured[name]).decode("utf-8", "replace") != process[name] for name in ("stdout", "stderr")):
        reasons.add("review_stream_mismatch")
    if len(captured["stdout"]) + len(captured["stderr"]) != process["output_bytes"]:
        reasons.add("review_capture_size_mismatch")
    if (process["exit_code"] not in (0, 1, 2) or process["timed_out"] or process["cancelled"]
            or process["output_limited"] or process["protocol_error"] is not None):
        reasons.add("review_process_incomplete")
    if (not process["termination_confirmed"] or not process["group_termination_confirmed"]
            or process["unaccounted_descendants"] or process["lifetime_backend"] not in {"linux-child-subreaper", "darwin-kqueue-no-fork"}):
        reasons.add("review_cessation_unproven")
    if process["receipt"]["executable_sha256"] != profile["entrypoint"]["sha256"]:
        reasons.add("review_executable_mismatch")
    if (outcome.get("base_sha") != subject.get("base_commit") or outcome.get("head_sha") != subject.get("candidate_commit")
            or hashlib.sha256(captured["diff"]).hexdigest() != subject.get("diff_sha256")):
        reasons.add("review_subject_mismatch")
    if (result["provider"] != profile["expected_reported_provider"] or result.get("model") != profile["expected_model"]):
        reasons.add("review_producer_mismatch")
    if (result.get("review_status") != "complete" or outcome["status"] != "reviewed"
            or result.get("coverage_mode") not in {"full", "fallback-full"}
            or result.get("evidence_policy") != "legacy" or "transaction" in result
            or result.get("coverage_only_partial", False) or "persistence_status" in result
            or "bounded_work_receipt" in result
            or any(item["state"] == "uncertain" for item in result.get("finding_lifecycles", []))):
        reasons.add("review_text_incomplete")
    if not outcome["stage_summary"] or any(value != "complete" for value in outcome["stage_summary"].values()):
        reasons.add("review_stage_incomplete")
    # The existing parser is version-neutral; the old 0.8.8 acceptance predicate
    # and reviewer adapter remain unchanged and are deliberately not called.
    from .integrations.reviewsensei import diff_inventory
    paths, hunks = diff_inventory(captured["diff"])
    if any(comment["path"] not in paths for comment in result["comments"]):
        reasons.add("review_finding_subject_mismatch")
    coverage = result.get("coverage", {})
    files, actual_hunks = coverage.get("files", []), coverage.get("hunks", [])
    if (coverage.get("enumeration_complete") is not True or coverage.get("fully_reviewed") is not True
            or sorted(coverage.get("enumerated_paths", [])) != sorted(paths)
            or len(files) != len(paths) or {item["path"] for item in files} != set(paths)
            or len(actual_hunks) != len(hunks) or {(item["index"], item["path"]) for item in actual_hunks} != set(hunks)
            or any(item["outcome"] != "reviewed" or "reason" in item for item in (*files, *actual_hunks))):
        reasons.add("review_coverage_incomplete")
    if process["exit_code"] in (1, 2) and not result["comments"]:
        reasons.add("review_required_inventory_missing")
    if process["exit_code"] == 0 and any(comment.get("blocking") is True for comment in result["comments"]):
        reasons.add("review_exit_inconsistent")
    result_sha = originals["result"]["sha256"]
    findings = [{"index": index, "fingerprint": digest({"result_sha256": result_sha, "index": index,
                  "comment": comment}, exclude_digest=False)} for index, comment in enumerate(result["comments"])]
    document = {"selected_profile_digest": digest(profile), "contract": profile["contract"],
                "process_capture_contract": "taskalong-process-redaction-v1", "subject": subject,
                "originals": originals, "observed": {"exit_code": process["exit_code"],
                "review_status": result.get("review_status", "unknown"), "outcome_status": outcome["status"],
                "provider": result["provider"], "model": result.get("model")},
                "observation_complete": not reasons, "reason_codes": sorted(reasons), "findings": findings,
                "coverage": {"files": len(files), "hunks": len(actual_hunks)},
                "usage": {"provider_calls": outcome["provider_calls"], "tokens": None, "cost_usd": None},
                "observation_only": True, "installation_authenticated": False, "native_app_approval": False}
    return TrialReviewReceipt.from_dict(seal_versioned("review-receipt", document, version="2.8"))
