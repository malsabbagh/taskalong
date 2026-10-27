"""Deterministic independent-evidence admission, separate from worker claims.

This module evaluates only records already issued by owned core invocations. It
has no import/approval mechanism and cannot authenticate arbitrary JSON receipts.
"""
from __future__ import annotations

from typing import Any, Iterable

from .errors import TaskAlongError
from .validation import digest, validate


def canonical_subject(candidate: dict[str, Any]) -> dict[str, str]:
    """Translate a durable candidate into its evidence subject without fallbacks."""
    return {"base_commit": candidate["base_commit"],
            "candidate_commit": candidate.get("candidate_commit", candidate.get("commit")),
            "candidate_tree": candidate.get("candidate_tree", candidate.get("tree")),
            "diff_sha256": candidate["diff_sha256"]}


def acceptance_reasons(
    spec: dict[str, Any], run: dict[str, Any], evidence: Iterable[dict[str, Any]], *,
    workspace_quiescent: bool = True, current_subject: dict[str, Any],
    packet_digest: str | None = None, lease_generation: int | None = None,
    owned_invocation_ids: Iterable[str] | None = None,
    verification_profile_digest: str | None = None,
) -> list[dict[str, str]]:
    """Return typed reasons blocking acceptance; an empty list means eligible.

    The caller reads records and blob integrity from its private store and proves
    current workspace/process state. Provenance identifiers are supplied from
    the core's actual invocations, never inferred from a receipt's claimed role.
    """
    reasons: list[dict[str, str]] = []

    def block(code: str, message: str) -> None:
        if not any(item["code"] == code for item in reasons):
            reasons.append({"code": code, "message": message})

    subject = canonical_subject(current_subject)
    expected_candidate = canonical_subject(run["candidate"]) if run.get("candidate") else None
    if not workspace_quiescent or run.get("active_attempt_id") is not None:
        block("workspace_not_quiescent", "Independent acceptance requires confirmed worker cessation.")
    if expected_candidate != subject or spec["repository"]["base_commit"] != subject["base_commit"]:
        block("acceptance_subject_stale", "The current candidate differs from the submitted subject.")
    if run.get("spec_digest") != spec["digest"] or run.get("task_revision") != spec["revision"]:
        block("acceptance_spec_stale", "The run and immutable task specification differ.")
    if run.get("pending_effect_ids"):
        block("effect_unreconciled", "Outstanding effects require reconciliation before acceptance.")
    if run.get("blockers") and run.get("state") != "verifying":
        block("run_blocked", "An unresolved run blocker prevents acceptance.")
    if packet_digest is None or lease_generation is None:
        block("evidence_binding_missing", "Expected packet and lease bindings must come from the private attempt.")
    if owned_invocation_ids is None:
        block("producer_provenance_missing", "Owned invocation receipts must come from the independent verifier.")
    owned = set(owned_invocation_ids or ())
    expected_attempt = run.get("attempts", [{}])[-1].get("attempt_id") if run.get("attempts") else None
    records = list(evidence)
    expected_profile = (verification_profile_digest if spec.get("schema_version") in {"2.2", "2.3", "2.4", "2.5", "2.6", "2.9", "2.10"}
                        else spec["execution"]["profile_digest"])
    if expected_profile is None:
        block("evidence_binding_missing", "V2 acceptance needs the exact independently resolved check profile.")
    seen_ids: set[str] = set()
    commands: dict[str, list[dict]] = {}
    scope_records: list[dict] = []
    review_records: list[dict] = []
    for record in records:
        try:
            validate("evidence", record)
        except TaskAlongError:
            block("evidence_invalid", "An evidence record violates the v1 contract.")
            continue
        if record["evidence_id"] in seen_ids:
            block("evidence_duplicate", "The acceptance evidence set contains a duplicate identity.")
        seen_ids.add(record["evidence_id"])
        if record["type"] in {"worker_claim", "authority"}:
            # They may be retained as private data but never satisfy checks/review.
            continue
        if (record["producer"]["role"] != "verifier" or record["producer"]["invocation_id"] not in owned):
            block("evidence_producer_unowned", "Only an actual owned independent invocation may issue verifier evidence.")
        if (record["run_id"] != run["run_id"] or record["task_revision"] != spec["revision"]
            or record["spec_digest"] != spec["digest"] or record["subject"] != subject
            or record["packet_digest"] != packet_digest or record["lease_generation"] != lease_generation
            or record["attempt_id"] != expected_attempt):
            block("evidence_stale", "Evidence does not match the exact current task, attempt, lease and candidate.")
        if (record["qualification"] != run["qualification"] or spec["qualification"] != run["qualification"]
            or record["inputs"]["runtime_profile_digest"] != expected_profile):
            block("evidence_policy_stale", "Evidence qualification or runtime policy differs from the submitted specification.")
        if record["result"] != "passed":
            block("evidence_not_passed", "A required independent evidence record did not pass.")
        if not record["artifacts"]:
            block("evidence_artifact_missing", "Independent evidence requires an immutable artifact reference.")
        if record["type"] == "command":
            commands.setdefault(record["inputs"]["check_digest"], []).append(record)
        elif record["type"] == "scope":
            scope_records.append(record)
        elif record["type"] == "review":
            review_records.append(record)
    if len(scope_records) != 1:
        block("scope_evidence_missing", "Exactly one independently observed current scope manifest is required.")
    check_by_id = {check["id"]: check for check in spec["checks"]}
    required_ids = {check["id"] for check in spec["checks"] if check["required"]}
    for criterion in spec["criteria"]:
        required_ids.update(criterion["check_ids"])
        if not criterion["check_ids"]:
            block("criterion_unproved", "Every criterion requires independently observed checks.")
    for check_id in sorted(required_ids):
        check = check_by_id.get(check_id)
        if check is None:
            block("criterion_check_missing", "A criterion names an absent required check.")
            continue
        matches = commands.get(digest(check), [])
        if len(matches) != 1:
            block("required_check_missing", "Every required check needs one exact independent receipt.")
            continue
        receipt = matches[0]
        command = receipt["command"]
        if (command is None or command["argv_digest"] != digest(check["argv"])
            or command["cwd_relative"] != check["cwd"] or command["exit_code"] != 0
            or check["expected_exit_code"] != 0 or command["timed_out"] is not False
            or set(receipt["criterion_ids"]) != set(check["criterion_ids"])):
            block("required_check_mismatch", "The required command, outcome or criterion bindings do not match.")
    if spec["review"].get("required") is not True or spec["review"].get("contract") != "0.8.8/v1":
        block("required_review_policy_invalid", "The first verified workflow requires the pinned independent review contract.")
    if len(review_records) != 1:
        block("required_review_missing", "Exactly one current complete independent review is required.")
    else:
        review = review_records[0]
        receipt = review["extensions"].get("taskalong:review", {})
        if (review["producer"]["tool"] != "review-sensei" or review["producer"]["version"] != "0.8.8"
            or review["inputs"]["review_config_digest"] != spec["review"]["config_digest"]
            or receipt.get("config_digest") != spec["review"]["config_digest"]
            or receipt.get("subject") != subject or receipt.get("qualification") != run["qualification"]
            or receipt.get("invocation_id") != review["producer"]["invocation_id"]
            or receipt.get("executable_sha256") != review["producer"]["executable_sha256"]
            or receipt.get("version") != "0.8.8" or receipt.get("result") != "passed"
            or receipt.get("producer_role") != "verifier" or receipt.get("assurance") != "full-reviewed-diff-v1"):
            block("review_receipt_mismatch", "The pinned review receipt does not match its actual producer, subject and policy.")
        if run["qualification"] == "production" and receipt.get("provider") == "fixture":
            block("fixture_in_production", "Fixture evidence cannot qualify production acceptance.")
    return reasons
