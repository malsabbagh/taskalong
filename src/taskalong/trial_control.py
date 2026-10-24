"""Trusted OS control plane for offline E1 history and non-executing inspection.

The caller has the same single-user trust boundary as RunService. Worker JSON
cannot register itself. No function installs a live route, discovers credentials
or launches a process; activation-shaped history remains historical evidence.
"""
from datetime import datetime

from .errors import TaskAlongError
from .trial import (LocalReviewAssessment, TrialActivation, TrialDriverConfig, TrialPacketProjection,
                    TrialPublishIntent, TrialReviewerProfile, TrialReviewReceipt, TrialTaskSpec, TrialWorkerPacket)
from .validation import canonical_bytes, digest, loads

_HISTORICAL = (TrialDriverConfig, TrialTaskSpec, TrialWorkerPacket, TrialPacketProjection, TrialReviewerProfile,
               TrialActivation, TrialPublishIntent, TrialReviewReceipt, LocalReviewAssessment)


def register_trial_document(store, document, *, operation_key):
    """Store one exact immutable document; never register execution authority."""
    if store.format_version != 8:
        raise TaskAlongError("store_upgrade_required", "Trial history requires explicit format-8 maintenance.", exit_code=3)
    if type(document) not in _HISTORICAL:
        raise TaskAlongError("history_document_invalid", "Select an exact supported immutable trial document.")
    document = type(document)(document.to_bytes())
    return store.record_document(document, operation_key=operation_key)


def inspect_trial_route(*, task=None, driver_config=None, reviewer_profile=None, activation=None, at):
    """Report bounded structural gaps. A sealed document is never current trust.

    This deliberately excludes installation/provider/policy authentication. Even
    a fully linked generated tuple has no available execution backend here.
    Missing data is reported without inventing a partially sealed route.
    """
    from .validation import _utc_time
    try:
        valid_time = type(at) is str and _utc_time(at)
    except (ValueError, TypeError):
        valid_time = False
    if not valid_time:
        raise TaskAlongError("trial_inspection_invalid", "An explicit UTC inspection time is required.")
    instant = datetime.fromisoformat(at.replace("Z", "+00:00"))
    values, missing, reasons = {}, [], {"trial_runtime_unqualified", "current_authority_unproven",
                                      "installation_and_policy_qualification_unproven"}
    for name, value, cls in (("task", task, TrialTaskSpec), ("driver_config", driver_config, TrialDriverConfig),
                             ("reviewer_profile", reviewer_profile, TrialReviewerProfile), ("activation", activation, TrialActivation)):
        if value is None:
            missing.append(name)
        elif type(value) is not cls:
            raise TaskAlongError("trial_inspection_invalid", "Select exact immutable trial documents.")
        else:
            values[name] = cls(value.to_bytes()).to_dict()
    structural = set()
    if task is not None and driver_config is not None:
        s, c = values["task"], values["driver_config"]
        if s["execution"] != {"binding_digest": c["binding_digest"], "driver_config_digest": c["digest"]}:
            structural.add("trial_driver_subject_mismatch")
    if task is not None and reviewer_profile is not None:
        s, r = values["task"], values["reviewer_profile"]
        if s["review"]["reviewer_profile_digest"] != r["digest"] or s["review"]["config_digest"] != r["config_digest"]:
            structural.add("trial_reviewer_subject_mismatch")
    if activation is not None:
        a = values["activation"]
        if not datetime.fromisoformat(a["valid_from"].replace("Z", "+00:00")) <= instant < datetime.fromisoformat(a["valid_until"].replace("Z", "+00:00")):
            structural.add("activation_expired")
        expected = {}
        if task is not None:
            s = values["task"]
            expected.update(spec_digest=s["digest"], repository_registration_id=s["repository"]["registration_id"],
                            base_commit=s["repository"]["base_commit"], scope_digest=digest(s["scope"], exclude_digest=False),
                            reviewer_profile_digest=s["review"]["reviewer_profile_digest"])
            if a["limits"] != s["budget"] or not set(a["allowed_effects"]) <= set(s["permissions"]["allowed_effects"]):
                structural.add("activation_limits_mismatch")
        if driver_config is not None:
            c = values["driver_config"]
            expected.update(driver_config_digest=c["digest"], binding_digest=c["binding_digest"],
                            provider_profile_digest=c["provider_profile_digest"], host_digest=c["host"]["host_digest"],
                            runtime_closure_digest=c["host"]["runtime_closure_digest"])
        if any(a["subject"][key] != wanted for key, wanted in expected.items()):
            structural.add("activation_subject_mismatch")
    return loads(canonical_bytes({"kind": "trial_route_inspection", "schema_version": "2.8", "at": at,
                 "structurally_complete": not missing and not structural, "missing": sorted(missing),
                 "reason_codes": sorted(reasons | structural), "activation_eligible": False,
                 "execution_available": False, "production_dispatch_allowed": False,
                 "supported_recovery": "completed-worker-before-verify/1", "native_resume_supported": False,
                 "remote_cancellation_supported": False}))


def assessment_consistency(receipt, assessment=None):
    """Pure per-instance consistency, explicitly without issuer authentication.

    This reports useful assessment progress while the combined local-review
    gate remains blocked for installation qualification. Raw reviewer statuses
    and receipt bytes are never edited and no disposition means verified-fixed.
    """
    if type(receipt) is not TrialReviewReceipt:
        raise TaskAlongError("trial_assessment_invalid", "Select an exact trial review receipt.")
    r = TrialReviewReceipt(receipt.to_bytes()).to_dict()
    reasons, status = {"reviewer_qualification_unverified"}, "awaiting_assessment"
    if not r["observation_complete"]:
        reasons.add("review_observation_incomplete")
        status = "blocked"
    if assessment is not None:
        if type(assessment) is not LocalReviewAssessment:
            raise TaskAlongError("trial_assessment_invalid", "Select an exact local review assessment.")
        a = LocalReviewAssessment(assessment.to_bytes()).to_dict()
        expected = {item["fingerprint"] for item in r["findings"]}
        actual = {item["fingerprint"] for item in a["decisions"]}
        if (a["review_receipt_digest"] != receipt.digest or a["subject"] != r["subject"]
                or a["reviewer_profile_digest"] != r["selected_profile_digest"] or actual - expected):
            reasons.add("review_assessment_subject_mismatch")
            status = "blocked"
        elif expected - actual:
            reasons.add("review_assessment_missing")
        elif any(item["disposition"] == "unfixed_defect" for item in a["decisions"]):
            reasons.add("review_unfixed_defect")
            status = "blocked"
        elif status != "blocked":
            status = "consistent"
    elif not r["findings"] and status != "blocked" and r["observed"]["exit_code"] == 0:
        status = "consistent"
    else:
        reasons.add("review_assessment_missing")
    return {"kind": "trial_local_review_inspection", "schema_version": "2.8", "assessment_status": status,
            "installation_qualification": "unknown", "taskalong_local_review_gate": "awaiting_assessment" if status == "awaiting_assessment" else "blocked",
            "reason_codes": sorted(reasons), "authority_checked": False, "policy_checked": False,
            "activation_eligible": False, "execution_available": False, "native_app_approval": False}


def assessment_intent_digest(assessment):
    """Bind the exact judgment without a self-referential authority hash.

    The preselected authority ID, subject, receipt, profile, policy, assessor,
    timestamp and every decision are inside this intent. Only authority_digest
    and the assessment's own top-level digest are excluded. The final historical
    assessment separately binds the authority bytes that authorize this intent.
    Computing a digest never issues that authority.
    """
    if type(assessment) is not LocalReviewAssessment:
        raise TaskAlongError("trial_assessment_invalid", "Select an exact local review assessment.")
    value = LocalReviewAssessment(assessment.to_bytes()).to_dict()
    return digest({key: item for key, item in value.items() if key not in {"digest", "authority_digest"}}, exclude_digest=False)


def inspect_local_assessment(store, receipt, *, profile, schemas, assessment=None):
    """Re-read originals and current OS authority/policy, without accepting work.

    The existing Store is the trusted control plane, not a supplied authority
    dictionary. This function never creates a run/authority or issues a grant.
    Missing applicable stored authority remains a precise blocked prerequisite.
    """
    from .store import now
    from .trial_review import TrialReviewEvidence, observe_review
    if store.format_version != 8 or type(receipt) is not TrialReviewReceipt:
        raise TaskAlongError("trial_assessment_invalid", "Trial assessment requires its exact fenced history and receipt.")
    raw = receipt.to_dict()
    blobs = {ref["sha256"]: store.get_blob(ref["sha256"]) for ref in raw["originals"].values()}
    reproduced = observe_review(profile, subject=raw["subject"], originals=raw["originals"],
                                evidence=TrialReviewEvidence.from_blobs(blobs), schemas=schemas)
    if reproduced.to_bytes() != receipt.to_bytes():
        raise TaskAlongError("trial_review_invalid", "The immutable review receipt differs from its original captures.")
    result = assessment_consistency(reproduced, assessment)
    reasons = set(result["reason_codes"])
    if assessment is None:
        reasons.add("current_assessment_authority_unproven")
        result["reason_codes"] = sorted(reasons)
        return result
    a = LocalReviewAssessment(assessment.to_bytes()).to_dict()
    policy = store.setting("trial-review-assessment-policy")
    fields = {"policy_digest", "revoked_authority_ids", "revoked_receipt_digests", "revoked_profile_digests"}
    if (type(policy) is not dict or set(policy) != fields or policy["policy_digest"] != a["policy_digest"]
            or any(type(policy[key]) is not list or len(policy[key]) > 128
                   or any(type(value) is not str or not 1 <= len(value) <= 256 for value in policy[key])
                   for key in fields - {"policy_digest"})):
        reasons.add("review_assessment_policy_unproven")
    elif (a["authority_id"] in policy["revoked_authority_ids"] or receipt.digest in policy["revoked_receipt_digests"]
          or raw["selected_profile_digest"] in policy["revoked_profile_digests"]):
        reasons.add("review_assessment_revoked")
    else:
        result["policy_checked"] = True
    try:
        run = store.run(a["subject"]["run_id"])
        spec = store.spec(run)
        candidate = run["candidate"]
        if (run["spec_digest"] != a["subject"]["spec_digest"] or spec["schema_version"] != "2.8"
                or spec["review"]["reviewer_profile_digest"] != raw["selected_profile_digest"]
                or spec["review"]["config_digest"] != profile.to_dict()["config_digest"]
                or candidate is None or spec["repository"]["base_commit"] != a["subject"]["base_commit"]
                or any(candidate.get(key) != a["subject"][field] for key, field in
                       (("base_commit", "base_commit"), ("commit", "candidate_commit"), ("tree", "candidate_tree"), ("diff_sha256", "diff_sha256")))):
            raise TaskAlongError("review_assessment_subject_mismatch", "The stored current candidate differs from the assessment.")
        authority = store.authority(run, {"verify"}, assessment_intent_digest(assessment), a["authority_id"])
        if (authority["digest"] != a["authority_digest"] or authority["principal"] != a["assessor"]["principal"]
                or a["assessor"]["human_decision_observed"] != authority["human_decision_observed"]
                or not authority["issued_at"] <= a["assessed_at"] <= now()
                or a["assessed_at"] >= authority["expires_at"]):
            raise TaskAlongError("review_assessment_authority_mismatch", "The current exact authority does not cover the assessment.")
        result["authority_checked"] = True
    except TaskAlongError as exc:
        reasons.add(exc.code)
    if not result["policy_checked"] or not result["authority_checked"]:
        result["assessment_status"] = "blocked"
        result["taskalong_local_review_gate"] = "blocked"
    result["reason_codes"] = sorted(reasons)
    return loads(canonical_bytes(result))
