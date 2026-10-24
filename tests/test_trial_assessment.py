"""Separate engineering consistency never fabricates CLI or App approval."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
import uuid

from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, digest, seal, seal_versioned
from test_trial_review import generated_review, observe_generated


def assessment_for(receipt, *, authority_id=None, authority_digest=None):
    value = receipt.to_dict()
    return {"review_receipt_digest": receipt.digest, "subject": value["subject"],
            "reviewer_profile_digest": value["selected_profile_digest"], "policy_digest": "f" * 64,
            "authority_id": authority_id or str(uuid.uuid4()), "authority_digest": authority_digest or "e" * 64,
            "assessor": {"principal": str(os.getuid()), "role": "delegated_engineering", "human_decision_observed": False},
            "assessed_at": "2026-10-24T12:00:00Z", "gate": "taskalong_local_review_gate", "native_app_approval": False,
            "decisions": [{"fingerprint": item["fingerprint"], "disposition": "not_applicable",
                           "reason": "Generated counterexample: the source and declared regression contradict this allegation.",
                           "supporting_refs": ["source:arithmetic.py:1", "test:test_arithmetic.py"]}
                          for item in value["findings"]]}


class TrialAssessmentTests(unittest.TestCase):
    def example(self):
        values = generated_review([{"path": "arithmetic.py", "line": 1, "body": "Generated required allegation", "blocking": True},
                                   {"path": "arithmetic.py", "line": 1, "body": "Generated optional allegation", "blocking": False}], exit_code=2)
        receipt, evidence = observe_generated(*values)
        return values, receipt, evidence

    def test_complete_per_instance_assessment_is_consistency_only_and_preserves_original_exit2(self):
        from taskalong.trial import LocalReviewAssessment
        from taskalong.trial_control import assessment_consistency
        _, receipt, evidence = self.example()
        original = receipt.to_bytes()
        assessed = LocalReviewAssessment.from_dict(seal_versioned("local-review-assessment", assessment_for(receipt), version="2.8"))
        result = assessment_consistency(receipt, assessed)
        self.assertEqual(result["assessment_status"], "consistent")
        self.assertEqual(result["taskalong_local_review_gate"], "blocked")
        self.assertEqual(result["installation_qualification"], "unknown")
        self.assertIn("reviewer_qualification_unverified", result["reason_codes"])
        self.assertFalse(result["execution_available"])
        self.assertFalse(result["native_app_approval"])
        self.assertEqual(receipt.to_bytes(), original)
        self.assertEqual(receipt.to_dict()["observed"]["exit_code"], 2)

    def test_missing_extra_duplicate_wrong_subject_unfixed_and_partial_cannot_be_assessed_as_consistent(self):
        from taskalong.trial import LocalReviewAssessment
        from taskalong.trial_control import assessment_consistency
        values, receipt, _ = self.example()
        self.assertEqual(assessment_consistency(receipt)["assessment_status"], "awaiting_assessment")
        for defect in ("missing", "extra", "duplicate", "subject", "receipt", "unfixed", "human"):
            with self.subTest(defect=defect):
                value = assessment_for(receipt)
                if defect == "missing": value["decisions"].pop()
                elif defect == "extra": value["decisions"][0]["fingerprint"] = "0" * 64
                elif defect == "duplicate": value["decisions"].append(value["decisions"][0].copy())
                elif defect == "subject": value["subject"] = value["subject"] | {"candidate_commit": "e" * 40}
                elif defect == "receipt": value["review_receipt_digest"] = "0" * 64
                elif defect == "unfixed": value["decisions"][1]["disposition"] = "unfixed_defect"
                elif defect == "human": value["assessor"]["human_decision_observed"] = True
                try:
                    assessed = LocalReviewAssessment.from_dict(seal_versioned("local-review-assessment", value, version="2.8"))
                except TaskAlongError:
                    continue
                self.assertNotEqual(assessment_consistency(receipt, assessed)["assessment_status"], "consistent")
        profile, subject, result, outcome, process = values
        result["coverage"]["fully_reviewed"] = False
        partial, _ = observe_generated(profile, subject, result, outcome, process)
        assessed = LocalReviewAssessment.from_dict(seal_versioned("local-review-assessment", assessment_for(partial), version="2.8"))
        self.assertEqual(assessment_consistency(partial, assessed)["assessment_status"], "blocked")

    def test_trusted_inspection_recomputes_originals_and_requires_current_stored_authority_and_policy(self):
        from taskalong.store import Store, encode
        from taskalong.trial import LocalReviewAssessment
        from taskalong.trial_control import inspect_local_assessment
        from test_antigravity_store import upgrade_through
        from test_trial_contracts import example_trial_spec, reviewer_schema_bytes
        # All generated store rows below are explicit counterexamples. They do
        # not authorize a real production run or install an authorizer API.
        values, receipt, evidence = self.example()
        profile = values[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with Store(root / "state"):
                pass
            with Store.maintenance(root / "state") as store:
                upgrade_through(store, root, 8)
                task = example_trial_spec()
                task["repository"]["base_commit"] = values[1]["base_commit"]
                task["review"]["reviewer_profile_digest"] = profile.digest
                task["review"]["config_digest"] = profile.to_dict()["config_digest"]
                run = store.create_run(seal_versioned("task-spec", task, version="2.8"), "counterexample-only")
                # Match the stored immutable subject by regenerating the raw
                # observation, never rewriting an already sealed receipt.
                subject = values[1] | {"run_id": run["run_id"], "spec_digest": run["spec_digest"]}
                receipt, evidence = observe_generated(profile, subject, values[2], values[3], values[4])
                run["candidate"] = {"base_commit": subject["base_commit"], "commit": subject["candidate_commit"],
                                    "tree": subject["candidate_tree"], "diff_sha256": subject["diff_sha256"]}
                store.db.execute("UPDATE runs SET document=? WHERE run_id=?", (encode(run), run["run_id"]))
                authority = seal("authority", {"authority_id": str(uuid.uuid4()), "run_id": run["run_id"],
                    "source": "local_operator", "principal": str(os.getuid()), "decision": "authorized",
                    "scope": ["verify"], "intent_digest": run["spec_digest"], "issued_at": "2026-10-24T00:00:00Z",
                    "expires_at": "2099-01-01T00:00:00Z", "human_decision_observed": False, "qualification": "production"})
                assessed = LocalReviewAssessment.from_dict(seal_versioned("local-review-assessment", assessment_for(
                    receipt, authority_id=authority["authority_id"], authority_digest=authority["digest"]), version="2.8"))
                for key, raw in evidence._entries:
                    store.put_blob(raw, redaction_version="private-original")
                policy = {"policy_digest": "f" * 64, "revoked_authority_ids": [],
                          "revoked_receipt_digests": [], "revoked_profile_digests": []}
                store.set_setting("trial-review-assessment-policy", policy)
                missing = inspect_local_assessment(store, receipt, profile=profile, schemas=reviewer_schema_bytes(), assessment=assessed)
                self.assertEqual(missing["assessment_status"], "blocked")
                store.add_authority(run["run_id"], authority)
                generic = inspect_local_assessment(store, receipt, profile=profile, schemas=reviewer_schema_bytes(), assessment=assessed)
                self.assertEqual(generic["assessment_status"], "blocked", "Generic task authority cannot authorize this exact assessment")
                from taskalong.trial_control import assessment_intent_digest
                draft = assessment_for(receipt, authority_id=str(uuid.uuid4()))
                draft_document = LocalReviewAssessment.from_dict(seal_versioned("local-review-assessment", draft, version="2.8"))
                authority = seal("authority", authority | {"authority_id": draft["authority_id"],
                                  "intent_digest": assessment_intent_digest(draft_document)})
                assessed = LocalReviewAssessment.from_dict(seal_versioned("local-review-assessment", draft | {
                    "authority_digest": authority["digest"]}, version="2.8"))
                self.assertEqual(assessment_intent_digest(draft_document), assessment_intent_digest(assessed))
                store.add_authority(run["run_id"], authority)
                current = inspect_local_assessment(store, receipt, profile=profile, schemas=reviewer_schema_bytes(), assessment=assessed)
                self.assertEqual(current["assessment_status"], "consistent")
                self.assertEqual(current["taskalong_local_review_gate"], "blocked")
                altered = assessed.to_dict()
                altered["decisions"][0]["reason"] = "A different judgment requires a new exact authorization."
                changed = LocalReviewAssessment.from_dict(seal_versioned("local-review-assessment", altered, version="2.8"))
                refused = inspect_local_assessment(store, receipt, profile=profile, schemas=reviewer_schema_bytes(), assessment=changed)
                self.assertEqual(refused["assessment_status"], "blocked")
                store.set_setting("trial-review-assessment-policy", policy | {"revoked_authority_ids": [authority["authority_id"]]})
                revoked = inspect_local_assessment(store, receipt, profile=profile, schemas=reviewer_schema_bytes(), assessment=assessed)
                self.assertEqual(revoked["assessment_status"], "blocked")


if __name__ == "__main__":
    unittest.main()
