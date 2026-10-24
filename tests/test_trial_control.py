"""Generated offline control documents never grant a live route."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from taskalong.errors import TaskAlongError
from taskalong.validation import seal_versioned
from test_trial_contracts import example_trial_config, example_trial_spec


def example_activation():
    spec = seal_versioned("task-spec", example_trial_spec(), version="2.8")
    config = seal_versioned("driver-config", example_trial_config(), version="2.8")
    return {"activation_id": str(uuid.uuid4()), "issuer_id": "example-assessor",
            "authorization_ref": "1" * 64, "nonce": str(uuid.uuid4()),
            "subject": {"run_id": str(uuid.uuid4()), "spec_digest": spec["digest"],
                        "repository_registration_id": spec["repository"]["registration_id"],
                        "base_commit": spec["repository"]["base_commit"],
                        "scope_digest": "2" * 64, "binding_digest": config["binding_digest"],
                        "driver_config_digest": config["digest"],
                        "provider_profile_digest": config["provider_profile_digest"],
                        "reviewer_profile_digest": spec["review"]["reviewer_profile_digest"],
                        "host_digest": config["host"]["host_digest"],
                        "runtime_closure_digest": config["host"]["runtime_closure_digest"],
                        "policy_digest": "3" * 64},
            "qualification_decision_digests": ["4" * 64], "raw_evidence_digests": ["5" * 64],
            "allowed_effects": ["execute", "verify"], "limits": spec["budget"],
            "valid_from": "2026-10-24T00:00:00Z", "valid_until": "2026-10-25T00:00:00Z"}


def example_publish_intent():
    target = {"host": "github.com", "repository_id": 123, "repository_full_name": "example/trial",
              "base_branch": "main", "title": "Fix the agreed example bug", "body_template_digest": "0" * 64}
    target.update(expected_visibility="public", base_commit="a" * 40,
                  trial_branch="taskalong/example-e1", draft_only=True, final_merge_gate="user",
                  disclosure_digest="1" * 64, authorization_ref="2" * 64)
    return {"run_id": str(uuid.uuid4()), "spec_digest": "3" * 64,
            "candidate_commit": "b" * 40, "candidate_tree": "c" * 40, "diff_sha256": "4" * 64,
            "target": target, "title": target["title"], "body": "Generated safe draft explanation.",
            "body_sha256": "5" * 64, "local_assessment_digest": "6" * 64,
            "authorization_ref": target["authorization_ref"], "draft_only": True, "final_merge_gate": "user"}


class TrialControlContractTests(unittest.TestCase):
    def test_historical_registration_is_fenced_and_inspection_never_installs_a_route(self):
        from taskalong.store import Store
        from taskalong.trial import TrialActivation, TrialDriverConfig, TrialTaskSpec
        from taskalong.trial_control import inspect_trial_route, register_trial_document
        from test_antigravity_store import upgrade_through
        config = TrialDriverConfig.from_dict(seal_versioned("driver-config", example_trial_config(), version="2.8"))
        task = TrialTaskSpec.from_dict(seal_versioned("task-spec", example_trial_spec(), version="2.8"))
        activation = TrialActivation.from_dict(seal_versioned("trial-activation", example_activation(), version="2.8"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with Store(root / "state") as store:
                before = list(store.db.iterdump())
                with self.assertRaises(TaskAlongError) as old:
                    register_trial_document(store, config, operation_key="unfenced")
                self.assertEqual(old.exception.code, "store_upgrade_required")
                self.assertEqual(list(store.db.iterdump()), before)
            with Store.maintenance(root / "state") as store:
                upgrade_through(store, root, 8)
                with patch("subprocess.Popen", side_effect=AssertionError("No launcher")), \
                        patch("socket.socket", side_effect=AssertionError("No network")):
                    result = register_trial_document(store, config, operation_key="e1-config")
                    self.assertTrue(result["historical_only"])
                    self.assertEqual(register_trial_document(store, config, operation_key="e1-config"), result)
                    self.assertEqual(store.document_history("driver_config", config.digest), (config,))
                    self.assertIsNone(store.setting("execution-trust:" + config.to_dict()["binding_digest"]))
                    before = list(store.db.iterdump())
                    incomplete = inspect_trial_route(at="2026-10-24T12:00:00Z")
                    inspected = inspect_trial_route(task=task, driver_config=config, activation=activation,
                                                    at="2026-10-24T12:00:00Z")
                    expired = inspect_trial_route(task=task, driver_config=config, activation=activation,
                                                  at="2026-10-25T12:00:00Z")
                self.assertIn("task", incomplete["missing"])
                self.assertIn("activation_expired", expired["reason_codes"])
                self.assertFalse(inspected["execution_available"])
                self.assertFalse(inspected["activation_eligible"])
                self.assertIn("trial_runtime_unqualified", inspected["reason_codes"])
                self.assertEqual(list(store.db.iterdump()), before)

    def test_activation_is_exact_bounded_intent_not_registration_or_runtime_authority(self):
        from taskalong.trial import TrialActivation
        with patch("subprocess.Popen", side_effect=AssertionError("must not launch")), \
                patch("socket.socket", side_effect=AssertionError("must not connect")):
            value = example_activation()
            sealed = seal_versioned("trial-activation", value, version="2.8")
            record = TrialActivation.from_dict(sealed)
            self.assertEqual(record.to_dict(), sealed)
            for key, replacement in (("valid_until", value["valid_from"]),
                                     ("allowed_effects", ["remote_cancel"]),
                                     ("raw_evidence_digests", []), ("issuer_id", "*"),
                                     ("production_dispatch_allowed", True)):
                with self.subTest(key=key), self.assertRaises(TaskAlongError):
                    seal_versioned("trial-activation", value | {key: replacement}, version="2.8")

    def test_publish_intent_binds_exact_body_and_target_without_any_publication(self):
        import hashlib
        from taskalong.trial import TrialPublishIntent
        value = example_publish_intent()
        value["body_sha256"] = hashlib.sha256(value["body"].encode()).hexdigest()
        record = TrialPublishIntent.from_dict(seal_versioned("publish-intent", value, version="2.8"))
        self.assertEqual(record.to_dict()["target"]["expected_visibility"], "public")
        for key, replacement in (("body", "Changed without renewed binding"),
                                 ("title", "Changed title"), ("draft_only", False),
                                 ("final_merge_gate", "agent"), ("authorization_ref", "f" * 64)):
            with self.subTest(key=key), self.assertRaises(TaskAlongError):
                TrialPublishIntent.from_dict(seal_versioned("publish-intent", value | {key: replacement}, version="2.8"))

    def test_public_private_target_drift_and_conflicts_refuse_without_transport(self):
        import hashlib
        from taskalong.trial import TrialPublishIntent, TrialTaskSpec, validate_publish_target
        value = example_publish_intent()
        task = TrialTaskSpec.from_dict(seal_versioned("task-spec", example_trial_spec() | {"publication": value["target"]}, version="2.8"))
        value["spec_digest"] = task.digest
        value["body_sha256"] = hashlib.sha256(value["body"].encode()).hexdigest()
        intent = TrialPublishIntent.from_dict(seal_versioned("publish-intent", value, version="2.8"))
        target = value["target"]
        observed = {key: target[key] for key in ("host", "repository_id", "repository_full_name", "base_branch", "base_commit", "trial_branch")}
        observed.update(visibility="public", archived=False, disabled=False, can_push=True, branch_conflict=False, pr_conflict=False)
        with patch("subprocess.Popen", side_effect=AssertionError("No transport")), patch("socket.socket", side_effect=AssertionError("No network")):
            self.assertEqual(validate_publish_target(intent, task, observed_target=observed), intent)
            for key, replacement in (("visibility", "private"), ("repository_id", 124), ("base_commit", "f" * 40),
                                     ("archived", True), ("disabled", True), ("can_push", False),
                                     ("branch_conflict", True), ("pr_conflict", True)):
                with self.subTest(key=key), self.assertRaises(TaskAlongError):
                    validate_publish_target(intent, task, observed_target=observed | {key: replacement})


if __name__ == "__main__":
    unittest.main()
