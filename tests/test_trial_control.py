"""Generated offline control documents never grant a live route."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from taskalong.errors import TaskAlongError
from taskalong.validation import digest, seal_versioned
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


class TrialTargetIdentityTests(unittest.TestCase):
    def linked_targets(self, visibility="public"):
        import hashlib
        from taskalong.validation import digest
        intent = example_publish_intent()
        intent["target"].update(expected_visibility=visibility, base_branch="release/1.2",
                                trial_branch="feature/task-1")
        task = example_trial_spec() | {"publication": copy.deepcopy(intent["target"])}
        task["repository"]["base_commit"] = intent["target"]["base_commit"]
        task = seal_versioned("task-spec", task, version="2.8")
        intent["spec_digest"] = task["digest"]
        intent["body_sha256"] = hashlib.sha256(intent["body"].encode()).hexdigest()
        intent = seal_versioned("publish-intent", intent, version="2.8")
        self.assertEqual(task["digest"], digest(task))
        return task, intent

    def observed_target(self, target):
        result = {key: target[key] for key in
                  ("host", "repository_id", "repository_full_name", "base_branch", "base_commit", "trial_branch")}
        result.update(visibility=target["expected_visibility"], archived=False, disabled=False,
                      can_push=True, branch_conflict=False, pr_conflict=False)
        return result

    def valid_target_controls(self):
        from taskalong.trial import TrialTaskSpec, TrialPublishIntent, validate_publish_target
        for visibility in ("public", "private"):
            task, intent = self.linked_targets(visibility)
            immutable_task = TrialTaskSpec.from_dict(task)
            immutable_intent = TrialPublishIntent.from_dict(intent)
            self.assertEqual(validate_publish_target(immutable_intent, immutable_task,
                             observed_target=self.observed_target(intent["target"])), immutable_intent)
        no_publication = seal_versioned("task-spec", example_trial_spec() | {"publication": None}, version="2.8")
        self.assertIsNone(TrialTaskSpec.from_dict(no_publication).to_dict()["publication"])

    def assert_invalid_target(self, task, intent, *, case):
        from taskalong.trial import TrialTaskSpec, TrialPublishIntent, validate_publish_target
        from taskalong.validation import digest
        task["digest"] = digest(task)
        intent["spec_digest"] = task["digest"]
        intent["digest"] = digest(intent)
        for name, reader, document in (("task-spec", TrialTaskSpec, task),
                                       ("publish-intent", TrialPublishIntent, intent)):
            with self.subTest(case=case, reader=name):
                before = copy.deepcopy(document)
                with self.assertRaises(TaskAlongError) as refused:
                    reader.from_dict(document)
                self.assertEqual(refused.exception.code, "trial_target_invalid")
                self.assertEqual(document, before)
                with self.assertRaises(TaskAlongError) as sealing:
                    seal_versioned(name, document, version="2.8")
                self.assertEqual(sealing.exception.code, "trial_target_invalid")
        with self.subTest(case=case, boundary="linked-target"):
            with self.assertRaises(TaskAlongError) as refused:
                validate_publish_target(TrialPublishIntent.from_dict(intent), TrialTaskSpec.from_dict(task),
                                        observed_target=self.observed_target(intent["target"]))
            self.assertEqual(refused.exception.code, "trial_target_invalid")

    def test_trial_targets_require_distinct_base_and_trial_branches(self):
        with patch("subprocess.Popen", side_effect=AssertionError("Target reading cannot launch")) as spawn, \
                patch("socket.socket", side_effect=AssertionError("Target reading cannot connect")) as sockets:
            self.valid_target_controls()
            task, intent = self.linked_targets()
            for target in (task["publication"], intent["target"]):
                target["trial_branch"] = target["base_branch"]
            self.assert_invalid_target(task, intent, case="same-branch")
            self.assertEqual((spawn.call_count, sockets.call_count), (0, 0))

    def test_trial_targets_refuse_ascii_controls_without_normalization(self):
        with patch("subprocess.Popen", side_effect=AssertionError("Target reading cannot launch")) as spawn, \
                patch("socket.socket", side_effect=AssertionError("Target reading cannot connect")) as sockets:
            self.valid_target_controls()
            for control in ("\n", "\t", "\x00", "\x7f"):
                task, intent = self.linked_targets()
                for target in (task["publication"], intent["target"]):
                    target["base_branch"] += control
                self.assert_invalid_target(task, intent, case="control-" + str(ord(control)))
            self.assertEqual((spawn.call_count, sockets.call_count), (0, 0))


class TrialTimeConsumerTests(unittest.TestCase):
    def assert_typed(self, call, code):
        with self.assertRaises(TaskAlongError) as refused:
            call()
        self.assertEqual(refused.exception.code, code)

    def test_inspection_uses_the_checked_suffix_and_preserves_original_time(self):
        from taskalong.trial_control import inspect_trial_route
        with patch("subprocess.Popen", side_effect=AssertionError("No process")) as spawn, \
                patch("socket.socket", side_effect=AssertionError("No network")) as sockets:
            for stamp in ("2026-10-24T12:00:00Z", "2026-10-24Z12:00:00Z"):
                with self.subTest(valid=stamp):
                    result = inspect_trial_route(at=stamp)
                    self.assertEqual(result["at"], stamp)
                    self.assertEqual(result["missing"], ["activation", "driver_config", "reviewer_profile", "task"])
                    self.assertFalse(result["activation_eligible"])
                    self.assertFalse(result["execution_available"])
                    self.assertFalse(result["production_dispatch_allowed"])
            for stamp in ("2026-10-24Z", "2026-10-24T12:00:00", "2026-10-24T12:00:00+00:00",
                          "not-timeZ", None, 1):
                with self.subTest(invalid=stamp):
                    self.assert_typed(lambda: inspect_trial_route(at=stamp), "trial_inspection_invalid")
            self.assertEqual((spawn.call_count, sockets.call_count), (0, 0))

    def test_activation_readers_and_sealing_share_checked_time_and_window_order(self):
        from taskalong.trial import TrialActivation
        from taskalong.trial_control import inspect_trial_route
        value = example_activation()
        value.update(valid_from="2026-10-24T12:00:00Z", valid_until="2026-10-24T13:00:00Z")
        original = seal_versioned("trial-activation", value, version="2.8")
        with patch("subprocess.Popen", side_effect=AssertionError("No process")) as spawn, \
                patch("socket.socket", side_effect=AssertionError("No network")) as sockets:
            for fields in ((), ("valid_from",), ("valid_until",), ("valid_from", "valid_until")):
                with self.subTest(valid_fields=fields):
                    document = copy.deepcopy(original)
                    for field in fields:
                        document[field] = document[field].replace("T", "Z", 1)
                    document["digest"] = digest(document)
                    before = copy.deepcopy(document)
                    record = TrialActivation.from_dict(document)
                    self.assertEqual(record.to_dict(), before)
                    self.assertEqual(seal_versioned("trial-activation", document, version="2.8"), before)
                    result = inspect_trial_route(activation=record, at="2026-10-24Z12:30:00Z")
                    self.assertNotIn("activation_expired", result["reason_codes"])
                    self.assertFalse(result["execution_available"])
                    expired = inspect_trial_route(activation=record, at="2026-10-24T13:00:00Z")
                    self.assertIn("activation_expired", expired["reason_codes"])
                    self.assertEqual(document, before)
                    self.assertEqual(record.to_dict(), before)
            for field in ("valid_from", "valid_until"):
                for stamp in ("2026-10-24Z", "2026-10-24T12:00:00", "not-timeZ", None, 1):
                    document = copy.deepcopy(original)
                    document[field] = stamp
                    document["digest"] = digest(document)
                    for boundary, call in (("reader", lambda: TrialActivation.from_dict(document)),
                                           ("sealer", lambda: seal_versioned("trial-activation", document, version="2.8"))):
                        with self.subTest(field=field, stamp=stamp, boundary=boundary):
                            self.assert_typed(call, "schema_validation")
            reversed_window = copy.deepcopy(original)
            reversed_window.update(valid_from="2026-10-24Z13:00:00Z", valid_until="2026-10-24Z12:00:00Z")
            reversed_window["digest"] = digest(reversed_window)
            for boundary, call in (("reader", lambda: TrialActivation.from_dict(reversed_window)),
                                   ("sealer", lambda: seal_versioned("trial-activation", reversed_window, version="2.8"))):
                with self.subTest(reversed_boundary=boundary):
                    self.assert_typed(call, "trial_activation_invalid")
            self.assertEqual((spawn.call_count, sockets.call_count), (0, 0))



if __name__ == "__main__":
    unittest.main()
