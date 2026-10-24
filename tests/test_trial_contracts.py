"""Generated E1 contract counterexamples; no actual route or inference is qualified."""
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import uuid
import unittest
from importlib import resources
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.validation import schema, schema_names, seal_versioned


def example_trial_config():
    """Hypothetical closed data, never an observed or authorized installation."""
    return {
        "driver_id": "codex-real-start-1", "harness": "codex-cli", "cli_version": "0.163.0",
        "projection": "codex-real-start/1", "qualification": "production",
        "registration": "operator_registered_trial",
        "installation_digest": "a" * 64, "provider_profile_digest": "b" * 64,
        "binding_digest": "c" * 64,
        "executable": {"path": "/opt/taskalong/example-codex", "sha256": "d" * 64},
        "credential_ref": "example-account-reference", "expected_reported_model": "example-model",
        "policy_digests": {"instructions": "e" * 64, "tools": "f" * 64,
                           "worker_sandbox": "1" * 64, "check_binding": "2" * 64},
        "host": {"backend_id": "linux-child-subreaper", "backend_version": "example-exact-1",
                 "host_digest": "3" * 64, "runtime_closure_digest": "4" * 64},
        "launch": {"operation": "start", "session_policy": "fresh",
                   "result_contract": "codex-exec-0.163.0-json/1",
                   "protective_policy": "preserve-managed-rules"},
    }


def example_trial_spec():
    from test_contracts import example_spec
    value = example_spec()
    value.update(schema_version="2.8", qualification="production", task_id="example-e1-intent",
                 goal="Correct an agreed bounded bug; this generated document is not a live trial.")
    value["execution"] = {"binding_digest": "c" * 64,
                          "driver_config_digest": seal_versioned("driver-config", example_trial_config(), version="2.8")["digest"]}
    value["permissions"]["inference_destination_id"] = "example-provider"
    value["review"] = {"required": True, "integration": "reviewsensei",
                       "contract": "reviewsensei-installed-0.8.12/full-diff-v1",
                       "reviewer_profile_digest": "5" * 64, "config_digest": "6" * 64,
                       "require_full_coverage": True}
    value["recovery"] = {"policy": "completed-worker-before-verify/1",
                         "repeat_completed_worker": False, "reset_budget": False}
    return value


def example_trial_packet():
    task = seal_versioned("task-spec", example_trial_spec(), version="2.8")
    return seal_versioned("worker-packet", {
        "packet_id": str(uuid.uuid4()), "run_id": str(uuid.uuid4()), "attempt_id": str(uuid.uuid4()),
        "spec_digest": task["digest"], "goal": task["goal"], "non_goals": task["non_goals"],
        "scope": task["scope"], "checks": task["checks"],
        "bindings": {"base_commit": task["repository"]["base_commit"], "initial_head": "a" * 40,
                     "initial_content_digest": "7" * 64, "workspace_id": str(uuid.uuid4()),
                     "lease_generation": 1, "driver_config_digest": task["execution"]["driver_config_digest"],
                     "provider_profile_digest": "b" * 64},
        "remaining_budget": task["budget"], "qualification": "production", "extensions": {},
        "result_schema_id": "urn:taskalong:schema:v2.8:worker-result",
        "binding_digest": task["execution"]["binding_digest"], "admission_digest": "8" * 64,
        "activation_digest": "9" * 64, "reviewer_profile_digest": task["review"]["reviewer_profile_digest"],
        "projection": "codex-real-start/1", "session_policy": "fresh",
    }, version="2.8")


def example_trial_result(packet):
    return {"kind": "worker_result", "schema_version": "2.8", "extensions": {},
            "result_id": str(uuid.uuid4()), "packet_id": packet["packet_id"],
            "packet_digest": packet["digest"], "run_id": packet["run_id"],
            "attempt_id": packet["attempt_id"], "spec_digest": packet["spec_digest"],
            "driver_config_digest": packet["bindings"]["driver_config_digest"],
            "provider_profile_digest": packet["bindings"]["provider_profile_digest"],
            "status": "completed", "changed_files": [], "command_claims": [],
            "summary": "Generated result contract example; no actual worker ran.",
            "blockers": [], "deviations": [], "residual_risks": [], "qualification": "production"}


def reviewer_schema_bytes():
    root = Path(__file__).parent / "fixtures/reviewsensei-0.8.12"
    return {name: (root / (name + ".schema.json")).read_bytes()
            for name in ("review-result", "run-outcome", "review-transaction", "coverage-manifest")}


def example_reviewer_profile():
    return {
        "profile_id": "example-independent-reviewer",
        "contract": "reviewsensei-installed-0.8.12/full-diff-v1", "version": "0.8.12",
        "published_wheel_sha256": "ed13addc413752ba968564550be7e300c1c69d3ccd9e4a832782a4f7cb12b8c3",
        "entrypoint": {"path": "/opt/taskalong/example/review-sensei", "sha256": "a" * 64},
        "interpreter": {"path": "/opt/taskalong/example/python", "sha256": "b" * 64},
        "import_root": "/opt/taskalong/example/site-packages/review_sensei",
        "runtime_closure_digest": "c" * 64, "import_closure_digest": "d" * 64,
        "backend": "cloud-ollama", "expected_reported_provider": "ollama",
        "expected_model": "example-review-model", "credential_ref": "example-review-account",
        "config_digest": "e" * 64, "effective_context_digest": "f" * 64,
        "allowed_read_roots": ["/opt/taskalong/example/workspace"],
        "allowed_context_roots": ["/opt/taskalong/example/approved-context"],
        "invocation": {"diff_scope": "base-to-candidate", "format": "json", "exit_semantics": "review",
                       "learning_proposals": False, "fixture_response": False,
                       "custom_endpoint_override": False, "unqualified_profile_override": False},
        "schema_digests": {name: hashlib.sha256(raw).hexdigest() for name, raw in reviewer_schema_bytes().items()},
    }


class TrialDriverContractTests(unittest.TestCase):
    def test_family_inventory_and_all_inherited_resource_bytes_remain_explicit(self):
        from jsonschema import Draft202012Validator
        expected = {"task-spec", "driver-config", "worker-packet", "worker-result", "packet-projection",
                    "reviewer-profile", "trial-activation", "publish-intent", "review-receipt", "local-review-assessment"}
        self.assertEqual(set(schema_names(version="2.8")), expected)
        for name in expected:
            Draft202012Validator.check_schema(schema(name, version="2.8"))
        retained = json.loads((Path(__file__).parent / "fixtures/pre-e1-resources.json").read_bytes())
        self.assertEqual(len(retained["resources"]), 54)
        root = resources.files("taskalong.resources")
        for name, wanted in retained["resources"].items():
            with self.subTest(resource=name):
                raw = root.joinpath(name.removeprefix("src/taskalong/resources/")).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), wanted)
    def test_exact_immutable_start_description_refuses_fixture_and_unbounded_options_without_effects(self):
        self.assertIn("driver-config", schema_names(version="2.8"))
        from taskalong.trial import TrialDriverConfig
        with patch("subprocess.Popen", side_effect=AssertionError("Reading cannot launch")) as spawn, \
                patch("socket.socket", side_effect=AssertionError("Reading cannot connect")) as sockets:
            original = example_trial_config()
            sealed = seal_versioned("driver-config", original, version="2.8")
            config = TrialDriverConfig.from_dict(sealed)
            before = config.to_bytes()
            sealed["host"]["backend_version"] = "changed"
            config.to_dict()["launch"]["operation"] = "resume"
            self.assertEqual(config.to_bytes(), before)
            with self.assertRaises(FrozenInstanceError):
                config._canonical = b"{}"
            for section, key, value in [
                (None, "qualification", "synthetic"), (None, "cli_version", "latest"),
                (None, "expected_reported_model", "*"), (None, "driver_id", "codex-cli"),
                ("launch", "operation", "resume"), ("launch", "argv", ["--dangerously-bypass-approvals-and-sandbox"]),
                ("launch", "environment", {"EXAMPLE": "value"}),
                ("launch", "protective_policy", "ignore-managed-rules"),
            ]:
                with self.subTest(section=section, key=key):
                    changed = example_trial_config()
                    (changed if section is None else changed[section])[key] = value
                    with self.assertRaises(TaskAlongError) as failure:
                        seal_versioned("driver-config", changed, version="2.8")
                    self.assertEqual(failure.exception.code, "schema_validation")
            self.assertEqual((spawn.call_count, sockets.call_count), (0, 0))


class TrialTaskContractTests(unittest.TestCase):
    def test_explicit_task_keeps_core_check_invariants_and_requires_real_review_and_durable_recovery(self):
        from taskalong.execution import read_task_spec
        with patch("subprocess.Popen", side_effect=AssertionError("Intent cannot launch")) as spawn:
            value = seal_versioned("task-spec", example_trial_spec(), version="2.8")
            task = read_task_spec(value)
            self.assertEqual(task.to_dict(), value)
            before = task.to_bytes()
            task.to_dict()["checks"][0]["argv"].append("different")
            self.assertEqual(task.to_bytes(), before)
            for section, key, replacement in [
                (None, "qualification", "synthetic"), ("review", "contract", "0.8.8/v1"),
                ("review", "require_full_coverage", False), ("recovery", "policy", "native-resume"),
                ("recovery", "repeat_completed_worker", True), ("recovery", "reset_budget", True),
            ]:
                with self.subTest(section=section, key=key), self.assertRaises(TaskAlongError):
                    changed = example_trial_spec()
                    (changed if section is None else changed[section])[key] = replacement
                    seal_versioned("task-spec", changed, version="2.8")
            for defect in ("shell", "scope", "criteria", "budget"):
                with self.subTest(defect=defect), self.assertRaises(TaskAlongError):
                    changed = example_trial_spec()
                    if defect == "shell":
                        changed["checks"][0]["argv"] = ["sh", "-c", "true"]
                    elif defect == "scope":
                        changed["scope"]["files"] = ["../outside.py"]
                    elif defect == "criteria":
                        changed["criteria"][0]["check_ids"] = ["missing"]
                    else:
                        changed["budget"]["total_active_seconds"] = 1
                    seal_versioned("task-spec", changed, version="2.8")
            self.assertEqual(spawn.call_count, 0)


class TrialResultContractTests(unittest.TestCase):
    def test_production_result_has_its_own_family_and_all_exact_packet_subjects_are_required(self):
        self.assertEqual(schema("worker-result", version="2.5")["properties"]["qualification"],
                         {"const": "synthetic"})
        self.assertEqual(schema("worker-result", version="2.8")["properties"]["qualification"],
                         {"const": "production"})
        from taskalong.trial import TrialDriverConfig, TrialTaskSpec, TrialWorkerPacket, TrialWorkerResult, validate_linked_result
        packet = TrialWorkerPacket.from_dict(example_trial_packet())
        raw = example_trial_result(packet.to_dict())
        result = TrialWorkerResult.from_dict(raw)
        context = {"task": TrialTaskSpec.from_dict(seal_versioned("task-spec", example_trial_spec(), version="2.8")),
                   "driver_config": TrialDriverConfig.from_dict(seal_versioned("driver-config", example_trial_config(), version="2.8")),
                   "provider_profile_digest": "b" * 64, "run_id": packet.to_dict()["run_id"],
                   "attempt_id": packet.to_dict()["attempt_id"], "lease_generation": 1}
        with patch("subprocess.Popen", side_effect=AssertionError("Linked validation cannot launch")) as spawn, \
                patch("socket.socket", side_effect=AssertionError("Linked validation cannot connect")) as sockets:
            self.assertEqual(validate_linked_result(packet, result, **context).to_bytes(), result.to_bytes())
            for key in ("packet_id", "packet_digest", "run_id", "attempt_id", "spec_digest",
                        "driver_config_digest", "provider_profile_digest"):
                changed = dict(raw)
                changed[key] = str(uuid.uuid4()) if key.endswith("_id") else "0" * 64
                with self.subTest(key=key), self.assertRaises(TaskAlongError) as failure:
                    validate_linked_result(packet, TrialWorkerResult.from_dict(changed), **context)
                self.assertEqual(failure.exception.code, "trial_result_mismatch")
            for change in ({"schema_version": "2.5", "qualification": "synthetic"},
                           {"schema_version": "1.0"}, {"qualification": "synthetic"},
                           {"reported_model": "invented"}):
                with self.subTest(change=change), self.assertRaises(TaskAlongError):
                    TrialWorkerResult.from_dict(raw | change)
            for field, replacement in (("run_id", str(uuid.uuid4())), ("attempt_id", str(uuid.uuid4())),
                                       ("lease_generation", 2), ("provider_profile_digest", "0" * 64)):
                with self.subTest(context=field), self.assertRaises(TaskAlongError):
                    validate_linked_result(packet, result, **(context | {field: replacement}))
            self.assertEqual((spawn.call_count, sockets.call_count), (0, 0))


class TrialProjectionContractTests(unittest.TestCase):
    def test_projection_binds_original_canonical_wire_and_lease_without_digest_cycles(self):
        self.assertIn("packet-projection", schema_names(version="2.8"))
        from taskalong.trial import TrialPacketProjection, TrialWorkerPacket, validate_projection
        packet = TrialWorkerPacket.from_dict(example_trial_packet())
        p = packet.to_dict()
        wire = packet.to_bytes()
        fields = {"run_id": p["run_id"], "attempt_id": p["attempt_id"], "spec_digest": p["spec_digest"],
                  "canonical_packet_digest": packet.digest, "wire_packet_digest": hashlib.sha256(wire).hexdigest(),
                  "binding_digest": p["binding_digest"], "admission_digest": p["admission_digest"],
                  "activation_digest": p["activation_digest"], "reviewer_profile_digest": p["reviewer_profile_digest"],
                  "registration_digest": "a" * 64, "projection": "codex-real-start/1",
                  "driver_config_digest": p["bindings"]["driver_config_digest"],
                  "provider_profile_digest": p["bindings"]["provider_profile_digest"],
                  "lease_generation": p["bindings"]["lease_generation"],
                  "session_policy": "fresh", "input_framing": "canonical-packet-json/1"}
        projection = TrialPacketProjection.from_dict(seal_versioned("packet-projection", fields, version="2.8"))
        context = {"wire_bytes": wire, "registration_digest": "a" * 64,
                   "run_id": p["run_id"], "attempt_id": p["attempt_id"], "lease_generation": 1}
        with patch("subprocess.Popen", side_effect=AssertionError("Projection cannot launch")) as spawn:
            self.assertEqual(validate_projection(projection, packet, **context).to_bytes(), projection.to_bytes())
            for key in ("canonical_packet_digest", "activation_digest", "reviewer_profile_digest",
                        "wire_packet_digest", "registration_digest", "driver_config_digest"):
                with self.subTest(key=key), self.assertRaises(TaskAlongError) as failure:
                    changed = seal_versioned("packet-projection", fields | {key: "0" * 64}, version="2.8")
                    validate_projection(TrialPacketProjection.from_dict(changed), packet, **context)
                self.assertEqual(failure.exception.code, "trial_projection_mismatch")
            altered_wire = wire + b" "
            updated = TrialPacketProjection.from_dict(seal_versioned("packet-projection", fields | {
                "wire_packet_digest": hashlib.sha256(altered_wire).hexdigest()}, version="2.8"))
            with self.assertRaises(TaskAlongError):
                validate_projection(updated, packet, **(context | {"wire_bytes": altered_wire}))
            with self.assertRaises(TaskAlongError):
                seal_versioned("worker-packet", p | {"projection_digest": projection.digest}, version="2.8")
            self.assertEqual(packet.to_bytes(), wire)
            self.assertEqual(spawn.call_count, 0)


class TrialReviewerProfileTests(unittest.TestCase):
    def test_exact_released_reviewer_keeps_backend_distinct_and_refuses_fixture_or_bypass(self):
        self.assertIn("reviewer-profile", schema_names(version="2.8"))
        from taskalong.trial import TrialReviewerProfile
        with patch("subprocess.Popen", side_effect=AssertionError("Profile inspection cannot launch")) as spawn, \
                patch("socket.socket", side_effect=AssertionError("Profile inspection cannot connect")) as sockets:
            value = seal_versioned("reviewer-profile", example_reviewer_profile(), version="2.8")
            profile = TrialReviewerProfile.from_dict(value)
            self.assertEqual(profile.to_dict()["backend"], "cloud-ollama")
            self.assertEqual(profile.to_dict()["expected_reported_provider"], "ollama")
            before = profile.to_bytes()
            profile.to_dict()["allowed_read_roots"].append("/unapproved")
            self.assertEqual(profile.to_bytes(), before)
            for key, replacement in (("version", "0.8.8"), ("version", "latest"), ("backend", "fixture"),
                                     ("expected_reported_provider", "openrouter"), ("expected_model", "*"),
                                     ("published_wheel_sha256", "0" * 64), ("argv", ["--allow-unqualified-profile"])):
                with self.subTest(key=key, replacement=replacement), self.assertRaises(TaskAlongError):
                    seal_versioned("reviewer-profile", example_reviewer_profile() | {key: replacement}, version="2.8")
            for key in ("fixture_response", "custom_endpoint_override", "unqualified_profile_override", "learning_proposals"):
                changed = example_reviewer_profile()
                changed["invocation"][key] = True
                with self.subTest(invocation=key), self.assertRaises(TaskAlongError):
                    seal_versioned("reviewer-profile", changed, version="2.8")
            changed = example_reviewer_profile()
            changed["schema_digests"]["run-outcome"] = "0" * 64
            with self.assertRaises(TaskAlongError):
                seal_versioned("reviewer-profile", changed, version="2.8")
            self.assertEqual((spawn.call_count, sockets.call_count), (0, 0))


if __name__ == "__main__":
    unittest.main()
