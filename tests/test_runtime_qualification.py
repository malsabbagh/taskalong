"""Qualification measurements are bounded data, never execution authority."""
import copy
import dataclasses
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes


HOST_CASES = [
    "permitted-read", "permitted-write", "bounded-capture", "predispatch-tool-denial",
    "owned-completion", "closed-gate-cancel", "running-cancel",
]


def sealed(document):
    value = copy.deepcopy(document)
    value.pop("digest", None)
    value["digest"] = hashlib.sha256(canonical_bytes(value)).hexdigest()
    return value


def original_plan():
    return sealed({
        "kind": "runtime_experiment_plan", "format_version": "1.0",
        "campaign_id": "285e6f63-c1fd-493c-a152-20f64d3f1fa8",
        "stage": "model-free", "profile": "owned-host-canaries-v1",
        "package_origin": "source", "inference": "never",
        "runner_digest": "a" * 64, "helper_digest": "b" * 64,
        "test_inventory_digest": "c" * 64,
        "subject": {"kind": "host-experiment", "interpreter_digest": "d" * 64,
                    "backend_id": "darwin-kqueue-no-fork", "backend_digest": "e" * 64,
                    "context_digest": "f" * 64, "package_digest": "0" * 64,
                    "host_digest": "1" * 64},
        "bounds": {"inventory_ms": 10000, "case_ms": 5000,
                   "capture_bytes": 65536, "execution_ms": 60000},
        "case_ids": HOST_CASES,
    })


def private_ref(data, media="application/json"):
    return {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data),
            "media_type": media, "classification": "private"}


def qualifier_context():
    """The frozen installed harness explicitly supplies its actual artifact."""
    tests = Path(__file__).absolute().parent
    if tests.name == "installed-tests":
        return tests.parent / "tools" / "qualify_runtime.py", [
            "--package-origin", "installed", "--artifact-inventory",
            str(tests.parent / "runtime-artifact-inventory.json")]
    return tests.parent / "tools" / "qualify_runtime.py", ["--package-origin", "source"]


def original_incomplete_proof():
    """Original synthetic data; this is deliberately not a successful experiment."""
    plan = original_plan()
    context = canonical_bytes({"campaign_id": plan["campaign_id"], "nonce": "9" * 64, "payload": "original payload\n"})
    plan["subject"]["context_digest"] = hashlib.sha256(context).hexdigest()
    plan = sealed(plan)
    inventory = canonical_bytes({"subject": plan["subject"], "closure_complete": False, "measurements": None,
                                 "unmeasured_components": ["Original test data, not host measurements."]})
    inventory_ref, context_ref = private_ref(inventory), private_ref(context)
    cases = [{"id": name, "campaign_id": plan["campaign_id"], "verdict": "not_run",
              "capability": "unknown", "reason": "not_run_after_failure", "dispatch": "not_sent",
              "process_ref": None, "capture_refs": None, "observation_ref": None} for name in HOST_CASES]
    manifest = sealed({"kind": "runtime_qualification_manifest", "format_version": "1.0",
                       "plan": plan, "producer_id": "original-synthetic-producer",
                       "inventory_ref": inventory_ref, "context_ref": context_ref,
                       "started_at": "2026-10-24T00:00:00Z", "finished_at": "2026-10-24T00:00:01Z",
                       "execution_ms": 0, "finalization_ms": 1,
                       "observed_route": {"model": None, "account": None, "route": None,
                                          "reason": "not_requested_model_free"},
                       "cases": cases, "complete": False,
                       "first_error": {"case_id": None, "code": "inventory_failed"},
                       "quarantined": False, "inputs_rechecked": False})
    return manifest, {inventory_ref["sha256"]: inventory, context_ref["sha256"]: context}


class RuntimePlanContractTests(unittest.TestCase):
    def test_existing_schema_bytes_names_sql_and_license_identity_are_preserved(self):
        from importlib import resources
        from taskalong.validation import schema_names

        identities = json.loads((Path(__file__).parent / "fixtures/runtime-prior-contracts.json").read_bytes())
        self.assertEqual(len(identities["resources"]), 53)
        root = resources.files("taskalong.resources")
        for relative, expected in identities["resources"].items():
            with self.subTest(resource=relative):
                self.assertEqual(hashlib.sha256(root.joinpath(relative).read_bytes()).hexdigest(), expected)
        for version, names in identities["schema_names"].items():
            self.assertEqual(list(schema_names(version=version)), names)
        if qualifier_context()[1][1] == "source":
            license_path = Path(__file__).parent.parent / "LICENSE"
        else:
            import importlib.metadata
            license_path = Path(importlib.metadata.distribution("taskalong").locate_file(
                "taskalong-0.1.0a1.dist-info/licenses/LICENSE"))
        self.assertEqual(hashlib.sha256(license_path.read_bytes()).hexdigest(), identities["license_sha256"])
        with self.assertRaises(TaskAlongError):
            schema_names(version="2.7")
    def test_explicit_plan_is_immutable_data_without_process_or_network_effects(self):
        from taskalong.runtime_qualification import ExperimentPlan

        source = original_plan()
        with patch("subprocess.Popen", side_effect=AssertionError("no launch")), \
                patch("socket.create_connection", side_effect=AssertionError("no network")):
            plan = ExperimentPlan.from_bytes(canonical_bytes(source))
            self.assertEqual(plan.to_dict(), source)
            self.assertEqual(plan.to_bytes(), canonical_bytes(source))
            self.assertEqual(plan.digest, source["digest"])
            self.assertTrue(plan.executable)
        source["bounds"]["case_ms"] = 1
        projection = plan.to_dict()
        projection["case_ids"].clear()
        self.assertEqual(plan.to_dict()["bounds"]["case_ms"], 5000)
        self.assertEqual(plan.to_dict()["case_ids"], HOST_CASES)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            plan._canonical = b"{}"

    def test_plan_cannot_select_code_inference_privileges_or_unbounded_experiments(self):
        from taskalong.runtime_qualification import ExperimentPlan

        variants = []
        for key, value in [("profile", "arbitrary-plugin"), ("inference", "allowed"),
                           ("stage", "live"), ("format_version", "2.7"),
                           ("argv", ["PRIVATE-CANARY"]), ("allow_network", True),
                           ("case_ids", HOST_CASES[:-1]),
                           ("case_ids", HOST_CASES + [HOST_CASES[0]])]:
            candidate = original_plan()
            candidate[key] = value
            variants.append(sealed(candidate))
        for key, value in [("inventory_ms", 10001), ("case_ms", 0),
                           ("capture_bytes", 65537), ("execution_ms", 60001)]:
            candidate = original_plan()
            candidate["bounds"][key] = value
            variants.append(sealed(candidate))
        candidate = original_plan()
        candidate["subject"]["provider"] = "invented-vendor-identity"
        variants.append(sealed(candidate))
        for candidate in variants:
            with self.subTest(candidate=candidate), self.assertRaises(TaskAlongError) as error:
                ExperimentPlan.from_dict(candidate)
            self.assertEqual(error.exception.code, "runtime_proof_invalid")
            self.assertNotIn("PRIVATE-CANARY", str(error.exception))

    def test_live_stage_names_never_grant_an_executable_plan(self):
        from taskalong.runtime_qualification import ExperimentPlan

        for stage in ("controlled-responder", "actual-provider", "native-resume", "inventory", "installed-replay"):
            candidate = original_plan()
            candidate.update(stage=stage, case_ids=[])
            if stage == "installed-replay":
                candidate["package_origin"] = "installed"
            plan = ExperimentPlan.from_dict(sealed(candidate))
            self.assertFalse(plan.executable)
        candidate = original_plan()
        candidate["stage"] = "installed-replay"
        with self.assertRaises(TaskAlongError):
            ExperimentPlan.from_dict(sealed(candidate))
        candidate["package_origin"] = "installed"
        candidate["case_ids"] = []
        self.assertFalse(ExperimentPlan.from_dict(sealed(candidate)).executable)

    def test_bound_harness_metadata_is_separate_from_host_measurements_and_resume_mode(self):
        from taskalong.runtime_qualification import ExperimentPlan
        from test_qualification import subject

        candidate = original_plan()
        candidate.update(stage="actual-provider", case_ids=[])
        candidate["subject"] = {"kind": "bound-harness", "qualification_subject": subject(),
                                "mode": "start", "driver_config_digest": "2" * 64,
                                "projection_id": "original-fixture-projection/1",
                                "packet_digest": "3" * 64, "input_digest": "4" * 64}
        plan = ExperimentPlan.from_dict(sealed(candidate))
        self.assertFalse(plan.executable)
        self.assertEqual(plan.to_dict()["subject"]["qualification_subject"], subject())
        malformed = copy.deepcopy(candidate)
        malformed["subject"]["qualification_subject"]["invented_authority"] = True
        with self.assertRaises(TaskAlongError):
            ExperimentPlan.from_dict(sealed(malformed))
        for changes in ({"stage": "native-resume"}, {"subject_mode": "native_resume"}):
            malformed = copy.deepcopy(candidate)
            if "stage" in changes:
                malformed["stage"] = changes["stage"]
            else:
                malformed["subject"]["mode"] = changes["subject_mode"]
            with self.assertRaises(TaskAlongError):
                ExperimentPlan.from_dict(sealed(malformed))


class RuntimeManifestContractTests(unittest.TestCase):
    def completed_measurements(self):
        path, origin = qualifier_context()
        spec = importlib.util.spec_from_file_location("original_completed_qualifier", path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "original-measurement"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = tool.main(origin + ["--stage", "model-free",
                                  "--evidence-dir", str(destination)])
            self.assertEqual(code, 0, stdout.getvalue())
            return json.loads((destination / "manifest.json").read_bytes()), {
                p.stem: p.read_bytes() for p in (destination / "blobs").iterdir()}

    def test_incomplete_measurements_are_immutable_and_cannot_create_authority(self):
        from taskalong.runtime_qualification import ExperimentPlan, ProofEvidence, RuntimeProofManifest, validate_proof

        document, blobs = original_incomplete_proof()
        proof = RuntimeProofManifest.from_bytes(canonical_bytes(document))
        plan = ExperimentPlan.from_dict(document["plan"])
        with patch("subprocess.Popen", side_effect=AssertionError("no launch")), \
                patch("socket.create_connection", side_effect=AssertionError("no network")):
            result = validate_proof(proof, expected_plan=plan, evidence=ProofEvidence.from_blobs(blobs))
        self.assertFalse(result.complete)
        self.assertFalse(result.passed)
        self.assertFalse(result.production_dispatch_allowed)
        self.assertEqual(result.subject_kind, "host-experiment")
        document["cases"][0]["verdict"] = "passed"
        self.assertEqual(proof.to_dict()["cases"][0]["verdict"], "not_run")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.passed = True

    def test_manifest_cannot_hide_cases_change_plan_or_promote_incomplete_data(self):
        from taskalong.runtime_qualification import ExperimentPlan, ProofEvidence, RuntimeProofManifest, validate_proof

        original, blobs = original_incomplete_proof()
        variants = []
        for field, value in [("complete", True), ("first_error", None),
                             ("approved", True), ("cases", original["cases"][:-1]),
                             ("cases", original["cases"] + [original["cases"][0]])]:
            document = copy.deepcopy(original)
            document[field] = value
            variants.append(sealed(document))
        document = copy.deepcopy(original)
        document["cases"][0]["campaign_id"] = "5b0a987e-740f-49d2-9ef4-148ed3b8b903"
        variants.append(sealed(document))
        for document in variants:
            with self.subTest(document=document), self.assertRaises(TaskAlongError):
                RuntimeProofManifest.from_dict(document)
        other = copy.deepcopy(original["plan"])
        other["runner_digest"] = "9" * 64
        with self.assertRaises(TaskAlongError):
            validate_proof(RuntimeProofManifest.from_dict(original),
                           expected_plan=ExperimentPlan.from_dict(sealed(other)),
                           evidence=ProofEvidence.from_blobs(blobs))
        with self.assertRaises(TaskAlongError):
            validate_proof(RuntimeProofManifest.from_dict(original),
                           expected_plan=ExperimentPlan.from_dict(original["plan"]),
                           evidence=ProofEvidence.from_blobs({}))

    def test_private_byte_snapshot_is_bounded_immutable_and_preserves_empty_capture(self):
        from taskalong.runtime_qualification import ProofEvidence

        empty = hashlib.sha256(b"").hexdigest()
        supplied = {empty: b""}
        evidence = ProofEvidence.from_blobs(supplied)
        supplied.clear()
        self.assertEqual(evidence.get(empty), b"")
        self.assertIsNone(evidence.get("0" * 64))
        for value in [{"0" * 64: b"wrong"}, {empty: bytearray()},
                      {hashlib.sha256(b"a" * 65537).hexdigest(): b"a" * 65537}]:
            with self.subTest(value_type=type(next(iter(value.values())))), self.assertRaises(TaskAlongError):
                ProofEvidence.from_blobs(value)
        with self.assertRaises(TaskAlongError):
            ProofEvidence.from_blobs(lambda _: b"callback")

    def test_replay_refuses_boolean_counts_or_exit_codes_after_resealing(self):
        from taskalong.runtime_qualification import ExperimentPlan, ProofEvidence, RuntimeProofManifest, validate_proof

        original, original_blobs = self.completed_measurements()
        plan = ExperimentPlan.from_dict(original["plan"])
        self.assertTrue(validate_proof(RuntimeProofManifest.from_dict(original), expected_plan=plan,
                                       evidence=ProofEvidence.from_blobs(original_blobs)).passed)
        for case_id, field, value in [("predispatch-tool-denial", "target_invocations", False),
                                     ("owned-completion", "target_invocations", True),
                                     ("owned-completion", "exit_code", False)]:
            document, blobs = copy.deepcopy(original), dict(original_blobs)
            case = next(c for c in document["cases"] if c["id"] == case_id)
            key = "process_ref" if field == "exit_code" else "observation_ref"
            ref = case[key]
            raw = json.loads(blobs.pop(ref["sha256"]))
            raw[field] = value
            data = canonical_bytes(raw)
            case[key] = private_ref(data)
            blobs[case[key]["sha256"]] = data
            with self.subTest(case_id=case_id, field=field), self.assertRaises(TaskAlongError):
                validate_proof(RuntimeProofManifest.from_dict(sealed(document)), expected_plan=plan,
                               evidence=ProofEvidence.from_blobs(blobs))

    def test_manifest_refuses_execution_after_not_run_or_false_first_error_identity(self):
        from taskalong.runtime_qualification import RuntimeProofManifest

        original, _ = self.completed_measurements()
        document = copy.deepcopy(original)
        document.update(complete=False, inputs_rechecked=False,
                        first_error={"case_id": None, "code": "runtime_campaign_deadline"})
        document["cases"][0].update(verdict="not_run", capability="unknown", reason="not_run_after_failure",
                                       dispatch="not_sent", process_ref=None, capture_refs=None, observation_ref=None)
        with self.assertRaises(TaskAlongError):
            RuntimeProofManifest.from_dict(sealed(document))

        document = copy.deepcopy(original)
        document.update(complete=False, inputs_rechecked=False,
                        first_error={"case_id": HOST_CASES[1], "code": "runtime_canary_failed"})
        document["cases"][0].update(verdict="failed", capability="unknown", reason="oracle_failed")
        for case in document["cases"][1:]:
            case.update(verdict="not_run", capability="unknown", reason="not_run_after_failure",
                        dispatch="not_sent", process_ref=None, capture_refs=None, observation_ref=None)
        with self.assertRaises(TaskAlongError):
            RuntimeProofManifest.from_dict(sealed(document))

    def test_replay_requires_original_effect_capture_identity_and_cleanup_facts(self):
        from taskalong.runtime_qualification import ExperimentPlan, ProofEvidence, RuntimeProofManifest, validate_proof

        original, original_blobs = self.completed_measurements()
        plan = ExperimentPlan.from_dict(original["plan"])
        variants = [("process_ref", "termination_confirmed", False), ("process_ref", "timed_out", True),
                    ("process_ref", "unaccounted_descendants", True), ("process_ref", "output_limited", True),
                    ("observation_ref", "nonce", "0" * 64), ("observation_ref", "input_consumed", False)]
        for key, field, value in variants:
            document, blobs = copy.deepcopy(original), dict(original_blobs)
            case = document["cases"][0]
            raw = json.loads(blobs.pop(case[key]["sha256"]))
            raw[field] = value
            data = canonical_bytes(raw)
            case[key] = private_ref(data)
            blobs[case[key]["sha256"]] = data
            with self.subTest(field=field), self.assertRaises(TaskAlongError):
                validate_proof(RuntimeProofManifest.from_dict(sealed(document)), expected_plan=plan,
                               evidence=ProofEvidence.from_blobs(blobs))
        for stream in ("stdin", "stdout", "stderr"):
            document, blobs = copy.deepcopy(original), dict(original_blobs)
            # Resealing a self-consistent digest does not establish truthful
            # protocol bytes or permit losing the originals.
            data = b"forged pass\n"
            document["cases"][0]["capture_refs"][stream] = private_ref(data, "application/octet-stream")
            blobs[hashlib.sha256(data).hexdigest()] = data
            with self.subTest(stream=stream), self.assertRaises(TaskAlongError):
                validate_proof(RuntimeProofManifest.from_dict(sealed(document)), expected_plan=plan,
                               evidence=ProofEvidence.from_blobs(blobs))

    def test_failed_measurements_cannot_hide_malformed_process_or_unknown_cleanup(self):
        from taskalong.runtime_qualification import ExperimentPlan, ProofEvidence, RuntimeProofManifest, validate_proof

        original, original_blobs = self.completed_measurements()
        for field, value in [("exit_code", False), ("termination_confirmed", "true"),
                             ("group_termination_confirmed", False)]:
            document, blobs = copy.deepcopy(original), dict(original_blobs)
            case = document["cases"][0]
            raw = json.loads(blobs[case["process_ref"]["sha256"]])
            raw[field] = value
            data = canonical_bytes(raw)
            case["process_ref"] = private_ref(data)
            blobs[case["process_ref"]["sha256"]] = data
            case.update(verdict="failed", capability="unknown", reason="oracle_failed")
            document.update(complete=False, inputs_rechecked=False,
                            first_error={"case_id": case["id"], "code": "runtime_canary_failed"})
            for later in document["cases"][1:]:
                later.update(verdict="not_run", capability="unknown", reason="not_run_after_failure",
                             dispatch="not_sent", process_ref=None, capture_refs=None, observation_ref=None)
            # Retain only referenced originals, then demand structural validity
            # even though failure can never become a supported capability.
            refs = {document[k]["sha256"] for k in ("inventory_ref", "context_ref")}
            refs.update(case[k]["sha256"] for k in ("process_ref", "observation_ref"))
            refs.update(v["sha256"] for v in case["capture_refs"].values())
            observation = json.loads(blobs[case["observation_ref"]["sha256"]])
            refs.update(observation[k]["sha256"] for k in ("invocation_ref", "effect_ref", "control_ref")
                        if observation[k] is not None)
            evidence = ProofEvidence.from_blobs({key: blobs[key] for key in refs})
            with self.subTest(field=field), self.assertRaises(TaskAlongError):
                validate_proof(RuntimeProofManifest.from_dict(sealed(document)),
                               expected_plan=ExperimentPlan.from_dict(document["plan"]), evidence=evidence)

    def synthetic_verifier_inventory(self, original, measured, *, privilege=None):
        from taskalong.runtime_qualification import ProofEvidence

        # This constructed verifier is deliberately untrusted test data; a
        # consistency-valid inventory does not authenticate installed execution.
        verifier = copy.deepcopy(original)
        facts = json.loads(measured[verifier["inventory_ref"]["sha256"]])
        if privilege is not None:
            facts["measurements"]["host"]["privilege"] = copy.deepcopy(privilege)
        package = facts["measurements"]["package"]
        package.update(origin="installed", artifact_digest="a" * 64,
                       source_artifact_digest="b" * 64, source_artifact_kind="sdist")
        verifier["plan"]["package_origin"] = "installed"
        verifier["plan"]["stage"] = "inventory"
        verifier["plan"]["case_ids"] = []
        verifier["plan"]["subject"]["package_digest"] = hashlib.sha256(canonical_bytes(package)).hexdigest()
        verifier["plan"]["subject"]["host_digest"] = hashlib.sha256(canonical_bytes(facts["measurements"]["host"])).hexdigest()
        verifier["plan"] = sealed(verifier["plan"])
        facts["subject"] = verifier["plan"]["subject"]
        inventory = canonical_bytes(facts)
        verifier["inventory_ref"] = private_ref(inventory)
        verifier["cases"] = []
        verifier = sealed(verifier)
        verifier_bytes = canonical_bytes(verifier)
        verifier_evidence = ProofEvidence.from_blobs({hashlib.sha256(inventory).hexdigest(): inventory,
            verifier["context_ref"]["sha256"]: measured[verifier["context_ref"]["sha256"]]})
        return verifier, verifier_bytes, verifier_evidence

    def test_offline_replay_keeps_failed_source_proof_and_untrusted_verifier_separate(self):
        from taskalong.runtime_qualification import (
            ProofEvidence, RuntimeReplayReport, evidence_set_digest, validate_replay,
        )

        measured_original, measured = self.completed_measurements()
        verifier, verifier_bytes, verifier_evidence = self.synthetic_verifier_inventory(measured_original, measured)
        original, original_blobs = original_incomplete_proof()
        original_bytes = canonical_bytes(original)
        original_evidence = ProofEvidence.from_blobs(original_blobs)
        report = sealed({"kind": "runtime_qualification_replay", "format_version": "1.0", "operation": "installed-replay",
            "original_manifest_ref": private_ref(original_bytes), "original_proof_digest": original["digest"],
            "original_subject": original["plan"]["subject"], "original_evidence_set_digest": evidence_set_digest(original_evidence),
            "verifier_manifest_ref": private_ref(verifier_bytes), "verifier_proof_digest": sealed(verifier)["digest"],
            "original_complete": False, "original_passed": False, "integrity_valid": True})
        with patch("subprocess.Popen", side_effect=AssertionError("no replay launch")), \
                patch("socket.socket", side_effect=AssertionError("no replay network")):
            result = validate_replay(RuntimeReplayReport.from_dict(report), original_bytes=original_bytes,
                original_evidence=original_evidence, verifier_bytes=verifier_bytes, verifier_evidence=verifier_evidence)
        self.assertFalse(result.passed)
        self.assertFalse(result.complete)
        self.assertFalse(result.producer_authenticated)
        self.assertFalse(result.production_dispatch_allowed)
        self.assertEqual(original["plan"]["package_origin"], "source")
        for field, value in [("original_passed", True), ("original_complete", True),
                             ("original_evidence_set_digest", "0" * 64), ("original_subject", verifier["plan"]["subject"])]:
            changed = sealed(dict(report, **{field: value}))
            with self.subTest(field=field), self.assertRaises(TaskAlongError):
                validate_replay(RuntimeReplayReport.from_dict(changed), original_bytes=original_bytes,
                    original_evidence=original_evidence, verifier_bytes=verifier_bytes, verifier_evidence=verifier_evidence)

    def test_controller_privilege_shapes_are_strict_even_after_rebinding_digests(self):
        from taskalong.runtime_qualification import ExperimentPlan, ProofEvidence, RuntimeProofManifest, validate_proof

        original, original_blobs = self.completed_measurements()
        valid = {"scope": "controller", "effective_uid": 123, "class": "effective_uid_nonzero"}
        variants = [None, {}, valid | {"effective_uid": True}, valid | {"effective_uid": -1},
                    valid | {"effective_uid": "123"}, valid | {"effective_uid": 2**32},
                    valid | {"scope": "child"}, valid | {"class": "effective_uid_zero"}, valid | {"extra": False}]
        for index, privilege in enumerate(variants):
            document, blobs = copy.deepcopy(original), dict(original_blobs)
            old = document["inventory_ref"]["sha256"]
            inventory = json.loads(blobs.pop(old))
            host = inventory["measurements"]["host"]
            if privilege is None:
                host.pop("privilege")
            else:
                host["privilege"] = privilege
            document["plan"]["subject"]["host_digest"] = hashlib.sha256(canonical_bytes(host)).hexdigest()
            document["plan"] = sealed(document["plan"])
            inventory["subject"] = document["plan"]["subject"]
            raw = canonical_bytes(inventory)
            document["inventory_ref"] = private_ref(raw)
            blobs[hashlib.sha256(raw).hexdigest()] = raw
            with self.subTest(variant=index), self.assertRaises(TaskAlongError):
                validate_proof(RuntimeProofManifest.from_dict(sealed(document)),
                    expected_plan=ExperimentPlan.from_dict(document["plan"]), evidence=ProofEvidence.from_blobs(blobs))

    def test_replay_keeps_original_privilege_separate_from_constructed_verifier_class(self):
        from taskalong.runtime_qualification import ProofEvidence, RuntimeReplayReport, evidence_set_digest, validate_replay

        original, blobs = self.completed_measurements()
        inventory = json.loads(blobs[original["inventory_ref"]["sha256"]])
        observed = inventory["measurements"]["host"]["privilege"]
        # Synthetic consistency fixture only; no UID change or privileged trial.
        different = {"scope": "controller", "effective_uid": 0 if observed["effective_uid"] else 123,
                     "class": "effective_uid_zero" if observed["effective_uid"] else "effective_uid_nonzero"}
        original_bytes = canonical_bytes(original)
        verifier, verifier_bytes, verifier_evidence = self.synthetic_verifier_inventory(original, blobs, privilege=different)
        self.assertEqual(original_bytes, canonical_bytes(original))
        evidence = ProofEvidence.from_blobs(blobs)
        report = sealed({"kind": "runtime_qualification_replay", "format_version": "1.0", "operation": "installed-replay",
            "original_manifest_ref": private_ref(original_bytes), "original_proof_digest": original["digest"],
            "original_subject": original["plan"]["subject"], "original_evidence_set_digest": evidence_set_digest(evidence),
            "verifier_manifest_ref": private_ref(verifier_bytes), "verifier_proof_digest": verifier["digest"],
            "original_complete": True, "original_passed": True, "integrity_valid": True})
        with patch("os.geteuid", side_effect=AssertionError("pure replay cannot measure identity")), \
                patch("subprocess.Popen", side_effect=AssertionError("pure replay cannot launch")), \
                patch("socket.socket", side_effect=AssertionError("pure replay cannot connect")):
            result = validate_replay(RuntimeReplayReport.from_dict(report), original_bytes=original_bytes,
                original_evidence=evidence, verifier_bytes=verifier_bytes, verifier_evidence=verifier_evidence)
        self.assertTrue(result.passed)
        self.assertFalse(result.producer_authenticated)
        self.assertFalse(result.production_dispatch_allowed)
        self.assertEqual(original_bytes, canonical_bytes(original))
        self.assertEqual(blobs[original["inventory_ref"]["sha256"]], canonical_bytes(inventory))



class RuntimeCanaryHelperTests(unittest.TestCase):
    def launch(self, mode):
        from taskalong.process import minimal_environment, run_bounded

        helper = Path(__file__).parent / "fixtures" / "runtime_canary.py"
        request = {"campaign_id": original_plan()["campaign_id"], "nonce": "5" * 64,
                   "case_id": mode, "payload": "original private canary\n"}
        stdin = canonical_bytes(request) + b"\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "workspace").mkdir()
            (root / "workspace" / "permitted.txt").write_text(request["payload"])
            env = minimal_environment()
            for key, name in [("HOME", "home"), ("XDG_CONFIG_HOME", "config"),
                              ("XDG_CACHE_HOME", "cache"), ("XDG_DATA_HOME", "data"),
                              ("TMPDIR", "tmp")]:
                directory = root / name
                directory.mkdir()
                env[key] = str(directory)
            raw = {}
            result = run_bounded([sys.executable, "-I", "-S", str(helper), mode],
                                 cwd=root, stdin=stdin, env=env, timeout_seconds=5,
                                 max_output_bytes=65536,
                                 _capture_private_output=lambda out, err: raw.update(stdout=out, stderr=err))
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(result.termination_confirmed)
            self.assertFalse(result.unaccounted_descendants)
            self.assertFalse(result.output_limited)
            observed = json.loads(raw["stdout"])
            self.assertEqual(observed["campaign_id"], request["campaign_id"])
            self.assertEqual(observed["case_id"], mode)
            self.assertEqual(observed["nonce"], request["nonce"])
            self.assertEqual(observed["input_sha256"], hashlib.sha256(stdin).hexdigest())
            invocations = (root / "target-invocations.jsonl").read_text().splitlines()
            self.assertEqual(len(invocations), 1)
            self.assertEqual(json.loads(invocations[0]), {"campaign_id": request["campaign_id"],
                             "case_id": mode, "input_sha256": hashlib.sha256(stdin).hexdigest()})
            if mode == "permitted-write":
                self.assertEqual((root / "workspace" / "created.txt").read_bytes(), request["payload"].encode())
            return request, observed, raw, result

    def test_owned_original_helper_performs_nonce_bound_permitted_read_and_write(self):
        for mode in ("permitted-read", "permitted-write"):
            request, observed, raw, result = self.launch(mode)
            self.assertEqual(observed["effect_sha256"], hashlib.sha256(request["payload"].encode()).hexdigest())
            self.assertEqual(raw["stderr"], b"")
            self.assertEqual(observed["event"], "completed")
            self.assertFalse(any(name.startswith(("OLLAMA", "ANTHROPIC", "OPENAI", "GITHUB", "CURSOR"))
                                 for name in observed["environment_keys"]))

    def test_private_capture_preserves_generated_redactor_canary_originals(self):
        request, observed, raw, result = self.launch("bounded-capture")
        self.assertEqual(raw["stderr"], b"Bearer " + request["nonce"].encode() + b"\n")
        self.assertNotEqual(raw["stderr"], result.stderr)
        self.assertIn(b"[REDACTED]", result.stderr)
        self.assertIsNone(observed["effect_sha256"])

    def test_provider_credential_key_is_refused_before_helper_effects(self):
        from taskalong.process import minimal_environment, run_bounded

        helper = Path(__file__).parent / "fixtures" / "runtime_canary.py"
        request = {"campaign_id": original_plan()["campaign_id"], "nonce": "6" * 64,
                   "case_id": "owned-completion", "payload": "generated canary"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = minimal_environment()
            env.update(HOME=str(root), OLLAMA_KEY="original-synthetic-provider-canary")
            result = run_bounded([sys.executable, "-I", "-S", str(helper), request["case_id"]],
                                 cwd=root, env=env, stdin=canonical_bytes(request) + b"\n",
                                 timeout_seconds=5, max_output_bytes=65536)
            self.assertEqual(result.exit_code, 2)
            self.assertTrue(result.termination_confirmed)
            self.assertFalse((root / "target-invocations.jsonl").exists())
            self.assertEqual(result.stdout, b"")
            self.assertEqual(result.stderr, b"canary_input_or_effect_failed\n")

    def test_closed_owned_gate_reports_not_sent_confirmed_cleanup_and_zero_target(self):
        from taskalong.process import ProcessBoundaryError, minimal_environment, run_bounded

        helper = Path(__file__).parent / "fixtures" / "runtime_canary.py"
        request = {"campaign_id": original_plan()["campaign_id"], "nonce": "7" * 64,
                   "case_id": "closed-gate-cancel", "payload": "generated gate canary"}

        def close_gate(_receipt):
            raise ProcessBoundaryError("original closed-gate control", code="qualification_gate_cancelled",
                                       effect_outcome="not_sent")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = minimal_environment()
            env["HOME"] = str(root)
            capture = {}
            with self.assertRaises(ProcessBoundaryError) as caught:
                run_bounded([sys.executable, "-I", "-S", str(helper), request["case_id"]],
                            cwd=root, env=env, stdin=canonical_bytes(request) + b"\n",
                            timeout_seconds=5, max_output_bytes=65536, on_spawn=close_gate,
                            _capture_private_output=lambda out, err: capture.update(stdout=out, stderr=err))
            error = caught.exception
            self.assertEqual(error.effect_outcome, "not_sent")
            self.assertEqual(error.code, "qualification_gate_cancelled")
            self.assertIsNotNone(error.process_result)
            result = error.process_result
            self.assertTrue(result.termination_confirmed)
            self.assertTrue(result.group_termination_confirmed)
            self.assertFalse(result.unaccounted_descendants)
            self.assertFalse((root / "target-invocations.jsonl").exists())
            self.assertEqual(set(capture), {"stdout", "stderr"})

    def test_running_owned_helper_cancels_after_nonce_bound_ready_and_reaps(self):
        from taskalong.process import minimal_environment, run_bounded

        helper = Path(__file__).parent / "fixtures" / "runtime_canary.py"
        request = {"campaign_id": original_plan()["campaign_id"], "nonce": "8" * 64,
                   "case_id": "running-cancel", "payload": "generated running canary"}
        stdin = canonical_bytes(request) + b"\n"
        ready = {"observed": False}

        def observe(line):
            frame = json.loads(line)
            self.assertEqual(frame["event"], "ready")
            self.assertEqual(frame["nonce"], request["nonce"])
            self.assertEqual(frame["input_sha256"], hashlib.sha256(stdin).hexdigest())
            ready["observed"] = True

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = minimal_environment()
            env["HOME"] = str(root)
            result = run_bounded([sys.executable, "-I", "-S", str(helper), request["case_id"]],
                                 cwd=root, env=env, stdin=stdin, timeout_seconds=5,
                                 max_output_bytes=65536, on_stdout_line=observe,
                                 cancel_requested=lambda: ready["observed"])
            self.assertTrue(ready["observed"])
            self.assertTrue(result.cancelled)
            self.assertFalse(result.timed_out)
            self.assertEqual(result.exit_code, 130)
            self.assertTrue(result.termination_confirmed)
            self.assertTrue(result.group_termination_confirmed)
            self.assertFalse(result.unaccounted_descendants)
            self.assertEqual(len((root / "target-invocations.jsonl").read_text().splitlines()), 1)


class RuntimeQualificationEntryTests(unittest.TestCase):
    def entrypoint(self):
        path, _ = qualifier_context()
        spec = importlib.util.spec_from_file_location("original_runtime_qualifier", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_future_stages_refuse_before_credentials_socket_spawn_or_evidence_effects(self):
        from taskalong.process import minimal_environment, run_bounded

        tool, _ = qualifier_context()
        guard = r'''
import os,pathlib,runpy,socket,subprocess,sys
marker=pathlib.Path(sys.argv[4])
def forbidden(*args, **kwargs):
    marker.write_bytes(b"forbidden effect attempted")
    raise AssertionError("forbidden effect")
original=type(os.environ).__getitem__
def getitem(self,key):
    if str(key).upper().startswith(("OLLAMA","ANTHROPIC","OPENAI","GITHUB","CURSOR")):
        forbidden()
    return original(self,key)
type(os.environ).__getitem__=getitem
socket.socket=forbidden
socket.create_connection=forbidden
subprocess.Popen=forbidden
sys.argv=[sys.argv[1],"--stage",sys.argv[2],"--package-origin","installed",
          "--inference","never","--evidence-dir",sys.argv[3]]
runpy.run_path(sys.argv[0],run_name="__main__")
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = minimal_environment()
            env["HOME"] = str(root)
            for stage in ("controlled-responder", "actual-provider", "native-resume"):
                destination, marker = root / stage, root / (stage + ".forbidden")
                result = run_bounded([sys.executable, "-I", "-S", "-c", guard,
                                      str(tool), stage, str(destination), str(marker)],
                                     cwd=root, env=env, timeout_seconds=5, max_output_bytes=8192)
                self.assertEqual(result.exit_code, 3)
                self.assertTrue(result.termination_confirmed)
                self.assertFalse(marker.exists())
                self.assertFalse(destination.exists())
                summary = json.loads(result.stdout)
                self.assertEqual(summary["code"], "runtime_stage_unsupported")
                self.assertEqual(summary["requested_stage"], stage)
                self.assertFalse(summary["production_dispatch_allowed"])
                self.assertFalse(summary["durable_evidence"])

    def test_help_has_no_package_dependency_or_experiment_effect(self):
        from taskalong.process import minimal_environment, run_bounded

        tool, _ = qualifier_context()
        with tempfile.TemporaryDirectory() as temporary:
            result = run_bounded([sys.executable, "-I", "-S", str(tool), "--help"],
                                 cwd=temporary, env=minimal_environment(), timeout_seconds=5,
                                 max_output_bytes=8192)
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(result.termination_confirmed)
            self.assertIn(b"owned-host-canaries-v1", result.stdout)
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_replay_source_origin_is_refused_before_input_reads_or_dispatch(self):
        tool = self.entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "never-created"
            stdout = io.StringIO()
            with patch("taskalong.process.run_bounded", side_effect=AssertionError("no launch")), redirect_stdout(stdout):
                code = tool.main(["--stage", "installed-replay", "--package-origin", "source",
                                  "--replay-dir", str(Path(temporary) / "missing"), "--evidence-dir", str(output)])
            self.assertEqual(code, 3)
            self.assertEqual(json.loads(stdout.getvalue())["code"], "runtime_origin_inputs_invalid")
            self.assertFalse(output.exists())

    def test_replay_input_loader_retains_private_originals_and_refuses_missing_or_changed_bytes(self):
        import time
        from taskalong import runtime_qualification as rq

        tool = self.entrypoint()
        document, blobs = original_incomplete_proof()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proof_dir = root / "original"
            proof_dir.mkdir(mode=0o700)
            (proof_dir / "blobs").mkdir(mode=0o700)
            raw = canonical_bytes(document) + b"\n"
            (proof_dir / "manifest.json").write_bytes(raw)
            (proof_dir / "manifest.json").chmod(0o600)
            for key, data in blobs.items():
                path = proof_dir / "blobs" / (key + ".bin")
                path.write_bytes(data)
                path.chmod(0o600)
            before = {str(p.relative_to(proof_dir)): p.read_bytes() for p in proof_dir.rglob("*") if p.is_file()}
            with patch("subprocess.Popen", side_effect=AssertionError("no replay launch")), \
                    patch("socket.socket", side_effect=AssertionError("no replay network")):
                measured, evidence, result = tool._read_proof_directory(proof_dir, rq, time.monotonic() + 10)
            self.assertEqual(measured, raw)
            self.assertEqual({key: evidence.get(key) for key in blobs}, blobs)
            self.assertFalse(result.passed)
            self.assertFalse(result.producer_authenticated)
            self.assertEqual(before, {str(p.relative_to(proof_dir)): p.read_bytes() for p in proof_dir.rglob("*") if p.is_file()})
            target = next((proof_dir / "blobs").iterdir())
            saved = target.read_bytes()
            target.write_bytes(b"changed original")
            with self.assertRaises(tool._Failed):
                tool._read_proof_directory(proof_dir, rq, time.monotonic() + 10)
            target.write_bytes(saved)
            target.rename(root / "retained-blob")
            with self.assertRaises(TaskAlongError):
                tool._read_proof_directory(proof_dir, rq, time.monotonic() + 10)
            target.symlink_to(root / "retained-blob")
            with self.assertRaises(OSError):
                tool._read_proof_directory(proof_dir, rq, time.monotonic() + 10)

    def test_replay_checks_actual_installed_origin_and_preserves_failed_source_proof(self):
        from taskalong.runtime_qualification import RuntimeReplayReport

        tool = self.entrypoint()
        _, origin = qualifier_context()
        installed = origin[1] == "installed"
        original, blobs = original_incomplete_proof()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_dir = root / "original"
            original_dir.mkdir(mode=0o700)
            (original_dir / "blobs").mkdir(mode=0o700)
            for name, data in {"manifest.json": canonical_bytes(original),
                               **{"blobs/" + key + ".bin": raw for key, raw in blobs.items()}}.items():
                path = original_dir / name
                path.write_bytes(data)
                path.chmod(0o600)
            before = {str(p.relative_to(original_dir)): p.read_bytes() for p in original_dir.rglob("*") if p.is_file()}
            args = origin if installed else ["--package-origin", "installed", "--artifact-inventory", str(root / "missing-inventory")]
            destination = root / "replay"
            stdout = io.StringIO()
            with patch("subprocess.Popen", side_effect=AssertionError("replay cannot launch")), \
                    patch("socket.socket", side_effect=AssertionError("replay cannot connect")), redirect_stdout(stdout):
                code = tool.main(args + ["--stage", "installed-replay", "--replay-dir", str(original_dir),
                                         "--evidence-dir", str(destination)])
            summary = json.loads(stdout.getvalue())
            self.assertEqual(code, 1 if installed else 3)
            self.assertFalse(summary["production_dispatch_allowed"])
            self.assertNotIn(str(original_dir), stdout.getvalue())
            if installed:
                self.assertTrue(summary["integrity_valid"])
                self.assertFalse(summary["original_complete"])
                self.assertFalse(summary["original_passed"])
                self.assertEqual((summary["helper_invocations"], summary["owned_invocations"]), (0, 0))
                report = RuntimeReplayReport.from_bytes((destination / "replay-report.json").read_bytes()).to_dict()
                self.assertEqual(report["original_proof_digest"], original["digest"])
                self.assertEqual(report["original_subject"], original["plan"]["subject"])
                verifier = json.loads((destination / "manifest.json").read_bytes())
                self.assertEqual(verifier["plan"]["package_origin"], "installed")
                self.assertEqual(verifier["cases"], [])
            else:
                self.assertEqual(summary["code"], "runtime_package_origin_mismatch")
                self.assertFalse((destination / "replay-report.json").exists())
            self.assertEqual(before, {str(p.relative_to(original_dir)): p.read_bytes() for p in original_dir.rglob("*") if p.is_file()})

    def test_source_inventory_persists_private_consistent_measurement_without_helpers(self):
        from taskalong.runtime_qualification import ExperimentPlan, ProofEvidence, RuntimeProofManifest, validate_proof

        tool = self.entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "new-experiment"
            stdout = io.StringIO()
            with patch("taskalong.process.run_bounded", side_effect=AssertionError("inventory cannot launch")), \
                    patch("socket.socket", side_effect=AssertionError("inventory cannot connect")), \
                    redirect_stdout(stdout):
                code = tool.main(qualifier_context()[1] + ["--stage", "inventory",
                                  "--evidence-dir", str(destination)])
            self.assertEqual(code, 0)
            summary = json.loads(stdout.getvalue())
            self.assertEqual(summary["outcome"], "inventory_complete")
            self.assertTrue(summary["durable_evidence"])
            self.assertFalse(summary["production_dispatch_allowed"])
            self.assertNotIn(str(destination), stdout.getvalue())
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            raw = (destination / "manifest.json").read_bytes()
            proof = RuntimeProofManifest.from_bytes(raw)
            self.assertEqual(proof.digest, summary["proof_digest"])
            document = proof.to_dict()
            self.assertEqual(document["plan"]["stage"], "inventory")
            self.assertEqual(document["cases"], [])
            blobs = {path.stem: path.read_bytes() for path in (destination / "blobs").iterdir()}
            facts = json.loads(blobs[document["inventory_ref"]["sha256"]])["measurements"]
            uid = os.geteuid()
            self.assertTrue(facts["host"]["privilege"] == {"scope": "controller", "effective_uid": uid,
                "class": "effective_uid_zero" if uid == 0 else "effective_uid_nonzero"}, "controller identity binding differs")
            self.assertEqual(document["plan"]["subject"]["host_digest"], hashlib.sha256(canonical_bytes(facts["host"])).hexdigest())
            self.assertNotIn("effective_uid", stdout.getvalue())
            self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600
                                for path in (destination / "blobs").iterdir()))
            assessment = validate_proof(proof, expected_plan=ExperimentPlan.from_dict(document["plan"]),
                                        evidence=ProofEvidence.from_blobs(blobs))
            self.assertTrue(assessment.complete)
            self.assertTrue(assessment.passed)
            self.assertFalse(assessment.producer_authenticated)
            context = json.loads(blobs[document["context_ref"]["sha256"]])
            self.assertNotIn(context["nonce"], stdout.getvalue())

    def test_existing_evidence_destination_is_refused_without_reuse_or_overwrite(self):
        tool = self.entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            sentinel = destination / "preserve.txt"
            sentinel.write_bytes(b"retained evidence")
            stdout = io.StringIO()
            with patch("taskalong.process.run_bounded", side_effect=AssertionError("no dispatch")), redirect_stdout(stdout):
                code = tool.main(qualifier_context()[1] + ["--stage", "inventory",
                                  "--evidence-dir", str(destination)])
            self.assertEqual(code, 3)
            self.assertEqual(json.loads(stdout.getvalue())["code"], "runtime_evidence_destination_unsafe")
            self.assertEqual(sentinel.read_bytes(), b"retained evidence")
            self.assertEqual([path.name for path in destination.iterdir()], ["preserve.txt"])

    def test_source_model_free_campaign_reconciles_all_real_owned_canaries(self):
        from taskalong.process import run_bounded
        from taskalong.runtime_qualification import ExperimentPlan, ProofEvidence, RuntimeProofManifest, validate_proof

        tool = self.entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "model-free"
            stdout = io.StringIO()
            with patch("taskalong.process.run_bounded", wraps=run_bounded) as owner, redirect_stdout(stdout):
                code = tool.main(qualifier_context()[1] + ["--stage", "model-free",
                                  "--inference", "never", "--evidence-dir", str(destination)])
            self.assertEqual(code, 0)
            self.assertEqual(owner.call_count, 6)
            summary = json.loads(stdout.getvalue())
            self.assertEqual(summary["outcome"], "model_free_complete")
            self.assertEqual(summary["helper_invocations"], 5)
            self.assertFalse(summary["production_dispatch_allowed"])
            self.assertFalse(summary["closure_complete"])
            self.assertEqual(summary["vendor_capabilities"]["start"], "unknown")
            self.assertNotIn(str(destination), stdout.getvalue())
            proof = RuntimeProofManifest.from_bytes((destination / "manifest.json").read_bytes())
            document = proof.to_dict()
            self.assertEqual([case["id"] for case in document["cases"]], HOST_CASES)
            self.assertTrue(all(case["verdict"] == "passed" for case in document["cases"]))
            blobs = {path.stem: path.read_bytes() for path in (destination / "blobs").iterdir()}
            evidence = ProofEvidence.from_blobs(blobs)
            assessment = validate_proof(proof, expected_plan=ExperimentPlan.from_dict(document["plan"]),
                                        evidence=evidence)
            self.assertTrue(assessment.complete)
            self.assertTrue(assessment.passed)
            self.assertFalse(assessment.producer_authenticated)
            denied = next(c for c in document["cases"] if c["id"] == "predispatch-tool-denial")
            self.assertEqual(denied["capability"], "unsupported")
            self.assertIsNone(denied["process_ref"])
            closed = next(c for c in document["cases"] if c["id"] == "closed-gate-cancel")
            observed = json.loads(evidence.get(closed["observation_ref"]["sha256"]))
            self.assertEqual(observed["boundary_error"]["effect_outcome"], "not_sent")
            self.assertEqual(observed["target_invocations"], 0)
            self.assertFalse(observed["input_consumed"])
            result = json.loads(evidence.get(closed["process_ref"]["sha256"]))
            self.assertTrue(result["termination_confirmed"])
            running = next(c for c in document["cases"] if c["id"] == "running-cancel")
            result = json.loads(evidence.get(running["process_ref"]["sha256"]))
            self.assertTrue(result["cancelled"])
            self.assertEqual(result["exit_code"], 130)
            if qualifier_context()[1][1] == "installed":
                replay_stdout = io.StringIO()
                with patch("subprocess.Popen", side_effect=AssertionError("offline replay cannot launch")), \
                        patch("socket.socket", side_effect=AssertionError("offline replay cannot connect")), \
                        redirect_stdout(replay_stdout):
                    replay_code = tool.main(qualifier_context()[1] + ["--stage", "installed-replay",
                        "--replay-dir", str(destination), "--evidence-dir", str(Path(temporary) / "replayed")])
                self.assertEqual(replay_code, 0)
                replay_summary = json.loads(replay_stdout.getvalue())
                self.assertTrue(replay_summary["original_passed"])
                self.assertEqual(replay_summary["owned_invocations"], 0)
                replay = json.loads((Path(temporary) / "replayed/replay-report.json").read_bytes())
                self.assertEqual(replay["original_proof_digest"], proof.digest)
                self.assertEqual(replay["original_subject"], document["plan"]["subject"])

    def test_uncertain_boundary_stops_campaign_and_never_reports_zero_invocations(self):
        tool = self.entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "uncertain"
            stdout = io.StringIO()
            with patch("taskalong.process.run_bounded", side_effect=RuntimeError("PRIVATE-EXCEPTION")) as owner, \
                    redirect_stdout(stdout):
                code = tool.main(qualifier_context()[1] + ["--evidence-dir", str(destination)])
            self.assertEqual(code, 1)
            self.assertEqual(owner.call_count, 1)
            report = json.loads(stdout.getvalue())
            self.assertIsNone(report["helper_invocations"])
            self.assertIsNone(report["owned_invocations"])
            self.assertFalse(report["invocation_count_complete"])
            self.assertNotIn("PRIVATE-EXCEPTION", stdout.getvalue())
            document = json.loads((destination / "manifest.json").read_bytes())
            self.assertTrue(document["quarantined"])
            self.assertEqual(document["first_error"]["case_id"], HOST_CASES[0])
            self.assertEqual([c["verdict"] for c in document["cases"]], ["failed"] + ["not_run"] * 6)
            raw = (destination / "blobs" / (document["cases"][0]["observation_ref"]["sha256"] + ".bin")).read_bytes()
            self.assertIsNone(json.loads(raw)["target_invocations"])

    def test_destination_substitution_is_refused_before_owned_dispatch(self):
        tool = self.entrypoint()
        original = tool._PrivateEvidence.case_directory
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "experiment"
            redirected = root / "redirected"
            redirected.mkdir()

            def substitute(writer, *args):
                result = original(writer, *args)
                destination.rename(root / "retained-original")
                destination.symlink_to(redirected, target_is_directory=True)
                return result

            stdout = io.StringIO()
            with patch.object(tool._PrivateEvidence, "case_directory", substitute), \
                    patch("taskalong.process.run_bounded", side_effect=AssertionError("no launch")) as owner, \
                    redirect_stdout(stdout):
                code = tool.main(qualifier_context()[1] + ["--evidence-dir", str(destination)])
            self.assertEqual(code, 1)
            self.assertEqual(owner.call_count, 0)
            self.assertFalse(json.loads(stdout.getvalue())["durable_evidence"])
            self.assertEqual(list(redirected.iterdir()), [])

    def test_evidence_write_failure_retains_safe_failure_without_durable_claim(self):
        tool = self.entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "failed-write"
            stdout = io.StringIO()
            with patch.object(tool._PrivateEvidence, "manifest", side_effect=OSError("PRIVATE-WRITE-DETAIL")), \
                    patch("taskalong.process.run_bounded", side_effect=AssertionError("inventory cannot launch")), \
                    redirect_stdout(stdout):
                code = tool.main(qualifier_context()[1] + ["--stage", "inventory", "--evidence-dir", str(destination)])
            self.assertEqual(code, 1)
            self.assertFalse(json.loads(stdout.getvalue())["durable_evidence"])
            self.assertNotIn("PRIVATE-WRITE-DETAIL", stdout.getvalue())
            self.assertFalse((destination / "manifest.json").exists())
            self.assertFalse(json.loads((destination / "failure.json").read_bytes())["durable_evidence"])

    def test_secondary_evidence_failure_preserves_first_unknown_cleanup(self):
        tool = self.entrypoint()
        original = tool._PrivateEvidence.blob
        calls = {"count": 0}
        def fail_later(writer, *args, **kwargs):
            calls["count"] += 1
            if calls["count"] > 2:
                raise OSError("PRIVATE-SECONDARY-ERROR")
            return original(writer, *args, **kwargs)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "unknown-and-write-failed"
            stdout = io.StringIO()
            with patch.object(tool._PrivateEvidence, "blob", fail_later), \
                    patch("taskalong.process.run_bounded", side_effect=RuntimeError("PRIVATE-FIRST-ERROR")), \
                    redirect_stdout(stdout):
                code = tool.main(qualifier_context()[1] + ["--evidence-dir", str(destination)])
            self.assertEqual(code, 1)
            summary = json.loads(stdout.getvalue())
            self.assertEqual(summary["code"], "runtime_cleanup_unknown")
            self.assertTrue(summary["cleanup_uncertain"])
            self.assertFalse(summary["durable_evidence"])
            failure = json.loads((destination / "failure.json").read_bytes())
            self.assertEqual(failure["primary_error"], {"case_id": HOST_CASES[0], "code": "runtime_cleanup_unknown"})
            self.assertTrue(failure["cleanup_uncertain"])
            self.assertNotIn("PRIVATE-", stdout.getvalue())


    def test_interrupted_owned_call_preserves_uncertainty_and_stops_later_cases(self):
        tool = self.entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "interrupted"
            stdout = io.StringIO()
            with patch("taskalong.process.run_bounded", side_effect=KeyboardInterrupt()) as owner, redirect_stdout(stdout):
                code = tool.main(qualifier_context()[1] + ["--evidence-dir", str(destination)])
            self.assertEqual(code, 1)
            self.assertEqual(owner.call_count, 1)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["code"], "runtime_cleanup_unknown")
            self.assertTrue(result["cleanup_uncertain"])
            self.assertIsNone(result["helper_invocations"])
            self.assertIsNone(result["owned_invocations"])
            document = json.loads((destination / "manifest.json").read_bytes())
            self.assertTrue(document["quarantined"])
            self.assertEqual(document["first_error"], {"case_id": HOST_CASES[0], "code": "runtime_cleanup_unknown"})
            self.assertEqual([c["verdict"] for c in document["cases"]], ["failed"] + ["not_run"] * 6)

    def test_unavailable_backend_is_blocked_without_launch_or_success_claim(self):
        tool = self.entrypoint()
        original = tool._inventory_measurements
        def unavailable(*args):
            rq, facts, watch = original(*args)
            facts["backend"] = {"id": "unsupported", "implementation_digest": None,
                                "components": {"taskalong/process.py": facts["package"]["payloads"]["taskalong/process.py"]}}
            return rq, facts, watch
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "unsupported"
            stdout = io.StringIO()
            with patch.object(tool, "_inventory_measurements", unavailable), \
                    patch("taskalong.process.run_bounded", side_effect=AssertionError("no fallback")) as owner, \
                    redirect_stdout(stdout):
                code = tool.main(qualifier_context()[1] + ["--evidence-dir", str(destination)])
            self.assertEqual(code, 3)
            self.assertEqual(owner.call_count, 0)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["outcome"], "unsupported")
            self.assertEqual(result["code"], "runtime_lifecycle_unsupported")
            self.assertFalse(result["complete"])
            self.assertEqual((result["helper_invocations"], result["owned_invocations"]), (0, 0))
            document = json.loads((destination / "manifest.json").read_bytes())
            self.assertTrue(all(c["verdict"] == "not_run" for c in document["cases"]))

    def test_replay_rechecks_verifier_inputs_after_original_proof_read(self):
        import time
        tool = self.entrypoint()
        _, origin = qualifier_context()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            if origin[1] == "source":
                # Portable filesystem oracle for the same final watch used by
                # replay. The installed lane exercises the public replay below.
                watched = root / "verifier-input"
                watched.write_bytes(b"original verifier bytes")
                expected = tool._measure(watched, time.monotonic() + 10)
                watched.write_bytes(b"changed verifier bytes")
                with self.assertRaises(tool._Failed):
                    tool._recheck_inputs([(watched, expected, False, 65536)], time.monotonic() + 10)
                return
            original, blobs = original_incomplete_proof()
            supplied = root / "original"
            supplied.mkdir(mode=0o700)
            (supplied / "blobs").mkdir(mode=0o700)
            for name, data in {"manifest.json": canonical_bytes(original),
                               **{"blobs/" + key + ".bin": raw for key, raw in blobs.items()}}.items():
                target = supplied / name
                target.write_bytes(data)
                target.chmod(0o600)
            helper = tool._helper_path("installed")
            saved = helper.read_bytes()
            read_original = tool._read_proof_directory
            changed = {"once": False}
            def drift(*args):
                value = read_original(*args)
                if not changed["once"]:
                    helper.write_bytes(saved + b"\n# original injected cooperative drift\n")
                    changed["once"] = True
                return value
            destination = root / "replay"
            stdout = io.StringIO()
            try:
                with patch.object(tool, "_read_proof_directory", drift), \
                        patch("subprocess.Popen", side_effect=AssertionError("no replay launch")), \
                        patch("socket.socket", side_effect=AssertionError("no replay network")), redirect_stdout(stdout):
                    code = tool.main(origin + ["--stage", "installed-replay", "--replay-dir", str(supplied),
                                               "--evidence-dir", str(destination)])
            finally:
                helper.write_bytes(saved)
            self.assertTrue(changed["once"])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(stdout.getvalue())["code"], "runtime_inputs_changed")
            self.assertFalse(json.loads(stdout.getvalue())["durable_evidence"])
            self.assertFalse((destination / "replay-report.json").exists())

    def test_missing_package_dependencies_are_blocked_before_helper_effects(self):
        from taskalong.process import minimal_environment, run_bounded
        tool, _ = qualifier_context()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = run_bounded([sys.executable, "-I", "-S", str(tool), "--stage", "inventory",
                "--package-origin", "source", "--evidence-dir", str(root / "no-site-packages")],
                cwd=root, env=minimal_environment(), timeout_seconds=5, max_output_bytes=8192)
            self.assertEqual(result.exit_code, 3)
            report = json.loads(result.stdout)
            self.assertIn(report["code"], {"runtime_package_unavailable", "runtime_dependency_unavailable"})
            self.assertEqual(report["helper_invocations"], 0)
            self.assertFalse(report["durable_evidence"])
            self.assertEqual(result.stderr, b"")

    def test_inventory_recheck_failure_cannot_report_inventory_complete(self):
        tool = self.entrypoint()
        original = tool._measure
        watched = tool._helper_path(qualifier_context()[1][1])
        count = {"reads": 0}
        def drift(path, *args, **kwargs):
            measured = original(path, *args, **kwargs)
            if Path(path) == watched:
                count["reads"] += 1
                if count["reads"] > 1:
                    return measured | {"sha256": "0" * 64}
            return measured
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "changed-inventory"
            stdout = io.StringIO()
            with patch.object(tool, "_measure", drift), \
                    patch("taskalong.process.run_bounded", side_effect=AssertionError("inventory cannot launch")), \
                    redirect_stdout(stdout):
                code = tool.main(qualifier_context()[1] + ["--stage", "inventory", "--evidence-dir", str(destination)])
            self.assertEqual(code, 1)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["code"], "runtime_inputs_changed")
            self.assertFalse(result["complete"])
            document = json.loads((destination / "manifest.json").read_bytes())
            self.assertEqual(document["first_error"], {"case_id": None, "code": "runtime_inputs_changed"})
            self.assertFalse(document["inputs_rechecked"])

    def test_missing_locked_distribution_metadata_is_blocked_before_helper_effects(self):
        import importlib.metadata
        tool = self.entrypoint()
        original = importlib.metadata.distribution
        def missing(name):
            if name == "build":
                raise importlib.metadata.PackageNotFoundError(name)
            return original(name)
        with tempfile.TemporaryDirectory() as temporary:
            stdout = io.StringIO()
            with patch("importlib.metadata.distribution", side_effect=missing), \
                    patch("taskalong.process.run_bounded", side_effect=AssertionError("no dependency fallback")) as owner, \
                    redirect_stdout(stdout):
                code = tool.main(qualifier_context()[1] + ["--stage", "inventory",
                    "--evidence-dir", str(Path(temporary) / "missing-locked-metadata")])
            self.assertEqual(code, 3)
            self.assertEqual(owner.call_count, 0)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["code"], "runtime_dependency_unavailable")
            self.assertFalse(result["durable_evidence"])

    def test_unavailable_controller_uid_refuses_before_owned_dispatch(self):
        tool = self.entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            for index, value in enumerate([None, True, -1, "123", OSError("PRIVATE-UID-ERROR")]):
                stdout = io.StringIO()
                options = {"side_effect": value} if isinstance(value, OSError) else {"return_value": value}
                with self.subTest(value_type=type(value)), patch("os.geteuid", **options), \
                        patch("taskalong.process.run_bounded", side_effect=AssertionError("no dispatch")) as owner, \
                        redirect_stdout(stdout):
                    code = tool.main(qualifier_context()[1] + ["--evidence-dir", str(Path(temporary) / str(index))])
                self.assertEqual(code, 3)
                self.assertEqual(owner.call_count, 0)
                self.assertEqual(json.loads(stdout.getvalue())["code"], "runtime_privilege_unavailable")
                self.assertNotIn("PRIVATE-UID-ERROR", stdout.getvalue())

    def test_zero_and_nonzero_controller_classes_are_mocked_inventory_only(self):
        tool = self.entrypoint()
        with tempfile.TemporaryDirectory() as temporary:
            for uid, label in [(0, "effective_uid_zero"), (123, "effective_uid_nonzero")]:
                destination = Path(temporary) / label
                stdout = io.StringIO()
                with patch("os.geteuid", return_value=uid), \
                        patch("taskalong.process.run_bounded", side_effect=AssertionError("no privileged execution")) as owner, \
                        redirect_stdout(stdout):
                    code = tool.main(qualifier_context()[1] + ["--stage", "inventory", "--evidence-dir", str(destination)])
                self.assertEqual(code, 0)
                self.assertEqual(owner.call_count, 0)
                document = json.loads((destination / "manifest.json").read_bytes())
                facts = json.loads((destination / "blobs" / (document["inventory_ref"]["sha256"] + ".bin")).read_bytes())["measurements"]
                self.assertEqual(facts["host"]["privilege"], {"scope": "controller", "effective_uid": uid, "class": label})
                self.assertNotIn("effective_uid", stdout.getvalue())

    def test_controller_identity_drift_stops_before_next_owned_dispatch(self):
        from taskalong.process import run_bounded
        tool = self.entrypoint()
        original = tool._controller_privilege
        finished = {"first": False}
        def changed_identity():
            value = original()
            if finished["first"]:
                value = {"scope": "controller", "effective_uid": value["effective_uid"] + 1,
                         "class": "effective_uid_nonzero"}
            return value
        def first_owned(*args, **kwargs):
            value = run_bounded(*args, **kwargs)
            finished["first"] = True
            return value
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "identity-drift"
            stdout = io.StringIO()
            with patch.object(tool, "_controller_privilege", changed_identity), \
                    patch("taskalong.process.run_bounded", side_effect=first_owned) as owner, redirect_stdout(stdout):
                code = tool.main(qualifier_context()[1] + ["--evidence-dir", str(destination)])
            self.assertEqual(code, 1)
            self.assertEqual(owner.call_count, 1)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["code"], "runtime_inputs_changed")
            document = json.loads((destination / "manifest.json").read_bytes())
            self.assertEqual([case["verdict"] for case in document["cases"]], ["passed"] + ["not_run"] * 6)
            self.assertEqual(document["first_error"], {"case_id": None, "code": "runtime_inputs_changed"})
            self.assertFalse(document["quarantined"])


from test_execution_bindings import BindingFixture


class RuntimeProofAdmissionTests(BindingFixture, unittest.TestCase):
    def test_host_canary_proof_cannot_replace_admission_or_independent_acceptance(self):
        import shutil
        from taskalong.executors.codex_cli import CodexCLI

        document, _ = RuntimeManifestContractTests().completed_measurements()
        self.assertTrue(document["complete"])
        with self.assertRaises(TaskAlongError):
            self.service.configure_execution(**(self.configuration | {"receipts": [document]}))
        self.assertEqual(self.invocations(), [])
        reviewer = shutil.which("review-sensei") or str(Path(sys.executable).parent / "review-sensei")
        fixtures = Path(__file__).parent / "fixtures/reviewsensei"
        selected = self.service.configure_review(fixtures / "approved.yml", fixture_response=fixtures / "clean.json", executable=reviewer)
        self.task["review"]["config_digest"] = selected["config_digest"]
        self.check["review_config_digest"] = selected["config_digest"]
        from taskalong.validation import seal_versioned
        self.check = seal_versioned("check-binding", self.check, version="2.2")
        self.refresh_binding()
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        approval = self.trust["approvals"][0]["digest"]
        self.trust["revoked_approval_digests"] = [approval]
        self.service.configure_execution(**self.configuration)
        with self.assertRaises(TaskAlongError) as failure:
            self.start(run)
        self.assertEqual(failure.exception.code, "qualification_unsatisfied")
        self.assertEqual(self.invocations(), [])
        self.assertEqual(self.service.inspect(run["run_id"])["budget_consumed"]["attempts"], 0)
        self.trust["revoked_approval_digests"] = []
        self.service.configure_execution(**self.configuration)
        self.start(run, key="current-independent-approval")
        accepted = self.wait(run["run_id"])
        self.assertEqual(accepted["state"], "accepted", accepted["blockers"])
        self.assertEqual(len(self.invocations()), 1)
        result = self.service.result(run["run_id"])
        self.assertTrue(result["independently_accepted"])
        self.assertIsNotNone(result["acceptance_digest"])
        with self.assertRaises(TaskAlongError):
            CodexCLI(self.profile).preflight(qualification="production", budget={})


if __name__ == "__main__":
    unittest.main()
