"""Offline qualification uses explicit trusted approvals, not asserted flags."""
import json
import hashlib
import copy
import dataclasses
import unittest
from importlib import resources

from jsonschema import Draft202012Validator
from unittest.mock import patch
from pathlib import Path

from taskalong.errors import TaskAlongError

from taskalong.validation import canonical_bytes, schema, schema_names, seal_versioned


NOW = "2026-10-22T12:00:00Z"


def inputs():
    from taskalong.bindings import ExecutionBinding, HarnessInstallation, ProviderProfile
    root = resources.files("taskalong.resources").joinpath("examples/v2")
    installation = HarnessInstallation(root.joinpath("harness-installation.json").read_bytes())
    provider = ProviderProfile(root.joinpath("provider-profile.json").read_bytes())
    b = json.loads(root.joinpath("execution-binding.json").read_bytes())
    b["required_capabilities"] = ["start"]
    binding = ExecutionBinding.from_dict(seal_versioned("execution-binding", b, version="2.0"))
    context = {"artifact_digest": "a" * 64, "host_digest": "b" * 64, "effective_context_digest": "c" * 64,
               "test_inputs_digest": "d" * 64, "session_digest": None, "prior_invocation_digest": None}
    return binding, installation, provider, context


def subject(binding=None, supplied_context=None):
    b, i, p, context = inputs()
    b = binding if binding is not None else b
    context = supplied_context if supplied_context is not None else context
    data = b.to_dict()
    return {key: data[key] for key in ("installation_digest", "provider_profile_digest", "instruction_bundle_digest", "tool_policy_digest", "worker_sandbox_digest", "check_binding_digest")} | {
        "binding_digest": b.digest, "runtime_closure_digest": i.to_dict()["runtime_closure_digest"],
        "backend_id": i.to_dict()["platform"]["backend_id"], "provider": p.to_dict()["provider"],
        "model_digest": p.to_dict()["model"]["resolved_digest"],
        "native_resume_compatibility_digest": data["native_resume"]["compatibility_digest"] if data["native_resume"] else None, **context}


def reference(data, media="application/json"):
    return {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data), "media_type": media, "classification": "public"}


def example_receipt():
    capture = b"original synthetic dispatch observation\n"
    raw_ref = reference(capture, "text/plain")
    observation = {"kind": "qualification_observation", "schema_version": "2.1", "producer_id": "fixture-qa", "subject": subject(),
                   "mode": "start", "evidence_level": "offline_fixture", "capability": "start", "criterion_id": "fixture-start",
                   "expected_outcome": "supported", "observations": {"dispatch_observed": True, "subject_matched": True}, "capture_refs": [raw_ref]}
    raw = canonical_bytes(observation)
    ref = reference(raw)
    document = seal_versioned("qualification-receipt", {"receipt_id": "fixture-receipt", "producer_id": "fixture-qa", "subject": subject(),
        "mode": "start", "evidence_level": "offline_fixture", "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z",
        "results": [{"capability": "start", "outcome": "supported", "evidence_refs": [ref]}],
        "usage": {"input_tokens": None, "output_tokens": None, "cost_micro_usd": None}, "limitations": ["Synthetic fixture; no provider proof."]}, version="2.1")
    return document, {ref["sha256"]: raw, raw_ref["sha256"]: capture}


def policy_for(receipt):
    approval = {"producer_id": receipt["producer_id"], "receipt_digest": receipt["digest"],
                "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z"}
    approval["digest"] = hashlib.sha256(json.dumps(approval, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"producers": [{"producer_id": receipt["producer_id"], "allowed_evidence_levels": ["offline_fixture"]}],
            "approvals": [approval], "revoked_receipt_digests": [], "revoked_approval_digests": [], "revoked_evidence_digests": []}


def reseal(receipt):
    return seal_versioned("qualification-receipt", receipt, version="2.1")


def measured(capability, facts, outcome="supported", *, binding=None, context=None, mode="start"):
    receipt, blobs = example_receipt()
    old = receipt["results"][0]["evidence_refs"][0]
    obs = json.loads(blobs.pop(old["sha256"]))
    obs.update(capability=capability, observations=facts, subject=subject(binding, context), mode=mode)
    raw = canonical_bytes(obs)
    ref = reference(raw)
    blobs[ref["sha256"]] = raw
    receipt.update(subject=obs["subject"], mode=mode, results=[{"capability": capability, "outcome": outcome, "evidence_refs": [ref]}])
    return reseal(receipt), blobs


def run_case(receipt, blobs, *, policy=None, binding=None, context=None, mode="start", now=NOW):
    from taskalong.qualification import EvidenceStore, TrustPolicy, evaluate
    b, i, p, original_context = inputs()
    return evaluate(binding if binding is not None else b, installation=i, provider=p,
        context=context if context is not None else original_context, mode=mode, receipts=[receipt],
        trust=TrustPolicy.from_dict(policy if policy is not None else policy_for(receipt)),
        evidence=EvidenceStore.from_blobs(blobs), now=now, minimum_level="offline_fixture")


class QualificationResourceTests(unittest.TestCase):
    def test_packaged_offline_example_reproduces_sealed_decision_and_report(self):
        from taskalong.bindings import ExecutionBinding, HarnessInstallation, ProviderProfile
        from taskalong.qualification import EvidenceStore, QualificationReceipt, QualificationDecision, CapabilityReport, TrustPolicy, evaluate
        root = resources.files("taskalong.resources")
        example = root.joinpath("examples/v2.1")
        binding = ExecutionBinding(example.joinpath("binding-fixture.json").read_bytes())
        installation = HarnessInstallation(root.joinpath("examples/v2/harness-installation.json").read_bytes())
        provider = ProviderProfile(root.joinpath("examples/v2/provider-profile.json").read_bytes())
        receipt = QualificationReceipt(example.joinpath("qualification-receipt.json").read_bytes())
        policy = TrustPolicy(example.joinpath("trust-policy.json").read_bytes())
        blobs = {}
        for name in ("evidence-observation.json", "capture.txt"):
            raw = example.joinpath(name).read_bytes()
            blobs[hashlib.sha256(raw).hexdigest()] = raw
        context = {key: receipt.to_dict()["subject"][key] for key in ("artifact_digest", "host_digest", "effective_context_digest", "test_inputs_digest", "session_digest", "prior_invocation_digest")}
        result = evaluate(binding, installation=installation, provider=provider, context=context, mode="start", receipts=[receipt], trust=policy, evidence=EvidenceStore.from_blobs(blobs), now=NOW, minimum_level="offline_fixture")
        self.assertEqual(result.decision.to_bytes(), QualificationDecision(example.joinpath("qualification-decision.json").read_bytes()).to_bytes())
        self.assertEqual(result.report.to_bytes(), CapabilityReport(example.joinpath("capability-report.json").read_bytes()).to_bytes())
        self.assertFalse(result.report.to_dict()["production_dispatch_allowed"])

    def test_new_records_do_not_redefine_m1_version_or_examples(self):
        from taskalong.qualification import QualificationReceipt
        self.assertEqual(set(schema_names(version="2.0")), {"harness-installation", "provider-profile", "execution-binding"})
        expected = {"qualification-receipt", "qualification-decision", "capability-report"}
        self.assertEqual(set(schema_names(version="2.1")), expected)
        for name in expected:
            doc = schema(name, version="2.1")
            Draft202012Validator.check_schema(doc)
            self.assertEqual(doc["$id"], "urn:taskalong:schema:v2.1:" + name)
        raw = resources.files("taskalong.resources").joinpath("examples/v2.1/qualification-receipt.json").read_bytes()
        receipt = QualificationReceipt(raw)
        self.assertEqual(receipt.to_dict()["schema_version"], "2.1")
        frozen = json.loads((Path(__file__).parent / "fixtures/m1-contract-hashes.json").read_text())
        for name, expected_hash in frozen.items():
            self.assertEqual(hashlib.sha256(resources.files("taskalong.resources").joinpath(name).read_bytes()).hexdigest(), expected_hash)


class QualificationTests(unittest.TestCase):
    def test_start_mode_cannot_report_native_resume_support(self):
        from taskalong.bindings import ExecutionBinding
        from taskalong.qualification import EvidenceStore, TrustPolicy, evaluate
        b, i, p, context = inputs()
        data = b.to_dict()
        data["required_capabilities"] = ["native_resume", "start"]
        data["native_resume"] = {"protocol_version": "fixture-1", "session_scope": "exact_stored_session"}
        semantic = {key: value for key, value in data.items() if key != "digest"}
        data["native_resume"]["compatibility_digest"] = hashlib.sha256(json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        binding = ExecutionBinding.from_dict(seal_versioned("execution-binding", data, version="2.0"))
        for supplied in (context, context | {"session_digest": "e" * 64, "prior_invocation_digest": "f" * 64}):
            start, start_blobs = measured("start", {"dispatch_observed": True, "subject_matched": True}, binding=binding, context=supplied)
            resume, resume_blobs = measured("native_resume", {"exact_session": True, "compatibility_matched": True,
                "previous_invocation_stopped": True, "fresh_attempt": True}, binding=binding, context=supplied)
            policy = policy_for(start)
            policy["approvals"] += policy_for(resume)["approvals"]
            result = evaluate(binding, installation=i, provider=p, context=supplied, mode="start", receipts=[start, resume],
                trust=TrustPolicy.from_dict(policy), evidence=EvidenceStore.from_blobs(start_blobs | resume_blobs), now=NOW,
                minimum_level="offline_fixture").decision.to_dict()
            with self.subTest(context=supplied):
                self.assertFalse(result["requirements_satisfied"])
                native = next(item for item in result["capability_results"] if item["capability"] == "native_resume")
                self.assertEqual(native["outcome"], "unknown")
                self.assertEqual(result["rejected_receipts"], [{"input_index": 1, "reason_code": "mode_mismatch"}])

    def test_native_resume_requires_exact_prior_session_and_separate_mode(self):
        from taskalong.bindings import ExecutionBinding
        b, _, _, context = inputs()
        data = b.to_dict()
        data["required_capabilities"] = ["native_resume"]
        data["native_resume"] = {"protocol_version": "fixture-1", "session_scope": "exact_stored_session"}
        subject_data = {k:v for k,v in data.items() if k != "digest"}
        data["native_resume"]["compatibility_digest"] = hashlib.sha256(json.dumps(subject_data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        binding = ExecutionBinding.from_dict(seal_versioned("execution-binding", data, version="2.0"))
        context = context | {"session_digest": "e" * 64, "prior_invocation_digest": "f" * 64}
        facts = {"exact_session": True, "compatibility_matched": True, "previous_invocation_stopped": True, "fresh_attempt": True}
        receipt, blobs = measured("native_resume", facts, binding=binding, context=context, mode="native_resume")
        self.assertTrue(run_case(receipt, blobs, binding=binding, context=context, mode="native_resume").decision.to_dict()["requirements_satisfied"])
        changed = run_case(receipt, blobs, binding=binding, context=context | {"session_digest": "d" * 64}, mode="native_resume")
        self.assertEqual(changed.decision.to_dict()["rejected_receipts"][0]["reason_code"], "subject_mismatch")
        start = reseal(receipt | {"mode": "start"})
        self.assertEqual(run_case(start, blobs, binding=binding, context=context, mode="native_resume").decision.to_dict()["rejected_receipts"][0]["reason_code"], "mode_mismatch")
        with self.assertRaises(TaskAlongError):
            run_case(receipt, blobs, binding=binding, mode="native_resume")

    def test_rotation_preserves_binding_and_prior_decision_and_conflicts_fail_closed(self):
        from taskalong.qualification import EvidenceStore, TrustPolicy, evaluate
        b, i, p, context = inputs()
        original, blobs = example_receipt()
        first = run_case(original, blobs)
        before = first.decision.to_bytes()
        rotated = reseal(original | {"receipt_id": "rotated-receipt"})
        second = run_case(rotated, blobs)
        self.assertEqual(first.decision.to_bytes(), before)
        self.assertNotEqual(first.decision.digest, second.decision.digest)
        self.assertEqual(first.decision.to_dict()["subject"]["binding_digest"], b.digest)
        self.assertEqual(second.decision.to_dict()["subject"]["binding_digest"], b.digest)
        for fact, outcome in ((None, "unknown"), (False, "unsupported")):
            negative, more = measured("start", {"dispatch_observed": fact, "subject_matched": True}, outcome)
            policy = policy_for(original)
            policy["approvals"] += policy_for(negative)["approvals"]
            result = evaluate(b, installation=i, provider=p, context=context, mode="start", receipts=[original, negative, original],
                trust=TrustPolicy.from_dict(policy), evidence=EvidenceStore.from_blobs(blobs | more), now=NOW, minimum_level="offline_fixture")
            self.assertEqual(result.report.to_dict()["overall_outcome"], outcome)
            self.assertEqual(len(result.decision.to_dict()["verified_receipt_digests"]), 2)

    def test_snapshot_inputs_and_contracts_are_strict_and_bounded(self):
        from taskalong.qualification import EvidenceStore, TrustPolicy, evaluate
        receipt, blobs = example_receipt()
        bad = policy_for(receipt)
        bad["approvals"][0]["digest"] = "0" * 64
        with self.assertRaises(TaskAlongError):TrustPolicy.from_dict(bad)
        data = b"x" * 1_048_577
        with self.assertRaises(TaskAlongError):EvidenceStore.from_blobs({hashlib.sha256(data).hexdigest(): data})
        b, i, p, context = inputs()
        trust = TrustPolicy.from_dict(policy_for(receipt))
        for extra in ({"mode": {}}, {"minimum_level": []}, {"now": "2026-10-22 12:00:00Z"}, {"receipts": [receipt] * 65}):
            args = {"installation": i, "provider": p, "context": context, "mode": "start", "receipts": [receipt], "trust": trust, "evidence": EvidenceStore.from_blobs(blobs), "now": NOW, **extra}
            with self.subTest(extra=extra), self.assertRaises(TaskAlongError):evaluate(b, **args)

    def test_verified_receipt_limitations_survive_the_report(self):
        receipt, blobs = example_receipt()
        result = run_case(receipt, blobs)
        self.assertIn(receipt["limitations"][0], result.report.to_dict()["limitations"])

    def test_exact_subject_fields_and_modes_are_never_inferred(self):
        original, blobs = example_receipt()
        for key in original["subject"]:
            changed = copy.deepcopy(original)
            value = changed["subject"][key]
            changed["subject"][key] = "other-backend" if key == "backend_id" else "anthropic-api" if key == "provider" else "e" * 64
            if changed["subject"][key] == value:
                changed["subject"][key] = "f" * 64
            with self.subTest(key=key):
                result = run_case(reseal(changed), blobs).decision.to_dict()
                self.assertFalse(result["requirements_satisfied"])
                self.assertEqual(result["rejected_receipts"][0]["reason_code"], "subject_mismatch")
        for mode in ("observe", "cancel", "result", "provider_lookup", "remote_cancel"):
            result = run_case(original, blobs, mode=mode).decision.to_dict()
            self.assertEqual(result["rejected_receipts"][0]["reason_code"], "mode_mismatch")

    def test_trusted_names_hashes_and_current_approvals_are_not_interchangeable(self):
        receipt, blobs = example_receipt()
        policy = policy_for(receipt)
        cases = [
            (policy | {"producers": []}, "producer_untrusted"),
            (policy | {"producers": [{"producer_id": "fixture-qa", "allowed_evidence_levels": ["actual_provider"]}]}, "evidence_level_untrusted"),
            (policy | {"approvals": []}, "approval_missing"),
            (policy | {"revoked_receipt_digests": [receipt["digest"]]}, "receipt_revoked"),
            (policy | {"revoked_approval_digests": [policy["approvals"][0]["digest"]]}, "approval_revoked"),
            (policy | {"revoked_evidence_digests": [receipt["results"][0]["evidence_refs"][0]["sha256"]]}, "evidence_revoked"),
        ]
        expired = copy.deepcopy(policy)
        expired["approvals"][0]["valid_until"] = NOW
        approval = expired["approvals"][0]
        approval["digest"] = hashlib.sha256(json.dumps({k:v for k,v in approval.items() if k != "digest"},sort_keys=True,separators=(",", ":")).encode()).hexdigest()
        cases.append((expired, "approval_not_current"))
        for data, code in cases:
            with self.subTest(code=code):
                result = run_case(receipt, blobs, policy=data).decision.to_dict()
                self.assertFalse(result["requirements_satisfied"])
                self.assertEqual(result["rejected_receipts"][0]["reason_code"], code)
        forged = reseal(receipt | {"receipt_id": "forged-under-known-producer"})
        self.assertEqual(run_case(forged, blobs, policy=policy).decision.to_dict()["rejected_receipts"][0]["reason_code"], "approval_missing")
        for now in ("2025-12-31T23:59:59Z", "2027-01-01T00:00:00Z"):
            self.assertEqual(run_case(receipt, blobs, now=now).decision.to_dict()["rejected_receipts"][0]["reason_code"], "receipt_not_current")

    def test_missing_tampered_or_mismatched_raw_evidence_never_qualifies(self):
        from taskalong.qualification import EvidenceStore
        receipt, blobs = example_receipt()
        obs_ref = receipt["results"][0]["evidence_refs"][0]
        for data in ({}, {obs_ref["sha256"]: blobs[obs_ref["sha256"]]}):
            self.assertEqual(run_case(receipt, data).decision.to_dict()["rejected_receipts"][0]["reason_code"], "evidence_missing")
        with self.assertRaises(TaskAlongError):
            EvidenceStore.from_blobs({obs_ref["sha256"]: b"tampered bytes"})
        wrong_size = copy.deepcopy(receipt)
        wrong_size["results"][0]["evidence_refs"][0]["size_bytes"] += 1
        self.assertEqual(run_case(reseal(wrong_size), blobs).decision.to_dict()["rejected_receipts"][0]["reason_code"], "evidence_mismatch")
        obs = json.loads(blobs[obs_ref["sha256"]])
        for change in ({"mode": "cancel"}, {"producer_id": "different-producer"}, {"subject": subject() | {"model_digest": "e" * 64}}):
            raw = canonical_bytes(obs | change)
            changed = copy.deepcopy(receipt)
            changed["results"][0]["evidence_refs"] = [reference(raw)]
            result = run_case(reseal(changed), blobs | {hashlib.sha256(raw).hexdigest(): raw})
            self.assertEqual(result.decision.to_dict()["rejected_receipts"][0]["reason_code"], "evidence_subject_mismatch")
        malformed = b'{"kind":"qualification_observation","kind":"duplicate"}'
        changed = copy.deepcopy(receipt)
        changed["results"][0]["evidence_refs"] = [reference(malformed)]
        self.assertEqual(run_case(reseal(changed), {**blobs, hashlib.sha256(malformed).hexdigest(): malformed}).decision.to_dict()["rejected_receipts"][0]["reason_code"], "evidence_invalid")

    def test_delivered_signal_is_not_cessation_and_local_is_not_remote(self):
        from taskalong.bindings import ExecutionBinding
        b = inputs()[0].to_dict() | {"required_capabilities": ["local_cessation"]}
        binding = ExecutionBinding.from_dict(seal_versioned("execution-binding", b, version="2.0"))
        for descendant, outcome in ((None, "unknown"), (False, "unsupported"), (True, "supported")):
            receipt, blobs = measured("local_cessation", {"root_stopped": True, "owned_descendants_stopped": descendant}, outcome, binding=binding, mode="cancel")
            result = run_case(receipt, blobs, binding=binding, mode="cancel")
            self.assertEqual(result.report.to_dict()["overall_outcome"], outcome)
            remote = run_case(receipt, blobs, binding=binding, mode="remote_cancel")
            self.assertFalse(remote.decision.to_dict()["requirements_satisfied"])
            if descendant is None:
                forged = reseal(receipt | {"results": [receipt["results"][0] | {"outcome": "supported"}]})
                self.assertEqual(run_case(forged, blobs, binding=binding, mode="cancel").decision.to_dict()["rejected_receipts"][0]["reason_code"], "evidence_outcome_mismatch")

    def test_hard_caps_require_complete_facts_and_exact_numeric_limit(self):
        from taskalong.bindings import ExecutionBinding
        for cap, key, flag in (("hard_token_cap", "max_tokens", "hard_token_cap_required"), ("hard_cost_cap", "max_cost_micro_usd", "hard_cost_cap_required")):
            b = inputs()[0].to_dict()
            b["required_capabilities"] = [cap]
            b["budget"].update({key: 10, flag: True})
            binding = ExecutionBinding.from_dict(seal_versioned("execution-binding", b, version="2.0"))
            facts = {"all_routes_accounted": True, "enforced_before_dispatch": True, "prevents_overrun": True, "limit": 10}
            if cap == "hard_cost_cap":facts["billing_bound_known"] = True
            for changed, expected in ((facts, "supported"), (facts | {"limit": 100}, "unsupported"), (facts | {"all_routes_accounted": None}, "unknown")):
                receipt, blobs = measured(cap, changed, expected, binding=binding)
                result = run_case(receipt, blobs, binding=binding).report.to_dict()
                entry = next(x for x in result["capability_results"] if x["capability"] == cap)
                self.assertEqual(entry["outcome"], "supported" if expected == "supported" else "unsupported")
                self.assertFalse(result["production_dispatch_allowed"])

    def test_frozen_receipts_policy_and_report_preserve_null_usage(self):
        from taskalong.qualification import QualificationReceipt, TrustPolicy
        receipt, blobs = example_receipt()
        frozen = QualificationReceipt.from_dict(receipt)
        receipt["subject"]["host_digest"] = "e" * 64
        self.assertNotEqual(receipt["subject"], frozen.to_dict()["subject"])
        with self.assertRaises(dataclasses.FrozenInstanceError):
            frozen._canonical = b"{}"
        policy = policy_for(frozen.to_dict())
        trust = TrustPolicy.from_dict(policy)
        policy["producers"].clear()
        self.assertEqual(len(trust.to_dict()["producers"]), 1)
        result = run_case(frozen.to_dict(), blobs)
        self.assertIsNone(result.report.to_dict()["per_receipt_usage"][0]["usage"]["cost_micro_usd"])
        for change in ({"qualified": True}, {"schema_version": "2.0"}, {"usage": {"input_tokens": 1.5, "output_tokens": None, "cost_micro_usd": None}}, {"usage": {"input_tokens": 2**53, "output_tokens": None, "cost_micro_usd": None}}):
            with self.subTest(change=change), self.assertRaises(TaskAlongError):
                QualificationReceipt.from_dict(frozen.to_dict() | change)

    def test_exact_approved_capture_satisfies_only_requested_fixture_level(self):
        from taskalong.qualification import EvidenceStore, QualificationReceipt, TrustPolicy, evaluate
        b, i, p, context = inputs()
        receipt, blobs = example_receipt()
        kwargs = dict(installation=i, provider=p, context=context, mode="start", receipts=[QualificationReceipt.from_dict(receipt)],
                      trust=TrustPolicy.from_dict(policy_for(receipt)), evidence=EvidenceStore.from_blobs(blobs), now=NOW)
        result = evaluate(b, **kwargs, minimum_level="offline_fixture")
        decision, report = result.decision.to_dict(), result.report.to_dict()
        self.assertTrue(decision["requirements_satisfied"])
        self.assertEqual(report["overall_outcome"], "supported")
        self.assertFalse(report["production_dispatch_allowed"])
        self.assertEqual(decision["verified_receipt_digests"], [receipt["digest"]])
        self.assertEqual(report["per_receipt_usage"], [{"receipt_digest": receipt["digest"], "usage": {"input_tokens": None, "output_tokens": None, "cost_micro_usd": None}}])
        actual = evaluate(b, **kwargs)
        self.assertFalse(actual.decision.to_dict()["requirements_satisfied"])
        self.assertEqual(actual.decision.to_dict()["rejected_receipts"][0]["reason_code"], "evidence_level_insufficient")

    def test_empty_trust_defaults_unknown_without_external_effects_or_runtime_permission(self):
        from taskalong.qualification import EvidenceStore, TrustPolicy, evaluate
        b, i, p, context = inputs()
        trust = TrustPolicy.from_dict({"producers": [], "approvals": [], "revoked_receipt_digests": [], "revoked_approval_digests": [], "revoked_evidence_digests": []})
        with patch("subprocess.Popen", side_effect=AssertionError("spawn")), patch("socket.socket", side_effect=AssertionError("network")), patch("builtins.open", side_effect=AssertionError("discovery")):
            result = evaluate(b, installation=i, provider=p, context=context, mode="start", receipts=[], trust=trust, evidence=EvidenceStore.from_blobs({}), now=NOW)
        report = result.report.to_dict()
        self.assertEqual(report["overall_outcome"], "unknown")
        self.assertEqual(report["capability_results"], [{"capability": "start", "outcome": "unknown", "reason_codes": ["no_evidence"], "evidence_digests": []}])
        self.assertFalse(result.decision.to_dict()["requirements_satisfied"])
        self.assertFalse(report["production_dispatch_allowed"])


if __name__ == "__main__":
    unittest.main()
