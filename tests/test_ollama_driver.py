"""Original offline Ollama-through-Claude fixtures over the common lifecycle."""
import unittest
from unittest.mock import patch

from taskalong.bindings import ProviderProfile
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, digest, loads, seal_versioned
from test_claude_driver import ClaudeBindingFixture
from test_executor_contract import DurableDriverContract
from test_ollama_profiles import route_observation


class OllamaBindingFixture(ClaudeBindingFixture):
    cloud = False

    def setUp(self):
        super().setUp()
        from taskalong.api import RunService
        from taskalong.store import Store
        self.service.close()
        with Store.maintenance(self.state) as store:
            store.upgrade(operation_key="m6", backup_dir=self.root/"backup5", restore_dir=self.root/"restore5", target_version=5)
        self.service = RunService(self.state)
        self.provider = seal_versioned("provider-profile", self.provider | {
            "profile_id": "fixture-ollama-cloud" if self.cloud else "fixture-ollama-local",
            "provider": "ollama-cloud" if self.cloud else "ollama-local",
            "endpoint": "https://ollama.com" if self.cloud else "http://127.0.0.1:11434",
            "auth": {"mode": "credential-ref", "credential_ref": "fixture-ollama-cloud"} if self.cloud
                    else {"mode": "local-no-secret", "credential_ref": None},
            "effort": None, "allowed_disclosure": "provider-only" if self.cloud else "local-only"}, version="2.0")
        self.installation = seal_versioned("harness-installation", self.installation | {
            "installation_id": "fixture-claude-ollama", "driver_version": "claude-print-ollama-fixture-1",
            "cli_version": "synthetic-claude-ollama-1"}, version="2.0")
        self.driver_config = seal_versioned("driver-config", self.driver_config | {
            "schema_version": "2.4", "driver_version": "claude-print-ollama-fixture-1",
            "projection": "claude-ollama-fixture/1", "wire_version": "2.4",
            "installation_digest": self.installation["digest"], "provider_profile_digest": self.provider["digest"],
            "credential_ref": self.provider["auth"]["credential_ref"],
            "fixture_route_observation": route_observation(ProviderProfile.from_dict(self.provider),
                model_origin="cloud" if self.cloud else "local")}, version="2.4")
        self.refresh_binding()

    def refresh_binding(self):
        """Explicit fixture measurements bind the same config context in both modes."""
        from test_qualification import reference, policy_for
        self.binding = seal_versioned("execution-binding", self.binding | {
            "installation_digest": self.installation["digest"], "provider_profile_digest": self.provider["digest"],
            "check_binding_digest": self.check["digest"]}, version="2.0")
        self.driver_config = seal_versioned("driver-config", self.driver_config | {"policy_digests": {
            "instructions": self.binding["instruction_bundle_digest"], "tools": self.binding["tool_policy_digest"],
            "worker_sandbox": self.binding["worker_sandbox_digest"], "check_binding": self.check["digest"]}}, version="2.4")
        policies = [self.instructions, self.tools, self.worker_sandbox, self.check, self.check_sandbox]
        self.context["effective_context_digest"] = digest({"policies": sorted(policies, key=lambda item:item["digest"]),
            "driver_config_digest": self.driver_config["digest"]})
        subject = self.receipt["subject"] | {key: self.binding[key] for key in (
            "installation_digest", "provider_profile_digest", "instruction_bundle_digest", "tool_policy_digest",
            "worker_sandbox_digest", "check_binding_digest")} | {
            "binding_digest": self.binding["digest"], "runtime_closure_digest": self.installation["runtime_closure_digest"],
            "provider": self.provider["provider"], "model_digest": self.provider["model"]["resolved_digest"], **self.context}
        subject["native_resume_compatibility_digest"] = self.binding["native_resume"]["compatibility_digest"] if self.binding["native_resume"] else None
        source = loads(self.configuration["evidence"][self.receipt["results"][0]["evidence_refs"][0]["sha256"]])
        leaf = canonical_bytes(self.driver_config["fixture_route_observation"])
        capture = reference(leaf) | {"classification": "private"}
        blobs = {ref["sha256"]: self.configuration["evidence"][ref["sha256"]] for ref in source["capture_refs"]}
        blobs[capture["sha256"]] = leaf
        receipts = []
        for mode, capability in (("start", "start"), ("provider_lookup", "start"), ("provider_lookup", "provider_lookup")):
            facts = {"dispatch_observed": True, "subject_matched": True} if capability == "start" else {
                "destination_matched": True, "model_digest_matched": True, "auth_matched": True}
            observation = source | {"subject": subject, "mode": mode, "capability": capability, "observations": facts,
                "capture_refs": [capture] if capability == "provider_lookup" else source["capture_refs"]}
            raw = canonical_bytes(observation)
            ref = reference(raw)
            blobs[ref["sha256"]] = raw
            receipts.append(seal_versioned("qualification-receipt", self.receipt | {
                "subject": subject, "mode": mode,
                "results": [{"capability": capability, "outcome": "supported", "evidence_refs": [ref]}]}, version="2.1"))
        self.receipt = receipts[0]
        self.trust = policy_for(receipts[0])
        for receipt in receipts[1:]:
            self.trust["approvals"] += policy_for(receipt)["approvals"]
        self.configuration.update(binding=self.binding, installation=self.installation, provider=self.provider,
            driver_config=self.driver_config, policies=policies, receipts=receipts, trust=self.trust,
            evidence=blobs, context=self.context, projection="claude-ollama-fixture/1")
        self.task = seal_versioned("task-spec", self.task | {"schema_version": "2.4", "execution": {
            "binding_digest": self.binding["digest"], "driver_config_digest": self.driver_config["digest"]},
            "permissions": self.task["permissions"] | {"inference_destination_id": self.provider["profile_id"]}}, version="2.4")


class OllamaAdmissionTests(OllamaBindingFixture, unittest.TestCase):
    def test_external_server_cancellation_requirement_is_outside_the_projection(self):
        self.binding["required_capabilities"] = ["remote_cancellation", "start"]
        self.refresh_binding()
        with self.assertRaises(TaskAlongError) as failure:
            self.service.configure_execution(**self.configuration)
        self.assertEqual(failure.exception.code, "remote_cancellation_unsupported")
        self.assertEqual(self.invocations(), [])
        self.assertEqual(self.service._store.db.execute("SELECT count(*) FROM execution_projections").fetchone()[0], 0)

    def test_both_exact_mode_decisions_are_retained_and_capability_is_read_only(self):
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        before = self.service.inspect(run["run_id"])
        view = self.service.capabilities(run["run_id"])
        self.assertTrue(view["requirements_satisfied"])
        self.assertFalse(view["production_dispatch_allowed"])
        from taskalong.admission import resolve
        snapshot, _, _ = resolve(self.service._store, self.task)
        self.assertEqual(snapshot["decision"]["mode"], "start")
        self.assertEqual(snapshot["provider_lookup_decision"]["mode"], "provider_lookup")
        self.assertEqual(snapshot["decision"]["evaluated_at"], snapshot["provider_lookup_decision"]["evaluated_at"])
        self.assertEqual(snapshot["decision"]["subject"], snapshot["provider_lookup_decision"]["subject"])
        self.assertEqual(snapshot["digest"], digest(snapshot))
        self.assertEqual(self.service.inspect(run["run_id"]), before)
        self.assertEqual(self.invocations(), [])


class OllamaLifecycleContract:
    # The existing acceptance/restart oracles exercise each new provider route.
    from test_execution_bindings import ExecutionAdmissionTests as _Admission
    from test_claude_driver import ClaudePublicLifecycleTests as _Lifecycle
    configure_and_submit = _Admission.configure_and_submit
    assert_no_attempt = _Admission.assert_no_attempt
    test_full_independent_acceptance_keeps_verifier_binding_distinct = _Admission.test_full_independent_acceptance_keeps_verifier_binding_distinct
    test_readonly_views_do_not_prepare_reconcile_or_issue_authority = _Admission.test_readonly_views_do_not_prepare_reconcile_or_issue_authority
    test_nonnull_cost_or_token_limit_is_never_dropped = _Admission.test_nonnull_cost_or_token_limit_is_never_dropped
    test_required_native_resume_cannot_borrow_start_receipt = _Admission.test_required_native_resume_cannot_borrow_start_receipt
    test_restart_uses_new_attempt_session_and_cannot_reset_budget = _Lifecycle.test_restart_uses_new_attempt_session_and_cannot_reset_budget
    test_failed_restarts_exhaust_persisted_attempt_budget = _Lifecycle.test_failed_restarts_exhaust_persisted_attempt_budget

    def test_missing_lookup_evidence_can_be_registered_but_cannot_admit_or_dispatch(self):
        self.configuration["receipts"] = [self.receipt]
        self.service.configure_execution(**self.configuration)
        with self.assertRaises(TaskAlongError) as failure:
            self.service.submit(self.task, operation_key="without-lookup")
        self.assertEqual(failure.exception.code, "provider_route_evidence_unqualified")
        self.assertEqual(self.service._store.db.execute("SELECT count(*) FROM runs").fetchone()[0], 0)
        self.assertEqual(self.invocations(), [])

    def expire_at_dispatch(self, selected_mode):
        from datetime import datetime, timedelta, timezone
        from test_qualification import policy_for
        from taskalong.workflow import drive_run
        current = datetime.now(timezone.utc)
        expiry = (current+timedelta(hours=1)).isoformat(timespec="seconds").replace("+00:00", "Z")
        later = (current+timedelta(hours=2)).isoformat(timespec="seconds").replace("+00:00", "Z")
        receipts = [seal_versioned("qualification-receipt", item | {"valid_until": expiry}, version="2.1")
                    if item["mode"] == selected_mode else item for item in self.configuration["receipts"]]
        policy = policy_for(receipts[0])
        for item in receipts[1:]:
            policy["approvals"] += policy_for(item)["approvals"]
        self.configuration.update(receipts=receipts, trust=policy)
        run = self.configured_task()
        with patch.object(self.service._workflow, "_launch_supervisor"):
            prepared = self.start(run)
        with patch("taskalong.admission.now", return_value=later):
            drive_run(self.state, run["run_id"], prepared["active_attempt_id"])
        attempt = self.service._store.detail("attempts", prepared["active_attempt_id"])
        self.assertEqual(attempt["error"], "qualification_unsatisfied" if selected_mode == "start" else "provider_route_evidence_unqualified")
        self.assertTrue(attempt["termination_confirmed"])
        self.assertEqual(self.invocations(), [])
        self.assertIsNone(self.service.inspect(run["run_id"])["acceptance_id"])

    def test_start_expiry_after_prepare_never_dispatches(self):
        self.expire_at_dispatch("start")

    def test_lookup_expiry_after_prepare_never_dispatches(self):
        self.expire_at_dispatch("provider_lookup")

    def test_wrong_model_response_cannot_trigger_acceptance_or_a_provider_fallback(self):
        self.set_mode("wrong-model")
        run = self.configured_task()
        self.start(run)
        stopped = self.wait(run["run_id"])
        self.assertIsNone(stopped["acceptance_id"])
        self.assertEqual(len(self.invocations()), 1)
        self.assertEqual(self.invocations()[0]["ollama_fixture_request"]["endpoint"], self.provider["endpoint"])
        self.assertNotEqual(self.service.result(run["run_id"])["outcome"], "worker_completed")

    def test_controlled_request_matches_exact_route_without_inherited_credentials_or_server_effect(self):
        inherited = {"ANTHROPIC_API_KEY": "synthetic-inherited-value", "ANTHROPIC_MODEL": "unselected",
            "OLLAMA_API_KEY": "synthetic-inherited-value", "HTTPS_PROXY": "https://unselected.invalid"}
        run = self.configured_task()
        with patch.dict("os.environ", inherited):
            self.start(run)
            stopped = self.wait(run["run_id"])
        self.assertEqual(self.service.result(run["run_id"])["outcome"], "worker_completed")
        attempt = self.service._store.detail("attempts", stopped["attempts"][0]["attempt_id"])
        observed = self.invocations()[0]["ollama_fixture_request"]
        self.assertEqual(observed, {
            "endpoint": "https://ollama.com" if self.cloud else "http://127.0.0.1:11434",
            "requested_model": "fixture-claude-model", "resolved_model_digest": self.provider["model"]["resolved_digest"],
            "model_origin": "cloud" if self.cloud else "local", "driver_config_digest": self.driver_config["digest"],
            "provider_profile_digest": self.provider["digest"], "packet_digest": attempt["packet"]["digest"],
            "session_id": attempt["attempt_id"], "token_present": True, "token_matched": True,
            "unexpected_environment_present": False, "external_request": "not_sent", "qualification": "synthetic"})
        rendered = canonical_bytes({"invocations": self.invocations(), "result": self.service.result(run["run_id"]),
                                    "events": self.service.events(run["run_id"])})
        self.assertNotIn(b"synthetic-inherited-value", rendered)
        self.assertNotIn(b"taskalong-fixture-ollama-cloud-1", rendered)
        self.assertIsNone(stopped["budget_consumed"]["cost_usd"])

    def test_lookup_revocation_before_start_refuses_without_reservation_or_fallback(self):
        run = self.configured_task()
        lookup = self.configuration["receipts"][-1]
        self.trust["revoked_receipt_digests"] = [lookup["digest"]]
        self.service.configure_execution(**self.configuration)
        caps = self.service.capabilities(run["run_id"])
        self.assertFalse(caps["requirements_satisfied"])
        self.assertEqual(caps["reason_codes"], ["provider_route_evidence_unqualified"])
        with self.assertRaises(TaskAlongError) as failure:
            self.start(run)
        self.assertEqual(failure.exception.code, "provider_route_evidence_unqualified")
        self.assert_no_attempt(run)

    def test_lookup_revocation_at_owned_gate_never_executes_target(self):
        from taskalong.executors.claude_code import ClaudeCode
        from taskalong.workflow import drive_run
        run = self.configured_task()
        with patch.object(self.service._workflow, "_launch_supervisor"):
            prepared = self.start(run)
        original = ClaudeCode.build_argv
        def revoke(driver, packet):
            argv = original(driver, packet)
            self.trust["revoked_evidence_digests"] = [self.configuration["receipts"][-1]["results"][0]["evidence_refs"][0]["sha256"]]
            self.service.configure_execution(**self.configuration)
            return argv
        with patch.object(ClaudeCode, "build_argv", revoke):
            drive_run(self.state, run["run_id"], prepared["active_attempt_id"])
        current = self.service.inspect(run["run_id"])
        self.assertEqual(current["state"], "blocked")
        self.assertEqual(current["blockers"][0]["code"], "provider_route_evidence_unqualified")
        self.assertEqual(self.invocations(), [])
        self.assertIsNone(current["acceptance_id"])
        self.assertEqual(self.service.result(run["run_id"])["outcome"], "unknown")


class OllamaLocalContractTests(OllamaLifecycleContract, DurableDriverContract, OllamaBindingFixture, unittest.TestCase):
    pass


class OllamaCloudContractTests(OllamaLifecycleContract, DurableDriverContract, OllamaBindingFixture, unittest.TestCase):
    cloud = True
