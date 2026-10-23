"""Versioned single-step admission; policy data alone never grants execution."""
import unittest
import tempfile
import importlib.util
from pathlib import Path
import hashlib
import json
import platform
import sys
from importlib import resources
from unittest.mock import patch
from taskalong.errors import TaskAlongError

from taskalong.validation import canonical_bytes, digest, schema_names, seal_versioned
from test_contracts import example_spec
from helpers import ServiceFixture


class BindingFixture(ServiceFixture):
    def refresh_binding(self):
        """Issue a new synthetic measurement for newly selected immutable inputs."""
        self.binding["check_binding_digest"] = self.check["digest"]
        self.binding = seal_versioned("execution-binding", self.binding, version="2.0")
        self.context["effective_context_digest"] = digest(sorted([self.instructions, self.tools, self.worker_sandbox, self.check, self.check_sandbox], key=lambda item:item["digest"]))
        subject = {key:self.binding[key] for key in ("installation_digest", "provider_profile_digest", "instruction_bundle_digest", "tool_policy_digest", "worker_sandbox_digest", "check_binding_digest")} | {
            "binding_digest":self.binding["digest"], "runtime_closure_digest":self.installation["runtime_closure_digest"],
            "backend_id":self.installation["platform"]["backend_id"], "provider":self.provider["provider"],
            "model_digest":self.provider["model"]["resolved_digest"], "native_resume_compatibility_digest":self.binding["native_resume"]["compatibility_digest"] if self.binding["native_resume"] else None, **self.context}
        from test_qualification import reference, policy_for
        blobs = self.configuration["evidence"]
        old_ref = self.receipt["results"][0]["evidence_refs"][0]
        observation = json.loads(blobs.pop(old_ref["sha256"]))
        observation["subject"] = subject
        raw = canonical_bytes(observation)
        ref = reference(raw)
        blobs[ref["sha256"]] = raw
        self.receipt.update(subject=subject, results=[{"capability":"start", "outcome":"supported", "evidence_refs":[ref]}])
        self.receipt = seal_versioned("qualification-receipt", self.receipt, version="2.1")
        self.trust = policy_for(self.receipt)
        self.configuration.update(binding=self.binding, policies=[self.instructions,self.tools,self.worker_sandbox,self.check,self.check_sandbox], context=self.context, receipts=[self.receipt], trust=self.trust)
        self.task = seal_versioned("task-spec", self.task | {"execution":{"binding_digest":self.binding["digest"]}}, version="2.2")

    def setUp(self):
        super().setUp()
        from taskalong.api import RunService
        from taskalong.store import Store
        from taskalong.validation import digest, seal
        self.service.close()
        with Store.maintenance(self.state) as store:
            store.upgrade(operation_key="m3", backup_dir=self.root/"backup2", restore_dir=self.root/"restore2")
            store.upgrade(operation_key="m4", backup_dir=self.root/"backup3", restore_dir=self.root/"restore3", target_version=3)
        self.service = RunService(self.state)
        self.profile = seal("runtime-profile", self.profile | {"profile_id": "worker-v2", "credential_source_ref": "fixture-auth"})
        self.service.register_profile(self.profile)
        self.check_profile = seal("runtime-profile", self.profile | {"profile_id": "independent-check-v2"})
        self.service.register_profile(self.check_profile)
        self.task = self.spec(attempt_seconds=30, total_seconds=60)
        self.instructions = seal_versioned("instruction-bundle", {"texts": [], "ambient_context": "deny", "protective_policy_digest": self.profile["permission_policy_digest"]}, version="2.2")
        self.tools = seal_versioned("tool-policy", {"allowed_tools": ["fixture.edit"], "discovery": "deny", "network": "deny"}, version="2.2")
        self.worker_sandbox = seal_versioned("sandbox-policy", {"role": "worker", "backend_id": "synthetic-fixture", "network": "deny", "control_access": "deny", "credential_access": "deny", "permission_policy_digest": self.profile["permission_policy_digest"]}, version="2.2")
        self.check_sandbox = seal_versioned("sandbox-policy", self.worker_sandbox | {"role": "independent_check"}, version="2.2")
        self.check = seal_versioned("check-binding", {"sandbox_digest": self.check_sandbox["digest"], "runtime_profile_digest": self.check_profile["digest"], "checks_digest": digest(self.task["checks"]), "review_config_digest": self.task["review"]["config_digest"]}, version="2.2")
        self.installation = seal_versioned("harness-installation", {"installation_id": "fixture-codex", "revision": 1, "harness": "codex", "adapter_id": "codex-cli", "driver_version": "codex-v1-fixture-1", "cli_version": self.profile["runtime_version"], "platform": {"os": sys.platform, "architecture": "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x86_64", "backend_id": "synthetic-fixture"}, "executable_digest": self.profile["executable_sha256"], "runtime_closure_digest": digest({"profile": self.profile["digest"], "launcher": hashlib.sha256(self.sandbox.read_bytes()).hexdigest()})}, version="2.0")
        self.provider = seal_versioned("provider-profile", {"profile_id": "fixture-route", "revision": 1, "harness": "codex", "provider": "openai-account", "model": {"requested": self.profile["model"], "resolved_digest": digest({"simulated_model": self.profile["model"]})}, "endpoint": "https://fixture.invalid", "auth": {"mode": "account", "credential_ref": "fixture-auth"}, "effort": self.profile["reasoning_effort"], "service_tier": self.profile["service_tier"], "auxiliary_routes": [], "unlisted_auxiliary_routes": "deny", "allowed_disclosure": "provider-only", "fallback": "forbidden"}, version="2.0")
        self.binding = seal_versioned("execution-binding", {"installation_digest": self.installation["digest"], "provider_profile_digest": self.provider["digest"], "instruction_bundle_digest": self.instructions["digest"], "tool_policy_digest": self.tools["digest"], "worker_sandbox_digest": self.worker_sandbox["digest"], "check_binding_digest": self.check["digest"], "required_capabilities": ["start"], "budget": {"wall_seconds": 60, "max_attempts": 2, "max_cost_micro_usd": None, "max_tokens": None, "hard_cost_cap_required": False, "hard_token_cap_required": False}, "native_resume": None}, version="2.0")
        self.context = {"artifact_digest": "a"*64, "host_digest": "b"*64, "effective_context_digest": digest(sorted([self.instructions, self.tools, self.worker_sandbox, self.check, self.check_sandbox], key=lambda item:item["digest"])), "test_inputs_digest": "d"*64, "session_digest": None, "prior_invocation_digest": None}
        subject = {key:self.binding[key] for key in ("installation_digest", "provider_profile_digest", "instruction_bundle_digest", "tool_policy_digest", "worker_sandbox_digest", "check_binding_digest")} | {
            "binding_digest": self.binding["digest"], "runtime_closure_digest": self.installation["runtime_closure_digest"],
            "backend_id": "synthetic-fixture", "provider": self.provider["provider"], "model_digest": self.provider["model"]["resolved_digest"],
            "native_resume_compatibility_digest": None, **self.context}
        from test_qualification import example_receipt, reference, policy_for
        receipt, blobs = example_receipt()
        old_ref = receipt["results"][0]["evidence_refs"][0]
        observation = json.loads(blobs.pop(old_ref["sha256"]))
        observation["subject"] = subject
        raw = canonical_bytes(observation)
        ref = reference(raw)
        blobs[ref["sha256"]] = raw
        receipt.update(subject=subject, results=[{"capability": "start", "outcome": "supported", "evidence_refs": [ref]}])
        self.receipt = seal_versioned("qualification-receipt", receipt, version="2.1")
        self.trust = policy_for(self.receipt)
        self.configuration = dict(binding=self.binding, installation=self.installation, provider=self.provider,
            policies=[self.instructions, self.tools, self.worker_sandbox, self.check, self.check_sandbox],
            runtime_profile_digest=self.profile["digest"], receipts=[self.receipt], trust=self.trust, evidence=blobs,
            context=self.context, projection="codex-v1-fixture/1")
        self.task = seal_versioned("task-spec", self.task | {"schema_version": "2.2", "execution": {"binding_digest": self.binding["digest"]}}, version="2.2")


class ExecutionAdmissionTests(BindingFixture, unittest.TestCase):
    def test_submit_replay_precedes_revocation_and_changed_request_conflicts(self):
        run = self.configure_and_submit()
        self.trust["revoked_receipt_digests"] = [self.receipt["digest"]]
        self.service.configure_execution(**self.configuration)
        self.assertEqual(self.service.submit(self.task, operation_key="submit"), run)
        changed = seal_versioned("task-spec", self.task | {"execution":{"binding_digest":"f"*64}}, version="2.2")
        with self.assertRaises(TaskAlongError) as failure:
            self.service.submit(changed, operation_key="submit")
        self.assertEqual(failure.exception.code, "operation_key_conflict")
        self.assert_no_attempt(run)

    def test_cancel_between_initial_check_and_executor_prepare_is_confirmed(self):
        from taskalong.workflow import drive_run
        from taskalong.workspace import WorkspaceManager
        run = self.configure_and_submit()
        original_launch = self.service._workflow._launch_supervisor
        def capture_supervisor(*arguments):
            with patch("taskalong.workflow.subprocess.Popen") as launch:
                launch.return_value.wait.return_value = 0
                original_launch(*arguments)
                self.assertEqual(launch.call_count, 1)
        with patch.object(self.service._workflow, "_launch_supervisor", capture_supervisor):
            prepared = self.start(run)
        original_snapshot = WorkspaceManager.snapshot
        def cancel_at_snapshot(manager, *arguments, **options):
            current = self.service.inspect(run["run_id"])
            if current["state"] != "cancel_pending":
                self.service.cancel(run["run_id"], operation_key="race-cancel", expected_revision=current["revision"])
            return original_snapshot(manager, *arguments, **options)
        with patch.object(WorkspaceManager, "snapshot", cancel_at_snapshot):
            drive_run(self.state, run["run_id"], prepared["active_attempt_id"])
        current = self.service.inspect(run["run_id"])
        self.assertEqual(current["state"], "cancelled")
        self.assertIsNone(current["active_attempt_id"])
        attempt = self.service._store.detail("attempts", prepared["active_attempt_id"])
        self.assertTrue(attempt["termination_confirmed"])
        self.assertEqual(self.invocations(), [])
        self.assertEqual(current["pending_effect_ids"], [])
        self.assertEqual(self.service.result(run["run_id"])["outcome"], "cancelled")

    def configure_and_submit(self):
        self.service.configure_execution(**self.configuration)
        return self.submit(self.task)[0]

    def assert_no_attempt(self, run):
        observed = self.service.inspect(run["run_id"])
        self.assertEqual(observed["attempts"], [])
        self.assertEqual(observed["pending_effect_ids"], [])
        self.assertEqual(observed["budget_consumed"]["attempts"], 0)
        self.assertEqual(self.invocations(), [])
        self.assertFalse((self.root/"workspaces"/run["run_id"]).exists())

    def test_unregistered_binding_cannot_submit_from_portable_claims(self):
        with self.assertRaises(TaskAlongError) as failure:
            self.service.submit(self.task, operation_key="portable-claim")
        self.assertEqual(failure.exception.code, "execution_binding_unregistered")
        self.assertEqual(self.service._store.db.execute("SELECT count(*) FROM runs").fetchone()[0], 0)
        self.assertEqual(self.invocations(), [])

    def test_revoked_approval_before_start_has_no_effect_or_reservation(self):
        run = self.configure_and_submit()
        self.trust["revoked_approval_digests"] = [self.trust["approvals"][0]["digest"]]
        self.service.configure_execution(**self.configuration)
        with self.assertRaises(TaskAlongError) as failure:
            self.start(run)
        self.assertEqual(failure.exception.code, "qualification_unsatisfied")
        self.assert_no_attempt(run)

    def test_revocation_after_prepare_blocks_before_worker_dispatch(self):
        run = self.configure_and_submit()
        with patch.object(self.service._workflow, "_launch_supervisor"):
            prepared = self.start(run)
        before = self.service._store.detail("attempts", prepared["active_attempt_id"])["admission"]
        self.trust["revoked_receipt_digests"] = [self.receipt["digest"]]
        self.service.configure_execution(**self.configuration)
        from taskalong.workflow import drive_run
        drive_run(self.state, run["run_id"], prepared["active_attempt_id"])
        current = self.service.inspect(run["run_id"])
        attempt = self.service._store.detail("attempts", prepared["active_attempt_id"])
        self.assertEqual(attempt["admission"], before)
        self.assertTrue(attempt["termination_confirmed"])
        self.assertEqual(attempt["error"], "qualification_unsatisfied")
        self.assertIsNone(current["active_attempt_id"])
        self.assertEqual(self.invocations(), [])

    def test_authority_expiring_after_prepare_prevents_dispatch(self):
        run = self.configure_and_submit()
        with patch.object(self.service._workflow, "_launch_supervisor"):
            prepared = self.start(run)
        from taskalong.workflow import drive_run
        with patch("taskalong.store.now", return_value="2028-01-01T00:00:00Z"):
            drive_run(self.state, run["run_id"], prepared["active_attempt_id"])
        current = self.service.inspect(run["run_id"])
        self.assertEqual(current["blockers"][0]["code"], "authority_missing")
        self.assertEqual(self.invocations(), [])

    def test_required_native_resume_cannot_borrow_start_receipt(self):
        self.binding["required_capabilities"] = ["native_resume", "start"]
        self.binding["native_resume"] = {"protocol_version":"fixture-1", "session_scope":"exact_stored_session"}
        self.binding["native_resume"]["compatibility_digest"] = digest(self.binding)
        self.refresh_binding()
        self.service.configure_execution(**self.configuration)
        with self.assertRaises(TaskAlongError) as failure:
            self.service.submit(self.task, operation_key="requires-resume")
        self.assertEqual(failure.exception.code, "qualification_unsatisfied")
        self.assertEqual(self.invocations(), [])

    def test_nonnull_cost_or_token_limit_is_never_dropped(self):
        for field in ("max_cost_micro_usd", "max_tokens"):
            self.binding["budget"][field] = 1
            self.refresh_binding()
            with self.subTest(field=field), self.assertRaises(TaskAlongError) as failure:
                self.service.configure_execution(**self.configuration)
            self.assertEqual(failure.exception.code, "hard_budget_unsupported")
            self.binding["budget"][field] = None
        self.assertEqual(self.invocations(), [])

    def test_unknown_and_unrepresentable_policy_refuse_before_registration(self):
        self.instructions = seal_versioned("instruction-bundle", self.instructions | {"texts":["Additional instruction that v1 cannot enforce."]}, version="2.2")
        self.binding["instruction_bundle_digest"] = self.instructions["digest"]
        self.refresh_binding()
        with self.assertRaises(TaskAlongError) as failure:
            self.service.configure_execution(**self.configuration)
        self.assertEqual(failure.exception.code, "execution_projection_unsupported")
        self.configuration["policies"] = []
        with self.assertRaises(TaskAlongError) as failure:
            self.service.configure_execution(**self.configuration)
        self.assertEqual(failure.exception.code, "policy_unresolved")
        self.assertEqual(self.invocations(), [])

    def test_unrepresentable_legacy_profile_policy_is_not_silently_projected(self):
        from taskalong.validation import seal
        self.profile = seal("runtime-profile", self.profile | {
            "profile_id":"unrepresentable-fixture", "permission_policy":{"unknown_enforcement":True},
            "permission_policy_digest":digest({"unknown_enforcement":True})})
        self.service.register_profile(self.profile)
        self.configuration["runtime_profile_digest"] = self.profile["digest"]
        self.instructions = seal_versioned("instruction-bundle", self.instructions | {
            "protective_policy_digest":self.profile["permission_policy_digest"]}, version="2.2")
        self.worker_sandbox = seal_versioned("sandbox-policy", self.worker_sandbox | {
            "permission_policy_digest":self.profile["permission_policy_digest"]}, version="2.2")
        self.binding.update(instruction_bundle_digest=self.instructions["digest"], worker_sandbox_digest=self.worker_sandbox["digest"])
        self.refresh_binding()
        with self.assertRaises(TaskAlongError) as failure:
            self.service.configure_execution(**self.configuration)
        self.assertEqual(failure.exception.code, "execution_projection_unsupported")
        self.assertEqual(self.invocations(), [])

    def test_changed_executable_blocks_before_intent(self):
        run = self.configure_and_submit()
        self.executable.write_text(self.executable.read_text()+"\n# changed selected executable\n")
        with self.assertRaises(TaskAlongError) as failure:
            self.start(run)
        self.assertEqual(failure.exception.code, "runtime_changed")
        self.assert_no_attempt(run)

    def test_readonly_views_do_not_prepare_reconcile_or_issue_authority(self):
        run = self.configure_and_submit()
        from taskalong.maintenance import database_state
        before = database_state(self.service._store.db)
        with patch.object(self.service._workflow, "_launch_supervisor") as launch, patch.object(self.service._workflow, "reconcile") as reconcile:
            view = self.service.result(run["run_id"])
            caps = self.service.capabilities(run["run_id"])
            unsupported = self.service.capabilities(run["run_id"], mode="native_resume")
        self.assertEqual(view["outcome"], "pending")
        self.assertFalse(view["independently_accepted"])
        self.assertTrue(caps["requirements_satisfied"])
        self.assertFalse(caps["production_dispatch_allowed"])
        self.assertFalse(unsupported["requirements_satisfied"])
        self.assertEqual(database_state(self.service._store.db), before)
        launch.assert_not_called()
        reconcile.assert_not_called()

    def test_revocation_at_owned_gate_never_executes_target(self):
        from taskalong.executors.codex_cli import CodexCLI
        from taskalong.workflow import drive_run
        run = self.configure_and_submit()
        with patch.object(self.service._workflow, "_launch_supervisor"):
            prepared = self.start(run)
        original = CodexCLI.build_argv
        def revoke(driver, **options):
            argv = original(driver, **options)
            self.trust["revoked_receipt_digests"] = [self.receipt["digest"]]
            self.service.configure_execution(**self.configuration)
            return argv
        with patch.object(CodexCLI, "build_argv", revoke):
            drive_run(self.state, run["run_id"], prepared["active_attempt_id"])
        current = self.service.inspect(run["run_id"])
        self.assertEqual(current["state"], "blocked")
        self.assertEqual(current["blockers"][0]["code"], "qualification_unsatisfied")
        self.assertEqual(self.invocations(), [])
        self.assertIsNotNone(current["active_attempt_id"])
        self.assertEqual(self.service.result(run["run_id"])["outcome"], "unknown")

    def test_changed_request_conflicts_and_retry_never_spawns_again(self):
        run = self.configure_and_submit()
        with patch.object(self.service._workflow, "_launch_supervisor") as launch:
            first = self.start(run)
            replay = self.start(run)
            self.assertEqual(first, replay)
            with self.assertRaises(TaskAlongError) as failure:
                self.service.start(run["run_id"], operation_key="start", expected_revision=run["revision"], authority_id="changed")
            self.assertEqual(failure.exception.code, "operation_key_conflict")
            self.assertEqual(launch.call_count, 1)
        current = self.service.inspect(run["run_id"])
        self.service.cancel(run["run_id"], operation_key="cancel", expected_revision=current["revision"])
        current = self.service.inspect(run["run_id"])
        self.service.reconcile(run["run_id"], operation_key="reconcile", expected_revision=current["revision"])

    def test_full_independent_acceptance_keeps_verifier_binding_distinct(self):
        import shutil
        from taskalong.validation import load_json
        reviewer = shutil.which("review-sensei") or str(Path(sys.executable).parent / "review-sensei")
        config = Path(__file__).parent/"fixtures/reviewsensei/approved.yml"
        selected = self.service.configure_review(config, fixture_response=Path(__file__).parent/"fixtures/reviewsensei/clean.json", executable=reviewer)
        # The immutable check binding must bind the selected independent review.
        self.task["review"]["config_digest"] = selected["config_digest"]
        self.check["review_config_digest"] = selected["config_digest"]
        self.check = seal_versioned("check-binding", self.check, version="2.2")
        self.refresh_binding()
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        self.start(run)
        accepted = self.wait(run["run_id"])
        self.assertEqual(accepted["state"], "accepted", accepted["blockers"])
        view = self.service.result(run["run_id"])
        self.assertTrue(view["independently_accepted"])
        self.assertEqual(view["outcome"], "accepted")
        self.assertIsNotNone(view["acceptance_digest"])
        records = [self.service._store.detail("evidence", key) for key in accepted["evidence_ids"]]
        self.assertTrue(all(record["inputs"]["runtime_profile_digest"] == self.check_profile["digest"] for record in records))
        attempt = self.service._store.detail("attempts", accepted["attempts"][0]["attempt_id"])
        self.assertEqual(len(attempt["canonical_evidence_refs"]), 3)

    def test_supervisor_maps_one_v2_attempt_to_exact_wire_and_independent_result(self):
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        self.start(run)
        stopped = self.wait(run["run_id"])
        self.assertEqual(len(self.invocations()), 1)
        self.assertIsNone(stopped["acceptance_id"])
        attempt = self.service._store.detail("attempts", stopped["attempts"][0]["attempt_id"])
        self.assertTrue(attempt["termination_confirmed"])
        mapping = attempt["packet_projection"]
        self.assertEqual(mapping["canonical_packet_digest"], attempt["canonical_packet"]["digest"])
        self.assertEqual(mapping["wire_packet_digest"], attempt["packet"]["digest"])
        self.assertEqual(attempt["packet"]["extensions"]["taskalong:canonical_packet_digest"], attempt["canonical_packet"]["digest"])
        self.assertEqual(attempt["canonical_packet"]["spec_digest"], self.task["digest"])
        self.assertEqual(attempt["canonical_packet"]["admission_digest"], attempt["dispatch_admission"]["digest"])
        self.assertEqual(stopped["budget_consumed"]["attempts"], 1)
        view = self.service.result(run["run_id"])
        self.assertEqual(view["outcome"], "worker_completed")
        self.assertFalse(view["independently_accepted"])
        self.assertEqual(view["schema_version"], "2.2")
        self.assertEqual(view["canonical_packet_digest"], mapping["canonical_packet_digest"])
        self.assertNotIn(str(self.root), json.dumps(view))

    def test_v2_preparation_freezes_exact_policy_and_reserves_once(self):
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        with patch.object(self.service._workflow, "_launch_supervisor"):
            prepared = self.start(run)
            again = self.start(run)
        self.assertEqual(again, prepared)
        attempt = self.service._store.detail("attempts", prepared["active_attempt_id"])
        self.assertEqual(attempt["admission"]["binding"]["digest"], self.binding["digest"])
        self.assertTrue(attempt["admission"]["decision"]["requirements_satisfied"])
        self.assertFalse(attempt["admission"]["decision"]["production_dispatch_allowed"])
        self.assertEqual(prepared["budget_consumed"]["attempts"], 1)
        self.assertEqual(len(prepared["attempts"]), 1)
        self.assertEqual(self.invocations(), [])
        # No worker was released; reconcile the known undispatched attempt.
        self.service.cancel(run["run_id"], operation_key="cancel", expected_revision=self.service.inspect(run["run_id"])["revision"])
        current = self.service.inspect(run["run_id"])
        self.service.reconcile(run["run_id"], operation_key="reconcile", expected_revision=current["revision"])


class ExecutionDocumentTests(unittest.TestCase):
    def test_policy_documents_are_closed_frozen_and_exactly_resolved(self):
        from taskalong.execution import InstructionBundle, ToolPolicy, SandboxPolicy, PolicyResolver
        instruction = InstructionBundle.from_dict(seal_versioned("instruction-bundle", {
            "texts": [], "ambient_context": "deny", "protective_policy_digest": "c" * 64}, version="2.2"))
        tools = ToolPolicy.from_dict(seal_versioned("tool-policy", {
            "allowed_tools": ["fixture.edit"], "discovery": "deny", "network": "deny"}, version="2.2"))
        sandbox = SandboxPolicy.from_dict(seal_versioned("sandbox-policy", {
            "role": "worker", "backend_id": "synthetic-fixture", "network": "deny",
            "control_access": "deny", "credential_access": "deny", "permission_policy_digest": "d" * 64}, version="2.2"))
        resolver = PolicyResolver((instruction, tools, sandbox))
        self.assertEqual(resolver.resolve(instruction.digest, InstructionBundle).to_bytes(), instruction.to_bytes())
        exposed = resolver.resolve(tools.digest, ToolPolicy).to_dict()
        exposed["allowed_tools"].append("network")
        self.assertEqual(resolver.resolve(tools.digest, ToolPolicy).to_dict()["allowed_tools"], ["fixture.edit"])
        for key, kind in (("e" * 64, InstructionBundle), (instruction.digest, ToolPolicy)):
            with self.assertRaises(TaskAlongError) as failure:
                resolver.resolve(key, kind)
            self.assertEqual(failure.exception.code, "policy_unresolved")
        with self.assertRaises(TaskAlongError):
            seal_versioned("tool-policy", tools.to_dict() | {"discovery": "automatic"}, version="2.2")

    def test_explicit_reader_preserves_v1_bytes_and_adds_separate_v2_family(self):
        from taskalong.execution import TaskSpecV2, read_task_spec
        legacy = example_spec()
        self.assertEqual(read_task_spec(legacy).to_bytes(), canonical_bytes(legacy))
        current = dict(legacy, schema_version="2.2", execution={"binding_digest": "b" * 64})
        current = seal_versioned("task-spec", current, version="2.2")
        self.assertIsInstance(read_task_spec(current), TaskSpecV2)
        self.assertEqual(read_task_spec(current).to_bytes(), canonical_bytes(current))
        self.assertEqual(set(schema_names(version="2.0")), {"harness-installation", "provider-profile", "execution-binding"})
        self.assertEqual(set(schema_names(version="2.1")), {"qualification-receipt", "qualification-decision", "capability-report"})


class ExecutionStoreTests(unittest.TestCase):
    def test_format3_is_explicit_backed_up_and_excludes_predecessor(self):
        from taskalong.store import Store
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            state = root / "state"
            with Store(state) as store:
                self.assertEqual(store.format_version, 1)
                original = store.create_run(example_spec(), "submit")
            with Store.maintenance(state) as store:
                store.upgrade(operation_key="history", backup_dir=root/"b2", restore_dir=root/"r2")
                request = dict(operation_key="admission", backup_dir=root/"b3", restore_dir=root/"r3", target_version=3)
                receipt = store.upgrade(**request)
                self.assertEqual(receipt["from_version"], 2)
                self.assertEqual(receipt["to_version"], 3)
                self.assertEqual(store.upgrade(**request), receipt)
                self.assertEqual(store.run(original["run_id"]), original)
            module_spec = importlib.util.spec_from_file_location("taskalong._legacy_store_v2", Path(__file__).parent/"fixtures/legacy_store_v2.py")
            self.assertEqual(hashlib.sha256(Path(module_spec.origin).read_bytes()).hexdigest(), "35f28559442890427999f5e40fc0dba137d40e0d98319c6140ab610edb7ea9f6")
            predecessor = importlib.util.module_from_spec(module_spec)
            module_spec.loader.exec_module(predecessor)
            before = (state/"state.sqlite3").read_bytes()
            with self.assertRaises(TaskAlongError) as failure:
                predecessor.Store(state)
            self.assertEqual(failure.exception.code, "unsupported_store_version")
            self.assertEqual((state/"state.sqlite3").read_bytes(), before)
            with Store(state) as store:
                self.assertEqual(store.format_version, 3)
                self.assertEqual(store.run(original["run_id"]), original)


if __name__ == "__main__":
    unittest.main()
