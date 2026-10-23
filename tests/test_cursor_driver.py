"""Cursor's original fixture uses the shared core, never a vendor session."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import sys
from copy import deepcopy
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, digest, loads, seal_versioned
from test_cursor_protocol import cursor_packet, example_cursor_config
from test_execution_bindings import BindingFixture


def cursor_context(executable=None):
    profile = seal_versioned("provider-profile", {
        "profile_id": "fixture-cursor-route", "revision": 1, "harness": "cursor", "provider": "cursor-account",
        "model": {"requested": "synthetic-cursor-model", "resolved_digest":
            hashlib.sha256(b"taskalong-cursor-fixture-model-v1").hexdigest()},
        "endpoint": "https://api2.cursor.sh", "auth": {"mode": "account", "credential_ref": "fixture-cursor-account"},
        "effort": None, "service_tier": None, "auxiliary_routes": [], "unlisted_auxiliary_routes": "deny",
        "allowed_disclosure": "provider-only", "fallback": "forbidden"}, version="2.0")
    fields = example_cursor_config() | {"provider_profile_digest": profile["digest"]}
    if executable is not None:
        fields["executable"] = {"path": str(executable), "sha256": hashlib.sha256(Path(executable).read_bytes()).hexdigest()}
    return seal_versioned("driver-config", fields, version="2.5"), profile


def cursor_compiler_inputs(config):
    packet = cursor_packet()
    fields = {key: value for key, value in packet.items() if key not in (
        "kind", "schema_version", "digest", "binding_digest", "admission_digest", "projection", "session_policy",
        "allowed_tools", "result_schema_id")}
    fields["bindings"] = {key: value for key, value in fields["bindings"].items()
                          if key not in ("driver_config_digest", "provider_profile_digest")}
    admission = {"schema_version": "2.5", "spec_digest": fields["spec_digest"], "digest": "3" * 64,
        "driver_config": config, "binding": {"digest": "4" * 64,
            "provider_profile_digest": config["provider_profile_digest"], "installation_digest": config["installation_digest"]},
        "projection": {"projection": "cursor-print-fixture/1", "digest": "5" * 64,
                       "driver_config_digest": config["digest"]}}
    return fields, admission


class CursorDriverProjectionTests(unittest.TestCase):
    def test_compiler_and_argv_have_fresh_observed_session_and_no_foreign_flags(self):
        from taskalong.executors.cursor_cli import CursorCLI, compile_packet
        config, provider = cursor_context()
        fields, admission = cursor_compiler_inputs(config)
        packet, wire, mapping = compile_packet(fields, admission)
        self.assertEqual(packet, wire)
        self.assertEqual(packet["schema_version"], "2.5")
        self.assertEqual(packet["result_schema_id"], "urn:taskalong:schema:v2.5:worker-result")
        self.assertEqual(packet["session_policy"], "fresh")
        self.assertEqual(mapping["session_policy"], "fresh")
        self.assertNotIn("session_id", packet)
        self.assertNotIn("session_id", mapping)
        self.assertEqual(mapping["canonical_packet_digest"], packet["digest"])
        self.assertEqual(mapping["wire_packet_digest"], packet["digest"])
        self.assertEqual(packet["bindings"]["driver_config_digest"], config["digest"])
        self.assertEqual(packet["bindings"]["provider_profile_digest"], provider["digest"])
        driver = CursorCLI(config, provider=provider)
        self.assertFalse(driver.capabilities().native_resume)
        self.assertEqual(driver.build_argv(packet), [config["executable"]["path"], "--print",
            "--output-format", "stream-json", "--model", "synthetic-cursor-model"])

    def test_compiler_refuses_foreign_session_or_identity_fields_without_repair(self):
        from taskalong.executors.cursor_cli import compile_packet
        config, _ = cursor_context()
        fields, admission = cursor_compiler_inputs(config)
        changes = [{"session_policy": "latest"}, {"session_id": fields["attempt_id"]},
            {"projection": "claude-print-fixture/1"}, {"result_schema_id": "urn:taskalong:schema:v1:worker-result"},
            {"bindings": fields["bindings"] | {"driver_config_digest": "f" * 64}},
            {"bindings": fields["bindings"] | {"runtime_profile_digest": "f" * 64}}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(TaskAlongError):
                compile_packet(fields | change, admission)

    def test_direct_construction_and_preflight_refuse_identity_route_and_hard_caps(self):
        from taskalong.executors.cursor_cli import CursorCLI
        config, provider = cursor_context()
        other = seal_versioned("provider-profile", provider | {"revision": 2}, version="2.0")
        with self.assertRaises(TaskAlongError) as identity:
            CursorCLI(config, provider=other)
        self.assertEqual(identity.exception.code, "execution_identity_mismatch")
        changes = [{"model": provider["model"] | {"requested": "fallback"}},
            {"model": provider["model"] | {"resolved_digest": "f" * 64}},
            {"endpoint": "https://api2.cursor.sh/"}, {"effort": "high"}, {"service_tier": "priority"},
            {"auth": {"mode": "account", "credential_ref": "other-account"}},
            {"auxiliary_routes": [{"purpose": "subagent", "provider_profile_digest": "f" * 64}]},
            {"harness": "claude-code", "provider": "anthropic-account"}]
        for change in changes:
            changed = seal_versioned("provider-profile", provider | change, version="2.0")
            rebound = seal_versioned("driver-config", config | {"provider_profile_digest": changed["digest"]}, version="2.5")
            with self.subTest(change=change), self.assertRaises(TaskAlongError):
                CursorCLI(rebound, provider=changed)
        driver = CursorCLI(config, provider=provider)
        with self.assertRaises(TaskAlongError) as production:
            driver.preflight(qualification="production", budget={})
        self.assertEqual(production.exception.code, "runtime_policy_unsupported")
        for budget in ({"hard_tokens": 1}, {"hard_cost_usd": "0.01"}):
            with self.subTest(budget=budget), self.assertRaises(TaskAlongError) as hard:
                driver.preflight(qualification="synthetic", budget=budget)
            self.assertEqual(hard.exception.code, "hard_budget_unsupported")


class CursorOwnedProcessTests(unittest.TestCase):
    def test_original_fixture_returns_actual_private_stream_and_separate_session(self):
        from taskalong.executors.cursor_cli import CursorCLI, compile_packet
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            executable = root / "cursor-fixture"
            executable.write_bytes((Path(__file__).parent / "fixtures/fake_cursor.py").read_bytes())
            executable.chmod(0o700)
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            (workspace / "arithmetic.py").write_text("def add(a, b):\n    return a - b\n")
            config, provider = cursor_context(executable)
            fields, admission = cursor_compiler_inputs(config)
            packet, _, _ = compile_packet(fields, admission)
            result = CursorCLI(config, provider=provider).run(packet, workspace=workspace, output_dir=root / "output")
            self.assertEqual(result["state"], "completed")
            self.assertIs(result["process"]["termination_confirmed"], True)
            self.assertIs(result["process"]["group_termination_confirmed"], True)
            self.assertIsNone(result["usage"]["input_tokens"])
            self.assertIsNone(result["usage"]["cost_usd"])
            capture = result["_private_capture"]
            self.assertEqual(set(capture), {"stdout", "stderr"})
            self.assertIs(type(capture["stdout"]), bytes)
            self.assertEqual(capture["stderr"], b"")
            frames = [json.loads(line) for line in capture["stdout"].splitlines()]
            self.assertEqual(result["session_id"], frames[0]["session_id"])
            self.assertNotEqual(result["session_id"], packet["attempt_id"])
            self.assertNotIn("session_id", result["result"])
            self.assertEqual(result["result"], json.loads(frames[-1]["result"]))
            self.assertIn("return a + b", (workspace / "arithmetic.py").read_text())


class CursorBindingFixture(BindingFixture):
    """Neutral M4 fixture with a separate original Cursor worker and v1 verifier."""
    def setUp(self):
        super().setUp()
        from taskalong.api import RunService
        from taskalong.store import Store
        from test_cursor_store import upgrade_through
        self.service.close()
        with Store.maintenance(self.state) as store:
            upgrade_through(store, self.root, 6)
        self.service = RunService(self.state)
        self.executable = self.root / "fake-cursor"
        self.executable.write_text((Path(__file__).parent / "fixtures/fake_cursor.py").read_text().replace(
            "#!/usr/bin/env python3", "#!" + sys.executable, 1))
        self.executable.chmod(0o700)
        self.mode_file = self.executable.with_suffix(".mode.json")
        self.mode_file.write_text('{"mode":"good"}')
        self.barrier_file = self.executable.with_suffix(".hold")
        self.release_file = self.executable.with_suffix(".release")
        config, self.provider = cursor_context(self.executable)
        self.tools = seal_versioned("tool-policy", self.tools | {"allowed_tools": ["cursor.edit"]}, version="2.2")
        self.installation = seal_versioned("harness-installation", self.installation | {
            "installation_id": "fixture-cursor", "harness": "cursor", "adapter_id": "cursor-cli",
            "driver_version": "cursor-print-fixture-1", "cli_version": "synthetic-cursor-1",
            "executable_digest": config["executable"]["sha256"], "runtime_closure_digest": digest({
                "fixture": config["executable"]["sha256"], "python": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
                "check_launcher": hashlib.sha256(self.sandbox.read_bytes()).hexdigest()})}, version="2.0")
        self.binding = seal_versioned("execution-binding", self.binding | {
            "installation_digest": self.installation["digest"], "provider_profile_digest": self.provider["digest"],
            "tool_policy_digest": self.tools["digest"]}, version="2.0")
        self.driver_config = seal_versioned("driver-config", config | {
            "installation_digest": self.installation["digest"], "policy_digests": {
                "instructions": self.instructions["digest"], "tools": self.tools["digest"],
                "worker_sandbox": self.worker_sandbox["digest"], "check_binding": self.check["digest"]}}, version="2.5")
        self.refresh_cursor_binding()

    def refresh_cursor_binding(self):
        from test_qualification import reference, policy_for
        self.binding = seal_versioned("execution-binding", self.binding | {
            "check_binding_digest": self.check["digest"]}, version="2.0")
        self.driver_config = seal_versioned("driver-config", self.driver_config | {"policy_digests": {
            "instructions": self.binding["instruction_bundle_digest"], "tools": self.binding["tool_policy_digest"],
            "worker_sandbox": self.binding["worker_sandbox_digest"], "check_binding": self.check["digest"]}}, version="2.5")
        policies = [self.instructions, self.tools, self.worker_sandbox, self.check, self.check_sandbox]
        self.context["effective_context_digest"] = digest({"policies": sorted(policies, key=lambda item: item["digest"]),
            "driver_config_digest": self.driver_config["digest"]})
        subject = {key: self.binding[key] for key in ("installation_digest", "provider_profile_digest",
            "instruction_bundle_digest", "tool_policy_digest", "worker_sandbox_digest", "check_binding_digest")} | {
            "binding_digest": self.binding["digest"], "runtime_closure_digest": self.installation["runtime_closure_digest"],
            "backend_id": "synthetic-fixture", "provider": self.provider["provider"],
            "model_digest": self.provider["model"]["resolved_digest"],
            "native_resume_compatibility_digest": self.binding["native_resume"]["compatibility_digest"] if self.binding["native_resume"] else None,
            **self.context}
        blobs = self.configuration["evidence"]
        old_ref = self.receipt["results"][0]["evidence_refs"][0]
        observation = loads(blobs.pop(old_ref["sha256"]))
        raw = canonical_bytes(observation | {"subject": subject})
        ref = reference(raw)
        blobs[ref["sha256"]] = raw
        self.receipt = seal_versioned("qualification-receipt", self.receipt | {
            "subject": subject, "results": [{"capability": "start", "outcome": "supported", "evidence_refs": [ref]}]}, version="2.1")
        self.trust = policy_for(self.receipt)
        self.configuration = dict(binding=self.binding, installation=self.installation, provider=self.provider,
            policies=policies, driver_config=self.driver_config, receipts=[self.receipt], trust=self.trust,
            evidence=blobs, context=self.context, projection="cursor-print-fixture/1")
        self.task = seal_versioned("task-spec", self.task | {"schema_version": "2.5",
            "execution": {"binding_digest": self.binding["digest"], "driver_config_digest": self.driver_config["digest"]},
            "permissions": self.task["permissions"] | {"inference_destination_id": self.provider["profile_id"]}}, version="2.5")

    def refresh_binding(self):
        self.refresh_cursor_binding()

    def invocations(self):
        path = self.executable.with_suffix(".invocations.jsonl")
        return [loads(line) for line in path.read_bytes().splitlines()] if path.exists() else []


class CursorRegistrationTests(CursorBindingFixture, unittest.TestCase):
    def test_explicit_closed_registration_on_format6_does_not_start_a_worker(self):
        summary = self.service.configure_execution(**self.configuration)
        from taskalong.admission import registered_driver_config
        config, registration = registered_driver_config(self.service._store, self.binding["digest"])
        self.assertFalse(summary["production_dispatch_allowed"])
        self.assertEqual(config, self.driver_config)
        self.assertEqual(registration["schema_version"], "2.5")
        self.assertEqual(registration["projection"], "cursor-print-fixture/1")
        self.assertEqual(registration["driver_config_digest"], self.driver_config["digest"])
        self.assertEqual(registration["transport"], "operator_registered_fixture")
        self.assertEqual(self.service._store.format_version, 6)
        self.assertEqual(self.service._store.db.execute("SELECT count(*) FROM attempts").fetchone()[0], 0)
        self.assertEqual(self.invocations(), [])


class CursorAdmissionTests(CursorBindingFixture, unittest.TestCase):
    from test_execution_bindings import ExecutionAdmissionTests as _Cases
    configure_and_submit = _Cases.configure_and_submit
    assert_no_attempt = _Cases.assert_no_attempt
    test_unregistered_binding_cannot_submit_from_portable_claims = _Cases.test_unregistered_binding_cannot_submit_from_portable_claims
    test_revoked_approval_before_start_has_no_effect_or_reservation = _Cases.test_revoked_approval_before_start_has_no_effect_or_reservation
    test_revocation_after_prepare_blocks_before_worker_dispatch = _Cases.test_revocation_after_prepare_blocks_before_worker_dispatch
    test_authority_expiring_after_prepare_prevents_dispatch = _Cases.test_authority_expiring_after_prepare_prevents_dispatch
    test_required_native_resume_cannot_borrow_start_receipt = _Cases.test_required_native_resume_cannot_borrow_start_receipt
    test_nonnull_cost_or_token_limit_is_never_dropped = _Cases.test_nonnull_cost_or_token_limit_is_never_dropped
    test_unknown_and_unrepresentable_policy_refuse_before_registration = _Cases.test_unknown_and_unrepresentable_policy_refuse_before_registration
    test_changed_executable_blocks_before_intent = _Cases.test_changed_executable_blocks_before_intent
    test_readonly_views_do_not_prepare_reconcile_or_issue_authority = _Cases.test_readonly_views_do_not_prepare_reconcile_or_issue_authority
    test_changed_request_conflicts_and_retry_never_spawns_again = _Cases.test_changed_request_conflicts_and_retry_never_spawns_again
    test_cancel_between_initial_check_and_executor_prepare_is_confirmed = _Cases.test_cancel_between_initial_check_and_executor_prepare_is_confirmed


from test_executor_contract import DurableDriverContract


class CursorSharedContractTests(CursorBindingFixture, DurableDriverContract, unittest.TestCase):
    pass


class CursorPublicLifecycleTests(CursorBindingFixture, unittest.TestCase):
    from test_execution_bindings import ExecutionAdmissionTests as _Cases
    test_full_independent_acceptance_keeps_verifier_binding_distinct = _Cases.test_full_independent_acceptance_keeps_verifier_binding_distinct

    def test_same_length_redactor_canary_is_preserved_in_private_worker_bytes(self):
        canary = "Bearer abc"
        self.mode_file.write_text(json.dumps({"mode":"good", "summary":canary}))
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        self.start(run)
        stopped = self.wait(run["run_id"])
        attempt = self.service._store.detail("attempts", stopped["attempts"][-1]["attempt_id"])
        worker = loads(self.service._store.get_blob(attempt["result_artifact"]["sha256"]))
        self.assertEqual(worker["summary"], canary)
        capture = self.service._store.get_blob(attempt["cursor_capture"]["stdout"]["sha256"])
        self.assertIn(canary.encode(), capture)
        public = [self.service.result(run["run_id"]), self.service.events(run["run_id"]), self.export(run["run_id"])]
        self.assertNotIn(canary, canonical_bytes(public).decode())

    def test_finished_failure_cannot_block_a_newly_prepared_restart(self):
        import taskalong.workflow as workflow
        self.mode_file.write_text('{"mode":"scope_claim_mismatch"}')
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        with patch.object(self.service._workflow, "_launch_supervisor"):
            prepared = self.start(run)
        original = workflow._finish_attempt
        restarts = []
        def interleave(store, run_id, attempt_id, result, worker):
            finished = original(store, run_id, attempt_id, result, worker)
            if result["state"] == "failed" and not restarts:
                stopped = self.service.inspect(run_id)
                with patch.object(self.service._workflow, "_launch_supervisor"):
                    restarts.append(self.service.resume(run_id, mode="restart", operation_key="interleaved-restart",
                        expected_revision=stopped["revision"]))
            return finished
        with patch.object(workflow, "_finish_attempt", interleave):
            workflow.drive_run(self.state, run["run_id"], prepared["active_attempt_id"])
        current = self.service.inspect(run["run_id"])
        self.assertEqual(len(restarts), 1)
        self.assertEqual(current["state"], "ready")
        self.assertEqual(current["blockers"], [])
        self.assertEqual(current["active_attempt_id"], restarts[0]["active_attempt_id"])
        self.assertNotEqual(current["active_attempt_id"], prepared["active_attempt_id"])
        self.assertEqual(len(self.invocations()), 1)

    def test_fresh_restart_refuses_known_prior_observed_session_inside_finish(self):
        self.mode_file.write_text('{"mode":"scope_claim_mismatch"}')
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        self.start(run)
        failed = self.wait(run["run_id"])
        first = self.service._store.detail("attempts", failed["attempts"][-1]["attempt_id"])
        self.assertEqual(first["error"], "worker_scope_claim_mismatch")
        self.assertIs(first["termination_confirmed"], True)
        observed = first["checkpoint"]["observed_session_id"]
        self.assertEqual(observed, self.invocations()[0]["session_id"])
        self.mode_file.write_text(json.dumps({"mode":"good", "session":observed}))
        self.service.resume(run["run_id"], mode="restart", operation_key="reused-session", expected_revision=failed["revision"])
        stopped = self.wait(run["run_id"])
        last = self.service._store.detail("attempts", stopped["attempts"][-1]["attempt_id"])
        self.assertEqual(last["error"], "cursor_session_reused")
        self.assertEqual(last["status"], "failed")
        self.assertEqual(stopped["budget_consumed"]["attempts"], 2)
        self.assertIsNone(stopped["candidate"])
        self.assertIsNone(stopped["acceptance_id"])
        self.assertEqual(len(self.invocations()), 2)

    def test_settled_failed_restart_uses_new_session_without_resetting_unknown_totals(self):
        self.mode_file.write_text('{"mode":"nonzero"}')
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        self.start(run)
        failed = self.wait(run["run_id"])
        first = self.service._store.detail("attempts", failed["attempts"][-1]["attempt_id"])
        self.assertEqual(first["status"], "failed")
        self.assertIs(first["termination_confirmed"], True)
        self.assertEqual(first["process"]["exit_code"], 1)
        self.assertEqual(failed["pending_effect_ids"], [])
        self.assertIsNone(failed["active_attempt_id"])
        self.mode_file.write_text('{"mode":"good"}')
        self.service.resume(run["run_id"], mode="restart", operation_key="fresh-restart", expected_revision=failed["revision"])
        stopped = self.wait(run["run_id"])
        self.assertEqual(self.service.result(run["run_id"])["outcome"], "worker_completed")
        self.assertEqual(stopped["budget_consumed"]["attempts"], 2)
        self.assertEqual(len({item["session_id"] for item in self.invocations()}), 2)
        for name in ("input_tokens", "output_tokens", "cost_usd"):
            self.assertIsNone(stopped["budget_consumed"][name])

    def test_zero_exit_stderr_denial_retains_private_bytes_without_public_leak(self):
        canary = "Bearer SYNTHETIC_CURSOR_PRIVATE_DIAGNOSTIC_7"
        self.mode_file.write_text(json.dumps({"mode": "stderr", "diagnostic": canary}))
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        self.start(run)
        stopped = self.wait(run["run_id"])
        attempt = self.service._store.detail("attempts", stopped["attempts"][-1]["attempt_id"])
        self.assertEqual(attempt["status"], "failed")
        self.assertEqual(attempt["error"], "cursor_stderr_unsupported")
        self.assertEqual(attempt["process"]["exit_code"], 0)
        self.assertIs(attempt["termination_confirmed"], True)
        self.assertIsNone(attempt["cursor_capture"])
        self.assertIsNone(attempt["result_artifact"])
        self.assertIsNone(attempt["driver_report"]["reported_session_id"])
        raw = self.service._store.get_blob(attempt["cursor_raw_capture"]["stderr"]["sha256"])
        self.assertEqual(raw, (canary + "\n").encode())
        public = [self.service.result(run["run_id"]), self.service.events(run["run_id"]), self.export(run["run_id"])]
        self.assertNotIn(canary, canonical_bytes(public).decode())
        self.assertIsNone(stopped["candidate"])
        self.assertIsNone(stopped["acceptance_id"])

    def test_completed_handoff_retains_exact_private_stream_and_observed_session(self):
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        self.start(run)
        stopped = self.wait(run["run_id"])
        self.assertEqual(self.service.result(run["run_id"])["outcome"], "worker_completed")
        attempt = self.service._store.detail("attempts", stopped["attempts"][-1]["attempt_id"])
        association = attempt["cursor_capture"]
        capture = self.service._store.get_blob(association["stdout"]["sha256"])
        frames = [loads(line) for line in capture.splitlines()]
        worker_bytes = self.service._store.get_blob(attempt["result_artifact"]["sha256"])
        self.assertEqual(worker_bytes, canonical_bytes(loads(frames[-1]["result"])))
        self.assertEqual(association["observation"]["observed_session_id"], frames[0]["session_id"])
        self.assertNotEqual(frames[0]["session_id"], attempt["attempt_id"])
        self.assertEqual(association["stdout"]["bytes"], len(capture))
        self.assertEqual(association["stdout"]["sha256"], hashlib.sha256(capture).hexdigest())
        self.assertEqual(self.service._store.get_blob(association["stderr"]["sha256"]), b"")
        self.assertEqual(attempt["checkpoint"]["capture_digest"], association["digest"])
        self.assertEqual(attempt["checkpoint"]["session_policy"], "fresh")
        self.assertIsNone(attempt["checkpoint"]["requested_session_id"])
        self.assertEqual(attempt["checkpoint"]["observed_session_id"], frames[0]["session_id"])
        self.assertNotIn("session_id", loads(worker_bytes))
        self.assertEqual(attempt["process"]["output_bytes"], len(capture))
        self.assertIs(attempt["termination_confirmed"], True)
        self.assertEqual(len(self.invocations()), 1)

    def test_corrupt_completed_capture_is_refused_by_every_consuming_public_read(self):
        from taskalong.store import encode
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        self.start(run)
        stopped = self.wait(run["run_id"])
        attempt_id = stopped["attempts"][-1]["attempt_id"]
        original = self.service._store.detail("attempts", attempt_id)
        self.assertEqual(self.service.result(run["run_id"])["outcome"], "worker_completed")
        mutations = [lambda a: a.pop("cursor_capture"),
            lambda a: a["cursor_capture"]["observation"].update(frame_count=999),
            lambda a: a["cursor_capture"]["observation"].update(reported_model="other-model"),
            lambda a: a["cursor_capture"]["observation"].update(observed_session_id=run["run_id"]),
            lambda a: a["cursor_capture"]["stdout"].update(bytes=1),
            lambda a: a["cursor_capture"].update(provider_profile_digest="f" * 64),
            lambda a: a["cursor_capture"].update(mapping_digest="f" * 64),
            lambda a: a["cursor_capture"].update(packet_digest="f" * 64),
            lambda a: a["cursor_capture"].update(admission_digest="f" * 64),
            lambda a: a["cursor_capture"]["stderr"].update(sha256=a["cursor_capture"]["stdout"]["sha256"]),
            lambda a: a["checkpoint"].update(capture_digest="f" * 64),
            lambda a: a["process"].update(group_termination_confirmed=False)]
        actions = {"result": lambda: self.service.result(run["run_id"]),
            "verify": lambda: self.service.verify(run["run_id"], operation_key="tamper-verify", expected_revision=stopped["revision"]),
            "reconcile": lambda: self.service.reconcile(run["run_id"], operation_key="tamper-reconcile", expected_revision=stopped["revision"]),
            "publish_intent": lambda: self.service.publish_intent(run["run_id"])}
        try:
            for index, mutate in enumerate(mutations):
                changed = deepcopy(original)
                mutate(changed)
                if changed.get("cursor_capture"):
                    changed["cursor_capture"]["digest"] = digest(changed["cursor_capture"])
                    if index != 10:
                        changed["checkpoint"]["capture_digest"] = changed["cursor_capture"]["digest"]
                with self.service._store.transaction() as db:
                    db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(changed), attempt_id))
                before = self.service._store.db.total_changes
                for label, action in actions.items():
                    with self.subTest(index=index, action=label), self.assertRaises(TaskAlongError) as failure:
                        action()
                    self.assertEqual(failure.exception.code, "cursor_capture_invalid")
                self.assertEqual(self.service._store.db.total_changes, before)
                self.assertEqual(self.service.inspect(run["run_id"])["revision"], stopped["revision"])
                self.assertEqual(len(self.invocations()), 1)
        finally:
            with self.service._store.transaction() as db:
                db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(original), attempt_id))


class CursorCaptureFaultTests(CursorBindingFixture, unittest.TestCase):
    def run_with_fault(self, change):
        from taskalong.executors.cursor_cli import CursorCLI
        from taskalong.workflow import drive_run
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        with patch.object(self.service._workflow, "_launch_supervisor"):
            prepared = self.start(run)
        original = CursorCLI.run
        def inject(driver, *args, **kwargs):
            result = original(driver, *args, **kwargs)
            self.assertEqual(result["state"], "completed")
            self.assertIs(result["process"]["termination_confirmed"], True)
            change(result)
            return result
        with patch.object(CursorCLI, "run", inject):
            drive_run(self.state, run["run_id"], prepared["active_attempt_id"])
        stopped = self.service.inspect(run["run_id"])
        attempt = self.service._store.detail("attempts", prepared["active_attempt_id"])
        self.assertEqual(len(self.invocations()), 1)
        self.assertIsNone(stopped["candidate"])
        self.assertIsNone(stopped["acceptance_id"])
        return stopped, attempt

    def test_missing_capture_never_uses_completed_driver_flag(self):
        stopped, attempt = self.run_with_fault(lambda r: r.pop("_private_capture"))
        self.assertEqual(attempt["status"], "failed")
        self.assertEqual(attempt["error"], "cursor_capture_invalid")
        self.assertIs(attempt["termination_confirmed"], True)
        self.assertIsNone(stopped["active_attempt_id"])

    def test_mutable_capture_is_refused_without_serializing_bytes(self):
        stopped, attempt = self.run_with_fault(lambda r: r["_private_capture"].update(stdout=bytearray(r["_private_capture"]["stdout"])))
        self.assertEqual(attempt["error"], "cursor_capture_invalid")
        self.assertEqual(stopped["pending_effect_ids"], [])

    def test_valid_capture_cannot_override_unknown_cessation(self):
        stopped, attempt = self.run_with_fault(lambda r: r["process"].update(
            termination_confirmed=False, group_termination_confirmed=False))
        self.assertIs(attempt["termination_confirmed"], False)
        self.assertEqual(stopped["active_attempt_id"], attempt["attempt_id"])
        self.assertTrue(stopped["pending_effect_ids"])
        self.assertEqual(self.service.result(stopped["run_id"])["outcome"], "unknown")
        observed = self.service.reconcile(stopped["run_id"], operation_key="unknown-capture", expected_revision=stopped["revision"])
        self.assertEqual(self.service._store.lease(observed)["state"], "quarantined")

    def test_driver_observation_cannot_replace_core_decoding(self):
        _, attempt = self.run_with_fault(lambda r: r["cursor_observation"].update(frame_count=999))
        self.assertEqual(attempt["error"], "cursor_capture_invalid")
        self.assertIsNone(attempt["result_artifact"])
        self.assertIsNone(attempt["driver_report"]["reported_session_id"])

    def test_valid_but_substituted_worker_body_is_not_repaired(self):
        _, attempt = self.run_with_fault(lambda r: r["result"].update(summary="Substituted after stream decoding."))
        self.assertEqual(attempt["error"], "cursor_capture_invalid")
        self.assertIsNone(attempt["result_artifact"])

    def test_private_blob_write_failure_retains_unknown_effect(self):
        from taskalong.store import Store
        original = Store.put_blob
        def fail_private(store, raw, **options):
            if options.get("redaction_version") == "private-unredacted-cursor-capture/1":
                raise OSError("synthetic private capture storage failure")
            return original(store, raw, **options)
        with patch.object(Store, "put_blob", fail_private):
            stopped, attempt = self.run_with_fault(lambda r: None)
        self.assertIs(attempt["termination_confirmed"], False)
        self.assertEqual(stopped["active_attempt_id"], attempt["attempt_id"])
        self.assertTrue(stopped["pending_effect_ids"])
        self.assertEqual(self.service.result(stopped["run_id"])["outcome"], "unknown")
        observed = self.service.reconcile(stopped["run_id"], operation_key="capture-write-failed", expected_revision=stopped["revision"])
        self.assertEqual(self.service._store.lease(observed)["state"], "quarantined")

    def test_oversized_combined_capture_is_not_silently_truncated(self):
        _, attempt = self.run_with_fault(lambda r: r["_private_capture"].update(stderr=b"x" * (1024 * 1024)))
        self.assertEqual(attempt["error"], "cursor_capture_invalid")
        self.assertIsNone(attempt["cursor_raw_capture"])


class CursorRecoveryTests(CursorBindingFixture, unittest.TestCase):
    from test_recovery_regressions import RecoveryRegressions as _Recovery
    from test_claude_driver import ClaudeRecoveryTests as _Cases
    wait_file = _Recovery.wait_file
    cli_start = _Recovery.cli_start
    trace_environment = _Recovery.trace_environment
    test_lost_supervisor_before_finish_retains_unknown_effect_and_quarantine = _Cases.test_lost_supervisor_before_finish_retains_unknown_effect_and_quarantine
    test_exhausted_unreconciled_attempt_refuses_restart_without_new_effect = _Cases.test_exhausted_unreconciled_attempt_refuses_restart_without_new_effect

    def setUp(self):
        super().setUp()
        self.service.configure_execution(**self.configuration)

    def submit(self, spec=None, **options):
        return super().submit(self.task if spec is None else spec, **options)

    def assert_lost_supervisor_before_finish(self, *, exhausted):
        self._Cases.assert_lost_supervisor_before_finish(self, exhausted=exhausted)
        rows = self.service._store.db.execute("SELECT sha256,bytes FROM blobs WHERE redaction_version=? AND bytes>0",
            ("private-unredacted-cursor-capture/1",)).fetchall()
        self.assertTrue(rows, "Raw output was retained before the deliberately lost durable finish.")
        for row in rows:
            self.assertEqual(len(self.service._store.get_blob(row["sha256"])), row["bytes"])


class CursorPredecessorTests(CursorBindingFixture, unittest.TestCase):
    def completed_before_freeze(self):
        from taskalong.workflow import Workflow, drive_run
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        with patch.object(self.service._workflow, "_launch_supervisor"):
            prepared = self.start(run)
        # A controlled refusal, not a fake successful verifier or new authority.
        with patch.object(Workflow, "verify", side_effect=TaskAlongError("authority_missing", "Synthetic expired verifier boundary.", exit_code=3)):
            drive_run(self.state, run["run_id"], prepared["active_attempt_id"])
        stopped = self.service.inspect(run["run_id"])
        attempt = self.service._store.detail("attempts", prepared["active_attempt_id"])
        self.assertEqual(attempt["status"], "completed")
        self.assertIs(attempt["termination_confirmed"], True)
        self.assertIsNone(stopped["candidate"])
        self.assertIsNone(stopped["active_attempt_id"])
        self.assertEqual(stopped["pending_effect_ids"], [])
        self.assertEqual(self.service.result(run["run_id"])["outcome"], "worker_completed")
        return stopped, attempt

    def corrupt_previous(self, attempt):
        from taskalong.store import encode
        attempt = deepcopy(attempt)
        attempt["cursor_capture"]["observation"]["frame_count"] += 1
        attempt["cursor_capture"]["digest"] = digest(attempt["cursor_capture"])
        attempt["checkpoint"]["capture_digest"] = attempt["cursor_capture"]["digest"]
        with self.service._store.transaction() as db:
            db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(attempt), attempt["attempt_id"]))

    def test_restart_refuses_corrupt_completed_predecessor_without_reservation(self):
        stopped, previous = self.completed_before_freeze()
        self.corrupt_previous(previous)
        lease = self.service._store.lease(stopped)
        before = self.service._store.db.total_changes
        with self.assertRaises(TaskAlongError) as failure:
            self.service.resume(stopped["run_id"], mode="restart", operation_key="corrupt-predecessor", expected_revision=stopped["revision"])
        self.assertEqual(failure.exception.code, "cursor_capture_invalid")
        self.assertEqual(self.service._store.db.total_changes, before)
        self.assertEqual(self.service.inspect(stopped["run_id"]), stopped)
        self.assertEqual(self.service._store.lease(stopped), lease)
        self.assertEqual(len(self.invocations()), 1)

    def test_intact_completed_predecessor_allows_explicit_fresh_restart(self):
        from taskalong.workflow import drive_run
        stopped, previous = self.completed_before_freeze()
        with patch.object(self.service._workflow, "_launch_supervisor"):
            prepared = self.service.resume(stopped["run_id"], mode="restart", operation_key="intact-predecessor", expected_revision=stopped["revision"])
        drive_run(self.state, stopped["run_id"], prepared["active_attempt_id"])
        self.assertEqual(self.service.result(stopped["run_id"])["outcome"], "worker_completed")
        self.assertEqual(len(self.invocations()), 2)
        self.assertNotEqual(self.invocations()[0]["session_id"], self.invocations()[1]["session_id"])

    def test_corruption_after_restart_prepare_prevents_target_dispatch(self):
        from taskalong.workflow import drive_run
        stopped, previous = self.completed_before_freeze()
        with patch.object(self.service._workflow, "_launch_supervisor"):
            prepared = self.service.resume(stopped["run_id"], mode="restart", operation_key="prepared-predecessor", expected_revision=stopped["revision"])
        self.corrupt_previous(previous)
        drive_run(self.state, stopped["run_id"], prepared["active_attempt_id"])
        current = self.service.inspect(stopped["run_id"])
        last = self.service._store.detail("attempts", prepared["active_attempt_id"])
        self.assertEqual(last["error"], "cursor_capture_invalid")
        self.assertIs(last["termination_confirmed"], True)
        self.assertEqual(len(self.invocations()), 1)
        self.assertIsNone(current["candidate"])
        self.assertIsNone(current["acceptance_id"])
        self.assertIsNone(current["active_attempt_id"])
        self.assertEqual(current["pending_effect_ids"], [])

    def test_interrupted_reacquisition_validates_completed_predecessor(self):
        stopped, previous = self.completed_before_freeze()
        with patch.object(self.service._workflow, "_workspace_ready", side_effect=TaskAlongError("synthetic_reacquire_interruption", "Synthetic interruption after generation advance.", effect_outcome="uncertain")):
            with self.assertRaises(TaskAlongError):
                self.service.resume(stopped["run_id"], mode="restart", operation_key="interrupted-predecessor", expected_revision=stopped["revision"])
        self.corrupt_previous(previous)
        interrupted = self.service.inspect(stopped["run_id"])
        before = self.service._store.db.total_changes
        with patch.object(self.service._workflow, "_launch_supervisor") as launch:
            with self.assertRaises(TaskAlongError) as failure:
                self.service.reconcile(stopped["run_id"], operation_key="recover-predecessor", expected_revision=interrupted["revision"])
        self.assertEqual(failure.exception.code, "cursor_capture_invalid")
        launch.assert_not_called()
        self.assertEqual(self.service._store.db.total_changes, before)
        self.assertEqual(self.service.inspect(stopped["run_id"]), interrupted)
        self.assertEqual(len(self.invocations()), 1)

class CursorRawOutputTests(unittest.TestCase):
    def test_trusted_capture_gets_original_bytes_while_default_result_stays_redacted(self):
        from taskalong.process import run_bounded
        seen = []
        code = "import sys;sys.stdout.buffer.write(b'Bearer abc');sys.stderr.buffer.write(b'Bearer xyz')"
        for enabled in (False, True):
            options = {"_capture_private_output": lambda out, err: seen.append((out, err))} if enabled else {}
            result = run_bounded([sys.executable, "-c", code], cwd=tempfile.gettempdir(), **options)
            self.assertEqual((result.stdout, result.stderr), (b"[REDACTED]", b"[REDACTED]"))
            self.assertNotIn("Bearer", json.dumps(result.to_dict()))
            self.assertIs(result.termination_confirmed, True)
        self.assertEqual(seen, [(b"Bearer abc", b"Bearer xyz")])
        self.assertTrue(all(type(raw) is bytes for pair in seen for raw in pair))

    def test_closed_gate_refusal_still_delivers_exact_empty_capture_once(self):
        from taskalong.process import ProcessBoundaryError, run_bounded
        seen = []
        def refuse(_):
            raise TaskAlongError("cancel_pending", "Synthetic closed-gate cancellation.", effect_outcome="not_sent")
        with self.assertRaises(ProcessBoundaryError) as failure:
            run_bounded([sys.executable, "-c", "raise SystemExit(93)"], cwd=tempfile.gettempdir(),
                on_spawn=refuse, _capture_private_output=lambda out, err: seen.append((out, err)))
        self.assertEqual(failure.exception.code, "cancel_pending")
        self.assertEqual(failure.exception.effect_outcome, "not_sent")
        self.assertIs(failure.exception.process_result.termination_confirmed, True)
        self.assertEqual(seen, [(b"", b"")])

    def test_capture_failure_cannot_hide_behind_earlier_gate_cancellation(self):
        from taskalong.process import ProcessBoundaryError, run_bounded
        for gated in (False, True):
            seen = []
            def capture(out, err):
                seen.append((out, err))
                raise RuntimeError("SYNTHETIC_CALLBACK_PRIVATE_DETAIL")
            def refuse(_):
                raise TaskAlongError("cancel_pending", "Synthetic closed-gate cancellation.", effect_outcome="not_sent")
            with self.subTest(gated=gated), self.assertRaises(ProcessBoundaryError) as failure:
                run_bounded([sys.executable, "-c", "print('Bearer abc')"], cwd=tempfile.gettempdir(),
                    on_spawn=refuse if gated else None, _capture_private_output=capture)
            self.assertEqual(failure.exception.code, "process_capture_failed")
            self.assertNotIn("SYNTHETIC_CALLBACK_PRIVATE_DETAIL", str(failure.exception))
            import traceback
            self.assertNotIn("SYNTHETIC_CALLBACK_PRIVATE_DETAIL", "".join(traceback.format_exception(failure.exception)))
            self.assertNotIn("Bearer", json.dumps(failure.exception.process_result.to_dict()))
            self.assertEqual(len(seen), 1)
            self.assertIs(failure.exception.process_result.termination_confirmed, True)
            self.assertEqual(failure.exception.process_result.exit_code, None if gated else 0)

    def test_setup_refusal_does_not_invent_capture(self):
        from taskalong.process import ProcessBoundaryError, run_bounded
        seen = []
        with self.assertRaises(ProcessBoundaryError):
            run_bounded([sys.executable, "-c", "pass"], cwd=tempfile.gettempdir(), timeout_seconds=0,
                _capture_private_output=lambda out, err: seen.append((out, err)))
        self.assertEqual(seen, [])

    def test_output_limit_delivers_bounded_partial_bytes_without_completion(self):
        from taskalong.process import run_bounded
        seen = []
        result = run_bounded([sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'x'*10000)"],
            cwd=tempfile.gettempdir(), max_output_bytes=100,
            _capture_private_output=lambda out, err: seen.append((out, err)))
        self.assertEqual(len(seen), 1)
        self.assertLessEqual(sum(len(raw) for raw in seen[0]), 100)
        self.assertIs(result.output_limited, True)
        self.assertIs(result.termination_confirmed, True)

class CursorRemoteCapabilityTests(CursorBindingFixture, unittest.TestCase):
    def test_remote_cancellation_refuses_even_when_approved_start_evidence_satisfies_binding(self):
        from taskalong.bindings import ExecutionBinding, HarnessInstallation, ProviderProfile
        from taskalong.qualification import EvidenceStore, QualificationReceipt, TrustPolicy, evaluate
        from taskalong.store import now
        from test_qualification import policy_for, reference
        self.binding = seal_versioned("execution-binding", self.binding | {
            "required_capabilities": ["remote_cancellation", "start"]}, version="2.0")
        self.refresh_binding()
        blobs = self.configuration["evidence"]
        observation = loads(blobs[self.receipt["results"][0]["evidence_refs"][0]["sha256"]])
        observation.update(capability="remote_cancellation", criterion_id="fixture-remote-refusal",
            observations={"provider_acknowledged":True,"remote_work_stopped":True,"accounting_final":True})
        raw = canonical_bytes(observation)
        ref = reference(raw)
        blobs[ref["sha256"]] = raw
        self.receipt = seal_versioned("qualification-receipt", self.receipt | {
            "results":self.receipt["results"] + [{"capability":"remote_cancellation","outcome":"supported","evidence_refs":[ref]}]}, version="2.1")
        self.trust = policy_for(self.receipt)
        self.configuration.update(receipts=[self.receipt], trust=self.trust)
        decision = evaluate(ExecutionBinding.from_dict(self.binding),
            installation=HarnessInstallation.from_dict(self.installation), provider=ProviderProfile.from_dict(self.provider),
            context=self.context, mode="start", receipts=[QualificationReceipt.from_dict(self.receipt)],
            trust=TrustPolicy.from_dict(self.trust), evidence=EvidenceStore.from_blobs(blobs), now=now(), minimum_level="offline_fixture")
        self.assertTrue(decision.decision.to_dict()["requirements_satisfied"])
        before = self.service._store.db.total_changes
        with self.assertRaises(TaskAlongError) as failure:
            self.service.configure_execution(**self.configuration)
        self.assertEqual(failure.exception.code, "remote_cancellation_unsupported")
        self.assertEqual(self.service._store.db.total_changes, before)
        self.assertEqual(self.service._store.db.execute("SELECT count(*) FROM execution_projections").fetchone()[0], 0)
        self.assertEqual(self.invocations(), [])


if __name__ == "__main__":
    unittest.main()
