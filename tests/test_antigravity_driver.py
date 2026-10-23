"""Antigravity fixture launch and common lifecycle contracts; no vendor inference."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from copy import deepcopy
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, loads, seal_versioned
from test_antigravity_protocol import agy_packet, example_agy_config


def workspace_resolution_fault(workspace, error_type):
    """Inject only the selected workspace's nondeterministic filesystem fault."""
    resolve = Path.resolve
    def fail_selected(path, *args, **kwargs):
        if path == Path(workspace):
            raise error_type("synthetic-resolution-canary")
        return resolve(path, *args, **kwargs)
    return patch.object(Path, "resolve", fail_selected)


def agy_context(executable=None):
    provider = seal_versioned("provider-profile", {
        "profile_id": "fixture-agy-route", "revision": 1, "harness": "antigravity", "provider": "google-account",
        "model": {"requested": "fixture-agy-model", "resolved_digest":
            hashlib.sha256(b"taskalong-agy-fixture-model-v1").hexdigest()},
        "endpoint": "https://fixture.invalid", "auth": {"mode": "account", "credential_ref": "fixture-google-account"},
        "effort": None, "service_tier": None, "auxiliary_routes": [], "unlisted_auxiliary_routes": "deny",
        "allowed_disclosure": "provider-only", "fallback": "forbidden"}, version="2.0")
    fields = example_agy_config() | {"provider_profile_digest": provider["digest"]}
    if executable is not None:
        fields["executable"] = {"path": str(executable), "sha256": hashlib.sha256(Path(executable).read_bytes()).hexdigest()}
    return seal_versioned("driver-config", fields, version="2.6"), provider


def agy_compiler_inputs(config):
    packet = agy_packet()
    fields = {key: value for key, value in packet.items() if key not in (
        "kind", "schema_version", "digest", "binding_digest", "admission_digest", "projection", "session_policy",
        "allowed_tools", "result_schema_id")}
    fields["bindings"] = {key: value for key, value in fields["bindings"].items()
                          if key not in ("driver_config_digest", "provider_profile_digest")}
    admission = {"schema_version": "2.6", "spec_digest": fields["spec_digest"], "digest": "3" * 64,
        "driver_config": config, "binding": {"digest": "4" * 64,
            "provider_profile_digest": config["provider_profile_digest"], "installation_digest": config["installation_digest"]},
        "projection": {"projection": "antigravity-headless-fixture/1", "digest": "5" * 64,
                       "driver_config_digest": config["digest"]}}
    return fields, admission


class AntigravityDriverProjectionTests(unittest.TestCase):
    def test_explicit_stream_envelope_and_launch_never_select_continuation_or_bypass(self):
        from taskalong.executors.antigravity_cli import AntigravityCLI, compile_packet, encode_input
        config, provider = agy_context()
        packet, wire, mapping = compile_packet(*agy_compiler_inputs(config))
        self.assertEqual(packet, wire)
        self.assertEqual(mapping["input_framing"], "agy-user-ndjson/1")
        self.assertEqual(packet["result_schema_id"], "urn:taskalong:schema:v2.5:worker-result")
        raw = encode_input(packet)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(len(raw.splitlines()), 1)
        self.assertEqual(loads(raw), {"type": "user", "message": {
            "role": "user", "content": canonical_bytes(packet).decode()}})
        self.assertNotEqual(hashlib.sha256(raw).hexdigest(), packet["digest"])
        driver = AntigravityCLI(config, provider=provider)
        self.assertEqual(driver.build_argv(packet)[1:6], ["--input-format", "stream-json", "--output-format", "stream-json", "--model"])
        argv = driver.build_argv(packet)
        self.assertIn("--sandbox", argv)
        self.assertIn("--disable-slash-commands", argv)
        self.assertEqual(argv[argv.index("--print-timeout") + 1], "30s")
        for forbidden in ("-p", "--conversation", "--resume", "--continue", "--dangerously-skip-permissions"):
            self.assertNotIn(forbidden, argv)
        self.assertEqual(driver.capabilities().native_resume, False)
        self.assertEqual(driver.capabilities().provider_start_lookup, False)
        with self.assertRaises(TaskAlongError) as production:
            driver.preflight(qualification="production", budget={})
        self.assertEqual(production.exception.code, "runtime_policy_unsupported")

    def test_direct_factory_refuses_changed_provider_and_never_falls_back(self):
        from taskalong.executors.registry import executor_for
        config, provider = agy_context()
        for change in ({"model": provider["model"] | {"requested": "fallback"}},
                       {"endpoint": "https://other.invalid"}, {"effort": "high"},
                       {"auth": {"mode": "account", "credential_ref": "other-account"}},
                       {"harness": "cursor", "provider": "cursor-account"}):
            changed = seal_versioned("provider-profile", provider | change, version="2.0")
            rebound = seal_versioned("driver-config", config | {"provider_profile_digest": changed["digest"]}, version="2.6")
            with self.subTest(change=change), self.assertRaises(TaskAlongError):
                executor_for(rebound, provider=changed, task_version="2.6", projection="antigravity-headless-fixture/1")
        for version, projection in (("2.5", "antigravity-headless-fixture/1"), ("2.6", "cursor-print-fixture/1")):
            with self.assertRaises(TaskAlongError) as mismatch:
                executor_for(config, provider=provider, task_version=version, projection=projection)
            self.assertEqual(mismatch.exception.code, "adapter_unavailable")

    def test_compilation_refuses_native_identity_substitution_and_timeout_fits_remaining_budget(self):
        from taskalong.executors.antigravity_cli import AntigravityCLI, compile_packet
        config, provider = agy_context()
        fields, admission = agy_compiler_inputs(config)
        for change in ({"session_policy": "continue"}, {"session_id": fields["attempt_id"]},
                       {"bindings": fields["bindings"] | {"driver_config_digest": "f" * 64}},
                       {"result_schema_id": "urn:taskalong:schema:v1:worker-result"}):
            with self.subTest(change=change), self.assertRaises(TaskAlongError):
                compile_packet(fields | change, admission)
        fields["remaining_budget"]["attempt_seconds"] = 1
        packet, _, _ = compile_packet(fields, admission)
        argv = AntigravityCLI(config, provider=provider).build_argv(packet)
        self.assertEqual(argv[argv.index("--print-timeout") + 1], "1s")


class AntigravityOwnedProcessTests(unittest.TestCase):
    def test_original_fixture_uses_exact_stdin_and_observes_conversation_after_owned_cessation(self):
        from taskalong.executors.antigravity_cli import AntigravityCLI, compile_packet, encode_input
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            executable = root / "fake-agy"
            executable.write_text((Path(__file__).parent / "fixtures/fake_agy.py").read_text().replace(
                "#!/usr/bin/env python3", "#!" + sys.executable, 1))
            executable.chmod(0o700)
            workspace = root / "workspace"
            workspace.mkdir()
            for mode in ({"mode": "good"}, {"mode": "stderr", "diagnostic": "permission denied"},
                         {"mode": "stderr", "diagnostic": "benign warning"}, {"mode": "tool_denial"}):
                with self.subTest(mode=mode):
                    executable.with_suffix(".mode.json").write_text(json.dumps(mode))
                    (workspace / "arithmetic.py").write_text("def add(a, b):\n    return a - b\n")
                    config, provider = agy_context(executable)
                    packet, _, _ = compile_packet(*agy_compiler_inputs(config))
                    result = AntigravityCLI(config, provider=provider).run(packet, workspace=workspace,
                        output_dir=root / ("output-" + mode["mode"] + str(len(list(root.glob('output-*'))))))
                    self.assertIs(result["process"]["termination_confirmed"], True)
                    self.assertIs(result["process"]["group_termination_confirmed"], True)
                    self.assertEqual(result["_private_capture"]["stdin"], encode_input(packet))
                    self.assertIsNone(result["usage"]["input_tokens"])
                    self.assertIsNone(result["usage"]["cost_usd"])
                    if mode["mode"] == "good":
                        self.assertEqual(result["state"], "completed")
                        frames = [loads(line) for line in result["_private_capture"]["stdout"].splitlines()]
                        self.assertEqual(result["session_id"], frames[0]["conversation_id"])
                        self.assertNotEqual(result["session_id"], packet["attempt_id"])
                        self.assertEqual(result["result"], frames[-1]["structured_output"])
                        self.assertEqual(result["reported_usage"]["counters"],
                            {"input_tokens": 110, "output_tokens": 25, "total_tokens": 135})
                        self.assertIn("return a + b", (workspace / "arithmetic.py").read_text())
                    else:
                        self.assertEqual(result["state"], "failed")
                        self.assertEqual(result["process"]["exit_code"], 0)
                        self.assertEqual(result["error"], "agy_tool_failed" if mode["mode"] == "tool_denial"
                                         else "agy_diagnostics_unqualified")
                        self.assertIsNone(result["result"])

    def test_workspace_resolution_fault_after_owned_completion_never_returns_success(self):
        from taskalong.executors import antigravity_cli as agy
        for error_type in (OSError, RuntimeError):
            with self.subTest(fault=error_type.__name__), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                executable = root / "fake-agy"
                executable.write_text((Path(__file__).parent / "fixtures/fake_agy.py").read_text().replace(
                    "#!/usr/bin/env python3", "#!" + sys.executable, 1))
                executable.chmod(0o700)
                workspace = root / "workspace"
                workspace.mkdir()
                (workspace / "arithmetic.py").write_text("def add(a, b):\n    return a - b\n")
                config, provider = agy_context(executable)
                packet, _, _ = agy.compile_packet(*agy_compiler_inputs(config))
                run_bounded = agy.run_bounded
                observed, faults = {}, []
                def fail_after_real_completion(*args, **kwargs):
                    process = run_bounded(*args, **kwargs)
                    observed["process"] = process.to_dict()
                    fault = workspace_resolution_fault(workspace, error_type)
                    fault.start()
                    faults.append(fault)
                    return process
                try:
                    with patch.object(agy, "run_bounded", fail_after_real_completion):
                        result = agy.AntigravityCLI(config, provider=provider).run(
                            packet, workspace=workspace, output_dir=root / "output")
                finally:
                    for fault in faults:
                        fault.stop()
                process = observed["process"]
                process.pop("stdout")
                process.pop("stderr")
                self.assertEqual(result["process"], process)
                self.assertIs(result["process"]["termination_confirmed"], True)
                self.assertIs(result["process"]["group_termination_confirmed"], True)
                self.assertEqual(result["state"], "failed")
                self.assertEqual(result["error"], "agy_capture_invalid")
                for key in ("result", "session_id", "reported_usage", "antigravity_observation"):
                    self.assertIsNone(result[key])
                self.assertEqual(result["_private_capture"]["stdin"], agy.encode_input(packet))
                frames = [loads(line) for line in result["_private_capture"]["stdout"].splitlines()]
                self.assertEqual(frames[-1]["structured_output"]["status"], "completed")
                self.assertEqual(len(executable.with_suffix(".invocations.jsonl").read_bytes().splitlines()), 1)


from test_execution_bindings import BindingFixture
from taskalong.validation import digest
class AntigravityBindingFixture(BindingFixture):
    """Neutral M4 fixture with a separate original Antigravity worker and v1 verifier."""
    def setUp(self):
        super().setUp()
        from taskalong.api import RunService
        from taskalong.store import Store
        from test_antigravity_store import upgrade_through
        self.service.close()
        with Store.maintenance(self.state) as store:
            upgrade_through(store, self.root, 7)
        self.service = RunService(self.state)
        self.executable = self.root / "fake-agy"
        self.executable.write_text((Path(__file__).parent / "fixtures/fake_agy.py").read_text().replace(
            "#!/usr/bin/env python3", "#!" + sys.executable, 1))
        self.executable.chmod(0o700)
        self.mode_file = self.executable.with_suffix(".mode.json")
        self.mode_file.write_text('{"mode":"good"}')
        self.barrier_file = self.executable.with_suffix(".hold")
        self.release_file = self.executable.with_suffix(".release")
        config, self.provider = agy_context(self.executable)
        self.tools = seal_versioned("tool-policy", self.tools | {"allowed_tools": ["antigravity.write_file"]}, version="2.2")
        self.installation = seal_versioned("harness-installation", self.installation | {
            "installation_id": "fixture-agy", "harness": "antigravity", "adapter_id": "antigravity-cli",
            "driver_version": "agy-headless-fixture-1", "cli_version": "synthetic-agy-1",
            "executable_digest": config["executable"]["sha256"], "runtime_closure_digest": digest({
                "fixture": config["executable"]["sha256"], "python": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
                "check_launcher": hashlib.sha256(self.sandbox.read_bytes()).hexdigest()})}, version="2.0")
        self.binding = seal_versioned("execution-binding", self.binding | {
            "installation_digest": self.installation["digest"], "provider_profile_digest": self.provider["digest"],
            "tool_policy_digest": self.tools["digest"]}, version="2.0")
        self.driver_config = seal_versioned("driver-config", config | {
            "installation_digest": self.installation["digest"], "policy_digests": {
                "instructions": self.instructions["digest"], "tools": self.tools["digest"],
                "worker_sandbox": self.worker_sandbox["digest"], "check_binding": self.check["digest"]}}, version="2.6")
        self.refresh_agy_binding()

    def refresh_agy_binding(self):
        from test_qualification import reference, policy_for
        self.binding = seal_versioned("execution-binding", self.binding | {
            "check_binding_digest": self.check["digest"]}, version="2.0")
        self.driver_config = seal_versioned("driver-config", self.driver_config | {"policy_digests": {
            "instructions": self.binding["instruction_bundle_digest"], "tools": self.binding["tool_policy_digest"],
            "worker_sandbox": self.binding["worker_sandbox_digest"], "check_binding": self.check["digest"]}}, version="2.6")
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
            evidence=blobs, context=self.context, projection="antigravity-headless-fixture/1")
        self.task = seal_versioned("task-spec", self.task | {"schema_version": "2.6",
            "execution": {"binding_digest": self.binding["digest"], "driver_config_digest": self.driver_config["digest"]},
            "permissions": self.task["permissions"] | {"inference_destination_id": self.provider["profile_id"]}}, version="2.6")

    def refresh_binding(self):
        self.refresh_agy_binding()

    def invocations(self):
        path = self.executable.with_suffix(".invocations.jsonl")
        return [loads(line) for line in path.read_bytes().splitlines()] if path.exists() else []


class AntigravityRegistrationTests(AntigravityBindingFixture, unittest.TestCase):
    def test_explicit_registration_on_format7_does_not_start_a_worker(self):
        value = self.service.configure_execution(**self.configuration)
        self.assertFalse(value["production_dispatch_allowed"])
        self.assertEqual(self.invocations(), [])


class AntigravityPublicLifecycleTests(AntigravityBindingFixture, unittest.TestCase):
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
            capture = self.service._store.get_blob(attempt["antigravity_capture"]["stdout"]["sha256"])
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
            self.assertEqual(last["error"], "agy_session_reused")
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
            self.assertEqual(attempt["error"], "agy_diagnostics_unqualified")
            self.assertEqual(attempt["process"]["exit_code"], 0)
            self.assertIs(attempt["termination_confirmed"], True)
            self.assertIsNone(attempt["antigravity_capture"])
            self.assertIsNone(attempt["result_artifact"])
            self.assertIsNone(attempt["driver_report"]["reported_session_id"])
            raw = self.service._store.get_blob(attempt["antigravity_raw_capture"]["stderr"]["sha256"])
            self.assertEqual(raw, (canary + "\n").encode())
            public = [self.service.result(run["run_id"]), self.service.events(run["run_id"]), self.export(run["run_id"])]
            self.assertNotIn(canary, canonical_bytes(public).decode())
            self.assertIsNone(stopped["candidate"])
            self.assertIsNone(stopped["acceptance_id"])

    def test_corrupt_completed_capture_is_refused_by_every_consuming_public_read(self):
            from taskalong.store import encode
            self.service.configure_execution(**self.configuration)
            run, _ = self.submit(self.task)
            self.start(run)
            stopped = self.wait(run["run_id"])
            attempt_id = stopped["attempts"][-1]["attempt_id"]
            original = self.service._store.detail("attempts", attempt_id)
            self.assertEqual(self.service.result(run["run_id"])["outcome"], "worker_completed")
            mutations = [lambda a: a.pop("antigravity_capture"),
                lambda a: a["antigravity_capture"]["observation"].update(frame_count=999),
                lambda a: a["antigravity_capture"]["observation"].update(reported_model="other-model"),
                lambda a: a["antigravity_capture"]["observation"].update(observed_session_id=run["run_id"]),
                lambda a: a["antigravity_capture"]["stdout"].update(bytes=1),
                lambda a: a["antigravity_capture"].update(provider_profile_digest="f" * 64),
                lambda a: a["antigravity_capture"].update(mapping_digest="f" * 64),
                lambda a: a["antigravity_capture"].update(packet_digest="f" * 64),
                lambda a: a["antigravity_capture"].update(admission_digest="f" * 64),
                lambda a: a["antigravity_capture"]["stderr"].update(sha256=a["antigravity_capture"]["stdout"]["sha256"]),
                lambda a: a["checkpoint"].update(capture_digest="f" * 64),
                lambda a: a["process"].update(group_termination_confirmed=False),
                lambda a: a["antigravity_capture"]["stdin"].update(sha256=a["antigravity_capture"]["stdout"]["sha256"])]
            actions = {"result": lambda: self.service.result(run["run_id"]),
                "verify": lambda: self.service.verify(run["run_id"], operation_key="tamper-verify", expected_revision=stopped["revision"]),
                "reconcile": lambda: self.service.reconcile(run["run_id"], operation_key="tamper-reconcile", expected_revision=stopped["revision"]),
                "publish_intent": lambda: self.service.publish_intent(run["run_id"])}
            try:
                for index, mutate in enumerate(mutations):
                    changed = deepcopy(original)
                    mutate(changed)
                    if changed.get("antigravity_capture"):
                        changed["antigravity_capture"]["digest"] = digest(changed["antigravity_capture"])
                        if index != 10:
                            changed["checkpoint"]["capture_digest"] = changed["antigravity_capture"]["digest"]
                    with self.service._store.transaction() as db:
                        db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(changed), attempt_id))
                    before = self.service._store.db.total_changes
                    for label, action in actions.items():
                        with self.subTest(index=index, action=label), self.assertRaises(TaskAlongError) as failure:
                            action()
                        self.assertEqual(failure.exception.code, "agy_capture_invalid")
                    self.assertEqual(self.service._store.db.total_changes, before)
                    self.assertEqual(self.service.inspect(run["run_id"])["revision"], stopped["revision"])
                    self.assertEqual(len(self.invocations()), 1)
            finally:
                with self.service._store.transaction() as db:
                    db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(original), attempt_id))

from test_executor_contract import DurableDriverContract


class AntigravitySharedContractTests(AntigravityBindingFixture, DurableDriverContract, unittest.TestCase):
    pass


class AntigravityAdmissionTests(AntigravityBindingFixture, unittest.TestCase):
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


class AntigravityCaptureFaultTests(AntigravityBindingFixture, unittest.TestCase):
    def stopped_fault(self, change):
        from taskalong.executors.antigravity_cli import AntigravityCLI
        from taskalong.workflow import drive_run
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        with patch.object(self.service._workflow, "_launch_supervisor"):
            prepared = self.start(run)
        original = AntigravityCLI.run
        def inject(driver, *args, **kwargs):
            result = original(driver, *args, **kwargs)
            self.assertEqual(result["state"], "completed")
            change(result)
            return result
        with patch.object(AntigravityCLI, "run", inject):
            drive_run(self.state, run["run_id"], prepared["active_attempt_id"])
        stopped = self.service.inspect(run["run_id"])
        attempt = self.service._store.detail("attempts", prepared["active_attempt_id"])
        self.assertIsNone(stopped["acceptance_id"])
        self.assertIsNone(stopped["candidate"])
        return stopped, attempt

    def test_reported_usage_cannot_be_substituted_after_independent_wire_decoding(self):
        _, attempt = self.stopped_fault(lambda result: result["reported_usage"]["counters"].update(input_tokens=999))
        self.assertEqual(attempt["error"], "agy_capture_invalid")
        self.assertIsNone(attempt["result_artifact"])

    def test_workspace_resolution_fault_preserves_original_capture_and_real_cessation(self):
        observed = {}
        faults = []
        def fail_after_worker(result):
            observed.update(process=deepcopy(result["process"]), capture=deepcopy(result["_private_capture"]))
            workspace = loads(result["_private_capture"]["stdout"].splitlines()[0])["cwd"]
            fault = workspace_resolution_fault(workspace, RuntimeError)
            fault.start()
            faults.append(fault)
        try:
            stopped, attempt = self.stopped_fault(fail_after_worker)
        finally:
            for fault in faults:
                fault.stop()
        self.assertEqual(attempt.get("error"), "agy_capture_invalid")
        self.assertEqual(attempt["status"], "failed")
        self.assertEqual(attempt["process"], observed["process"])
        self.assertIs(attempt["termination_confirmed"], True)
        self.assertIsNone(attempt["result_artifact"])
        self.assertIsNone(attempt["antigravity_capture"])
        self.assertEqual(stopped["pending_effect_ids"], [])
        self.assertIsNone(stopped["active_attempt_id"])
        self.assertEqual(len(self.invocations()), 1)
        for stream, raw in observed["capture"].items():
            ref = attempt["antigravity_raw_capture"][stream]
            self.assertEqual(self.service._store.get_blob(ref["sha256"]), raw)

    def test_framed_input_cannot_be_substituted_even_when_output_is_valid(self):
        _, attempt = self.stopped_fault(lambda result: result["_private_capture"].update(stdin=b'{"type":"user"}\n'))
        self.assertEqual(attempt["error"], "agy_capture_invalid")
        self.assertIsNone(attempt["result_artifact"])

    def test_valid_capture_cannot_override_uncertain_owned_cessation(self):
        stopped, attempt = self.stopped_fault(lambda result: result["process"].update(
            termination_confirmed=False, group_termination_confirmed=False))
        self.assertIs(attempt["termination_confirmed"], False)
        self.assertEqual(stopped["active_attempt_id"], attempt["attempt_id"])
        self.assertTrue(stopped["pending_effect_ids"])
        self.assertEqual(self.service.result(stopped["run_id"])["outcome"], "unknown")

    def test_missing_original_capture_never_trusts_a_completed_driver_flag(self):
        stopped, attempt = self.stopped_fault(lambda result: result.pop("_private_capture"))
        self.assertEqual(attempt["error"], "agy_capture_invalid")
        self.assertIs(attempt["termination_confirmed"], True)
        self.assertEqual(stopped["pending_effect_ids"], [])


class AntigravityPredecessorTests(AntigravityBindingFixture, unittest.TestCase):
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
        attempt["antigravity_capture"]["observation"]["frame_count"] += 1
        attempt["antigravity_capture"]["digest"] = digest(attempt["antigravity_capture"])
        attempt["checkpoint"]["capture_digest"] = attempt["antigravity_capture"]["digest"]
        with self.service._store.transaction() as db:
            db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(attempt), attempt["attempt_id"]))

    def test_workspace_resolution_fault_refuses_completed_reads_and_restart_without_mutation(self):
        stopped, previous = self.completed_before_freeze()
        workspace = Path(previous["workspace"]["path"])
        before = self.service._store.db.total_changes
        operations = self.service._store.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
        lease = self.service._store.lease(stopped)
        actions = {
            "result": lambda: self.service.result(stopped["run_id"]),
            "verify": lambda: self.service.verify(stopped["run_id"], operation_key="fault-verify", expected_revision=stopped["revision"]),
            "reconcile": lambda: self.service.reconcile(stopped["run_id"], operation_key="fault-reconcile", expected_revision=stopped["revision"]),
            "publish_intent": lambda: self.service.publish_intent(stopped["run_id"]),
            "restart": lambda: self.service.resume(stopped["run_id"], mode="restart", operation_key="fault-restart", expected_revision=stopped["revision"]),
        }
        for error_type in (OSError, RuntimeError):
            for label, action in actions.items():
                with self.subTest(fault=error_type.__name__, action=label):
                    with workspace_resolution_fault(workspace, error_type), self.assertRaises(TaskAlongError) as failure:
                        action()
                    self.assertEqual(failure.exception.code, "agy_capture_invalid")
                    self.assertEqual(failure.exception.exit_code, 70)
                    self.assertNotIn("synthetic-resolution-canary", failure.exception.message)
                    self.assertNotIn(str(workspace), failure.exception.message)
                self.assertEqual(self.service._store.db.total_changes, before)
                self.assertEqual(self.service._store.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0], operations)
                self.assertEqual(self.service.inspect(stopped["run_id"]), stopped)
                self.assertEqual(self.service._store.detail("attempts", previous["attempt_id"]), previous)
                self.assertEqual(self.service._store.lease(stopped), lease)
                self.assertEqual(len(self.invocations()), 1)
        self.assertEqual(self.service.result(stopped["run_id"])["outcome"], "worker_completed")

    def test_restart_refuses_corrupt_completed_predecessor_without_reservation(self):
        stopped, previous = self.completed_before_freeze()
        self.corrupt_previous(previous)
        lease = self.service._store.lease(stopped)
        before = self.service._store.db.total_changes
        with self.assertRaises(TaskAlongError) as failure:
            self.service.resume(stopped["run_id"], mode="restart", operation_key="corrupt-predecessor", expected_revision=stopped["revision"])
        self.assertEqual(failure.exception.code, "agy_capture_invalid")
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
        self.assertEqual(last["error"], "agy_capture_invalid")
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
        self.assertEqual(failure.exception.code, "agy_capture_invalid")
        launch.assert_not_called()
        self.assertEqual(self.service._store.db.total_changes, before)
        self.assertEqual(self.service.inspect(stopped["run_id"]), interrupted)
        self.assertEqual(len(self.invocations()), 1)


class AntigravityRecoveryTests(AntigravityBindingFixture, unittest.TestCase):
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
            ("private-unredacted-antigravity-capture/1",)).fetchall()
        self.assertTrue(rows, "Raw output was retained before the deliberately lost durable finish.")
        for row in rows:
            self.assertEqual(len(self.service._store.get_blob(row["sha256"])), row["bytes"])


class AntigravityRemoteRefusalTests(AntigravityBindingFixture, unittest.TestCase):
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


class AntigravityMissingActionTests(AntigravityBindingFixture, unittest.TestCase):
    def test_success_claim_without_required_edit_never_becomes_acceptance(self):
        self.mode_file.write_text('{"mode":"no_edit"}')
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        self.start(run)
        stopped = self.wait(run["run_id"])
        attempt = self.service._store.detail("attempts", stopped["attempts"][-1]["attempt_id"])
        self.assertEqual(attempt["error"], "worker_scope_claim_mismatch")
        self.assertIsNone(stopped["candidate"])
        self.assertIsNone(stopped["acceptance_id"])
        self.assertIs(attempt["termination_confirmed"], True)
