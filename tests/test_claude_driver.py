"""Versioned Claude fixture integration; these are not real vendor transcripts."""
import unittest
import hashlib
import importlib.util
import tempfile
import uuid
import sys
import time
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
from pathlib import Path

from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, digest, loads, schema_names, seal_versioned
from test_execution_bindings import BindingFixture
from test_executor_contract import DurableDriverContract


def example_driver_config():
    return {
        "driver_id": "claude-code", "driver_version": "claude-print-fixture-1",
        "projection": "claude-print-fixture/1", "wire_version": "2.3",
        "installation_digest": "a" * 64, "provider_profile_digest": "b" * 64,
        "qualification": "synthetic", "registration": "operator_registered_fixture",
        "executable": {"path": "/opt/taskalong/fixture-claude", "sha256": "c" * 64},
        "credential_ref": "fixture-auth",
        "policy_digests": {"instructions": "d" * 64, "tools": "e" * 64,
                           "worker_sandbox": "f" * 64, "check_binding": "1" * 64},
        "launch": {"mode": "print", "input_format": "text", "output_format": "stream-json",
                   "verbose": True, "session_persistence": False, "settings_sources": [],
                   "strict_mcp": True, "background_agents": "deny", "customizations": "deny",
                   "permission_mode": "default"},
    }


def driver_packet_inputs():
    from test_contracts import example_spec
    spec = example_spec()
    packet = {"packet_id":str(uuid.uuid4()), "run_id":str(uuid.uuid4()), "attempt_id":str(uuid.uuid4()),
        "spec_digest":"2" * 64, "goal":spec["goal"], "non_goals":spec["non_goals"],
        "scope":spec["scope"], "checks":spec["checks"], "bindings":{
            "base_commit":"a" * 40, "initial_head":"a" * 40, "initial_content_digest":"b" * 64,
            "workspace_id":str(uuid.uuid4()), "lease_generation":1},
        "remaining_budget":spec["budget"], "qualification":"synthetic", "extensions":{}}
    config = seal_versioned("driver-config", example_driver_config(), version="2.3")
    admission = {"schema_version":"2.3", "spec_digest":packet["spec_digest"], "digest":"3" * 64,
        "binding":{"digest":"4" * 64}, "driver_config":config,
        "projection":{"projection":"claude-print-fixture/1", "digest":"5" * 64,
                      "driver_config_digest":config["digest"]}}
    return packet, admission


def fixture_driver_context(executable):
    provider = seal_versioned("provider-profile", {
        "profile_id":"fixture-claude-route", "revision":1, "harness":"claude-code", "provider":"anthropic-account",
        "model":{"requested":"fixture-claude-model", "resolved_digest":digest({"simulated_model":"fixture-claude-model"})},
        "endpoint":"https://fixture.invalid", "auth":{"mode":"account", "credential_ref":"fixture-auth"},
        "effort":"high", "service_tier":None, "auxiliary_routes":[], "unlisted_auxiliary_routes":"deny",
        "allowed_disclosure":"provider-only", "fallback":"forbidden"}, version="2.0")
    config = seal_versioned("driver-config", example_driver_config() | {
        "executable":{"path":str(executable), "sha256":hashlib.sha256(executable.read_bytes()).hexdigest()},
        "provider_profile_digest":provider["digest"]}, version="2.3")
    return config, provider


def driver_worker(packet):
    return {"kind":"worker_result", "schema_version":"2.3", "extensions":{},
        "result_id":str(uuid.uuid4()), "packet_id":packet["packet_id"], "packet_digest":packet["digest"],
        "run_id":packet["run_id"], "attempt_id":packet["attempt_id"], "spec_digest":packet["spec_digest"],
        "driver_config_digest":packet["bindings"]["driver_config_digest"],
        "provider_profile_digest":packet["bindings"]["provider_profile_digest"], "session_id":packet["session_id"],
        "status":"completed", "changed_files":[], "command_claims":[], "summary":"Synthetic worker result.",
        "blockers":[], "deviations":[], "residual_risks":[], "qualification":"synthetic"}


def assert_settled_failed_attempt(test, run):
    """Budget/restart oracles require real post-exit failure, never uncertainty."""
    latest = run["attempts"][-1]["attempt_id"]
    attempt = test.service._store.detail("attempts", latest)
    process = attempt.get("process") or {}
    diagnostic = canonical_bytes({
        "state":run["state"], "active_attempt_id":run["active_attempt_id"],
        "pending_effect_ids":run["pending_effect_ids"], "latest_attempt_id":latest,
        "attempt_id":attempt["attempt_id"], "attempt_status":attempt["status"],
        "attempt_error":attempt.get("error"), "termination_confirmed":attempt.get("termination_confirmed"),
        "process":{key:process.get(key) for key in ("exit_code", "termination_confirmed",
            "group_termination_confirmed", "timed_out", "cancelled", "output_limited",
            "protocol_error", "lifetime_backend", "unaccounted_descendants")}}).decode()
    test.assertEqual(run["state"], "blocked", diagnostic)
    test.assertIsNone(run["active_attempt_id"], diagnostic)
    test.assertEqual(run["pending_effect_ids"], [], diagnostic)
    test.assertIsNone(run["candidate"], diagnostic)
    test.assertIsNone(run["acceptance_id"], diagnostic)
    test.assertEqual(attempt["attempt_id"], latest, diagnostic)
    test.assertEqual(attempt["run_id"], run["run_id"], diagnostic)
    test.assertEqual(attempt["status"], "failed", diagnostic)
    test.assertEqual(attempt.get("error"), "claude_exit_failed", diagnostic)
    test.assertIs(attempt.get("termination_confirmed"), True, diagnostic)
    test.assertEqual(process.get("exit_code"), 1, diagnostic)
    test.assertIs(process.get("termination_confirmed"), True, diagnostic)
    test.assertIs(process.get("group_termination_confirmed"), True, diagnostic)
    for key in ("timed_out", "cancelled", "output_limited", "unaccounted_descendants"):
        test.assertIs(process.get(key), False, diagnostic)
    test.assertIsNone(process.get("protocol_error"), diagnostic)


class DriverConfigurationTests(unittest.TestCase):
    def test_driver_config_is_closed_frozen_and_explicitly_versioned(self):
        from taskalong.executors.config import DriverConfig
        original_names = schema_names(version="2.2")
        value = seal_versioned("driver-config", example_driver_config(), version="2.3")
        document = DriverConfig.from_dict(value)
        value["launch"]["mode"] = "interactive"
        self.assertEqual(document.to_dict()["launch"]["mode"], "print")
        with self.assertRaises(FrozenInstanceError):
            document._canonical = b"{}"
        with self.assertRaises(TaskAlongError) as failure:
            seal_versioned("driver-config", example_driver_config() | {
                "launch": example_driver_config()["launch"] | {"extra_args": ["--dangerously-skip-permissions"]}}, version="2.3")
        self.assertEqual(failure.exception.code, "schema_validation")
        self.assertEqual(schema_names(version="2.2"), original_names)
        self.assertNotIn("driver-config", schema_names())


class DriverTaskContractTests(unittest.TestCase):
    def test_malformed_version_values_preserve_typed_legacy_admission(self):
        from taskalong.workflow import Workflow
        for version in ([], {}, True, 2):
            with self.subTest(version=version):
                with self.assertRaises(TaskAlongError) as failure:
                    Workflow(None).submit({"schema_version":version}, operation_key="malformed-version")
                self.assertEqual(failure.exception.code, "schema_validation")

    def test_store_cannot_persist_driver_task_before_format4(self):
        from taskalong.store import Store
        from test_contracts import example_spec
        task = seal_versioned("task-spec", example_spec() | {"schema_version":"2.3",
            "execution":{"binding_digest":"a" * 64, "driver_config_digest":"b" * 64}}, version="2.3")
        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory).resolve()/"state") as store:
                with self.assertRaises(TaskAlongError) as failure:
                    store.create_run(task, "premature-driver-task")
                self.assertEqual(failure.exception.code, "store_upgrade_required")
                self.assertEqual(store.db.execute("SELECT count(*) FROM runs").fetchone()[0], 0)
                self.assertEqual(store.db.execute("SELECT count(*) FROM task_specs").fetchone()[0], 0)
                self.assertEqual(store.format_version, 1)

    def test_task_binds_explicit_driver_config_without_repurposing_legacy_profile(self):
        from taskalong.contracts import TaskSpec
        from taskalong.execution import DriverTaskSpec, read_task_spec
        from test_contracts import example_spec
        legacy = example_spec()
        before = TaskSpec.from_dict(legacy).to_bytes()
        config = seal_versioned("driver-config", example_driver_config(), version="2.3")
        task = seal_versioned("task-spec", legacy | {"schema_version":"2.3",
            "execution":{"binding_digest":"a" * 64, "driver_config_digest":config["digest"]}}, version="2.3")
        admitted = read_task_spec(task)
        self.assertIsInstance(admitted, DriverTaskSpec)
        self.assertEqual(admitted.to_dict()["execution"], {
            "binding_digest":"a" * 64, "driver_config_digest":config["digest"]})
        self.assertEqual(read_task_spec(legacy).to_bytes(), before)
        with self.assertRaises(TaskAlongError) as failure:
            seal_versioned("task-spec", task | {"execution":task["execution"] | {
                "runtime_profile_digest":"f" * 64}}, version="2.3")
        self.assertEqual(failure.exception.code, "schema_validation")


class DriverPacketContractTests(unittest.TestCase):
    def test_compiler_binds_attempt_session_config_and_canonical_wire_identity(self):
        from taskalong.executors.claude_code import compile_packet
        fields, admission = driver_packet_inputs()
        canonical, wire, mapping = compile_packet(fields, admission)
        self.assertEqual(canonical["session_id"], fields["attempt_id"])
        self.assertEqual(canonical["bindings"]["driver_config_digest"], admission["driver_config"]["digest"])
        self.assertEqual(canonical["bindings"]["provider_profile_digest"], admission["driver_config"]["provider_profile_digest"])
        self.assertNotIn("runtime_profile_digest", canonical["bindings"])
        self.assertEqual(canonical_bytes(canonical), canonical_bytes(wire))
        self.assertEqual(mapping["canonical_packet_digest"], canonical["digest"])
        self.assertEqual(mapping["wire_packet_digest"], wire["digest"])
        self.assertEqual(mapping["admission_digest"], admission["digest"])
        wire["bindings"]["driver_config_digest"] = "f" * 64
        self.assertEqual(canonical["bindings"]["driver_config_digest"], admission["driver_config"]["digest"])
        with self.assertRaises(TaskAlongError) as failure:
            compile_packet(fields | {"spec_digest":"f" * 64}, admission)
        self.assertEqual(failure.exception.code, "execution_identity_mismatch")


class DriverStreamContractTests(unittest.TestCase):
    def test_reported_tool_invocations_must_match_packet_policy(self):
        from taskalong.executors.claude_code import compile_packet
        from taskalong.executors.claude_protocol import ClaudeDriverStreamDecoder
        fields, admission = driver_packet_inputs()
        packet, _, _ = compile_packet(fields, admission)
        init = {"type":"system", "subtype":"init", "model":"fixture-model", "tools":["Edit"], "session_id":packet["session_id"]}
        terminal = {"type":"result", "subtype":"success", "is_error":False, "permission_denials":[],
            "session_id":packet["session_id"], "structured_output":driver_worker(packet)}
        allowed = {"type":"assistant", "session_id":packet["session_id"], "message":{
            "model":"fixture-model", "content":[{"type":"tool_use", "id":"allowed-edit", "name":"Edit", "input":{}}]}}
        decoder = ClaudeDriverStreamDecoder(packet, expected_session_id=packet["session_id"], expected_model="fixture-model")
        decoder.feed(b"\n".join(canonical_bytes(frame) for frame in (init,allowed,terminal))+b"\n")
        self.assertEqual(decoder.finish(exit_code=0).protocol_version, 2)
        for kind in ("tool_use", "server_tool_use"):
            for name in ("Bash", "Agent", "mcp__unapproved__tool"):
                for streamed in ("message", "block_start", "message_start"):
                    block = {"type":kind, "id":"synthetic-tool", "name":name, "input":{}}
                    if streamed == "block_start":
                        event = {"type":"stream_event", "event":{"type":"content_block_start", "index":0, "content_block":block}}
                    elif streamed == "message_start":
                        event = {"type":"stream_event", "event":{"type":"message_start", "message":{"model":"fixture-model", "content":[block]}}}
                    else:
                        event = {"type":"assistant", "message":{"model":"fixture-model", "content":[block]}}
                    event["session_id"] = packet["session_id"]
                    with self.subTest(kind=kind, name=name, streamed=streamed):
                        with self.assertRaises(TaskAlongError) as failure:
                            decoder = ClaudeDriverStreamDecoder(packet, expected_session_id=packet["session_id"], expected_model="fixture-model")
                            decoder.feed(b"\n".join(canonical_bytes(frame) for frame in (init,event,terminal))+b"\n")
                            decoder.finish(exit_code=0)
                        self.assertEqual(failure.exception.code, "claude_tool_unsupported")
        for block_type in ([], {}, None, "unknown_block"):
            event = {"type":"stream_event", "session_id":packet["session_id"], "event":{
                "type":"content_block_start", "index":0, "content_block":{"type":block_type}}}
            with self.subTest(block_type=block_type):
                with self.assertRaises(TaskAlongError) as failure:
                    decoder = ClaudeDriverStreamDecoder(packet, expected_session_id=packet["session_id"], expected_model="fixture-model")
                    decoder.feed(canonical_bytes(init)+b"\n"+canonical_bytes(event)+b"\n")
                self.assertEqual(failure.exception.code, "claude_tool_unsupported")

    def test_versioned_decoder_binds_config_provider_and_attempt_session(self):
        from taskalong.executors.claude_code import compile_packet
        from taskalong.executors.claude_protocol import ClaudeDriverStreamDecoder
        fields, admission = driver_packet_inputs()
        packet, _, _ = compile_packet(fields, admission)
        worker = {"kind":"worker_result", "schema_version":"2.3", "extensions":{},
            "result_id":str(uuid.uuid4()), "packet_id":packet["packet_id"], "packet_digest":packet["digest"],
            "run_id":packet["run_id"], "attempt_id":packet["attempt_id"], "spec_digest":packet["spec_digest"],
            "driver_config_digest":packet["bindings"]["driver_config_digest"],
            "provider_profile_digest":packet["bindings"]["provider_profile_digest"], "session_id":packet["session_id"],
            "status":"completed", "changed_files":[], "command_claims":[], "summary":"Synthetic worker result.",
            "blockers":[], "deviations":[], "residual_risks":[], "qualification":"synthetic"}
        init = {"type":"system", "subtype":"init", "model":"fixture-model", "tools":["Edit"], "session_id":packet["session_id"]}
        terminal = {"type":"result", "subtype":"success", "is_error":False,
            "permission_denials":[], "session_id":packet["session_id"], "structured_output":worker}
        def decode(result):
            decoder = ClaudeDriverStreamDecoder(packet, expected_session_id=packet["session_id"], expected_model="fixture-model")
            decoder.feed(canonical_bytes(init) + b"\n" + canonical_bytes(result) + b"\n")
            return decoder.finish(exit_code=0)
        result = decode(terminal)
        self.assertEqual(loads(result.worker_result_json), worker)
        self.assertEqual(result.protocol_version, 2)
        self.assertFalse(hasattr(result, "termination_confirmed"))
        with self.assertRaises(TaskAlongError) as failure:
            decode(terminal | {"structured_output":worker | {"driver_config_digest":"f" * 64}})
        self.assertEqual(failure.exception.code, "claude_result_binding_mismatch")


class ClaudeDriverBoundaryTests(unittest.TestCase):
    def test_nonregular_executable_has_typed_refusal_before_dispatch(self):
        from taskalong.executors.claude_code import ClaudeCode
        with tempfile.TemporaryDirectory() as directory:
            config, provider = fixture_driver_context(Path("/usr/bin/false"))
            config = seal_versioned("driver-config", config | {"executable":{
                "path":str(Path(directory).resolve()), "sha256":"c"*64}}, version="2.3")
            with self.assertRaises(TaskAlongError) as failure:
                ClaudeCode(config, provider=provider).preflight(qualification="synthetic", budget={})
            self.assertEqual(failure.exception.code, "runtime_unavailable")

    @contextmanager
    def fixture(self, mode, **budget):
        from taskalong.executors.claude_code import ClaudeCode, compile_packet
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            executable = root/"fake-claude"
            executable.write_text((Path(__file__).parent/"fixtures/fake_claude.py").read_text().replace("#!/usr/bin/env python3", "#!" + sys.executable, 1))
            executable.chmod(0o700)
            executable.with_suffix(".mode.json").write_bytes(canonical_bytes({"mode":mode}))
            workspace = root/"workspace"
            workspace.mkdir(mode=0o700)
            (workspace/"arithmetic.py").write_text("def add(a,b):\n    return a - b\n")
            config, provider = fixture_driver_context(executable)
            fields, admission = driver_packet_inputs()
            fields["remaining_budget"].update(budget)
            admission["driver_config"] = config
            admission["projection"]["driver_config_digest"] = config["digest"]
            packet, _, _ = compile_packet(fields, admission)
            try:
                yield ClaudeCode(config, provider=provider), packet, workspace, root
            finally:
                if mode == "persistent-child":
                    (root/"child-release").touch()
                    deadline = time.monotonic() + 5
                    while not (root/"child-stopped").exists() and time.monotonic() < deadline:
                        time.sleep(.01)
                    self.assertTrue((root/"child-stopped").exists(), "Self-ending test descendant did not finish")

    def test_external_malformed_denied_or_mismatched_result_cannot_succeed(self):
        cases = {"wrong-model":"claude_model_mismatch", "wrong-session":"claude_result_binding_mismatch",
            "wrong-config":"claude_result_binding_mismatch", "wrong-provider":"claude_result_binding_mismatch",
            "denied":"claude_permission_denied", "missing-denial-metadata":"claude_permission_status_unknown",
            "terminal-failure":"claude_result_failed", "nonzero":"claude_exit_failed",
            "missing-terminal":"claude_terminal_missing", "duplicate-terminal":"claude_event_after_terminal",
            "malformed-jsonl":"claude_frame_invalid", "truncated-terminal":"runtime_jsonl_truncated"}
        for mode, error in cases.items():
            with self.subTest(mode=mode), self.fixture(mode) as (driver, packet, workspace, root):
                result = driver.run(packet, workspace=workspace, output_dir=root/"output")
                self.assertEqual(result["state"], "failed")
                self.assertEqual(result["error"], error)
                self.assertTrue(result["process"]["termination_confirmed"])
                self.assertIsNone(result["result"])

    def test_output_and_timeout_limits_stop_owned_process(self):
        for mode, budget, error in (("stderr-flood", {"max_output_bytes":8192}, "runtime_output_limit"),
                                    ("hang", {"attempt_seconds":1}, "runtime_timeout")):
            with self.subTest(mode=mode), self.fixture(mode, **budget) as (driver, packet, workspace, root):
                result = driver.run(packet, workspace=workspace, output_dir=root/"output")
                self.assertEqual(result["error"], error)
                self.assertTrue(result["process"]["termination_confirmed"])
                self.assertIsNone(result["result"])
                self.assertNotIn("stdout", result["process"])
                self.assertNotIn("stderr", result["process"])
                if mode == "stderr-flood":
                    self.assertTrue(result["process"]["output_limited"])

    def test_successful_terminal_cannot_override_unaccounted_descendant(self):
        with self.fixture("persistent-child") as (driver, packet, workspace, root):
            result = driver.run(packet, workspace=workspace, output_dir=root/"output")
            self.assertEqual(result["state"], "unknown")
            self.assertEqual(result["error"], "cancellation_unconfirmed")
            self.assertFalse(result["process"]["termination_confirmed"])
            self.assertIsNone(result["result"])

    def test_owned_fixture_edit_and_report_do_not_become_acceptance_or_billing_proof(self):
        from taskalong.executors.claude_code import ClaudeCode, compile_packet
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            executable = root/"fake-claude"
            executable.write_text((Path(__file__).parent/"fixtures/fake_claude.py").read_text().replace("#!/usr/bin/env python3", "#!" + sys.executable, 1))
            executable.chmod(0o700)
            workspace = root/"workspace"
            workspace.mkdir(mode=0o700)
            (workspace/"arithmetic.py").write_text("def add(a,b):\n    return a - b\n")
            config, provider = fixture_driver_context(executable)
            fields, admission = driver_packet_inputs()
            admission["driver_config"] = config
            admission["projection"]["driver_config_digest"] = config["digest"]
            packet, _, _ = compile_packet(fields, admission)
            driver = ClaudeCode(config, provider=provider)
            result = driver.run(packet, workspace=workspace, output_dir=root/"output")
            self.assertEqual(result["state"], "completed")
            self.assertTrue(result["process"]["termination_confirmed"])
            self.assertIn("return a + b", (workspace/"arithmetic.py").read_text())
            self.assertEqual(result["result"]["packet_digest"], packet["digest"])
            self.assertEqual(result["session_id"], packet["attempt_id"])
            self.assertEqual(result["usage"], {"input_tokens":None, "output_tokens":None, "cost_usd":None})
            self.assertEqual(result["reported_usage"]["counter_scope"], "terminal_reported_scope_unknown")
            self.assertNotIn("acceptance", result)
            self.assertNotIn("stdout", result["process"])
            self.assertNotIn("stderr", result["process"])
            observed = loads(executable.with_suffix(".invocations.jsonl").read_bytes())
            self.assertEqual(observed["model"], provider["model"]["requested"])
            self.assertEqual(observed["session_id"], packet["attempt_id"])
            self.assertFalse(observed["credential_environment_present"])


class ClaudeRegistryContractTests(unittest.TestCase):
    def test_explicit_version_projection_and_config_select_one_driver_without_fallback(self):
        from taskalong.executors.claude_code import ClaudeCode
        from taskalong.executors.registry import executor_for
        config, provider = fixture_driver_context(Path("/usr/bin/false"))
        selected = executor_for(config, provider=provider, task_version="2.3", projection="claude-print-fixture/1")
        self.assertIsInstance(selected, ClaudeCode)
        self.assertFalse(selected.capabilities().native_resume)
        for version, projection in (("2.2", "claude-print-fixture/1"), ("2.3", "unknown/1"), ("1.0", "codex-v1")):
            with self.subTest(version=version, projection=projection):
                with self.assertRaises(TaskAlongError) as failure:
                    executor_for(config, provider=provider, task_version=version, projection=projection)
                self.assertEqual(failure.exception.code, "adapter_unavailable")


class ClaudeBindingFixture(BindingFixture):
    """Public control-plane fixture with a genuine separate v1 check profile."""
    def setUp(self):
        super().setUp()
        from taskalong.api import RunService
        from taskalong.store import Store
        from test_qualification import reference, policy_for
        self.service.close()
        with Store.maintenance(self.state) as store:
            store.upgrade(operation_key="m5", backup_dir=self.root/"backup4", restore_dir=self.root/"restore4", target_version=4)
        self.service = RunService(self.state)
        self.executable = self.root/"fake-claude"
        self.executable.write_text((Path(__file__).parent/"fixtures/fake_claude.py").read_text().replace("#!/usr/bin/env python3", "#!" + sys.executable, 1))
        self.executable.chmod(0o700)
        self.mode_file = self.executable.with_suffix(".mode.json")
        self.mode_file.write_text('{"mode":"good"}')
        self.barrier_file = self.executable.with_suffix(".hold")
        self.release_file = self.executable.with_suffix(".release")
        config, self.provider = fixture_driver_context(self.executable)
        self.tools = seal_versioned("tool-policy", self.tools | {"allowed_tools":["claude.edit"]}, version="2.2")
        self.installation = seal_versioned("harness-installation", self.installation | {
            "installation_id":"fixture-claude", "harness":"claude-code", "adapter_id":"claude-code",
            "driver_version":"claude-print-fixture-1", "cli_version":"synthetic-claude-1",
            "executable_digest":config["executable"]["sha256"], "runtime_closure_digest":digest({
                "fixture":config["executable"]["sha256"], "python":hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
                "check_launcher":hashlib.sha256(self.sandbox.read_bytes()).hexdigest()})}, version="2.0")
        self.binding = seal_versioned("execution-binding", self.binding | {
            "installation_digest":self.installation["digest"], "provider_profile_digest":self.provider["digest"],
            "tool_policy_digest":self.tools["digest"]}, version="2.0")
        self.driver_config = seal_versioned("driver-config", config | {
            "installation_digest":self.installation["digest"], "policy_digests":{
                "instructions":self.instructions["digest"], "tools":self.tools["digest"],
                "worker_sandbox":self.worker_sandbox["digest"], "check_binding":self.check["digest"]}}, version="2.3")
        policies = [self.instructions,self.tools,self.worker_sandbox,self.check,self.check_sandbox]
        self.context["effective_context_digest"] = digest({"policies":sorted(policies,key=lambda item:item["digest"]),
            "driver_config_digest":self.driver_config["digest"]})
        subject = {key:self.binding[key] for key in ("installation_digest","provider_profile_digest","instruction_bundle_digest",
            "tool_policy_digest","worker_sandbox_digest","check_binding_digest")} | {
            "binding_digest":self.binding["digest"], "runtime_closure_digest":self.installation["runtime_closure_digest"],
            "backend_id":"synthetic-fixture", "provider":self.provider["provider"],
            "model_digest":self.provider["model"]["resolved_digest"], "native_resume_compatibility_digest":None, **self.context}
        blobs = self.configuration["evidence"]
        old_ref = self.receipt["results"][0]["evidence_refs"][0]
        observation = loads(blobs.pop(old_ref["sha256"]))
        observation["subject"] = subject
        raw = canonical_bytes(observation)
        ref = reference(raw)
        blobs[ref["sha256"]] = raw
        self.receipt = seal_versioned("qualification-receipt", self.receipt | {
            "subject":subject, "results":[{"capability":"start","outcome":"supported","evidence_refs":[ref]}]}, version="2.1")
        self.trust = policy_for(self.receipt)
        self.configuration = dict(binding=self.binding, installation=self.installation, provider=self.provider,
            policies=policies, driver_config=self.driver_config, receipts=[self.receipt], trust=self.trust,
            evidence=blobs, context=self.context, projection="claude-print-fixture/1")
        self.task = seal_versioned("task-spec", self.task | {"schema_version":"2.3",
            "execution":{"binding_digest":self.binding["digest"],"driver_config_digest":self.driver_config["digest"]},
            "permissions":self.task["permissions"] | {"inference_destination_id":self.provider["profile_id"]}}, version="2.3")

    def invocations(self):
        path = self.executable.with_suffix(".invocations.jsonl")
        return [loads(line) for line in path.read_bytes().splitlines()] if path.exists() else []

    def refresh_binding(self):
        """Explicit synthetic remeasurement after changing a test policy."""
        from test_qualification import reference, policy_for
        self.binding = seal_versioned("execution-binding", self.binding | {
            "check_binding_digest":self.check["digest"]}, version="2.0")
        self.driver_config = seal_versioned("driver-config", self.driver_config | {"policy_digests":{
            "instructions":self.binding["instruction_bundle_digest"], "tools":self.binding["tool_policy_digest"],
            "worker_sandbox":self.binding["worker_sandbox_digest"], "check_binding":self.check["digest"]}}, version="2.3")
        policies = [self.instructions,self.tools,self.worker_sandbox,self.check,self.check_sandbox]
        self.context["effective_context_digest"] = digest({"policies":sorted(policies,key=lambda item:item["digest"]),
            "driver_config_digest":self.driver_config["digest"]})
        subject = self.receipt["subject"] | {key:self.binding[key] for key in (
            "installation_digest","provider_profile_digest","instruction_bundle_digest", "tool_policy_digest",
            "worker_sandbox_digest","check_binding_digest")} | {"binding_digest":self.binding["digest"], **self.context}
        if self.binding["native_resume"]:
            subject["native_resume_compatibility_digest"] = self.binding["native_resume"]["compatibility_digest"]
        blobs = self.configuration["evidence"]
        old_ref = self.receipt["results"][0]["evidence_refs"][0]
        observation = loads(blobs.pop(old_ref["sha256"]))
        raw = canonical_bytes(observation | {"subject":subject})
        ref = reference(raw)
        blobs[ref["sha256"]] = raw
        self.receipt = seal_versioned("qualification-receipt", self.receipt | {
            "subject":subject, "results":[{"capability":"start","outcome":"supported","evidence_refs":[ref]}]}, version="2.1")
        self.trust = policy_for(self.receipt)
        self.configuration.update(binding=self.binding, driver_config=self.driver_config, policies=policies,
            receipts=[self.receipt], trust=self.trust, context=self.context)
        self.task = seal_versioned("task-spec", self.task | {"execution":{
            "binding_digest":self.binding["digest"],"driver_config_digest":self.driver_config["digest"]}}, version="2.3")


class ClaudeFixtureContractTests(DurableDriverContract, ClaudeBindingFixture, unittest.TestCase):
    """The same public lifecycle contract also exercises the Claude fixture."""


class ClaudeAdmissionTests(ClaudeBindingFixture, unittest.TestCase):
    # Reuse unchanged public admission assertions for both explicit contracts.
    from test_execution_bindings import ExecutionAdmissionTests as _Cases
    test_revoked_approval_before_start_has_no_effect_or_reservation = _Cases.test_revoked_approval_before_start_has_no_effect_or_reservation
    test_revocation_after_prepare_blocks_before_worker_dispatch = _Cases.test_revocation_after_prepare_blocks_before_worker_dispatch
    test_authority_expiring_after_prepare_prevents_dispatch = _Cases.test_authority_expiring_after_prepare_prevents_dispatch
    test_required_native_resume_cannot_borrow_start_receipt = _Cases.test_required_native_resume_cannot_borrow_start_receipt
    test_nonnull_cost_or_token_limit_is_never_dropped = _Cases.test_nonnull_cost_or_token_limit_is_never_dropped
    test_unknown_and_unrepresentable_policy_refuse_before_registration = _Cases.test_unknown_and_unrepresentable_policy_refuse_before_registration
    test_changed_executable_blocks_before_intent = _Cases.test_changed_executable_blocks_before_intent
    test_readonly_views_do_not_prepare_reconcile_or_issue_authority = _Cases.test_readonly_views_do_not_prepare_reconcile_or_issue_authority
    test_changed_request_conflicts_and_retry_never_spawns_again = _Cases.test_changed_request_conflicts_and_retry_never_spawns_again
    test_full_independent_acceptance_keeps_verifier_binding_distinct = _Cases.test_full_independent_acceptance_keeps_verifier_binding_distinct
    configure_and_submit = _Cases.configure_and_submit
    assert_no_attempt = _Cases.assert_no_attempt


class ClaudePublicLifecycleTests(ClaudeBindingFixture, unittest.TestCase):
    def test_result_rejects_a_resealed_mapping_for_another_projection(self):
        from taskalong.store import encode
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        self.start(run)
        stopped = self.wait(run["run_id"])
        attempt = self.service._store.detail("attempts", stopped["attempts"][0]["attempt_id"])
        attempt["packet_projection"] = seal_versioned("packet-projection", attempt["packet_projection"] | {
            "projection_digest":"f"*64}, version="2.3")
        # Fault injection changes stored data; no successful core call is mocked.
        with self.service._store.transaction() as db:
            db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(attempt), attempt["attempt_id"]))
        with self.assertRaises(TaskAlongError) as failure:
            self.service.result(run["run_id"])
        self.assertEqual(failure.exception.code, "store_integrity")

    def test_restart_uses_new_attempt_session_and_cannot_reset_budget(self):
        self.service.configure_execution(**self.configuration)
        # A valid stream followed by exit 1 exercises settled failure accounting.
        self.set_mode("nonzero")
        run, _ = self.submit(self.task)
        self.start(run)
        failed = self.wait(run["run_id"])
        assert_settled_failed_attempt(self, failed)
        self.set_mode("good")
        receipt = self.service.resume(run["run_id"], mode="restart", operation_key="explicit-restart", expected_revision=failed["revision"])
        stopped = self.wait(run["run_id"])
        self.assertEqual(stopped["budget_consumed"]["attempts"], 2)
        self.assertEqual(stopped["lease_generation"], failed["lease_generation"] + 1)
        self.assertEqual(len(self.invocations()), 2)
        self.assertEqual(len({entry["session_id"] for entry in self.invocations()}), 2)
        self.assertEqual(self.service.resume(run["run_id"], mode="restart", operation_key="explicit-restart", expected_revision=0), receipt)
        self.assertEqual(self.service.result(run["run_id"])["outcome"], "worker_completed")
        for field in ("input_tokens", "output_tokens", "cost_usd"):
            self.assertIsNone(stopped["budget_consumed"][field])
        with self.assertRaises(TaskAlongError) as failure:
            self.service.resume(run["run_id"], mode="restart", operation_key="exhausted", expected_revision=stopped["revision"])
        self.assertEqual(failure.exception.code, "resume_candidate_unsupported")
        self.assertEqual(len(self.invocations()), 2)

    def test_failed_restarts_exhaust_persisted_attempt_budget(self):
        self.service.configure_execution(**self.configuration)
        self.set_mode("nonzero")
        run, _ = self.submit(self.task)
        self.start(run)
        failed = self.wait(run["run_id"])
        assert_settled_failed_attempt(self, failed)
        self.service.resume(run["run_id"], mode="restart", operation_key="second-failure", expected_revision=failed["revision"])
        stopped = self.wait(run["run_id"])
        assert_settled_failed_attempt(self, stopped)
        self.assertEqual(stopped["budget_consumed"]["attempts"], 2)
        with self.assertRaises(TaskAlongError) as failure:
            self.service.resume(run["run_id"], mode="restart", operation_key="exhausted", expected_revision=stopped["revision"])
        self.assertEqual(failure.exception.code, "budget_exhausted")
        self.assertEqual(self.service.inspect(run["run_id"]), stopped)
        self.assertEqual(len(self.invocations()), 2)

    def test_operator_can_revoke_trust_after_executable_changed(self):
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        self.executable.write_text("#!/bin/sh\nexit 1\n")
        self.trust["revoked_receipt_digests"] = [self.receipt["digest"]]
        self.service.configure_execution(**self.configuration)
        with self.assertRaises(TaskAlongError) as failure:
            self.start(run)
        self.assertEqual(failure.exception.code, "qualification_unsatisfied")
        self.assertEqual(self.invocations(), [])
        self.assertEqual(self.service.inspect(run["run_id"])["attempts"], [])

    def test_registered_driver_uses_one_supervised_attempt_without_claiming_independent_acceptance(self):
        self.service.configure_execution(**self.configuration)
        run, _ = self.submit(self.task)
        receipt = self.start(run)
        stopped = self.wait(run["run_id"])
        self.assertEqual(len(self.invocations()), 1)
        self.assertEqual(len(stopped["attempts"]), 1)
        attempt = self.service._store.detail("attempts", stopped["attempts"][0]["attempt_id"])
        self.assertEqual(attempt["driver_config_digest"], self.driver_config["digest"])
        self.assertNotIn("profile_digest", attempt)
        self.assertEqual(attempt["driver_session_id"], attempt["attempt_id"])
        self.assertIsNone(attempt["thread_id"])
        self.assertEqual(attempt["canonical_packet"]["schema_version"], "2.3")
        self.assertEqual(attempt["admission"]["check_profile_digest"], self.check_profile["digest"])
        self.assertEqual(self.service.start(run["run_id"], operation_key="start", expected_revision=run["revision"]), receipt)
        view = self.service.result(run["run_id"])
        self.assertEqual(view["outcome"], "worker_completed")
        self.assertFalse(view["independently_accepted"])
        self.assertFalse(view["production_dispatch_allowed"])


class ClaudeStoreFenceTests(unittest.TestCase):
    def test_format4_restore_refusal_preserves_source_backup_and_foreign_destination(self):
        from taskalong.store import Store
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with Store(root/"state"):
                pass
            with Store.maintenance(root/"state") as store:
                for version in (2, 3):
                    store.upgrade(operation_key="upgrade-" + str(version), backup_dir=root/("backup" + str(version)),
                                  restore_dir=root/("restore" + str(version)), target_version=version)
                prior_receipts = [tuple(row) for row in store.db.execute("SELECT number,document FROM store_migrations ORDER BY number")]
                destination = root/"restore4"
                destination.mkdir(mode=0o700)
                sentinel = destination/"foreign.txt"
                sentinel.write_bytes(b"preserve existing destination")
                sentinel.chmod(0o600)
                with self.assertRaises(TaskAlongError) as failure:
                    store.upgrade(operation_key="claude-fence", backup_dir=root/"backup4",
                                  restore_dir=destination, target_version=4)
                self.assertEqual(failure.exception.code, "restore_integrity")
                self.assertEqual(store.format_version, 3)
                self.assertEqual(store.db.execute("PRAGMA user_version").fetchone()[0], 3)
                self.assertEqual([tuple(row) for row in store.db.execute("SELECT number,document FROM store_migrations ORDER BY number")], prior_receipts)
                self.assertEqual(sentinel.read_bytes(), b"preserve existing destination")
                self.assertTrue((root/"backup4").is_dir())

    def test_out_of_sequence_format4_refuses_without_migration_effects(self):
        from taskalong.store import Store
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with Store(root/"state"):
                pass
            with Store.maintenance(root/"state") as store:
                with self.assertRaises(TaskAlongError) as failure:
                    store.upgrade(operation_key="skip-history", backup_dir=root/"backup4",
                                  restore_dir=root/"restore4", target_version=4)
                self.assertEqual(failure.exception.code, "store_migration_order")
                self.assertEqual(store.format_version, 1)
                self.assertEqual(store.db.execute("PRAGMA user_version").fetchone()[0], 1)
                self.assertEqual(store.db.execute("SELECT count(*) FROM operations").fetchone()[0], 0)
                self.assertFalse((root/"backup4").exists())
                self.assertFalse((root/"restore4").exists())

    def test_driver_history_requires_backed_up_format4_and_old_client_refuses(self):
        from taskalong.executors.config import DriverConfig
        from taskalong.store import Store
        from test_contracts import example_spec
        config = DriverConfig.from_dict(seal_versioned("driver-config", example_driver_config(), version="2.3"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            state = root / "state"
            with Store(state) as store:
                original = store.create_run(example_spec(), "legacy-run")
            with Store.maintenance(state) as store:
                for version in (2, 3):
                    store.upgrade(operation_key="upgrade-" + str(version), backup_dir=root/("backup" + str(version)),
                                  restore_dir=root/("restore" + str(version)), target_version=version)
                with self.assertRaises(TaskAlongError) as failure:
                    store.record_document(config, operation_key="unfenced-config")
                self.assertEqual(failure.exception.code, "store_upgrade_required")
                request = dict(operation_key="claude-fence", backup_dir=root/"backup4", restore_dir=root/"restore4", target_version=4)
                receipt = store.upgrade(**request)
                self.assertEqual((receipt["from_version"], receipt["to_version"]), (3, 4))
                self.assertEqual(store.upgrade(**request), receipt)
                result = store.record_document(config, operation_key="fenced-config")
                self.assertTrue(result["historical_only"])
                self.assertEqual(store.document_history("driver_config", config.digest), (config,))
                self.assertEqual(store.run(original["run_id"]), original)
            predecessor_file = Path(__file__).parent/"fixtures/legacy_store_v3.py"
            self.assertEqual(hashlib.sha256(predecessor_file.read_bytes()).hexdigest(), "208309f4bd363f8eaf38b9f7d6386e55dcc6add6aaa04a9f062bb80877a4cea7")
            module_spec = importlib.util.spec_from_file_location("taskalong._legacy_store_v3", predecessor_file)
            predecessor = importlib.util.module_from_spec(module_spec)
            module_spec.loader.exec_module(predecessor)
            before = (state/"state.sqlite3").read_bytes()
            with self.assertRaises(TaskAlongError) as failure:
                predecessor.Store(state)
            self.assertEqual(failure.exception.code, "unsupported_store_version")
            self.assertEqual((state/"state.sqlite3").read_bytes(), before)
            with Store(state) as store:
                self.assertEqual(store.format_version, 4)
                self.assertEqual(store.run(original["run_id"]), original)


class ClaudeRecoveryTests(ClaudeBindingFixture, unittest.TestCase):
    from test_recovery_regressions import RecoveryRegressions as _Cases
    wait_file = _Cases.wait_file
    cli_start = _Cases.cli_start
    trace_environment = _Cases.trace_environment

    def setUp(self):
        super().setUp()
        self.service.configure_execution(**self.configuration)

    def submit(self, spec=None, **options):
        return super().submit(self.task if spec is None else spec, **options)

    test_killed_supervisor_after_candidate_cas_reconciles_exact_candidate = _Cases.test_killed_supervisor_after_candidate_cas_reconciles_exact_candidate
    test_concurrent_same_key_clients_dispatch_one_attempt = _Cases.test_concurrent_same_key_clients_dispatch_one_attempt

    def test_lost_supervisor_before_finish_retains_unknown_effect_and_quarantine(self):
        self.assert_lost_supervisor_before_finish(exhausted=False)

    def test_exhausted_unreconciled_attempt_refuses_restart_without_new_effect(self):
        self.assert_lost_supervisor_before_finish(exhausted=True)

    def assert_lost_supervisor_before_finish(self, *, exhausted):
        self.service.configure_execution(**self.configuration)
        task = self.task
        if exhausted:
            task = seal_versioned("task-spec", task | {"budget":task["budget"] | {
                "max_attempts":1}}, version=task["schema_version"])
        run, _ = self.submit(task)
        environment, marker, _ = self.trace_environment("_finish_attempt")
        client = self.cli_start(run, "lost-supervisor", environment=environment)
        self.assertEqual(client.returncode, 0, client.stderr)
        self.wait_file(marker)
        before = self.service.inspect(run["run_id"])
        self.assertIsNotNone(before["active_attempt_id"])
        self.assertIsNone(before["acceptance_id"])
        self.assertTrue(before["pending_effect_ids"])
        observed = self.service.reconcile(run["run_id"], operation_key="unknown-owner", expected_revision=before["revision"])
        self.assertEqual(observed["state"], "blocked")
        self.assertEqual(observed["blockers"][0]["code"], "start_unreconciled")
        self.assertEqual(self.service._store.lease(observed)["state"], "quarantined")
        self.assertEqual(observed["pending_effect_ids"], before["pending_effect_ids"])
        self.assertIsNone(observed["candidate"])
        self.assertIsNone(observed["acceptance_id"])
        self.assertEqual(len(self.invocations()), 1)
        self.assertEqual(self.service.result(run["run_id"])["outcome"], "unknown")
        if exhausted:
            self.assertEqual(observed["budget_consumed"]["attempts"], task["budget"]["max_attempts"])
            self.assertEqual(observed["active_attempt_id"], before["active_attempt_id"])
            attempt = self.service._store.detail("attempts", observed["active_attempt_id"])
            self.assertIs(attempt["termination_confirmed"], False)
            effects = [self.service._store.detail("effects", value) for value in observed["pending_effect_ids"]]
            self.assertEqual([(effect["kind"], effect["phase"]) for effect in effects], [("executor.start", "prepared")])
            self.assertEqual(observed["blockers"][0]["effect_outcome"], "uncertain")
            lease = self.service._store.lease(observed)
            counts = {table:self.service._store.db.execute("SELECT count(*) FROM " + table).fetchone()[0]
                      for table in ("attempts", "effects", "operations")}
            with self.assertRaises(TaskAlongError) as failure:
                self.service.resume(run["run_id"], mode="restart", operation_key="exhausted-but-unreconciled",
                                    expected_revision=observed["revision"])
            self.assertEqual(failure.exception.code, "resume_not_reconciled")
            self.assertEqual(self.service.inspect(run["run_id"]), observed)
            self.assertEqual(self.service._store.detail("attempts", attempt["attempt_id"]), attempt)
            self.assertEqual(self.service._store.lease(observed), lease)
            self.assertEqual([self.service._store.detail("effects", effect["effect_id"]) for effect in effects], effects)
            self.assertEqual({table:self.service._store.db.execute("SELECT count(*) FROM " + table).fetchone()[0]
                              for table in counts}, counts)
            self.assertEqual(len(self.invocations()), 1)
            print(canonical_bytes({"kind":"unreconciled_budget_refusal", "attempts_consumed":observed["budget_consumed"]["attempts"],
                "max_attempts":task["budget"]["max_attempts"], "refusal":failure.exception.code,
                "product_cessation_confirmed":attempt["termination_confirmed"], "state_unchanged":True,
                "quarantine_retained":lease["state"] == "quarantined", "pending_effect_retained":True}).decode(), file=sys.stderr)


if __name__ == "__main__":
    unittest.main()
