"""Configured owner conformance with inert synthetic native observations.

No vendor executable, network, credentials or historical State is used.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from taskalong.api import RunService
from taskalong.errors import TaskAlongError
from taskalong import local_provider_runtime as owner
from taskalong.process import ProcessReceipt
from taskalong.validation import canonical_bytes, digest
from test_local_provider_adapters import configuration, wire


@unittest.skipUnless(os.name == "posix", "Configured POSIX owner")
class ProviderOwnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.env = patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
        self.env.start()
        for args in (("init", "-b", "main"), ("config", "user.name", "Synthetic Operator"),
                     ("config", "user.email", "synthetic@example.invalid"), ("config", "commit.gpgsign", "false")):
            self.git(*args)
        (self.repo / "reference.txt").write_text("Public reference.\n")
        self.git("add", ".")
        self.git("commit", "-m", "Synthetic baseline")
        self.base = self.git("rev-parse", "HEAD")
        self.exe = self.root / "inert-not-an-executable"
        self.exe.write_bytes(b"Synthetic descriptor bytes; never executed")
        self.exe.chmod(0o700)
        self.sha = hashlib.sha256(self.exe.read_bytes()).hexdigest()
        self.service = RunService(self.root / "state")
        self.calls = []

    def tearDown(self):
        self.service.close()
        self.env.stop()
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-c", "core.hooksPath=" + os.devnull, "-C", str(self.repo), *args],
                              capture_output=True, check=True, timeout=15).stdout.decode().strip()

    def request(self, **kw):
        return {"repository": str(self.repo), "base_commit": self.base,
                "task": "Create the declared public module.", "read_paths": ["reference.txt"],
                "writable_paths": ["new.py"]} | kw

    def configure(self, provider="codex"):
        config = configuration(provider)
        config["adapter_configuration"]["executable"] = {"path": str(self.exe), "sha256": self.sha, "version": "synthetic"}
        return self.service.configure_provider(provider, config)

    def process(self, config, prepared, invocation, *, output_chunk, cancelled, spawned):
        self.calls.append(prepared)
        raw_chunk = output_chunk
        observed = 0
        def output_chunk(stream, data):
            nonlocal observed
            observed += len(data)
            raw_chunk(stream, data)
        receipt = ProcessReceipt("synthetic-invocation", 100, 100, 101, 1234567, self.sha)
        spawned(receipt)
        response = {"bundle_digest": prepared["bundle_digest"], "changes": {"new.py": "answer = 42\n"}}
        provider = prepared["provider"]
        if provider == "codex":
            output_chunk("stdout", wire({"type": "thread.started", "thread_id": "synthetic-session"},
                {"type": "turn.completed", "usage": {"input_tokens": 3}}))
            result = Path(prepared["result_file"])
            result.write_bytes(canonical_bytes(response))
            result.chmod(0o600)
        elif provider == "antigravity":
            schema = owner._adapters().proposal_schema(owner._passive(config), prepared)
            output_chunk("stdout", wire({"event": "init", "conversation_id": "synthetic-session", "init": {
                "cwd": prepared["workspace"], "model": "synthetic-model", "tools": [],
                "permission_mode": "request-review", "json_schema": schema}},
                {"event": "result", "result": {"conversation_id": "synthetic-session", "status": "SUCCESS",
                    "response": "Synthetic structured result", "structured_output": response,
                    "num_turns": 1, "duration_seconds": 1.0}}))
        else:
            common = {"session_id": prepared["attempt_id"], "parent_tool_use_id": None}
            output_chunk("stdout", wire(common | {"type": "system", "subtype": "init", "model": "synthetic-model", "tools": []},
                common | {"type": "result", "subtype": "success", "is_error": False,
                    "permission_denials": [], "structured_output": response}))
        return {"receipt": receipt.to_dict(), "root_exit_code": 0, "root_exit_observed": True,
                "group_termination_confirmed": True, "descendant_cessation": "unknown",
                "timed_out": False, "cancelled": False, "output_limited": False,
                "observed_output_bytes": observed, "termination_confirmed": False}

    def test_normal_api_stages_each_adapter_without_application_or_acceptance(self):
        for provider in ("codex", "antigravity", "claude-code"):
            with self.subTest(provider=provider):
                view = self.configure(provider)
                self.assertFalse(view["activation_required"])
                with patch.object(owner, "_process", side_effect=self.process):
                    result = self.service.run_provider(provider, request=self.request())
                self.assertEqual(result["state"], "proposal_ready")
                self.assertEqual(result["controller_submissions"], 1)
                self.assertEqual(result["remote_usage"], "unknown")
                self.assertFalse(result["acceptance_allowed"])
                self.assertFalse((self.repo / "new.py").exists())
                self.assertTrue(Path(result["proposal_path"]).read_bytes().startswith(b"diff --git "))
                self.assertEqual(self.service.inspect(result["run_id"])["state"], "proposal_ready")
                self.assertEqual(self.service.result(result["run_id"])["runtime_observation"]["local_termination"], "observed")
                receipt = self.service.cancel(result["run_id"], operation_key="cancel-"+provider,
                                              expected_revision=result["revision"])
                self.assertEqual(receipt["status"], "observation_only")
        self.assertEqual(len(self.calls), 3)

    def test_changed_budget_or_transport_does_not_redispatch_consumed_intent(self):
        self.configure()
        with patch.object(owner, "_process", side_effect=self.process):
            first = self.service.run_provider("codex", request=self.request())
        with patch.object(owner, "_process") as spawn:
            with self.assertRaises(TaskAlongError) as caught:
                self.service.run_provider("codex", request=self.request(artifact_format="unified-diff/1"))
            self.assertEqual(caught.exception.code, "provider_already_submitted")
            spawn.assert_not_called()
        self.assertEqual(self.service.result(first["run_id"])["controller_submissions"], 1)

    def test_model_free_preparation_and_budget_have_no_claim_or_native_effect(self):
        self.configure()
        with patch.object(owner, "_process") as native:
            plan = self.service.prepare_provider_task("codex", request=self.request())
            budget = self.service.provider_budget("codex", request=self.request())
            self.assertEqual(plan["digest"], budget["plan_digest"])
            self.assertFalse(budget["response_fit_guaranteed"])
            native.assert_not_called()
        self.assertEqual(self.service._store.db.execute("SELECT count(*) FROM settings WHERE name LIKE 'configured-provider-claim:%'").fetchone()[0], 0)

    def test_binary_change_and_invalid_scope_stop_before_claim(self):
        self.configure()
        self.exe.write_bytes(b"changed")
        with patch.object(owner, "_process") as native:
            with self.assertRaises(TaskAlongError):
                self.service.run_provider("codex", request=self.request())
            native.assert_not_called()
        self.assertEqual(self.service._store.db.execute("SELECT count(*) FROM settings WHERE name LIKE 'configured-provider-claim:%'").fetchone()[0], 0)

    def test_failure_preserves_claim_capture_and_cannot_be_retried(self):
        self.configure()
        def invalid(config, prepared, invocation, **callbacks):
            self.calls.append(prepared)
            callbacks["spawned"](ProcessReceipt("synthetic-invocation",100,100,101,1234567,self.sha))
            callbacks["output_chunk"]("stdout", b"not valid protocol\n")
            callbacks["output_chunk"]("stderr", b"retained after parser rejection\n")
            self.assertTrue(callbacks["cancelled"]())
            return {"receipt": ProcessReceipt("synthetic-invocation",100,100,101,1234567,self.sha).to_dict(),
                "root_exit_code": 130, "root_exit_observed": True, "timed_out": False, "cancelled": True,
                "output_limited": False, "group_termination_confirmed": True, "termination_confirmed": False,
                "observed_output_bytes": len(b"not valid protocol\nretained after parser rejection\n")}
        with patch.object(owner, "_process", side_effect=invalid):
            self.service.run_provider("codex", request=self.request())
        run_id = self.calls[0]["run_id"]
        result = self.service.inspect(run_id)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["controller_submissions"], 1)
        self.assertEqual(result["remote_usage"], "unknown")
        self.assertTrue(result["process"]["process_stream_complete"])
        self.assertEqual(result["capture"]["streams"]["stderr"]["retained_bytes"], len(b"retained after parser rejection\n"))
        with patch.object(owner, "_process") as native:
            with self.assertRaises(TaskAlongError):
                self.service.run_provider("codex", request=self.request())
            native.assert_not_called()
        self.assertEqual(len(self.calls), 1)

    def test_codex_run_is_only_entry_and_does_not_change_production_refusal(self):
        self.configure()
        from taskalong.executors.codex_cli import CodexCLI
        original = CodexCLI.run
        entries = []
        def counted(executor, *a, **kw):
            entries.append(executor.profile["provider"])
            return original(executor, *a, **kw)
        with patch.object(CodexCLI, "run", counted), patch.object(owner, "_process", side_effect=self.process):
            self.service.run_provider("codex", request=self.request())
        self.assertEqual(entries, ["codex"])
        config = self.service._store.setting("provider:codex")
        with self.assertRaises(TaskAlongError):
            CodexCLI(config).run({}, workspace="/wrong", output_dir="/wrong")

    def test_actual_stdlib_process_roundtrip_and_darwin_diagnostics_are_json(self):
        self.configure()
        original = owner._process
        def stdlib_process(config, prepared, invocation, **callbacks):
            # An injected inert test transport, never native Codex execution.
            code = ("import json,pathlib,sys\n"
                "sys.stdin.buffer.read()\n"
                "p=pathlib.Path(" + repr(prepared["result_file"]) + ")\n"
                "p.write_text(json.dumps(" + repr({"bundle_digest": prepared["bundle_digest"], "changes": {"new.py": "answer = 42\n"}}) + "))\n"
                "p.chmod(0o600)\n"
                "print(json.dumps({'type':'thread.started','thread_id':'synthetic-session'}),flush=True)\n"
                "print(json.dumps({'type':'turn.completed'}),flush=True)\n"
                "print('retained diagnostic',file=sys.stderr,flush=True)\n")
            return original(config, prepared, invocation | {"argv": [sys.executable, "-I", "-c", code]}, **callbacks)
        with patch.object(owner, "_process", side_effect=stdlib_process):
            result = self.service.run_provider("codex", request=self.request())
        self.assertEqual(result["state"], "proposal_ready")
        self.assertTrue(result["process"]["process_stream_complete"])
        self.assertEqual(result["capture"]["streams"]["stderr"]["retained_bytes"], 20)
        self.assertEqual(self.service.inspect(result["run_id"])["runtime_observation"]["local_termination"], "observed")
        self.assertFalse(result["acceptance_allowed"])
        self.assertEqual(result["descendant_cessation"], "unknown")

    def test_actual_parser_rejection_keeps_drained_stderr_and_truthful_capture(self):
        self.configure()
        original = owner._process
        def stdlib_process(config, prepared, invocation, **callbacks):
            self.calls.append(prepared)
            code = "import os;os.write(1,b'invalid\\n');os.write(2,b'buffered diagnostic\\n')"
            return original(config, prepared, invocation | {"argv": [sys.executable,"-I","-c",code]}, **callbacks)
        with patch.object(owner, "_process", side_effect=stdlib_process):
            result = self.service.run_provider("codex", request=self.request())
        self.assertEqual(result["state"], "failed")
        self.assertTrue(result["process"]["process_stream_complete"])
        streams = result["capture"]["streams"]
        self.assertEqual(sum(streams[s]["observed_bytes"] for s in ("stdout", "stderr")), result["process"]["observed_output_bytes"])
        self.assertEqual(streams["stderr"]["retained_bytes"], len(b"buffered diagnostic\n"))
        self.assertEqual(result["remote_usage"], "unknown")

    def test_cancel_before_spawn_revision_prevents_target_gate_release(self):
        self.configure()
        original = owner._process
        target_marker = self.root / "must-not-run"
        def stdlib_process(config, prepared, invocation, **callbacks):
            record = self.service._store.setting("provider-run:" + prepared["run_id"])
            receipt = self.service.cancel(record["run_id"], operation_key="before-spawn",
                                          expected_revision=record["revision"])
            self.assertEqual(receipt["status"], "requested")
            code = "from pathlib import Path;Path(" + repr(str(target_marker)) + ").touch()"
            return original(config, prepared, invocation | {"argv": [sys.executable,"-I","-c",code]}, **callbacks)
        with patch.object(owner, "_process", side_effect=stdlib_process):
            result = self.service.run_provider("codex", request=self.request())
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["process"]["failure_code"], "cancel_pending")
        self.assertFalse(target_marker.exists())
        self.assertEqual(result["controller_submissions"], 1)
        self.assertEqual(result["remote_usage"], "unknown")


if __name__ == "__main__":
    unittest.main()
