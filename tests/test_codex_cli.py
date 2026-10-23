"""Public subprocess protocol against an external synthetic executable."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import uuid

from taskalong.errors import TaskAlongError
from taskalong.executors.registry import executor_for
from taskalong.executors.codex_cli import CodexCLI
from taskalong.executors.base import ExecutionRequest, ExecutionLookup, ExecutionHandle
from taskalong.process import fingerprint
from taskalong.validation import canonical_bytes, digest, seal


def fixture_profile(executable):
    return seal("runtime-profile", {"profile_id": "fixture", "qualification": "synthetic",
        "adapter": "codex-cli", "executable_path": str(executable), "executable_sha256": fingerprint(executable),
        "runtime_version": "0.163.0", "model": "fixture", "reasoning_effort": "low", "service_tier": None,
        "inference_destination_id": "fixture", "permission_policy": {}, "permission_policy_digest": digest({}),
        "toolchain_read_roots": [], "credential_source_ref": None, "qualification_receipt_ids": []})


def fixture_packet(profile, mode="good", *, run_id=None):
    return seal("worker-packet", {"packet_id": str(uuid.uuid4()), "run_id": run_id or str(uuid.uuid4()),
        "attempt_id": str(uuid.uuid4()), "spec_digest": "a"*64, "goal": "fixture:" + mode,
        "non_goals": [], "scope": {"files": ["arithmetic.py"], "operations": ["modify"]},
        "checks": [{"id": "unit", "argv": [sys.executable, "-m", "unittest"], "cwd": ".", "timeout_seconds": 10,
                    "expected_exit_code": 0, "criterion_ids": ["arithmetic"], "required": True}],
        "bindings": {"base_commit": "a"*40, "initial_head": "a"*40, "initial_content_digest": "a"*64,
                     "workspace_id": str(uuid.uuid4()), "lease_generation": 1, "runtime_profile_digest": profile["digest"]},
        "remaining_budget": {"max_attempts": 2, "attempt_seconds": 10, "total_active_seconds": 30,
                             "max_output_bytes": 1048576, "hard_cost_usd": None, "hard_tokens": None},
        "result_schema_id": "urn:taskalong:schema:v1:worker-result", "qualification": "synthetic"})


class CodexCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        (self.workspace / "arithmetic.py").write_text("def add(a,b):\n    return a - b\n")
        self.executable = self.root / "fake-codex"
        source = Path(__file__).parent / "fixtures/fake_codex.py"
        text = source.read_text().replace("#!/usr/bin/env python3", "#!" + sys.executable, 1)
        self.executable.write_text(text)
        self.executable.chmod(0o700)
        self.profile = fixture_profile(self.executable)
        self.adapter = executor_for(self.profile)

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, mode="good", **kwargs):
        directory = self.root / str(uuid.uuid4())
        return self.adapter.run(fixture_packet(self.profile, mode), workspace=self.workspace,
                                output_dir=directory, **kwargs)

    def test_actual_edit_handoff_and_usage_do_not_mean_acceptance(self):
        result = self.invoke()
        self.assertEqual(result["state"], "completed")
        self.assertIn("return a + b", (self.workspace / "arithmetic.py").read_text())
        self.assertEqual(result["usage"], {"input_tokens": 19, "output_tokens": 7, "cost_usd": None})
        self.assertEqual(result["result"]["changed_files"], [{"path": "arithmetic.py", "operation": "modify"}])
        self.assertNotIn("stdout", result["process"])
        self.assertNotIn("acceptance", result)

    def test_untrusted_and_missing_output_cannot_complete(self):
        cases = {"wrong-packet": "worker_result_invalid", "oversized-result": "worker_result_invalid",
                 "duplicate-result": "worker_result_invalid", "self-acceptance": "worker_result_invalid",
                 "missing-terminal": "runtime_terminal_missing", "nonzero": "runtime_failed",
                 "malformed-jsonl": "runtime_protocol_invalid", "invalid-utf8": "runtime_protocol_invalid",
                 "unflushed-terminal": "runtime_jsonl_truncated", "stderr-flood": "runtime_output_limit"}
        for mode, error in cases.items():
            with self.subTest(mode=mode):
                result = self.invoke(mode)
                self.assertEqual(result["state"], "failed")
                self.assertEqual(result["error"], error)

    def test_final_result_file_cannot_exceed_remaining_aggregate_budget(self):
        # Keep the JSON/schema valid and below the independent 1MiB result cap.
        # Only its sum with the actual JSONL pipes exceeds the task's small cap.
        source = self.executable.read_text().replace(
            '"summary": "Synthetic fixture handoff; independent checks are still required.",',
            '"summary": "x" * 2048,')
        self.executable.write_text(source)
        profile = fixture_profile(self.executable)
        packet = fixture_packet(profile)
        packet["remaining_budget"]["max_output_bytes"] = 1024
        packet = seal("worker-packet", packet)
        directory = self.root / "result-budget"
        result = CodexCLI(profile).run(packet, workspace=self.workspace, output_dir=directory)
        emitted = json.loads((directory / "worker-result.json").read_text())
        self.assertEqual(len(emitted["summary"]), 2048)
        self.assertGreater((directory / "worker-result.json").stat().st_size, 1024)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["error"], "runtime_output_limit")
        self.assertTrue(result["process"]["termination_confirmed"])
        self.assertTrue(result["process"]["output_limited"])
        self.assertGreater(result["process"]["output_bytes"], packet["remaining_budget"]["max_output_bytes"])
        self.assertIsNone(result["result"])

    def test_successful_output_receipt_includes_actual_final_file_bytes(self):
        packet = fixture_packet(self.profile)
        directory = self.root / "counted-result"
        result = self.adapter.run(packet, workspace=self.workspace, output_dir=directory)
        expected_jsonl = (json.dumps({"type": "thread.started", "thread_id": "fixture-" + packet["run_id"]}) + "\n"
            + json.dumps({"type": "turn.completed", "usage": {"input_tokens": 19, "output_tokens": 7}}) + "\n").encode()
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["process"]["output_bytes"],
                         len(expected_jsonl) + (directory / "worker-result.json").stat().st_size)

    def test_unknown_events_are_counted_without_trusting_payloads(self):
        result = self.invoke("unknown-event")
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["diagnostics"], {"unknown_event_count": 1})

    def test_native_resume_uses_exact_thread_and_new_packet(self):
        first_packet = fixture_packet(self.profile)
        first = self.adapter.run(first_packet, workspace=self.workspace, output_dir=self.root/"first")
        second_packet = fixture_packet(self.profile, run_id=first_packet["run_id"])
        result = self.adapter.run(second_packet, workspace=self.workspace, output_dir=self.root/"second",
                                 mode="native_resume", thread_id=first["thread_id"])
        self.assertEqual(result["state"], "completed")
        self.assertEqual(first["thread_id"], result["thread_id"])
        self.assertNotEqual(first["result"]["attempt_id"], result["result"]["attempt_id"])
        argv = self.adapter.build_argv(workspace=self.workspace, git_common_dir=self.root/"git", control_dir=self.root/"control",
                                       schema_path="/schema", result_path="/result", mode="native_resume", thread_id=first["thread_id"])
        self.assertEqual(argv[1:5], ["--no-daemon", "exec", "resume", first["thread_id"]])
        self.assertNotIn("-C", argv)
        self.assertNotIn("--last", argv)
        with self.assertRaises(TaskAlongError):
            self.adapter.build_argv(workspace=self.workspace, git_common_dir=self.root/"git", control_dir=self.root/"control",
                                    schema_path="/schema", result_path="/result", mode="native_resume")

    def test_result_file_must_be_fresh(self):
        directory = self.root / "old"
        directory.mkdir(mode=0o700)
        (directory/"worker-result.json").write_text("{}")
        with self.assertRaises(TaskAlongError) as error:
            self.adapter.run(fixture_packet(self.profile), workspace=self.workspace, output_dir=directory)
        self.assertEqual(error.exception.code, "stale_output")

    def test_native_resume_rejects_a_different_observed_thread(self):
        packet = fixture_packet(self.profile, "wrong-resume-thread")
        result = self.adapter.run(packet, workspace=self.workspace,
            output_dir=self.root/"wrong-resume", mode="native_resume",
            thread_id="fixture-exact-authorized-thread")
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["error"], "native_resume_thread_mismatch")
        self.assertTrue(result["process"]["termination_confirmed"])
        self.assertIsNone(result["thread_id"])
        self.assertIsNone(result["checkpoint"])
        self.assertIsNone(result["result"])
        records = self.executable.with_name("fake-codex-invocations.jsonl").read_text().splitlines()
        self.assertEqual(len(records), 1)
        self.assertIn('"mode": "native_resume"', records[0])

    def test_cancellation_confirms_owned_local_process_only(self):
        result = self.invoke("hang", cancel_requested=lambda: True)
        self.assertEqual(result["state"], "cancelled")
        self.assertTrue(result["process"]["termination_confirmed"])

    def test_direct_protocol_launch_cannot_bypass_durable_supervisor(self):
        packet = fixture_packet(self.profile)
        request = ExecutionRequest(packet["run_id"], packet["attempt_id"], packet["spec_digest"],
            canonical_bytes(packet), self.workspace, self.root/"unused", 1, self.profile["digest"])
        result = self.adapter.start(request, operation_key="not-authority")
        self.assertEqual(result.disposition, "unsupported")
        self.assertEqual(result.observation.error_code, "supervisor_required")
        self.assertFalse(self.executable.with_name("fake-codex-invocations.jsonl").exists())
        handle = ExecutionHandle("codex-cli", "0.163.0", str(uuid.uuid4()))
        self.assertEqual(self.adapter.status(ExecutionLookup(handle=handle)).state, "unknown")
        self.assertEqual(self.adapter.cancel(handle, operation_key="cancel").disposition, "unknown")


if __name__ == "__main__":
    unittest.main()
