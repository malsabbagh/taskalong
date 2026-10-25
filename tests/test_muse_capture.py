"""Original Python synthetic transport through the existing owned supervisor."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.executors.base import ExecutionRequest


FIXTURE = '''import argparse,json,os,pathlib,sys,time
p=argparse.ArgumentParser()
p.add_argument('command',choices=['exec'])
for key in ['provider','workspace','prompt-file','model','permission-profile','max-model-steps','approval-mode','sandbox-network']:
 p.add_argument('--'+key,required=True)
p.add_argument('--disable-request-user-input',action='store_true')
a=p.parse_args()
data=json.loads(pathlib.Path(a.prompt_file).read_bytes())
with open('invocations.log','ab') as f:f.write(b'1\\n')
if data.get('wait'):
 print('READY',flush=True)
 time.sleep(30)
if data.get('write_bad'):
 pathlib.Path('calculator.py').write_text('def add(a,b): return a-b\\n')
for target,key in [(2,'stderr'),(1,'stdout')]:
 for chunk in data.get(key,[]):os.write(target,bytes.fromhex(chunk))
sys.exit(data.get('exit_code',0))
'''


class MuseCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="taskalong-muse-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.workspace, self.output = self.root / "workspace", self.root / "output"
        self.workspace.mkdir(mode=0o700)
        self.output.mkdir(mode=0o700)
        self.worker = self.root / "original-python-fixture"
        self.worker.write_text("#!" + sys.executable + "\n" + FIXTURE)
        self.worker.chmod(0o700)
        self.request = ExecutionRequest(str(uuid.uuid4()), str(uuid.uuid4()), "a" * 64,
            b'{}', self.workspace, self.output, 1, "b" * 64)

    def run_capture(self, data, **options):
        from taskalong.executors.muse_capture import MuseCaptureConfig, capture_muse_turn
        config = MuseCaptureConfig(str(self.worker), hashlib.sha256(self.worker.read_bytes()).hexdigest(),
                                   "1.4.10-R6427.1", "requested-model", "fixture-profile", 1)
        request = replace(self.request, packet=json.dumps(data).encode())
        return capture_muse_turn(request, config=config, qualification=options.pop("qualification", "synthetic"),
                                 timeout_seconds=options.pop("timeout_seconds", 3),
                                 max_output_bytes=options.pop("max_output_bytes", 1048576), **options)

    def test_exact_private_bytes_and_bound_receipt_reach_existing_supervisor(self):
        stdout, stderr = b"A\xe2\x80\xa8\xff\r\nZ", b"diagnostic\x00\xfe"
        result = self.run_capture({"stdout": [stdout[:2].hex(), stdout[2:].hex()], "stderr": [stderr.hex()]})
        receipt = result.observation()
        self.assertEqual(receipt["status"], "local_turn_completed")
        self.assertEqual((result.directory / "stdout.bin").read_bytes(), stdout)
        self.assertEqual((result.directory / "stderr.bin").read_bytes(), stderr)
        self.assertEqual(receipt["binding"]["attempt_id"], self.request.attempt_id)
        self.assertEqual(receipt["binding"]["prompt_sha256"], hashlib.sha256((result.directory / "prompt.txt").read_bytes()).hexdigest())
        self.assertEqual(receipt["process"]["receipt"]["executable_sha256"], hashlib.sha256(self.worker.read_bytes()).hexdigest())
        self.assertTrue(receipt["process"]["termination_confirmed"])
        self.assertIn(receipt["process"]["lifetime_backend"], ["darwin-kqueue-no-fork", "linux-child-subreaper"])
        self.assertFalse(receipt["independently_accepted"])
        self.assertIsNone(receipt["structured_result"])
        self.assertEqual((result.directory / "receipt.json").read_bytes(), result.receipt_json)
        self.assertEqual((self.workspace / "invocations.log").read_bytes(), b"1\n")
        self.assertTrue(all(not p.stat().st_mode & 0o077 for p in result.directory.iterdir()))

    def test_executable_change_in_spawn_callback_refuses_before_target_exec(self):
        def change(_receipt):
            self.worker.write_text(self.worker.read_text() + "\n# changed at callback\n")
        result = self.run_capture({}, on_spawn=change).observation()
        self.assertEqual(result["status"], "not_sent")
        self.assertEqual(result["error"], "muse_executable_changed")
        self.assertFalse((self.workspace / "invocations.log").exists())

    def test_output_claims_never_supply_identity_usage_structured_result_or_acceptance(self):
        forged = b'{"model":"verified","session_id":"invented","usage":{"cost_usd":0},"accepted":true,"tests":"all passed"}'
        receipt = self.run_capture({"stdout": [forged.hex()]}).observation()
        self.assertEqual(receipt["status"], "local_turn_completed")
        self.assertIsNone(receipt["observed_model"])
        self.assertIsNone(receipt["observed_session"])
        self.assertEqual(receipt["usage"], {"input_tokens": None, "output_tokens": None, "cost_usd": None})
        self.assertIsNone(receipt["structured_result"])
        self.assertFalse(receipt["independently_accepted"])

    def test_exit_zero_incorrect_code_still_fails_a_predetermined_independent_check(self):
        from taskalong.process import run_bounded
        receipt = self.run_capture({"write_bad": True}).observation()
        self.assertEqual(receipt["status"], "local_turn_completed")
        check = run_bounded([sys.executable, "-I", "-S", "-c",
            "exec(open('calculator.py').read()); assert add(2,3)==5"], cwd=self.workspace, timeout_seconds=3)
        self.assertNotEqual(check.exit_code, 0)
        self.assertTrue(check.termination_confirmed)
        self.assertFalse(receipt["independently_accepted"])

    def test_prompt_change_in_spawn_callback_refuses_before_target_exec(self):
        def change(_receipt):
            (self.output / "muse-raw" / "prompt.txt").write_bytes(b'{}')
        receipt = self.run_capture({"stdout": [b"original".hex()]}, on_spawn=change).observation()
        self.assertEqual(receipt["status"], "not_sent")
        self.assertEqual(receipt["error"], "muse_prompt_changed")
        self.assertFalse((self.workspace / "invocations.log").exists())

    def test_nonzero_convincing_success_text_is_unsuccessful_and_exit_one_is_ambiguous(self):
        receipt = self.run_capture({"exit_code": 1, "stdout": [b'All tests passed; success!'.hex()]}).observation()
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["error"], "muse_nonzero_exit")
        self.assertEqual(receipt["process"]["exit_code"], 1)
        self.assertFalse(receipt["process"]["cancelled"])

    def test_simultaneous_large_streams_and_redaction_like_bytes_are_retained_exactly(self):
        stdout = b"sk-synthetic0123456789\n" + b"x" * 200000
        stderr = b"y" * 200000
        result = self.run_capture({"stdout": [stdout.hex()], "stderr": [stderr.hex()]})
        self.assertEqual((result.directory / "stdout.bin").read_bytes(), stdout)
        self.assertEqual((result.directory / "stderr.bin").read_bytes(), stderr)
        self.assertEqual(result.observation()["status"], "local_turn_completed")

    def test_output_limit_remains_failure_and_retained_captures_stay_bounded(self):
        result = self.run_capture({"stdout": [(b"x" * 10000).hex()]}, max_output_bytes=128)
        receipt = result.observation()
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["error"], "muse_output_limit")
        self.assertTrue(receipt["process"]["output_limited"])
        self.assertLessEqual(sum(x["bytes"] for x in receipt["captures"].values()), 128)

    def test_timeout_and_actual_local_cancellation_are_distinct(self):
        receipt = self.run_capture({"wait": True}, timeout_seconds=3).observation()
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["error"], "muse_timeout")
        self.assertTrue(receipt["process"]["timed_out"])
        self.assertTrue(receipt["process"]["termination_confirmed"])
        fresh = self.output / "cancel"
        fresh.mkdir(mode=0o700)
        self.request = replace(self.request, output_dir=fresh, attempt_id=str(uuid.uuid4()))
        (self.workspace / "invocations.log").unlink()
        receipt = self.run_capture({"wait": True},
            cancel_requested=lambda: (self.workspace / "invocations.log").exists()).observation()
        self.assertEqual(receipt["status"], "cancelled_local")
        self.assertTrue(receipt["process"]["termination_confirmed"])
        self.assertTrue(receipt["process"]["cancelled"])
        self.assertFalse(receipt["remote_cessation_proven"])

    def test_callback_refusal_is_not_sent_and_has_no_target_invocation(self):
        def refuse(_receipt):
            raise TaskAlongError("synthetic_admission_revoked", "Safe refusal.", effect_outcome="not_sent")
        receipt = self.run_capture({}, on_spawn=refuse).observation()
        self.assertEqual(receipt["status"], "not_sent")
        self.assertEqual(receipt["error"], "synthetic_admission_revoked")
        self.assertFalse((self.workspace / "invocations.log").exists())

    def test_callback_error_after_dispatch_is_preserved_without_private_exception_text(self):
        def fail():
            raise RuntimeError("PRIVATE_CALLBACK_DETAIL")
        result = self.run_capture({"wait": True}, heartbeat=fail)
        receipt = result.observation()
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["error"], "process_callback_failed")
        self.assertNotIn(b"PRIVATE_CALLBACK_DETAIL", result.receipt_json)
        self.assertTrue(receipt["process"]["termination_confirmed"])

    def test_uncertain_descendant_observation_cannot_complete_or_replay(self):
        from taskalong.executors import muse_capture
        original = muse_capture.run_bounded
        def uncertain(*args, **kwargs):
            observed = original(*args, **kwargs)
            return replace(observed, termination_confirmed=False, unaccounted_descendants=True)
        with patch.object(muse_capture, "run_bounded", uncertain):
            receipt = self.run_capture({}).observation()
        self.assertEqual(receipt["status"], "unknown")
        self.assertEqual(receipt["error"], "muse_termination_unconfirmed")
        with self.assertRaises(TaskAlongError) as failure:
            self.run_capture({})
        self.assertEqual(failure.exception.code, "muse_capture_exists")
        self.assertEqual((self.workspace / "invocations.log").read_bytes(), b"1\n")

    def test_unstructured_supervisor_error_after_dispatch_is_unknown_not_not_sent(self):
        from taskalong.executors import muse_capture
        original = muse_capture.run_bounded
        def lose_result(*args, **kwargs):
            observed = original(*args, **kwargs)
            self.assertTrue(observed.termination_confirmed)  # Test leaves no real unknown child.
            raise OSError("PRIVATE_SUPERVISOR_FAILURE")
        with patch.object(muse_capture, "run_bounded", lose_result):
            result = self.run_capture({"stdout": [b"retained".hex()]})
        receipt = result.observation()
        self.assertEqual((self.workspace / "invocations.log").read_bytes(), b"1\n")
        self.assertEqual(receipt["status"], "unknown")
        self.assertEqual(receipt["boundary_effect_outcome"], "uncertain")
        self.assertFalse(receipt["owned_cessation_confirmed"])
        self.assertEqual((result.directory / "stdout.bin").read_bytes(), b"retained")
        self.assertTrue((result.directory / "spawn.json").is_file())
        with self.assertRaises(TaskAlongError) as failure:
            self.run_capture({})
        self.assertEqual(failure.exception.code, "muse_capture_exists")

    def test_repeated_capture_never_overwrites_retained_result_or_launches_again(self):
        result = self.run_capture({})
        with self.assertRaises(TaskAlongError) as failure:
            self.run_capture({"stdout": [b"different".hex()]})
        self.assertEqual(failure.exception.code, "muse_capture_exists")
        self.assertEqual((result.directory / "receipt.json").read_bytes(), result.receipt_json)
        self.assertEqual((self.workspace / "invocations.log").read_bytes(), b"1\n")

    def test_capture_write_failure_preserves_primary_callback_error_and_blocks_replay(self):
        from taskalong.executors import muse_capture
        original = muse_capture._save
        def write(directory, name, data):
            if name == "receipt.json":
                raise OSError("PRIVATE_FILE_ERROR")
            return original(directory, name, data)
        def refuse(_receipt):
            raise TaskAlongError("synthetic_admission_revoked", "Safe refusal.", effect_outcome="not_sent")
        with patch.object(muse_capture, "_save", write), self.assertRaises(TaskAlongError) as failure:
            self.run_capture({}, on_spawn=refuse)
        self.assertEqual(failure.exception.code, "muse_capture_not_durable")
        self.assertEqual(failure.exception.effect_outcome, "not_sent")
        self.assertEqual(failure.exception.recovery[0]["primary_error"], "synthetic_admission_revoked")
        self.assertNotIn("PRIVATE_FILE_ERROR", str(failure.exception))
        with self.assertRaises(TaskAlongError):
            self.run_capture({})

    def test_production_native_resume_and_invalid_limits_refuse_without_invocation(self):
        from taskalong.executors.muse_capture import capabilities
        for options in [{"qualification": "production"}, {"mode": "native"}, {"thread_id": "old"},
                        {"timeout_seconds": 0}, {"timeout_seconds": True}, {"max_output_bytes": True}]:
            with self.subTest(options=options):
                with self.assertRaises(TaskAlongError) as failure:
                    self.run_capture({}, **options)
                self.assertEqual(failure.exception.effect_outcome, "not_sent")
        self.assertFalse(capabilities().structured_result)
        self.assertFalse(capabilities().native_resume)
        self.assertFalse(capabilities().provider_start_lookup)
        self.assertFalse((self.workspace / "invocations.log").exists())

    def test_capture_control_directory_cannot_overlap_worker_workspace(self):
        self.request = replace(self.request, output_dir=self.workspace)
        with self.assertRaises(TaskAlongError) as failure:
            self.run_capture({})
        self.assertEqual(failure.exception.code, "muse_capture_path_unsafe")
        self.assertEqual(failure.exception.effect_outcome, "not_sent")
        self.assertFalse((self.workspace / "invocations.log").exists())


if __name__ == "__main__":
    unittest.main()
