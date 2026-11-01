"""Owned finite stdlib children only; never a provider or actual operator State."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from taskalong import muse_experimental as muse
from taskalong import process
from taskalong.errors import TaskAlongError
from taskalong.experimental_process import FOREGROUND_EXPERIMENT, run_foreground_experiment
from taskalong.local_provider_capture import PrivateCapture, read_capture
from taskalong.validation import canonical_bytes, loads
from test_muse_native_lifecycle import SESSION, SECOND, row, raw, start_rows


class NativeGuardSelectionTests(unittest.TestCase):
    def test_legacy_operations_do_not_enable_new_guard(self):
        config = {"format": "local-muse-provider/6", "max_protocol_records": 131072}
        with patch.object(muse, "run_foreground_experiment") as invoke:
            for previous in (None, {"format": "manual-muse-successor/1"},
                             {"format": "manual-muse-successor/2"}, {"format": "manual-muse-successor/3"}):
                self.assertIsNone(muse._native_guard(previous, config, SESSION))
            invoke.assert_not_called()

    def test_interrupted_guard_requires_exact_policy_before_any_process(self):
        config = {"format": "local-muse-provider/6", "max_protocol_records": 131072}
        with patch.object(process.subprocess, "Popen") as spawn:
            for policy in (None, False, "unbound-policy"):
                with self.subTest(policy=policy), self.assertRaises(TaskAlongError) as error:
                    muse._native_guard({"format": "manual-muse-successor/4", "native_lifecycle_policy": policy}, config, SESSION)
                self.assertEqual(error.exception.code, "provider_successor_invalid")
                self.assertEqual(error.exception.effect_outcome, "not_sent")
            spawn.assert_not_called()


@unittest.skipUnless(sys.platform == "darwin", "Real foreground owner is Darwin-only")
class NativeStopProcessTests(unittest.TestCase):
    def invoke(self, frames, *, wait_for_stop, record_limit=131072):
        root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        root.chmod(0o700)
        sink = PrivateCapture(root / "capture", max_output_bytes=65536)
        self.addCleanup(sink.close)
        guard = muse._native_guard({"format": "manual-muse-successor/4",
                                    "native_lifecycle_policy": muse._NATIVE_STOP_POLICY},
                                   {"format": "local-muse-provider/6", "max_protocol_records": 131072}, SESSION)
        budget = muse._RecordBudget(record_limit)
        expected_stdout = b"\n".join(frames) + b"\n"
        # One bounded write queues all lifecycle rows before the owner can act;
        # cancellation must still drain and observe subsequent complete frames.
        self.assertLess(len(expected_stdout), 32768)
        code = ("import os,signal\n"
                "def stop(number,frame):\n"
                "    os.write(2,b'owned-stop\\n')\n"
                "    raise SystemExit(128+number)\n"
                "def deadline(number,frame):\n"
                "    raise SystemExit(77)\n"
                "signal.signal(signal.SIGINT,stop)\n"
                "signal.signal(signal.SIGTERM,stop)\n"
                "signal.signal(signal.SIGALRM,deadline)\n"
                "signal.alarm(2)\n"
                f"data={expected_stdout!r}\n"
                "while data:data=data[os.write(1,data):]\n"
                "os.write(2,b'owned-ready\\n')\n"
                + ("signal.pause()\n" if wait_for_stop else ""))
        observed_receipts, children = [], []
        original_popen = process.subprocess.Popen

        def spawn(*args, **kwargs):
            child = original_popen(*args, **kwargs)
            children.append(child)
            return child

        def observe(line):
            budget.observe(line)
            guard.observe(line)

        with patch.object(process.subprocess, "Popen", side_effect=spawn):
            result = run_foreground_experiment([sys.executable, "-I", "-S", "-c", code],
                cwd=root, mode=FOREGROUND_EXPERIMENT, timeout_seconds=3,
                max_output_bytes=65536, max_line_bytes=65536, signal_grace_seconds=.05,
                on_spawn=lambda receipt: observed_receipts.append(receipt.to_dict()),
                on_stdout_line=observe, cancel_requested=lambda: guard.stop_requested,
                _on_output_chunk=sink.write, _retain_output=False)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())
        with self.assertRaises(ChildProcessError):
            os.waitpid(children[0].pid, os.WNOHANG)
        self.assertEqual(observed_receipts, [result.receipt.to_dict()])
        self.assertEqual(result.receipt.pid, children[0].pid)
        self.assertTrue(result.root_exit_observed)
        self.assertTrue(result.group_termination_confirmed)
        self.assertFalse(result.fork_observed)
        self.assertEqual(result.tracking_errors, ())
        self.assertEqual(result.boundary_failures, ())
        self.assertFalse(result.timed_out)
        self.assertFalse(result.output_limited)
        self.assertLess(result.duration_ms, 3000)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")
        closure = sink.finalize()
        self.assertEqual(closure, read_capture(root / "capture"))
        self.assertTrue(closure["byte_closure"])
        self.assertEqual(closure["status"], "closed")
        self.assertEqual((root / "capture/stdout.bin").read_bytes(), expected_stdout)
        self.assertEqual(sum(closure["streams"][s]["observed_bytes"] for s in ("stdout", "stderr")), result.output_bytes)
        # Preserve an inspectable process receipt alongside the byte closure.
        # Closure proves captured bytes, never provider/remote cessation.
        summary = muse._summary(result)
        summary.update(native_lifecycle=guard.summary(), private_capture=closure)
        receipt_file = root / "synthetic-process-receipt.json"
        receipt_file.write_bytes(canonical_bytes(summary))
        self.assertEqual(loads(receipt_file.read_bytes())["receipt"], observed_receipts[0])
        self.assertFalse(summary["termination_confirmed"])
        self.assertEqual(summary["descendant_cessation"], "unknown")
        self.assertFalse(summary["acceptance_allowed"])
        self.assertFalse(summary["native_lifecycle"]["hard_native_attempt_limit_enforced"])
        self.assertEqual(summary["native_lifecycle"]["paid_call_count"], "unknown")
        self.assertEqual(summary["native_lifecycle"]["remote_usage"], "unknown")
        return result, guard.summary(), budget, (root / "capture/stderr.bin").read_bytes()

    def test_timeout_then_queued_second_task_stops_and_preserves_receipt(self):
        values = start_rows() + [row(4, "timed_out"), row(5, task=SECOND),
                               row(6, "side_effect_intent", SECOND), row(7, "started", SECOND)]
        result, guard, budget, stderr = self.invoke([raw(v) for v in values], wait_for_stop=True)
        self.assertTrue(result.cancelled)
        self.assertEqual(result.root_exit_code, 130)
        self.assertIsNone(result.failure_code)
        self.assertEqual(guard["first_stop_cause"], "model_task_timed_out")
        self.assertEqual(guard["model_tasks_started"], 2)
        self.assertEqual(guard["model_tasks_observed"], 2)
        self.assertTrue(guard["protocol_valid"])
        self.assertEqual(budget.observed, 7)
        self.assertTrue(stderr.endswith(b"owned-stop\n"))

    def test_second_task_without_timeout_requests_owned_stop(self):
        values = start_rows() + [row(4, "completed"), row(5, task=SECOND),
                               row(6, "side_effect_intent", SECOND), row(7, "started", SECOND)]
        result, guard, _, _ = self.invoke([raw(v) for v in values], wait_for_stop=True)
        self.assertTrue(result.cancelled)
        self.assertEqual(guard["first_stop_cause"], "second_model_task_observed")
        self.assertEqual(guard["model_tasks_started"], 2)

    def test_valid_one_task_child_exits_normally(self):
        result, guard, budget, _ = self.invoke([raw(v) for v in start_rows() + [row(4, "completed")]], wait_for_stop=False)
        self.assertEqual(result.root_exit_code, 0)
        self.assertFalse(result.cancelled)
        self.assertIsNone(result.failure_code)
        self.assertFalse(guard["stop_requested"])
        self.assertTrue(guard["protocol_valid"])
        self.assertEqual(guard["model_tasks_started"], 1)
        self.assertEqual(budget.observed, 4)

    def test_malformed_row_requests_owned_stop_without_callback_exception(self):
        result, guard, _, _ = self.invoke([b"synthetic malformed JSON"], wait_for_stop=True)
        self.assertTrue(result.cancelled)
        self.assertEqual(result.root_exit_code, 130)
        self.assertIsNone(result.failure_code)
        self.assertEqual(guard["first_stop_cause"], "malformed_native_lifecycle")
        self.assertFalse(guard["protocol_valid"])

    def test_record_budget_failure_retains_receipt_and_raw_capture(self):
        result, guard, budget, _ = self.invoke([raw(v) for v in start_rows()], wait_for_stop=True, record_limit=1)
        self.assertEqual(result.failure_code, "provider_protocol_record_limit")
        self.assertTrue(budget.limited)
        self.assertEqual(guard["records_observed"], 1)
        # Validity covers only the observed prefix; the separate process failure
        # must veto acceptance even though the guard did not see the extra rows.
        self.assertTrue(guard["protocol_valid"])
        self.assertFalse(guard["stop_requested"])


if __name__ == "__main__":
    unittest.main()
