"""Real child processes exercise pipes, cancellation and bounded diagnostics."""
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from taskalong.process import ProcessBoundaryError, receipt_is_alive, run_bounded
from taskalong._supervisor import run_guard
from taskalong.errors import TaskAlongError


class ProcessTests(unittest.TestCase):
    def run_python(self, code, **kwargs):
        return run_bounded([sys.executable, "-c", code], cwd=tempfile.gettempdir(), **kwargs)

    def test_concurrent_pipes_and_stdin_do_not_deadlock(self):
        result = self.run_python("import sys;sys.stderr.buffer.write(b'e'*200000);sys.stderr.flush();data=sys.stdin.buffer.read();sys.stdout.buffer.write(data)", stdin=b"x"*200000)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(len(result.stdout), 200000)
        self.assertEqual(len(result.stderr), 200000)
        self.assertTrue(result.termination_confirmed)

    def test_timeout_terminates_ignoring_child(self):
        result = self.run_python("import signal,time;signal.signal(signal.SIGINT,signal.SIG_IGN);signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(50)", timeout_seconds=.2, signal_grace_seconds=.1)
        self.assertTrue(result.timed_out)
        self.assertTrue(result.termination_confirmed)
        self.assertLess(result.duration_ms, 3000)
        self.assertEqual(result.exit_code, -signal.SIGKILL)

    def test_cancellation_is_observed_without_disk_pid_signals(self):
        start = time.monotonic()
        result = self.run_python("import time;time.sleep(50)", cancel_requested=lambda: time.monotonic()-start > .2)
        self.assertTrue(result.cancelled)
        self.assertTrue(result.termination_confirmed)

    def test_aggregate_output_limit_is_not_pipe_specific(self):
        result = self.run_python("import sys;sys.stdout.buffer.write(b'x'*5000);sys.stderr.buffer.write(b'y'*5000)", max_output_bytes=6000)
        self.assertTrue(result.output_limited)
        self.assertLessEqual(len(result.stdout)+len(result.stderr), 6000)

    def test_split_secret_is_redacted_after_stream_assembly(self):
        result = self.run_python("import sys,time;sys.stderr.write('supersecret');sys.stderr.flush();time.sleep(.1);sys.stderr.write('CANARY');sys.stderr.flush()", secrets=["supersecretCANARY"])
        self.assertEqual(result.stderr, b"[REDACTED]")

    def test_jsonl_partial_final_line_is_not_a_terminal_receipt(self):
        seen = []
        result = self.run_python("print('{}');print('unfinished',end='')", on_stdout_line=seen.append)
        self.assertEqual(seen, [b"{}"])
        self.assertEqual(result.protocol_error, "runtime_jsonl_truncated")

    def test_long_line_is_bounded(self):
        result = self.run_python("print('x'*10000)", on_stdout_line=lambda x:None, max_line_bytes=1024)
        self.assertEqual(result.protocol_error, "runtime_line_too_large")

    def test_failed_spawn_receipt_callback_stops_owned_child(self):
        receipts = []
        def fail(receipt):
            receipts.append(receipt)
            raise RuntimeError("do not persist raw callback details")
        with self.assertRaisesRegex(ProcessBoundaryError, "callback failed"):
            self.run_python("import time;time.sleep(50)", on_spawn=fail, signal_grace_seconds=.05)
        with self.assertRaises(ProcessLookupError):
            os.kill(receipts[0].pid, 0)

    def test_shell_string_is_rejected(self):
        with self.assertRaises(ProcessBoundaryError):
            run_bounded("echo unsafe", cwd=tempfile.gettempdir())

    def test_child_environment_omits_credential_variables(self):
        old = os.environ.get("GITHUB_TOKEN")
        os.environ["GITHUB_TOKEN"] = "CANARY-DO-NOT-PASS"
        try:
            result = self.run_python("import os;print(os.getenv('GITHUB_TOKEN','absent'))")
            self.assertEqual(result.stdout, b"absent\n")
        finally:
            if old is None: os.environ.pop("GITHUB_TOKEN", None)
            else: os.environ["GITHUB_TOKEN"] = old

    def test_malformed_or_live_receipt_is_not_proof_of_cessation(self):
        self.assertTrue(receipt_is_alive(None))
        self.assertTrue(receipt_is_alive({"pid": True, "pgid": True}))
        self.assertTrue(receipt_is_alive({"pid": os.getpid(), "pgid": os.getpid()}))

    def test_descendant_surviving_parent_is_unknown_not_cancelled(self):
        result = self.run_python("import subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(2.5)'])")
        self.assertFalse(result.termination_confirmed)
        self.assertLess(result.duration_ms, 2500)
        # The synthetic child terminates naturally; this test never signals a
        # PID or process group reconstructed from persisted output.
        time.sleep(1.2)

    def test_detached_grandchild_cannot_earn_a_cessation_receipt(self):
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw).resolve() / "escaped-write"
            release = target.parent / "release-detached-fixture"
            child = ("import time,pathlib;release=pathlib.Path(" + repr(str(release)) + ");"
                     "deadline=time.monotonic()+10\n"
                     "while not release.exists() and time.monotonic()<deadline: time.sleep(.01)\n"
                     "pathlib.Path(" + repr(str(target)) + ").write_text('escaped')")
            parent = "import subprocess,sys;subprocess.Popen([sys.executable,'-c'," + repr(child) + "],start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)"
            result = self.run_python(parent)
            # Release only after the actual runner returned its lifetime result.
            # This kernel/process barrier does not depend on scheduling a sleep.
            release.touch()
            self.assertEqual(result.exit_code, 0)
            self.assertTrue(result.group_termination_confirmed)
            self.assertFalse(result.termination_confirmed)
            self.assertTrue(result.unaccounted_descendants)
            deadline = time.monotonic() + 5
            while not target.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(target.read_text(), "escaped")

    def test_per_run_guard_excludes_second_owner_and_preserves_lock_file(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            run_id = str(uuid.uuid4())
            with run_guard(root, run_id):
                with self.assertRaises(TaskAlongError) as result:
                    with run_guard(root, run_id): pass
                self.assertEqual(result.exception.code, "supervisor_owned")
            path = root / "guards" / (run_id + ".lock")
            self.assertTrue(path.is_file())
            inode = path.stat().st_ino
            with run_guard(root, run_id):
                self.assertEqual(path.stat().st_ino, inode)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin kernel boundary fault injection")
    def test_unavailable_kernel_lifetime_boundary_never_releases_target(self):
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw).resolve() / "must-not-dispatch"
            receipts = []
            with patch("taskalong.process.select.kqueue", side_effect=OSError("unavailable")):
                with self.assertRaises(ProcessBoundaryError) as error:
                    self.run_python("from pathlib import Path;Path("+repr(str(target))+").write_text('bad')", on_spawn=receipts.append)
            self.assertEqual(error.exception.code, "runtime_lifecycle_unsupported")
            self.assertEqual(error.exception.effect_outcome, "not_sent")
            self.assertFalse(target.exists())
            self.assertEqual(receipts, [])


if __name__ == "__main__":
    unittest.main()
