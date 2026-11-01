"""Real child processes exercise pipes, cancellation and bounded diagnostics."""
import os
import json
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

    def test_empty_nonfirst_arguments_reach_owned_child_without_rewriting(self):
        expected = ['--tools', '', '--following', 'value', '', '雪', '']
        argv = (sys.executable, '-c', 'import json,sys;print(json.dumps(sys.argv[1:],ensure_ascii=False))', *expected)
        result = run_bounded(argv, cwd=tempfile.gettempdir(), timeout_seconds=2, max_output_bytes=8192)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(json.loads(result.stdout), expected)
        self.assertTrue(result.termination_confirmed)

    def test_invalid_argument_vectors_refuse_before_process_or_gate_creation(self):
        from taskalong import process as boundary
        cases = [None, [], (), '', 'command', b'command', {}, {sys.executable}, iter([sys.executable]),
                 [''], ['', 'later'], [None], [sys.executable, None], [sys.executable, 1],
                 [sys.executable, b''], [sys.executable, 'nul\0byte'], ['nul\0executable'],
                 [sys.executable, '\ud800'], [sys.executable, '\udcff'], ['\ud800']]
        for argv in cases:
            with self.subTest(argv=repr(argv)), patch.object(boundary.subprocess, 'Popen') as spawn, \
                    patch.object(boundary.os, 'pipe') as pipe, patch.object(boundary.os, 'write') as release, \
                    patch.object(boundary.selectors, 'DefaultSelector') as selector, patch.object(boundary, 'fingerprint') as fingerprint:
                with self.assertRaises(ProcessBoundaryError) as caught:
                    run_bounded(argv, cwd=tempfile.gettempdir())
                self.assertEqual(caught.exception.effect_outcome, 'not_sent')
                for effect in (spawn, pipe, release, selector, fingerprint):
                    effect.assert_not_called()

    def test_empty_arguments_do_not_bypass_existing_resource_validation(self):
        from taskalong import process as boundary
        for options in ({'timeout_seconds': 0}, {'signal_grace_seconds': -1},
                        {'max_output_bytes': 0}, {'stdin': b'x' * (1048576 + 1)}):
            with self.subTest(options=list(options)), patch.object(boundary.subprocess, 'Popen') as spawn:
                with self.assertRaises(ProcessBoundaryError):
                    run_bounded([sys.executable, '', 'later'], cwd=tempfile.gettempdir(), **options)
                spawn.assert_not_called()

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

    @unittest.skipUnless(sys.platform == "darwin", "Darwin owned signal denial")
    def test_denied_owned_signals_return_unknown_before_finite_child_exits(self):
        from taskalong import process as boundary
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            release, finished = root/"release", root/"finished"
            code = ("import pathlib,time;release=pathlib.Path("+repr(str(release))+");"
                    "finished=pathlib.Path("+repr(str(finished))+");deadline=time.monotonic()+10;"
                    "print('ready',flush=True)\n"
                    "while not release.exists() and time.monotonic()<deadline:time.sleep(.01)\n"
                    "finished.touch()")
            ready, children, denied = [], [], []
            real_spawn, real_signal = boundary.subprocess.Popen, os.killpg
            def spawn(*args, **kwargs):
                child = real_spawn(*args, **kwargs)
                children.append(child)
                return child
            def deny(pgid, sig):
                if sig == 0:
                    return real_signal(pgid, sig)
                denied.append(sig)
                raise PermissionError(1, "PRIVATE_SYNTHETIC_SIGNAL_DETAIL")
            try:
                with patch.object(boundary.subprocess, "Popen", spawn), patch.object(boundary.os, "killpg", deny):
                    with self.assertRaises(ProcessBoundaryError) as failure:
                        self.run_python(code, timeout_seconds=3,
                            on_stdout_line=ready.append, cancel_requested=lambda: bool(ready),
                            signal_grace_seconds=.05)
                    self.assertNotIn("PRIVATE_SYNTHETIC_SIGNAL_DETAIL", str(failure.exception))
                    self.assertEqual(failure.exception.code, "process_signal_failed")
                    result = failure.exception.process_result
                self.assertIsNotNone(result)
                self.assertTrue(denied)
                self.assertFalse(finished.exists(), "Return must not wait for the fixture's natural expiry")
                self.assertIsNone(children[0].poll())
                self.assertTrue(result.cancelled)
                self.assertFalse(result.termination_confirmed)
                self.assertTrue(result.unaccounted_descendants)
                self.assertIsNone(result.exit_code)
            finally:
                release.touch()
                for child in children:
                    child.wait(timeout=4)
                self.assertTrue(finished.exists())

    @unittest.skipUnless(sys.platform == "darwin", "Darwin owned signal exit race")
    def test_signal_denial_after_real_exit_still_requires_kernel_cessation(self):
        with tempfile.TemporaryDirectory() as raw:
            self._signal_denial_after_real_exit(Path(raw).resolve()/"release")

    def _signal_denial_after_real_exit(self, release):
        from taskalong import process as boundary
        real_signal = os.killpg
        children, denied, ready = [], [], []
        real_spawn = boundary.subprocess.Popen
        def spawn(*args, **kwargs):
            child = real_spawn(*args, **kwargs)
            children.append(child)
            return child
        def deny_after_exit(pgid, sig):
            if sig == 0:
                return real_signal(pgid, sig)
            release.touch()
            children[0].wait(timeout=3)
            denied.append(sig)
            raise PermissionError(1, "PRIVATE_SYNTHETIC_SIGNAL_DETAIL")
        code = ("import time,pathlib;release=pathlib.Path("+repr(str(release))+");"
                "deadline=time.monotonic()+10;print('ready',flush=True)\n"
                "while not release.exists() and time.monotonic()<deadline:time.sleep(.01)")
        try:
            with patch.object(boundary.subprocess, "Popen", spawn), patch.object(boundary.os, "killpg", deny_after_exit):
                with self.assertRaises(ProcessBoundaryError) as failure:
                    self.run_python(code, timeout_seconds=3, on_stdout_line=ready.append,
                        cancel_requested=lambda: bool(ready), signal_grace_seconds=.05)
        finally:
            release.touch()
            for child in children:
                child.wait(timeout=4)
        self.assertEqual(failure.exception.code, "process_signal_failed")
        result = failure.exception.process_result
        self.assertTrue(denied)
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.termination_confirmed)
        self.assertFalse(result.unaccounted_descendants)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin owned signal fault campaign")
    def test_later_signal_denials_preserve_failure_and_real_lifetime_facts(self):
        from taskalong import process as boundary
        for selected in (signal.SIGTERM, signal.SIGKILL):
            with self.subTest(signal=selected), tempfile.TemporaryDirectory() as raw:
                release = Path(raw).resolve()/"release"
                code = ("import signal,time,pathlib;signal.signal(signal.SIGINT,signal.SIG_IGN);"
                        "signal.signal(signal.SIGTERM,signal.SIG_IGN);release=pathlib.Path("+repr(str(release))+");"
                        "deadline=time.monotonic()+10;print('ready',flush=True)\n"
                        "while not release.exists() and time.monotonic()<deadline:time.sleep(.01)")
                ready, children = [], []
                real_spawn, real_signal = boundary.subprocess.Popen, os.killpg
                def spawn(*args, **kwargs):
                    child = real_spawn(*args, **kwargs)
                    children.append(child)
                    return child
                def deny(pgid, sig):
                    if sig == selected:
                        raise PermissionError(1, "PRIVATE_SYNTHETIC_SIGNAL_DETAIL")
                    return real_signal(pgid, sig)
                try:
                    with patch.object(boundary.subprocess, "Popen", spawn), patch.object(boundary.os, "killpg", deny):
                        with self.assertRaises(ProcessBoundaryError) as failure:
                            self.run_python(code, timeout_seconds=3, on_stdout_line=ready.append,
                                cancel_requested=lambda: bool(ready), signal_grace_seconds=.05)
                    error = failure.exception
                    self.assertEqual(error.code, "process_signal_failed")
                    stage = "signal_term" if selected == signal.SIGTERM else "signal_kill"
                    self.assertEqual(error.boundary_failures[0], (stage, 1))
                    self.assertEqual(error.effect_outcome, "uncertain")
                    self.assertEqual(error.process_result.termination_confirmed, selected == signal.SIGTERM)
                    self.assertEqual(error.process_result.unaccounted_descendants, selected == signal.SIGKILL)
                finally:
                    release.touch()
                    for child in children:
                        child.wait(timeout=4)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin owned identity query denial")
    def test_ownership_query_denial_cannot_authorize_a_signal(self):
        from taskalong import process as boundary
        ready = []
        real_signal = os.killpg
        sent = []
        def observe(pgid, sig):
            if sig != 0:
                sent.append(sig)
            return real_signal(pgid, sig)
        with patch.object(boundary.os, "getpgid", side_effect=PermissionError(1, "PRIVATE_QUERY")), \
                patch.object(boundary.os, "killpg", observe):
            with self.assertRaises(ProcessBoundaryError) as failure:
                self.run_python("import time;print('ready',flush=True);time.sleep(.2)",
                    timeout_seconds=3, on_stdout_line=ready.append,
                    cancel_requested=lambda: bool(ready), signal_grace_seconds=.05)
        self.assertEqual(failure.exception.code, "process_signal_failed")
        self.assertEqual(sent, [])
        self.assertTrue(failure.exception.process_result.termination_confirmed)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin final cleanup fault campaign")
    def test_final_signal_denial_does_not_replace_primary_observation_failure(self):
        from taskalong import process as boundary
        with tempfile.TemporaryDirectory() as raw:
            release = Path(raw).resolve()/"release"
            code = ("import time,pathlib;release=pathlib.Path("+repr(str(release))+");"
                    "deadline=time.monotonic()+10;print('ready',flush=True)\n"
                    "while not release.exists() and time.monotonic()<deadline:time.sleep(.01)")
            ready, children = [], []
            real_selector, real_spawn, real_signal = boundary.selectors.DefaultSelector, boundary.subprocess.Popen, os.killpg
            def selector():
                selected = real_selector()
                real_select = selected.select
                def select(timeout):
                    if ready:
                        raise OSError(5, "PRIVATE_OBSERVATION")
                    return real_select(timeout)
                selected.select = select
                return selected
            def spawn(*args, **kwargs):
                child = real_spawn(*args, **kwargs)
                children.append(child)
                return child
            def deny(pgid, sig):
                if sig:
                    raise PermissionError(1, "PRIVATE_FINAL_SIGNAL")
                return real_signal(pgid, sig)
            try:
                with patch.object(boundary.selectors, "DefaultSelector", selector), \
                        patch.object(boundary.subprocess, "Popen", spawn), patch.object(boundary.os, "killpg", deny):
                    with self.assertRaises(ProcessBoundaryError) as failure:
                        self.run_python(code, timeout_seconds=3, on_stdout_line=ready.append)
                error = failure.exception
                self.assertEqual(error.code, "process_cleanup_failed")
                self.assertEqual(error.boundary_failures, (("observation", 5), ("final_signal_kill", 1)))
                self.assertFalse(error.process_result.termination_confirmed)
                self.assertIsNone(children[0].poll())
            finally:
                release.touch()
                for child in children:
                    child.wait(timeout=4)

    def test_cleanup_failures_preserve_gate_refusal_and_attempt_remaining_closes(self):
        from taskalong import process as boundary
        real_wait, real_selector = boundary.subprocess.Popen.wait, boundary.selectors.DefaultSelector
        real_close = boundary._LinuxTracker.close if sys.platform == "linux" else boundary._DescendantTracker.close
        tracker_type = boundary._LinuxTracker if sys.platform == "linux" else boundary._DescendantTracker
        real_spawn = boundary.subprocess.Popen
        closed, children = [], []
        def selector():
            selected = real_selector()
            close = selected.close
            def fail():
                close()
                closed.append("selector")
                raise OSError(5, "PRIVATE_SELECTOR_CLOSE")
            selected.close = fail
            return selected
        def close_tracker(tracker):
            real_close(tracker)
            closed.append("tracker")
            raise OSError(5, "PRIVATE_TRACKER_CLOSE")
        def spawn(*args, **kwargs):
            child = real_spawn(*args, **kwargs)
            children.append(child)
            return child
        def veto(_):
            raise TaskAlongError("cancel_pending", "Synthetic gate refusal", effect_outcome="not_sent")
        try:
            with patch.object(boundary.selectors, "DefaultSelector", selector), \
                    patch.object(tracker_type, "close", close_tracker), patch.object(boundary.subprocess, "Popen", spawn), \
                    patch.object(real_spawn, "wait", side_effect=OSError(5, "PRIVATE_WAIT")):
                with self.assertRaises(ProcessBoundaryError) as failure:
                    self.run_python("raise SystemExit(93)", timeout_seconds=3, on_spawn=veto, signal_grace_seconds=.05)
            error = failure.exception
            self.assertEqual(error.code, "cancel_pending")
            self.assertEqual(error.effect_outcome, "not_sent")
            self.assertIn(("completion_wait", 5), error.boundary_failures)
            self.assertIn(("selector_close", 5), error.boundary_failures)
            self.assertIn(("tracker_close", 5), error.boundary_failures)
            self.assertEqual(closed, ["selector", "tracker"])
            self.assertFalse(error.process_result.termination_confirmed)
            self.assertTrue(error.process_result.unaccounted_descendants)
            self.assertTrue(all(pipe.closed for child in children for pipe in (child.stdin, child.stdout, child.stderr)))
        finally:
            for child in children:
                real_wait(child, timeout=4)

    def test_failed_pipe_close_does_not_skip_other_owned_pipes(self):
        from taskalong import process as boundary
        real_spawn, children, closes = boundary.subprocess.Popen, [], []
        class FailingClose:
            def __init__(self, pipe, name):
                self.pipe, self.name = pipe, name
            def __getattr__(self, name):
                return getattr(self.pipe, name)
            def close(self):
                self.pipe.close()
                closes.append(self.name)
                raise OSError(5, "PRIVATE_PIPE_CLOSE")
        def spawn(*args, **kwargs):
            child = real_spawn(*args, **kwargs)
            child.stdout = FailingClose(child.stdout, "stdout")
            child.stderr = FailingClose(child.stderr, "stderr")
            children.append(child)
            return child
        try:
            with patch.object(boundary.subprocess, "Popen", spawn):
                with self.assertRaises(ProcessBoundaryError) as failure:
                    self.run_python("print('finite')", timeout_seconds=3)
            error = failure.exception
            self.assertEqual(error.code, "process_cleanup_failed")
            self.assertIn(("observation", 5), error.boundary_failures)
            self.assertIn(("pipe_close", 5), error.boundary_failures)
            self.assertCountEqual(closes, ["stdout", "stderr"])
            self.assertFalse(error.process_result.termination_confirmed)
            self.assertTrue(all(pipe.closed for child in children for pipe in (child.stdin, child.stdout, child.stderr)))
        finally:
            for child in children:
                child.wait(timeout=4)

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
