"""Kernel-backed lifetime contract, exercised only on Linux hosts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from typing import Callable
from contextlib import contextmanager
from taskalong.process import _LinuxTracker
import taskalong
from taskalong.errors import TaskAlongError
from taskalong.process import ProcessBoundaryError, run_bounded


HELPER = Path(taskalong.__file__).resolve().parent / "_linux_lifetime.py"


class LifetimeChild:
    def __init__(self, target: list[str] | Callable[[int, int], list[str]]):
        self.gate_read, self.gate_write = os.pipe()
        status_read, status_write = os.pipe()
        self.status_read = status_read
        self.pending = bytearray()
        if callable(target):
            target = target(self.gate_read, status_write)
        self.process = subprocess.Popen(
            [sys.executable, "-I", "-S", str(HELPER), str(self.gate_read), str(status_write), *target],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=(self.gate_read, status_write), start_new_session=True,
        )
        os.close(self.gate_read)
        os.close(status_write)

    def read_status(self, timeout: float = 3.0) -> dict:
        deadline = time.monotonic() + timeout
        while b"\n" not in self.pending:
            available, _, _ = select.select([self.status_read], [], [], max(0, deadline - time.monotonic()))
            if not available:
                raise AssertionError("lifetime status timed out")
            chunk = os.read(self.status_read, 4096)
            if not chunk:
                raise AssertionError("lifetime status ended without a complete receipt")
            self.pending.extend(chunk)
        value, _, rest = self.pending.partition(b"\n")
        self.pending = bytearray(rest)
        return json.loads(value)

    def release(self) -> None:
        os.write(self.gate_write, b"1")
        os.close(self.gate_write)
        self.gate_write = -1

    def close(self) -> None:
        if self.gate_write != -1:
            os.close(self.gate_write)
            self.gate_write = -1
        if self.process.poll() is None:
            # A live handle created here owns this wrapper; never use a PID file.
            self.process.kill()
        self.process.communicate(timeout=3)
        os.close(self.status_read)


@unittest.skipUnless(sys.platform == "linux", "Linux prctl/subreaper kernel qualification")
class LinuxLifetimeTests(unittest.TestCase):
    def invoke(self, script: str) -> LifetimeChild:
        child = LifetimeChild([sys.executable, "-I", "-S", "-c", script])
        self.addCleanup(child.close)
        self.assertEqual(child.read_status(), {"protocol_version": 2, "ready": True})
        return child

    def assert_final(self, child: LifetimeChild, code: int, stopped: bool) -> dict:
        final = child.read_status()
        self.assertEqual(final["protocol_version"], 2)
        self.assertEqual(final["dispatch_state"], "started")
        self.assertEqual(final["root_exit_code"], code)
        self.assertEqual(final["descendants_stopped"], stopped)
        self.assertIs(type(final["root_pid"]), int)
        self.assertGreater(final["root_pid"], 1)
        self.assertEqual(final["root_pgid"], final["root_pid"])
        return final

    def test_gate_prevents_target_before_ready_receipt_and_release(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "executed"
            child = self.invoke(f"import pathlib;pathlib.Path({str(marker)!r}).write_text('synthetic')")
            self.assertFalse(marker.exists())
            child.release()
            self.assert_final(child, 0, True)
            child.process.wait(timeout=3)
            self.assertTrue(marker.exists())

    def test_gate_eof_reports_no_target_only_after_complete_owned_protocol(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "must-not-execute"
            child = self.invoke(f"import pathlib;pathlib.Path({str(marker)!r}).touch()")
            os.close(child.gate_write)
            child.gate_write = -1
            self.assertEqual(child.read_status(), {
                "protocol_version": 2, "dispatch_state": "not_released", "root_exit_code": None,
                "descendants_stopped": True, "root_pid": None, "root_pgid": None})
            self.assertEqual(child.process.wait(timeout=3), 0)
            self.assertEqual(child.pending, b"")
            self.assertEqual(os.read(child.status_read, 1), b"")
            self.assertFalse(marker.exists())

    def test_invalid_gate_token_cannot_supply_no_target_success(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "must-not-execute"
            child = self.invoke(f"import pathlib;pathlib.Path({str(marker)!r}).touch()")
            os.write(child.gate_write, b"x")
            os.close(child.gate_write)
            child.gate_write = -1
            self.assertEqual(child.read_status(), {"protocol_version": 2, "error": "invalid_gate_release"})
            self.assertEqual(child.process.wait(timeout=3), 125)
            self.assertFalse(marker.exists())

    def test_exact_nonzero_root_exit_is_reported(self):
        child = self.invoke("raise SystemExit(23)")
        child.release()
        self.assert_final(child, 23, True)

    def test_all_exited_grandchildren_are_reaped(self):
        # Root deliberately leaves an exited child unreaped for subreaper adoption.
        child = self.invoke("import os,time;pid=os.fork();os._exit(0) if pid==0 else time.sleep(0.05)")
        child.release()
        self.assert_final(child, 0, True)

    def test_live_detached_descendant_is_uncertain(self):
        script = (
            "import os,time\n"
            "r,w=os.pipe();pid=os.fork()\n"
            "if pid==0:\n"
            " os.close(r);os.setsid();os.write(w,b'1');os.close(w);time.sleep(0.3);os._exit(0)\n"
            "else:\n"
            " os.close(w);assert os.read(r,1)==b'1';os.close(r);os._exit(0)\n"
        )
        child = self.invoke(script)
        child.release()
        self.assert_final(child, 0, False)
        self.assertEqual(child.process.wait(timeout=3), 125)
        # The fixture ends by itself. The helper must not guess a detached PID.
        time.sleep(0.35)

    def test_live_same_group_descendant_is_uncertain(self):
        child = self.invoke("import os,time;pid=os.fork();time.sleep(0.3) if pid==0 else None;os._exit(0)")
        child.release()
        final = self.assert_final(child, 0, False)
        # Read-only group presence confirms why a wrapper-only group check fails.
        os.killpg(final["root_pgid"], 0)
        self.assertEqual(child.process.wait(timeout=3), 125)
        time.sleep(0.35)

    def test_control_descriptors_are_closed_before_exec(self):
        def target(gate_fd: int, status_fd: int) -> list[str]:
            script = (
                "import os,errno\n"
                f"for fd in ({gate_fd},{status_fd}):\n"
                " try: os.fstat(fd)\n"
                " except OSError as exc: assert exc.errno==errno.EBADF\n"
                " else: raise SystemExit(44)\n"
            )
            return [sys.executable, "-I", "-S", "-c", script]
        child = LifetimeChild(target)
        self.addCleanup(child.close)
        self.assertEqual(child.read_status(), {"protocol_version": 2, "ready": True})
        child.release()
        self.assert_final(child, 0, True)

    def test_same_uid_target_cannot_reopen_wrapper_status_descriptor(self):
        def target(_gate_fd: int, status_fd: int) -> list[str]:
            script = (
                "import os,errno\n"
                f"path='/proc/'+str(os.getppid())+'/fd/{status_fd}'\n"
                "try: fd=os.open(path,os.O_WRONLY|os.O_NONBLOCK)\n"
                "except PermissionError: pass\n"
                "else: os.close(fd);raise SystemExit(45)\n"
            )
            return [sys.executable, "-I", "-S", "-c", script]
        child = LifetimeChild(target)
        self.addCleanup(child.close)
        self.assertEqual(child.read_status(), {"protocol_version": 2, "ready": True})
        child.release()
        self.assert_final(child, 0, True)

    def test_target_killing_wrapper_cannot_supply_final_receipt(self):
        # The target can signal its same-UID parent. A missing trusted final must
        # remain unknown even when the target subsequently exits by itself.
        child = self.invoke("import os,signal,time;os.kill(os.getppid(),signal.SIGKILL);time.sleep(0.1)")
        child.release()
        self.assertEqual(child.process.wait(timeout=3), -signal.SIGKILL)
        with self.assertRaisesRegex(AssertionError, "without a complete receipt"):
            child.read_status()

    def test_signal_forwarding_preserves_wrapper_final_receipt(self):
        script = "import signal,time;signal.signal(signal.SIGINT,signal.SIG_IGN);signal.signal(signal.SIGTERM,signal.SIG_IGN);print('ready',flush=True);time.sleep(30)"
        child = self.invoke(script)
        child.release()
        self.assertEqual(child.process.stdout.readline(), b"ready\n")
        child.process.send_signal(signal.SIGINT)
        child.process.send_signal(signal.SIGTERM)
        self.assertIsNone(child.process.poll())
        child.process.send_signal(signal.SIGUSR1)
        self.assert_final(child, -signal.SIGKILL, True)
        self.assertEqual(child.process.wait(timeout=3), 0)

    def test_cancel_reaches_owned_root_after_it_joins_wrapper_group(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "joined-wrapper-group"
            script = (
                "import os,pathlib,signal,time\n"
                "for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGUSR1):\n"
                " signal.signal(sig,signal.SIG_IGN)\n"
                "os.setpgid(0,os.getppid())\n"
                "os.close(1);os.close(2)\n"
                f"pathlib.Path({str(marker)!r}).write_text('joined')\n"
                # A finite rescue lifetime makes the pre-fix failure bounded.
                "time.sleep(3)\n"
                "raise SystemExit(42)\n"
            )
            started = time.monotonic()
            result = run_bounded(
                [sys.executable, "-I", "-S", "-c", script], cwd=directory,
                timeout_seconds=4, signal_grace_seconds=0.05,
                cancel_requested=marker.exists,
            )
            self.assertTrue(marker.exists(), "target did not enter the adversarial group")
            self.assertTrue(result.cancelled)
            self.assertEqual(result.exit_code, -signal.SIGKILL)
            self.assertTrue(result.termination_confirmed)
            self.assertFalse(result.unaccounted_descendants)
            self.assertLess(time.monotonic() - started, 2)

    def test_stopped_wrapper_cannot_hold_cancellation_open(self):
        for close_output in (False, True):
            with self.subTest(close_output=close_output), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                ready, release, finished = [root / name for name in ("ready", "release", "finished")]
                script = (
                    "import os,pathlib,signal,time\n"
                    "for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGUSR1):\n"
                    " signal.signal(sig,signal.SIG_IGN)\n"
                    # A pidfd makes the finite rescue safe even after the
                    # original helper has died and its numeric PID was reused.
                    "parent=os.pidfd_open(os.getppid())\n"
                    "signal.pidfd_send_signal(parent,signal.SIGSTOP)\n"
                    + ("os.close(1);os.close(2)\n" if close_output else "")
                    + f"pathlib.Path({str(ready)!r}).write_text('stopped')\n"
                    + f"release=pathlib.Path({str(release)!r})\n"
                    "deadline=time.monotonic()+3\n"
                    "while not release.exists() and time.monotonic()<deadline: time.sleep(.01)\n"
                    + f"pathlib.Path({str(finished)!r}).write_text('finished')\n"
                    "try: signal.pidfd_send_signal(parent,signal.SIGCONT)\n"
                    "except ProcessLookupError: pass\n"
                    "os.close(parent)\n"
                )
                started = time.monotonic()
                try:
                    result = run_bounded(
                        [sys.executable, "-I", "-S", "-c", script], cwd=directory,
                        timeout_seconds=4, signal_grace_seconds=.05,
                        cancel_requested=ready.exists,
                    )
                    self.assertTrue(ready.exists())
                    self.assertTrue(result.cancelled)
                    self.assertFalse(result.termination_confirmed)
                    self.assertTrue(result.unaccounted_descendants)
                    self.assertIsNone(result.exit_code)
                    self.assertFalse(finished.exists(), "runner waited for the fixture rescue")
                    self.assertLess(time.monotonic() - started, 2)
                finally:
                    release.touch()
                    deadline = time.monotonic() + 5
                    while not finished.exists() and time.monotonic() < deadline:
                        time.sleep(.01)
                    self.assertTrue(finished.exists(), "synthetic target did not finish")


class CallbackOutcomeTests(unittest.TestCase):
    def test_invalid_timing_never_releases_a_target(self):
        for field in ("timeout_seconds", "signal_grace_seconds"):
            for value in (float("nan"), float("inf"), -1, True):
                with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as directory:
                    marker = Path(directory) / "must-not-run"
                    with self.assertRaises(ProcessBoundaryError):
                        run_bounded([sys.executable, "-I", "-S", "-c",
                            f"from pathlib import Path;Path({str(marker)!r}).touch()"],
                            cwd=directory, **{field: value})
                    self.assertFalse(marker.exists())

    def test_predispatch_callback_failure_keeps_not_sent(self):
        for code in ("fixture_callback", "cancel_pending"):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                marker = Path(directory) / "must-not-run"

                def fail(_receipt):
                    raise TaskAlongError(code, "Synthetic callback failure")

                with self.assertRaises(ProcessBoundaryError) as caught:
                    run_bounded([sys.executable, "-I", "-S", "-c",
                        f"from pathlib import Path;Path({str(marker)!r}).touch()"],
                        cwd=directory, on_spawn=fail, signal_grace_seconds=.05)
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(caught.exception.effect_outcome, "not_sent")
                result = caught.exception.process_result
                self.assertIsNotNone(result)
                self.assertTrue(result.termination_confirmed)
                self.assertTrue(result.group_termination_confirmed)
                self.assertFalse(result.unaccounted_descendants)
                self.assertIsNone(result.exit_code)
                self.assertFalse(marker.exists())

    def test_callback_after_dispatch_cannot_claim_not_sent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release, finished = root / "release", root / "finished"
            script = (
                "import os,pathlib,time\n"
                "r,w=os.pipe();pid=os.fork()\n"
                "if pid==0:\n"
                " os.close(r);os.setsid()\n"
                " null=os.open(os.devnull,os.O_RDWR)\n"
                " for fd in (0,1,2): os.dup2(null,fd)\n"
                " os.close(null);os.write(w,b'1');os.close(w)\n"
                + f" release=pathlib.Path({str(release)!r})\n"
                " deadline=time.monotonic()+5\n"
                " while not release.exists() and time.monotonic()<deadline: time.sleep(.01)\n"
                + f" pathlib.Path({str(finished)!r}).write_text('finished')\n"
                " os._exit(0)\n"
                "os.close(w);assert os.read(r,1)==b'1';os.close(r)\n"
                "print('callback',flush=True);time.sleep(5)\n"
            )

            def fail(_line):
                raise TaskAlongError("fixture_callback", "Synthetic callback failure")

            try:
                with self.assertRaises(ProcessBoundaryError) as caught:
                    run_bounded([sys.executable, "-I", "-S", "-c", script],
                        cwd=directory, on_stdout_line=fail, timeout_seconds=3,
                        signal_grace_seconds=.05)
                self.assertEqual(caught.exception.effect_outcome, "uncertain")
                self.assertFalse(finished.exists())
            finally:
                release.touch()
                deadline = time.monotonic() + 5
                while not finished.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(finished.exists())


@unittest.skipIf(sys.platform == "linux", "non-Linux refusal")
class UnsupportedLifetimeTests(unittest.TestCase):
    def test_non_linux_helper_never_releases_target(self):
        child = LifetimeChild([sys.executable, "-I", "-S", "-c", "raise SystemExit(99)"])
        self.addCleanup(child.close)
        self.assertEqual(child.read_status(), {"protocol_version": 2, "ready": False, "error": "lifetime_unsupported"})
        self.assertEqual(child.process.wait(timeout=3), 125)


READY = {"protocol_version":2,"ready":True}
CLOSED = {"protocol_version":2,"dispatch_state":"not_released","root_exit_code":None,
          "descendants_stopped":True,"root_pid":None,"root_pgid":None}
STARTED = {"protocol_version":2,"dispatch_state":"started","root_exit_code":-2,
           "descendants_stopped":True,"root_pid":12345,"root_pgid":12345}

def frames(*values):
    return b''.join(json.dumps(x).encode()+b'\n' for x in values)

class LinuxStatusProtocolTests(unittest.TestCase):
    @contextmanager
    def tracker(self, raw, *, eof=True):
        reader,writer=os.pipe()
        tracker=_LinuxTracker(reader)
        try:
            os.write(writer,raw)
            if eof:
                os.close(writer);writer=-1
            tracker.poll()
            yield tracker
        finally:
            if writer!=-1:os.close(writer)
            tracker.close()

    def test_valid_closed_gate_needs_owned_release_wrapper_and_complete_channel(self):
        with self.tracker(frames(READY,CLOSED)) as tracker:
            self.assertFalse(tracker.failed)
            self.assertEqual(tracker.dispatch_state,'not_released')
            self.assertIsNone(tracker.root_exit_code)
            self.assertIsNone(tracker.root_pgid)
            self.assertTrue(tracker.not_released_confirmed(gate_release_attempted=False,wrapper_returncode=0,wrapper_group_ceased=True))
            for kwargs in ({'gate_release_attempted':True},{'gate_release_attempted':None},
                           {'wrapper_returncode':None},{'wrapper_returncode':-9},{'wrapper_returncode':125},
                           {'wrapper_returncode':False},{'wrapper_group_ceased':False}):
                base={'gate_release_attempted':False,'wrapper_returncode':0,'wrapper_group_ceased':True}
                self.assertFalse(tracker.not_released_confirmed(**(base|kwargs)))
        with self.tracker(frames(READY,CLOSED),eof=False) as tracker:
            self.assertFalse(tracker.not_released_confirmed(gate_release_attempted=False,wrapper_returncode=0,wrapper_group_ceased=True))

    def test_started_terminal_retains_exact_target_and_group_semantics(self):
        with self.tracker(frames(READY,STARTED)) as tracker:
            self.assertFalse(tracker.failed)
            self.assertEqual(tracker.dispatch_state,'started')
            self.assertEqual(tracker.root_exit_code,-2)
            self.assertEqual(tracker.root_pgid,12345)
            self.assertFalse(tracker.active)
            self.assertFalse(tracker.not_released_confirmed(gate_release_attempted=False,wrapper_returncode=0,wrapper_group_ceased=True))
        with self.tracker(frames(READY,STARTED|{'descendants_stopped':False})) as tracker:
            self.assertFalse(tracker.failed)
            self.assertTrue(tracker.active)

    def test_malformed_missing_mixed_or_postterminal_data_cannot_prove_cleanup(self):
        cases=[frames(CLOSED),frames(READY),frames(READY,READY,CLOSED),frames(READY,CLOSED,CLOSED),
            frames(READY,CLOSED,READY),frames({'ready':True},CLOSED),frames(READY|{'protocol_version':1},CLOSED),
            frames(READY,CLOSED|{'protocol_version':True}),frames(READY,CLOSED|{'unexpected':True}),
            frames(READY,CLOSED|{'error':'dispatch_failed'}),frames(READY,CLOSED|{'root_pid':12345}),
            frames(READY,CLOSED|{'root_exit_code':0}),frames(READY,CLOSED|{'descendants_stopped':1}),
            frames(READY,CLOSED|{'descendants_stopped':False}),frames(READY,STARTED|{'root_pid':None}),
            frames(READY,STARTED|{'root_pgid':54321}),frames(READY,STARTED|{'root_exit_code':True}),
            frames(READY,STARTED|{'root_pid':True}),frames(READY,STARTED|{'root_exit_code':256}),
            frames(READY,CLOSED)[:-1],frames(READY,CLOSED)+b'garbage',frames(READY)+b'['*4100,
            frames(READY)+b'{"protocol_version":2,"protocol_version":2,"ready":true}\n',
            frames(READY)+b'NaN\n',frames(READY)+b'\xff\n',frames(READY,[]),frames(READY,CLOSED|{'dispatch_state':[]})]
        for index,raw in enumerate(cases):
            with self.subTest(index=index),self.tracker(raw) as tracker:
                self.assertTrue(tracker.failed)
                self.assertFalse(tracker.not_released_confirmed(gate_release_attempted=False,wrapper_returncode=0,wrapper_group_ceased=True))


if __name__ == "__main__":
    unittest.main()
