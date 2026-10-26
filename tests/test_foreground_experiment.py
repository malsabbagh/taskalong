"""Actual bounded Darwin processes; no vendor CLI, authentication or inference."""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from taskalong import process
from taskalong.experimental_process import FOREGROUND_EXPERIMENT, run_foreground_experiment


class ForegroundExperimentTests(unittest.TestCase):
    def invoke(self, code, root, **options):
        return run_foreground_experiment([sys.executable, '-c', code], cwd=root,
            mode=FOREGROUND_EXPERIMENT, timeout_seconds=2, max_output_bytes=8192,
            signal_grace_seconds=.05, **options)

    def assert_experimental(self, result):
        self.assertEqual(result.mode, FOREGROUND_EXPERIMENT)
        self.assertFalse(result.termination_confirmed)
        self.assertEqual(result.descendant_cessation, 'unknown')
        for field in ('production_dispatch_allowed', 'workspace_reuse_allowed', 'acceptance_allowed'):
            self.assertFalse(result.to_dict()[field])

    def test_explicit_mode_and_platform_refuse_before_launch(self):
        with patch.object(process.subprocess, 'Popen') as spawn:
            with self.assertRaises(process.ProcessBoundaryError) as caught:
                run_foreground_experiment([sys.executable, '-c', 'pass'], cwd='.', mode='production')
            self.assertEqual(caught.exception.effect_outcome, 'not_sent')
            with patch('taskalong.experimental_process.sys.platform', 'linux'):
                with self.assertRaises(process.ProcessBoundaryError) as caught:
                    run_foreground_experiment([sys.executable, '-c', 'pass'], cwd='.',
                                             mode=FOREGROUND_EXPERIMENT)
                self.assertEqual(caught.exception.effect_outcome, 'not_sent')
            spawn.assert_not_called()

    def test_default_process_result_keeps_its_existing_shape(self):
        with tempfile.TemporaryDirectory() as root:
            result = process.run_bounded([sys.executable, '-c', "print('ordinary')"], cwd=root,
                                         timeout_seconds=2, max_output_bytes=8192)
        self.assertTrue(result.termination_confirmed)
        self.assertEqual(set(result.to_dict()), {
            'exit_code', 'stdout', 'stderr', 'timed_out', 'cancelled', 'termination_confirmed',
            'group_termination_confirmed', 'output_limited', 'receipt', 'duration_ms',
            'output_bytes', 'lifetime_backend', 'unaccounted_descendants', 'protocol_error'})

    @unittest.skipUnless(sys.platform == 'darwin', 'Darwin foreground experiment processes')
    def test_fork_wait_rapid_exit_and_session_escape_keep_descendants_unknown(self):
        cases = {
            'no_fork': "print('done')",
            'fork_wait': "import os,time\np=os.fork()\nif p==0:time.sleep(.05);os._exit(0)\nos.waitpid(p,0)\nprint('done')",
            'rapid_exit': "import os,time\np=os.fork()\nif p:os._exit(0)\ntime.sleep(.1)\nos._exit(0)",
            # The escaped child is finite, closes inherited pipes, and writes a
            # completion marker before its deterministic exit. No PID is saved
            # or signalled to manufacture a cleanup witness.
            'session_escape': "import os,time,pathlib\np=os.fork()\nif p:os.waitpid(p,0);os._exit(0)\nos.setsid()\np=os.fork()\nif p:os._exit(0)\nfor fd in (0,1,2):os.close(fd)\ntime.sleep(.15)\npathlib.Path('escaped-finished').touch()\nos._exit(0)",
        }
        for name, code in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                try:
                    result = self.invoke(code, root)
                    self.assertEqual(result.root_exit_code, 0)
                    self.assertTrue(result.root_exit_observed)
                    self.assertEqual(result.fork_observed, name != 'no_fork')
                    self.assertEqual(result.tracking_errors, ())
                    self.assert_experimental(result)
                    if name in ('no_fork', 'fork_wait'):
                        self.assertTrue(result.group_termination_confirmed)
                finally:
                    if name == 'session_escape':
                        deadline = time.monotonic() + 2
                        while not (root / 'escaped-finished').exists() and time.monotonic() < deadline:
                            time.sleep(.01)
                        self.assertTrue((root / 'escaped-finished').exists())

    @unittest.skipUnless(sys.platform == 'darwin', 'Darwin foreground experiment processes')
    def test_timeout_cancellation_and_output_limit_use_owned_cleanup(self):
        code = ("import os,signal,time\nsignal.signal(signal.SIGINT,signal.SIG_IGN)\n"
                "p=os.fork()\nif p==0:time.sleep(2);os._exit(0)\n"
                "print('ready',flush=True)\ntime.sleep(2)")
        for case in ('timeout', 'cancel', 'output_limit'):
            ready = []
            with self.subTest(case=case), tempfile.TemporaryDirectory() as root:
                options = {'timeout_seconds': .15 if case == 'timeout' else 2,
                           'max_output_bytes': 64 if case == 'output_limit' else 8192}
                selected = code if case != 'output_limit' else code.replace(
                    "print('ready',flush=True)", "print('x'*200,flush=True)")
                result = run_foreground_experiment([sys.executable, '-c', selected], cwd=root,
                    mode=FOREGROUND_EXPERIMENT, signal_grace_seconds=.05,
                    on_stdout_line=ready.append,
                    cancel_requested=(lambda: bool(ready)) if case == 'cancel' else None, **options)
                self.assertTrue(result.root_exit_observed)
                self.assertTrue(result.fork_observed)
                self.assertTrue(result.group_termination_confirmed)
                self.assertTrue(getattr(result, {'timeout': 'timed_out', 'cancel': 'cancelled',
                                                'output_limit': 'output_limited'}[case]))
                self.assertLess(result.duration_ms, 2000)
                self.assert_experimental(result)

    @unittest.skipUnless(sys.platform == 'darwin', 'Darwin foreground experiment tracking faults')
    def test_tracking_failure_stays_separate_and_never_releases_a_refused_gate(self):
        original = process._DescendantTracker

        class Refuse(original):
            def __init__(self, pid):
                super().__init__(pid)
                self._tracking_error('registration')

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.object(process, '_DescendantTracker', Refuse):
                result = self.invoke("from pathlib import Path;Path('started').touch()", root)
            self.assertFalse((root / 'started').exists())
            self.assertFalse(result.root_exit_observed)
            self.assertFalse(result.fork_observed)
            self.assertIn('registration', result.tracking_errors)
            self.assertEqual(result.failure_code, 'runtime_lifecycle_unsupported')
            self.assertEqual(result.effect_outcome, 'not_sent')
            self.assert_experimental(result)

        class PollFailure(original):
            def poll(self):
                super().poll()
                self._tracking_error('poll')

        with tempfile.TemporaryDirectory() as root, patch.object(process, '_DescendantTracker', PollFailure):
            result = self.invoke("print('done')", root)
        self.assertEqual(result.root_exit_code, 0)
        self.assertFalse(result.fork_observed)
        self.assertIn('poll', result.tracking_errors)
        self.assert_experimental(result)


if __name__ == '__main__':
    unittest.main()
