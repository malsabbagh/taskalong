"""Real bounded stdlib children and private chunk sinks; no provider dispatch."""
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from taskalong import process
from taskalong.experimental_process import FOREGROUND_EXPERIMENT, run_foreground_experiment
from taskalong.local_provider_capture import PrivateCapture, read_capture


_LEGACY_RESULT_FIELDS = {
    'exit_code', 'stdout', 'stderr', 'timed_out', 'cancelled', 'termination_confirmed',
    'group_termination_confirmed', 'output_limited', 'receipt', 'duration_ms',
    'output_bytes', 'lifetime_backend', 'unaccounted_descendants', 'protocol_error',
}


@unittest.skipUnless(os.name == 'posix', 'bounded POSIX stdlib children')
class LocalProviderStreamingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def capture(self, maximum=262144):
        sink = PrivateCapture(self.root / 'capture', max_output_bytes=maximum)
        self.addCleanup(sink.close)
        return sink

    def invoke(self, code, *, foreground=False, **options):
        settings = dict(cwd=self.root, timeout_seconds=3, max_output_bytes=262144,
                        signal_grace_seconds=.05)
        settings.update(options)
        argv = [sys.executable, '-I', '-S', '-c', code]
        if foreground:
            return run_foreground_experiment(argv, mode=FOREGROUND_EXPERIMENT, **settings)
        return process.run_bounded(argv, **settings)

    def wait_for_marker(self, name):
        deadline = time.monotonic() + 1
        while not (self.root / name).exists():
            if time.monotonic() >= deadline:
                self.fail('synthetic child did not reach its output marker')
            time.sleep(.005)

    def assert_reaped(self, child):
        self.assertIsNotNone(child.poll())
        # Only the exact Popen child created by this test is inspected. A saved
        # identity is never used as authority to signal or clean up a process.
        with self.assertRaises(ChildProcessError):
            os.waitpid(child.pid, os.WNOHANG)

    def handshake(self, *, foreground=False):
        sink = self.capture()
        secret = b'sk-syntheticstreamingsecret12345'
        expected = {
            'stdout': b'\x00\xffOUT:' + secret + b'O' * 70000,
            'stderr': b'\xfeERR:' + b'E' * 70000,
        }
        seen = {stream: bytearray() for stream in expected}
        chunks = []
        live_snapshots = []
        code = (
            "import os,time\nfrom pathlib import Path\n"
            "Path('target-pid').write_text(str(os.getpid()))\n"
            "def emit(fd,data):\n"
            "    while data:data=data[os.write(fd,data):]\n"
            f"emit(1,b'\\x00\\xffOUT:'+{secret!r}+b'O'*70000)\n"
            "emit(2,b'\\xfeERR:'+b'E'*70000)\n"
            "deadline=time.monotonic()+2\n"
            "while not Path('release').exists():\n"
            "    if time.monotonic()>deadline:os._exit(77)\n"
            "    time.sleep(.005)\n"
            "Path('completed').touch()\n"
            "emit(1,b'OUT-END');emit(2,b'ERR-END')\n"
        )
        def retain_and_release(stream, chunk):
            self.assertIn(stream, ('stdout', 'stderr'))
            self.assertIs(type(chunk), bytes)
            self.assertTrue(chunk)
            chunks.append((stream, chunk))
            seen[stream].extend(chunk)
            sink.write(stream, chunk)
            if not (self.root / 'release').exists() and all(len(seen[s]) == len(expected[s]) for s in expected):
                self.assertFalse((self.root / 'completed').exists())
                os.kill(int((self.root / 'target-pid').read_text()), 0)
                sink.checkpoint()
                snapshot = read_capture(self.root / 'capture')
                self.assertFalse(snapshot['byte_closure'])
                self.assertEqual(snapshot['status'], 'incomplete')
                self.assertEqual(sum(s['checkpointed_bytes'] for s in snapshot['streams'].values()),
                                 sum(map(len, expected.values())))
                live_snapshots.append(snapshot)
                # The child cannot produce completion or its final bytes until
                # this raw callback runs and durable readback has succeeded.
                (self.root / 'release').touch()
        result = self.invoke(code, foreground=foreground, _on_output_chunk=retain_and_release,
                             secrets=(secret,))
        self.assertTrue((self.root / 'completed').exists())
        self.assertEqual(len(live_snapshots), 1)
        self.assertEqual(result.root_exit_code if foreground else result.exit_code, 0)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.output_limited)
        self.assertFalse(result.cancelled)
        self.assertGreaterEqual(len(chunks), 4)
        self.assertEqual(bytes(seen['stdout']), expected['stdout'] + b'OUT-END')
        self.assertEqual(bytes(seen['stderr']), expected['stderr'] + b'ERR-END')
        self.assertNotIn(secret, result.stdout)
        self.assertIn(b'[REDACTED]', result.stdout)
        self.assertEqual(result.stderr, expected['stderr'] + b'ERR-END')
        closure = sink.finalize()
        self.assertEqual(closure, read_capture(self.root / 'capture'))
        self.assertEqual(closure['status'], 'closed')
        self.assertTrue(closure['byte_closure'])
        self.assertEqual(result.output_bytes, sum(len(data) for data in seen.values()))
        for stream, data in seen.items():
            ref = closure['streams'][stream]
            self.assertEqual((self.root / 'capture' / ref['path']).read_bytes(), bytes(data))
            self.assertEqual(ref['sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(ref['retained_bytes'], len(data))
            self.assertEqual(ref['observed_bytes'], len(data))
        return result

    def test_raw_stdout_and_stderr_stream_while_child_waits_for_release(self):
        result = self.handshake()
        self.assertTrue(result.termination_confirmed)
        self.assertTrue(result.group_termination_confirmed)
        self.assertFalse(result.unaccounted_descendants)
        self.assertEqual(set(result.to_dict()), _LEGACY_RESULT_FIELDS)

    def test_explicit_stream_only_mode_keeps_finite_raw_evidence_without_buffers(self):
        sink = self.capture()
        result = self.invoke("import os;os.write(1,b'x'*100000);os.write(2,b'y'*100000)",
                             _on_output_chunk=sink.write, _retain_output=False)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'')
        self.assertEqual(result.output_bytes, 200000)
        self.assertFalse(result.output_limited)
        closure = sink.finalize()
        self.assertEqual(sum(v['retained_bytes'] for v in closure['streams'].values()), 200000)
        self.assertTrue(closure['byte_closure'])

    def test_stream_only_overflow_and_invalid_sink_cannot_become_success(self):
        for options in ({'_retain_output': False}, {'_retain_output': 0}):
            with self.assertRaises(process.ProcessBoundaryError):
                self.invoke("pass", **options)
        sink = self.capture(maximum=4096)
        result = self.invoke("import os;os.write(1,b'x'*100000)", max_output_bytes=4096,
                             _on_output_chunk=sink.write, _retain_output=False)
        self.assertTrue(result.output_limited)
        self.assertGreater(result.output_bytes, 4096)
        self.assertEqual(result.stdout, b'')
        closure = sink.finalize()
        self.assertEqual(closure['streams']['stdout']['retained_bytes'], 4096)
        self.assertEqual(closure['status'], 'limited')

    @unittest.skipUnless(sys.platform == 'darwin', 'explicit Darwin foreground passthrough')
    def test_foreground_passes_live_raw_chunks_without_promoting_cessation(self):
        result = self.handshake(foreground=True)
        self.assertEqual(result.mode, FOREGROUND_EXPERIMENT)
        self.assertIsNone(result.failure_code)
        self.assertTrue(result.root_exit_observed)
        self.assertTrue(result.group_termination_confirmed)
        self.assertFalse(result.termination_confirmed)
        self.assertEqual(result.descendant_cessation, 'unknown')
        for key in ('production_dispatch_allowed', 'workspace_reuse_allowed', 'acceptance_allowed'):
            self.assertFalse(result.to_dict()[key])

    def failing_child(self, *, foreground=False, force_uncertain_group=False):
        code = (
            "import os,signal\nfrom pathlib import Path\n"
            "signal.signal(signal.SIGINT,signal.SIG_IGN)\n"
            "with open('dispatches','ab') as f:f.write(b'one\\n')\n"
            "Path('target-pid').write_text(str(os.getpid()))\n"
            "os.write(1,b'ready');os.write(2,b'diagnostic')\n"
            "Path('output-ready').touch()\n"
            "while True:signal.pause()\n"
        )
        class SinkFailure(RuntimeError):
            code = 'synthetic_sink_failed'
        calls = []
        def fail(stream, chunk):
            calls.append((stream, chunk))
            # Both small writes fit in the pipes. Wait for the child's marker
            # before failing, so cancellation cannot race its second write.
            self.wait_for_marker('output-ready')
            raise SinkFailure('synthetic private sink error')
        real_popen = process.subprocess.Popen
        children = []
        def spawn(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child
        with patch.object(process.subprocess, 'Popen', side_effect=spawn) as dispatch:
            if force_uncertain_group:
                group_patch = patch.object(process, '_group_exists', return_value=True)
            else:
                group_patch = patch.object(process, '_group_exists', wraps=process._group_exists)
            with group_patch:
                if foreground:
                    result = self.invoke(code, foreground=True, _on_output_chunk=fail)
                    failure = result
                else:
                    with self.assertRaises(process.ProcessBoundaryError) as caught:
                        self.invoke(code, _on_output_chunk=fail)
                    failure = caught.exception
                    result = failure.process_result
            self.assertEqual(dispatch.call_count, 1)
        self.assertEqual(len(children), 1)
        self.assert_reaped(children[0])
        self.assertEqual((self.root / 'dispatches').read_bytes(), b'one\n')
        self.assertEqual(len(calls), 1)  # drain, but never replay the failed sink
        self.assertIsNotNone(result)
        self.assertEqual(result.stdout, b'ready')
        self.assertEqual(result.stderr, b'diagnostic')
        self.assertEqual(result.output_bytes, len(b'readydiagnostic'))
        self.assertFalse(result.timed_out)
        self.assertFalse(result.output_limited)
        self.assertEqual(failure.effect_outcome, 'uncertain')
        self.assertEqual(failure.failure_code if foreground else failure.code, 'synthetic_sink_failed')
        self.assertEqual(result.receipt.pid, children[0].pid)
        self.assertIsNotNone(result.root_exit_code if foreground else result.exit_code)
        # Read-only absence of the synthetic target accompanies exact Popen
        # reaping; no extra target is dispatched as compensation or retry.
        with self.assertRaises(ProcessLookupError):
            os.kill(int((self.root / 'target-pid').read_text()), 0)
        return result

    def test_sink_failure_stops_and_reaps_owned_child_without_replay_or_retry(self):
        result = self.failing_child()
        self.assertTrue(result.termination_confirmed)
        self.assertTrue(result.group_termination_confirmed)
        self.assertFalse(result.unaccounted_descendants)

    def test_sink_failure_preserves_unconfirmed_group_observation(self):
        result = self.failing_child(force_uncertain_group=True)
        self.assertFalse(result.group_termination_confirmed)
        self.assertFalse(result.termination_confirmed)

    @unittest.skipUnless(sys.platform == 'darwin', 'explicit Darwin foreground failure passthrough')
    def test_foreground_sink_failure_returns_uncertainty_without_second_dispatch(self):
        result = self.failing_child(foreground=True)
        self.assertEqual(result.descendant_cessation, 'unknown')
        self.assertFalse(result.termination_confirmed)
        for key in ('production_dispatch_allowed', 'workspace_reuse_allowed', 'acceptance_allowed'):
            self.assertFalse(result.to_dict()[key])

    def test_raw_capture_continues_after_stdout_decoder_callback_fails(self):
        sink = self.capture()
        malformed = b'{malformed-json}\n'
        trailing = b'after-decoder\n'
        diagnostic = b'buffered diagnostic\xff\n' * 100
        raw = {'stdout': bytearray(), 'stderr': bytearray()}
        decoded = []
        chunks_after_failure = []
        decoder_failed = False
        code = (
            "import os,signal,time\nfrom pathlib import Path\n"
            "signal.signal(signal.SIGINT,signal.SIG_IGN)\n"
            "with open('dispatches','ab') as f:f.write(b'one\\n')\n"
            f"os.write(1,{malformed!r})\n"
            "deadline=time.monotonic()+2\n"
            "while not Path('decoder-entered').exists():\n"
            "    if time.monotonic()>deadline:os._exit(77)\n"
            "    time.sleep(.005)\n"
            f"os.write(2,{diagnostic!r});os.write(1,{trailing!r})\n"
            "Path('output-ready').touch()\n"
            "while True:signal.pause()\n"
        )
        def retain(stream, chunk):
            raw[stream].extend(chunk)
            sink.write(stream, chunk)
            if decoder_failed:
                chunks_after_failure.append((stream, chunk))
        def decode(line):
            nonlocal decoder_failed
            decoded.append(line)
            # Produce additional pipe bytes only after the decoder has entered.
            # Both writes fit in the pipes while this synchronous callback waits,
            # so they can only reach the raw sink after the decoder has raised.
            (self.root / 'decoder-entered').touch()
            self.wait_for_marker('output-ready')
            decoder_failed = True
            json.loads(line)
        real_popen = process.subprocess.Popen
        children = []
        def spawn(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child
        with patch.object(process.subprocess, 'Popen', side_effect=spawn) as dispatch:
            with self.assertRaises(process.ProcessBoundaryError) as caught:
                self.invoke(code, on_stdout_line=decode, _on_output_chunk=retain)
            self.assertEqual(dispatch.call_count, 1)
        failure = caught.exception
        result = failure.process_result
        self.assertEqual(failure.code, 'process_callback_failed')
        self.assertEqual(failure.effect_outcome, 'uncertain')
        self.assertIsInstance(failure.__cause__, json.JSONDecodeError)
        self.assertEqual(decoded, [malformed.rstrip(b'\n')])
        self.assertEqual(len(children), 1)
        self.assert_reaped(children[0])
        self.assertEqual((self.root / 'dispatches').read_bytes(), b'one\n')
        self.assertIsNotNone(result)
        self.assertTrue(result.termination_confirmed)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.output_limited)
        self.assertEqual(result.stdout, malformed + trailing)
        self.assertEqual(result.stderr, diagnostic)
        self.assertEqual(bytes(raw['stdout']), result.stdout)
        self.assertEqual(bytes(raw['stderr']), result.stderr)
        self.assertTrue(any(stream == 'stderr' for stream, _ in chunks_after_failure))
        self.assertEqual(sum(map(len, raw.values())), result.output_bytes)
        closure = sink.finalize()
        self.assertEqual(closure, read_capture(self.root / 'capture'))
        self.assertTrue(closure['byte_closure'])
        self.assertEqual(closure['status'], 'closed')
        self.assertEqual(sum(ref['retained_bytes'] for ref in closure['streams'].values()),
                         result.output_bytes)
        self.assertEqual(sum(ref['observed_bytes'] for ref in closure['streams'].values()),
                         result.output_bytes)
        for stream, data in raw.items():
            self.assertEqual((self.root / 'capture' / (stream + '.bin')).read_bytes(), bytes(data))
            self.assertEqual(closure['streams'][stream]['sha256'], hashlib.sha256(data).hexdigest())

    def test_output_overflow_retains_combined_capture_prefix_and_reaps_child(self):
        maximum = 48
        sink = self.capture(maximum)
        expected = {'stdout': bytearray(), 'stderr': bytearray()}
        observed = {'stdout': bytearray(), 'stderr': bytearray()}
        chunks = []
        def retain(stream, chunk):
            chunks.append((stream, chunk))
            observed[stream].extend(chunk)
            self.wait_for_marker('output-ready')
            remaining = maximum - sum(map(len, expected.values()))
            expected[stream].extend(chunk[:remaining])
            sink.write(stream, chunk)
        code = (
            "import os,signal\nfrom pathlib import Path\n"
            "signal.signal(signal.SIGINT,signal.SIG_IGN)\n"
            "os.write(1,b'O'*256);os.write(2,b'E'*128)\n"
            "Path('output-ready').touch()\n"
            "while True:signal.pause()\n"
        )
        real_popen = process.subprocess.Popen
        children = []
        def spawn(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child
        with patch.object(process.subprocess, 'Popen', side_effect=spawn) as dispatch:
            result = self.invoke(code, max_output_bytes=maximum, _on_output_chunk=retain)
            self.assertEqual(dispatch.call_count, 1)
        self.assertEqual(len(children), 1)
        self.assert_reaped(children[0])
        self.assertTrue(result.output_limited)
        self.assertTrue(result.termination_confirmed)
        self.assertFalse(result.timed_out)
        self.assertEqual(sum(map(len, expected.values())), maximum)
        self.assertEqual(sum(map(len, observed.values())), 384)
        self.assertEqual(result.output_bytes, 384)
        self.assertTrue(any(len(chunk) > maximum for _, chunk in chunks))
        self.assertEqual(result.stdout, bytes(expected['stdout']))
        self.assertEqual(result.stderr, bytes(expected['stderr']))
        self.assertTrue(sink.limited)
        closure = sink.finalize()
        self.assertEqual(closure['status'], 'limited')
        self.assertTrue(closure['output_limited'])
        self.assertTrue(closure['byte_closure'])
        self.assertEqual(closure, read_capture(self.root / 'capture'))
        for stream in expected:
            self.assertEqual((self.root / 'capture' / (stream + '.bin')).read_bytes(), bytes(expected[stream]))
            self.assertEqual(closure['streams'][stream]['retained_bytes'], len(expected[stream]))
            self.assertEqual(closure['streams'][stream]['observed_bytes'], len(observed[stream]))

    def test_direct_process_result_legacy_fields_and_serialization_are_unchanged(self):
        receipt = process.ProcessReceipt('synthetic', 123, 123, 321, 0, '0' * 64)
        result = process.ProcessResult(0, b'ordinary\xff', b'diagnostic', False, False,
            True, True, False, receipt, 1, 19, 'synthetic-backend', False)
        self.assertEqual({field.name for field in dataclasses.fields(result)}, _LEGACY_RESULT_FIELDS)
        self.assertEqual(set(result.to_dict()), _LEGACY_RESULT_FIELDS)
        self.assertEqual(result.to_dict()['stdout'], 'ordinary\ufffd')
        self.assertEqual(result.to_dict()['stderr'], 'diagnostic')
        self.assertEqual(result.to_dict()['receipt'], receipt.to_dict())
        self.assertNotIn('_on_output_chunk', result.to_dict())
        self.assertIsNone(result.protocol_error)


if __name__ == '__main__':
    unittest.main()
