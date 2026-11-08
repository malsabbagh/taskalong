"""Model-free transport prevention; no test performs a network operation."""
import subprocess
import sys
import tempfile
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from taskalong import muse_experimental as muse
from taskalong.errors import TaskAlongError

class ConnectivityTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.root / 'workspace').mkdir()

    config = {'account_home': '/fixture/home', 'muse_home': '/fixture/data/muse'}

    def test_probe_has_no_credentials_body_redirect_or_retry(self):
        with patch.object(muse.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'401')) as run:
            result = muse._connectivity_preflight(self.config, self.root)
        argv = run.call_args.args[0]
        self.assertEqual(argv[:2], ['/usr/bin/curl', '--disable'])
        self.assertEqual(argv[-1], 'https://api.meta.ai/v1/responses')
        self.assertIn('--tlsv1.2', argv)
        for flag in ['--location', '--retry', '--insecure', '--data', '--header', '--user']:
            self.assertNotIn(flag, argv)
        self.assertEqual(run.call_args.kwargs['timeout'], 6)
        self.assertFalse(result['authenticated'])
        self.assertFalse(result['inference_admission'])

    def test_transport_errors_redirects_and_server_failures_refuse(self):
        for code, status in [(5,b'000'), (60,b'000'), (0,b'302'), (0,b'503'), (0,b'garbage')]:
            with self.subTest(code=code,status=status), patch.object(muse.subprocess,'run',return_value=SimpleNamespace(returncode=code,stdout=status)):
                with self.assertRaises(TaskAlongError) as error:
                    muse._connectivity_preflight(self.config, self.root)
                self.assertEqual(error.exception.code, 'provider_transport_unreachable' if code else 'provider_transport_http_rejected')
                receipt = json.loads((self.root/'connectivity.json').read_text())
                self.assertEqual(receipt, error.exception.observation)
                (self.root/'connectivity.json').unlink()

    def test_timeout_and_missing_probe_refuse(self):
        for error in [OSError(), subprocess.TimeoutExpired('curl', 6)]:
            with patch.object(muse.subprocess,'run',side_effect=error):
                with self.assertRaises(TaskAlongError) as caught:
                    muse._connectivity_preflight(self.config, self.root)
                self.assertEqual(caught.exception.code, "provider_transport_timeout" if isinstance(error, subprocess.TimeoutExpired) else "provider_transport_probe_unavailable")
                (self.root/"connectivity.json").unlink()

    def test_http_rejections_preserve_status_without_admission(self):
        for status in [403, 429]:
            with patch.object(muse.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=str(status).encode())):
                with self.assertRaises(TaskAlongError) as error:
                    muse._connectivity_preflight(self.config, self.root)
            self.assertEqual(error.exception.observation['http_status'], status)
            self.assertIn(str(status), error.exception.message)
            self.assertFalse(error.exception.observation['inference_admission'])
            (self.root/'connectivity.json').unlink()

    def test_curl_deadline_is_timeout_not_connection_failure(self):
        with patch.object(muse.subprocess, 'run', return_value=SimpleNamespace(returncode=28, stdout=b'000')):
            with self.assertRaises(TaskAlongError) as error:
                muse._connectivity_preflight(self.config, self.root)
        self.assertEqual(error.exception.code, 'provider_transport_timeout')
        self.assertIsNone(error.exception.observation['http_status'])

    def test_receipt_failure_retains_sanitized_probe_observation(self):
        for status in (b'401', b'429'):
            for failure in (OSError('private storage detail'), TaskAlongError('artifact_io', 'private storage detail')):
                with self.subTest(status=status, failure=type(failure).__name__), patch.object(muse.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=status)), patch.object(muse.pilot, '_write', side_effect=failure):
                    with self.assertRaises(muse._ConnectivityFailure) as error:
                        muse._connectivity_preflight(self.config, self.root)
                    self.assertEqual(error.exception.code, 'provider_transport_evidence_unavailable')
                    self.assertEqual(error.exception.effect_outcome, 'not_sent')
                    self.assertEqual(error.exception.observation['http_status'], int(status))
                    self.assertEqual(error.exception.observation['outcome'], 'reachable' if status == b'401' else 'provider_transport_http_rejected')
                    self.assertFalse(error.exception.observation['evidence_retained'])
                    self.assertNotIn('private storage detail', error.exception.message)

    def test_real_subprocess_timeout_kills_and_reaps_direct_child_without_network(self):
        real_run, real_popen = subprocess.run, subprocess.Popen
        children = []
        class TrackingPopen(real_popen):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                children.append(self)
        def sleeping_stub(command, **options):
            self.assertEqual(command[0], '/usr/bin/curl')
            self.assertEqual(options['timeout'], 6)
            # Replace the target before Popen: no curl or network operation.
            return real_run([sys.executable, '-I', '-c', 'import time; time.sleep(30)'], **(options | {'timeout': .1}))
        try:
            with patch.object(muse.subprocess, 'run', side_effect=sleeping_stub), patch.object(subprocess, 'Popen', TrackingPopen):
                with self.assertRaises(muse._ConnectivityFailure) as error:
                    muse._connectivity_preflight(self.config, self.root)
            self.assertEqual(error.exception.code, 'provider_transport_timeout')
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].returncode)
            self.assertEqual(children[0].wait(timeout=1), children[0].returncode)
            self.assertEqual(json.loads((self.root/'connectivity.json').read_text())['outcome'], 'provider_transport_timeout')
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=1)

    def test_reachable_statuses_are_only_unauthenticated_transport_observations(self):
        for status in (b'200', b'401', b'405'):
            with self.subTest(status=status), patch.object(muse.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=status)) as run:
                result = muse._connectivity_preflight(self.config, self.root)
            command = run.call_args.args[0]
            self.assertEqual(command[command.index('--output')+1], '/dev/null')
            self.assertEqual(result['outcome'], 'reachable')
            self.assertFalse(result['authenticated'])
            self.assertFalse(result['inference_admission'])
            (self.root/'connectivity.json').unlink()
