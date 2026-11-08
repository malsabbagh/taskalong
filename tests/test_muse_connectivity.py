"""Model-free transport prevention; all process calls are synthetic."""
import subprocess
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
