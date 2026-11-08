"""Model-free transport prevention; all process calls are synthetic."""
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from taskalong import muse_experimental as muse
from taskalong.errors import TaskAlongError

class ConnectivityTests(unittest.TestCase):
    config = {'account_home': '/fixture/home', 'muse_home': '/fixture/data/muse'}

    def test_probe_has_no_credentials_body_redirect_or_retry(self):
        with patch.object(muse.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'401')) as run:
            result = muse._connectivity_preflight(self.config, Path('/fixture/run'))
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
                    muse._connectivity_preflight(self.config, Path('/fixture/run'))
                self.assertEqual(error.exception.code, 'provider_transport_unreachable')

    def test_timeout_and_missing_probe_refuse(self):
        for error in [OSError(), subprocess.TimeoutExpired('curl', 6)]:
            with patch.object(muse.subprocess,'run',side_effect=error):
                with self.assertRaises(TaskAlongError):
                    muse._connectivity_preflight(self.config, Path('/fixture/run'))
