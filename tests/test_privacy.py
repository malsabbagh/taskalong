"""Synthetic privacy canaries at the actual bounded subprocess boundary."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from taskalong.process import minimal_environment, run_bounded


class PrivacyTests(unittest.TestCase):
    def test_split_secret_does_not_escape_captured_output(self):
        secret = "synthetic-secret-for-split-output-test"
        program = "import os,time; os.write(1,b'synthetic-secret-for-'); time.sleep(.05); os.write(1,b'split-output-test'); os.write(2,b'Bearer SYNTHETIC_TOKEN_FOR_TEST')"
        with tempfile.TemporaryDirectory() as directory:
            result = run_bounded([sys.executable, "-c", program], cwd=directory, timeout_seconds=5, secrets=[secret])
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.termination_confirmed)
        self.assertNotIn(secret.encode(), result.stdout + result.stderr)
        self.assertNotIn(b"SYNTHETIC_TOKEN_FOR_TEST", result.stdout + result.stderr)
        self.assertIn(b"[REDACTED]", result.stdout)

    def test_check_environment_contains_no_auth_or_source_import_override(self):
        from unittest.mock import patch
        with patch.dict("os.environ", {"GH_TOKEN": "synthetic-token", "OPENAI_API_KEY": "synthetic-token", "PYTHONPATH": "/synthetic/private/source", "GIT_SSH_COMMAND": "synthetic-helper", "AWS_SECRET_ACCESS_KEY": "synthetic-token"}):
            env = minimal_environment()
        for key in ("GH_TOKEN", "OPENAI_API_KEY", "PYTHONPATH", "GIT_SSH_COMMAND", "AWS_SECRET_ACCESS_KEY", "HOME"):
            self.assertNotIn(key, env)

    def test_package_directory_has_no_generated_control_state(self):
        import taskalong
        package = Path(taskalong.__file__).parent
        for forbidden in ("state.sqlite", "taskalong.sqlite3", "auth.json", "runs", ".taskalong", "evidence"):
            self.assertFalse((package / forbidden).exists())


if __name__ == "__main__":
    unittest.main()
