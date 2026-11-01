"""CLI consumes configured cancellation receipts, never implies cessation."""
from contextlib import redirect_stdout
import io
import json
import unittest
from unittest.mock import MagicMock, patch

from taskalong.cli import main


class ConfiguredProviderCLITests(unittest.TestCase):
    def invoke(self, receipt, *, wait=0, observations=()):
        service = MagicMock()
        service.cancel.return_value = receipt
        service.inspect.side_effect = list(observations)
        context = MagicMock()
        context.__enter__.return_value = service
        output = io.StringIO()
        with patch("taskalong.api.RunService", return_value=context), patch("taskalong.cli.time.sleep"), redirect_stdout(output):
            code = main(["--json", "cancel", "synthetic-run", "--key", "synthetic-key",
                         "--expected-revision", "3", "--wait", str(wait)])
        return code, json.loads(output.getvalue()), service

    def test_zero_wait_returns_each_receipt_without_state_key_or_replay(self):
        for status in ("requested", "observation_only", "publication_unknown"):
            with self.subTest(status=status):
                code, value, service = self.invoke({"run_id": "synthetic-run", "status": status})
                self.assertEqual(code, 0)
                self.assertEqual(value["data"]["status"], status)
                service.cancel.assert_called_once()
                service.inspect.assert_not_called()

    def test_wait_keeps_polling_active_configured_owner_until_terminal(self):
        code, value, service = self.invoke({"run_id": "synthetic-run", "status": "requested"}, wait=1,
            observations=({"state": "running"}, {"state": "running"}, {"state": "failed", "remote_usage": "unknown"}))
        self.assertEqual(code, 1)
        self.assertEqual(value["state"], "failed")
        self.assertEqual(service.inspect.call_count, 3)
        service.cancel.assert_called_once()

    def test_uncertain_publication_never_retries_or_waits_as_cancellation_proof(self):
        code, value, service = self.invoke({"status": "publication_unknown"}, wait=1)
        self.assertEqual(code, 0)
        self.assertEqual(value["data"]["status"], "publication_unknown")
        service.inspect.assert_not_called()
