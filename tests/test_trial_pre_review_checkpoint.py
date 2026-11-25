"""Model-free continuation using a positive checkpoint and the installed fixture reviewer."""
import json
import os
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from helpers import ServiceFixture
from taskalong.errors import TaskAlongError
from taskalong.store import Store


class TrialPreReviewCheckpointTests(ServiceFixture, unittest.TestCase):
    def _interrupt_first_verification(self, boundary):
        from test_recovery_regressions import RecoveryRegressions

        specification = RecoveryRegressions.configure_released_review(self)
        run, _ = self.submit(specification)
        first_env, first_marker, _ = RecoveryRegressions.trace_environment(self, "verify")
        with patch.dict(os.environ, first_env):
            self.start(run)
        RecoveryRegressions.wait_file(self, first_marker)
        checkpoint = self.service.inspect(run["run_id"])
        with Store(self.state) as store:
            attempt = store.detail("attempts", checkpoint["attempts"][-1]["attempt_id"])
        env, marker, _ = RecoveryRegressions.trace_environment(self, boundary)

        def verify(expected_revision, *, environment=None):
            return subprocess.run(
                [sys.executable, "-m", "taskalong", "--state-dir", str(self.state),
                 "verify", checkpoint["run_id"], "--key", "offline-checkpoint",
                 "--expected-revision", str(expected_revision), "--json"],
                cwd=self.root, env=environment, capture_output=True, text=True, timeout=15,
            )

        deadline = time.monotonic() + 5
        while True:
            stopped = verify(checkpoint["revision"], environment=env)
            if marker.exists():
                break
            self.assertEqual(stopped.returncode, 4, stopped.stderr + stopped.stdout)
            self.assertEqual(json.loads(stopped.stdout)["errors"][0]["code"], "operation_in_progress")
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.025)
        self.assertEqual(stopped.returncode, -signal.SIGKILL, stopped.stderr + stopped.stdout)
        self.assertTrue(marker.exists())
        return self.service.inspect(checkpoint["run_id"]), attempt, verify

    def test_same_key_continues_only_review_after_positive_pre_review_checkpoint(self):
        stopped, attempt, verify = self._interrupt_first_verification("diff_bytes")
        self.assertEqual(stopped["pending_effect_ids"], [])
        self.assertEqual(len(stopped["evidence_ids"]), 2)
        with Store(self.state) as store:
            before = [store.detail("evidence", eid) for eid in stopped["evidence_ids"]]
        self.assertEqual([record["type"] for record in before], ["scope", "command"])
        self.assertEqual(before[1]["result"], "passed")

        resumed = verify(stopped["revision"])
        self.assertEqual(resumed.returncode, 0, resumed.stderr + resumed.stdout)
        accepted = self.service.inspect(stopped["run_id"])
        self.assertEqual(accepted["state"], "accepted")
        self.assertEqual(accepted["evidence_ids"][:2], stopped["evidence_ids"])
        self.assertEqual(len(accepted["evidence_ids"]), 3)
        self.assertEqual(accepted["attempts"], stopped["attempts"])
        self.assertEqual(len(self.invocations()), 1)
        with Store(self.state) as store:
            self.assertEqual(store.detail("attempts", attempt["attempt_id"]), attempt)
            self.assertEqual(store.detail("evidence", accepted["evidence_ids"][-1])["type"], "review")
            self.assertEqual(store.db.execute(
                "SELECT count(*) FROM effects WHERE kind='verifier.capture'").fetchone()[0], 2)
        replayed = verify(accepted["revision"])
        self.assertEqual(replayed.returncode, 0, replayed.stderr + replayed.stdout)
        self.assertEqual(self.service.inspect(stopped["run_id"]), accepted)

    def test_same_key_holds_when_review_capture_was_prepared(self):
        stopped, _, verify = self._interrupt_first_verification("review")
        self.assertEqual(len(stopped["pending_effect_ids"]), 1)
        refused = verify(stopped["revision"])
        self.assertEqual(refused.returncode, 5, refused.stderr + refused.stdout)
        self.assertEqual(json.loads(refused.stdout)["errors"][0]["code"], "effect_unreconciled")
        self.assertEqual(self.service.inspect(stopped["run_id"]), stopped)
        self.assertEqual(len(self.invocations()), 1)

    def test_same_key_holds_when_exact_checkpoint_state_changed(self):
        stopped, _, verify = self._interrupt_first_verification("diff_bytes")
        current = verify(stopped["revision"] + 1)
        self.assertEqual(current.returncode, 4, current.stderr + current.stdout)
        self.assertEqual(json.loads(current.stdout)["errors"][0]["code"], "revision_conflict")
        self.assertEqual(self.service.inspect(stopped["run_id"]), stopped)
        self.assertEqual(len(self.invocations()), 1)

    def test_same_key_holds_when_saved_check_artifact_changed(self):
        stopped, _, verify = self._interrupt_first_verification("diff_bytes")
        with Store(self.state) as store:
            record = store.detail("evidence", stopped["evidence_ids"][-1])
            (store.blob_root / record["artifacts"][0]["sha256"]).write_bytes(b"changed fixture")
        refused = verify(stopped["revision"])
        self.assertEqual(refused.returncode, 70, refused.stderr + refused.stdout)
        self.assertEqual(json.loads(refused.stdout)["errors"][0]["code"], "blob_integrity")
        self.assertEqual(self.service.inspect(stopped["run_id"]), stopped)

    def test_same_key_holds_when_authority_expired(self):
        stopped, _, _ = self._interrupt_first_verification("diff_bytes")
        with patch("taskalong.store.now", return_value="2100-01-01T00:00:00Z"):
            with self.assertRaises(TaskAlongError) as refused:
                self.service.verify(stopped["run_id"], operation_key="offline-checkpoint",
                                    expected_revision=stopped["revision"])
        self.assertEqual(refused.exception.code, "authority_missing")
        self.assertEqual(self.service.inspect(stopped["run_id"]), stopped)

    def test_same_key_holds_while_another_controller_owns_the_boundary(self):
        stopped, _, verify = self._interrupt_first_verification("diff_bytes")
        with Store(self.state) as store, store.guard(stopped["run_id"], "verify"):
            refused = verify(stopped["revision"])
        self.assertEqual(refused.returncode, 4, refused.stderr + refused.stdout)
        self.assertEqual(json.loads(refused.stdout)["errors"][0]["code"], "operation_in_progress")
        self.assertEqual(self.service.inspect(stopped["run_id"]), stopped)
