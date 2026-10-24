"""Public synthetic completed-handoff recovery with a real controller SIGKILL.

This is workflow recovery before the first verify, not vendor native resume,
real provider execution, ReviewSensei0.8.12 invocation or E1 trial completion.
"""
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import time
import unittest
from unittest.mock import patch

from helpers import ServiceFixture, git
from taskalong.api import RunService
from taskalong.errors import TaskAlongError
from taskalong.store import Store, encode
from taskalong.validation import digest


class TrialHandoffRecoveryTests(ServiceFixture, unittest.TestCase):
    def completed_handoff(self):
        # Reuse only the existing observation/configuration helper methods. No
        # successful core/store/reviewer call is replaced or fabricated.
        from test_recovery_regressions import RecoveryRegressions
        specification = RecoveryRegressions.configure_released_review(self)
        run, _ = self.submit(specification)
        environment, marker, _ = RecoveryRegressions.trace_environment(self, "verify", mode="hold")
        owned = []
        real_spawn = subprocess.Popen
        def record_spawn(argv, *args, **kwargs):
            child = real_spawn(argv, *args, **kwargs)
            if "taskalong._supervisor" in argv:
                owned.append(child)
            return child
        with patch.dict(os.environ, environment), patch("taskalong.workflow.subprocess.Popen", record_spawn):
            self.service.start(run["run_id"], operation_key="one-worker", expected_revision=run["revision"])
        self.assertEqual(len(owned), 1)
        controller = owned[0]
        def cleanup_controller():
            if controller.poll() is None:
                controller.kill()
            controller.wait(timeout=5)
        self.addCleanup(cleanup_controller)
        deadline = time.monotonic() + 20
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(.025)
        self.assertTrue(marker.exists(), "Controller did not reach the public pre-verification boundary")
        checkpoint = self.service.inspect(run["run_id"])
        self.assertEqual(checkpoint["state"], "verifying")
        self.assertIsNone(checkpoint["active_attempt_id"])
        self.assertEqual(checkpoint["pending_effect_ids"], [])
        self.assertEqual(self.service.result(run["run_id"])["outcome"], "worker_completed")
        with Store(self.state) as store:
            attempt = store.detail("attempts", checkpoint["attempts"][-1]["attempt_id"])
            self.assertTrue(attempt["termination_confirmed"])
            self.assertEqual(attempt["status"], "completed")
            self.assertEqual(store.db.execute("SELECT count(*) FROM operations WHERE command='verification.claim'").fetchone()[0], 0)
        # The actual child handle was observed during the public start. No
        # guessed or disk-recovered numeric PID receives a signal.
        self.assertIsNone(controller.poll())
        controller.kill()
        controller.wait(timeout=5)
        self.assertEqual(controller.returncode, -signal.SIGKILL)
        return checkpoint, attempt

    def test_new_controller_verifies_once_without_repeating_completed_worker_edits_or_budget(self):
        checkpoint, attempt = self.completed_handoff()
        workspace = Path(attempt["workspace"]["path"])
        edited = (workspace / "arithmetic.py").read_bytes()
        self.assertIn(b"return a + b", edited)
        with Store(self.state) as store:
            effects = [tuple(r) for r in store.db.execute("SELECT effect_id,kind,operation_key FROM effects ORDER BY effect_id")]
            result_bytes = store.get_blob(attempt["result_artifact"]["sha256"])
        with RunService(self.state) as controller:
            before = controller.inspect(checkpoint["run_id"])
            self.assertEqual(before, checkpoint)
            accepted = controller.verify(checkpoint["run_id"], operation_key="first-verify", expected_revision=before["revision"])
            self.assertEqual(accepted["state"], "accepted")
            self.assertEqual(controller.verify(checkpoint["run_id"], operation_key="first-verify", expected_revision=1), accepted)
            self.assertTrue(controller.result(checkpoint["run_id"])["independently_accepted"])
        self.assertEqual((workspace / "arithmetic.py").read_bytes(), edited)
        self.assertEqual(len(self.invocations()), 1)
        self.assertEqual(accepted["attempts"], checkpoint["attempts"])
        for key in ("attempts", "active_seconds", "input_tokens", "output_tokens", "cost_usd"):
            self.assertEqual(accepted["budget_consumed"][key], checkpoint["budget_consumed"][key])
        # Fresh verification legitimately consumes output. Recovery must retain
        # the worker's already consumed output rather than reset/refund it.
        self.assertGreaterEqual(accepted["budget_consumed"]["output_bytes"], checkpoint["budget_consumed"]["output_bytes"])
        self.assertEqual(accepted["workspace_id"], checkpoint["workspace_id"])
        self.assertEqual(accepted["lease_generation"], checkpoint["lease_generation"])
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.base)
        with Store(self.state) as store:
            self.assertEqual(store.detail("attempts", attempt["attempt_id"]), attempt)
            self.assertEqual(store.get_blob(attempt["result_artifact"]["sha256"]), result_bytes)
            current = {tuple(r) for r in store.db.execute("SELECT effect_id,kind,operation_key FROM effects")}
            self.assertTrue(set(effects) <= current)
            self.assertEqual(store.db.execute("SELECT count(*) FROM operations WHERE command='verification.claim'").fetchone()[0], 1)
            records = [store.detail("evidence", eid) for eid in accepted["evidence_ids"]]
            self.assertEqual(sum(item["type"] == "command" for item in records), 1)
            self.assertEqual(sum(item["type"] == "review" for item in records), 1)

    def test_lost_cessation_refuses_before_new_verification_claim(self):
        checkpoint, attempt = self.completed_handoff()
        with Store(self.state) as store:
            attempt["termination_confirmed"] = False
            store.db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(attempt), attempt["attempt_id"]))
        with RunService(self.state) as controller:
            with self.assertRaises(TaskAlongError) as failure:
                controller.verify(checkpoint["run_id"], operation_key="must-refuse", expected_revision=checkpoint["revision"])
        self.assertEqual(failure.exception.code, "worker_handoff_missing")
        with Store(self.state) as store:
            self.assertEqual(store.db.execute("SELECT count(*) FROM operations WHERE command='verification.claim'").fetchone()[0], 0)
        self.assertEqual(len(self.invocations()), 1)

    def test_pending_effect_refuses_before_new_verification_claim(self):
        checkpoint, _ = self.completed_handoff()
        with Store(self.state) as store:
            def uncertain(run, db):
                run["pending_effect_ids"] = ["11111111-1111-4111-8111-111111111111"]
            pending = store.mutate(checkpoint["run_id"], "generated-unknown-effect", "unknown-effect", None, {}, uncertain)
        with RunService(self.state) as controller:
            with self.assertRaises(TaskAlongError) as failure:
                controller.verify(checkpoint["run_id"], operation_key="must-refuse", expected_revision=pending["revision"])
        self.assertEqual(failure.exception.code, "effect_unreconciled")
        with Store(self.state) as store:
            self.assertEqual(store.db.execute("SELECT count(*) FROM operations WHERE command='verification.claim'").fetchone()[0], 0)
        self.assertEqual(len(self.invocations()), 1)


if __name__ == "__main__":
    unittest.main()
