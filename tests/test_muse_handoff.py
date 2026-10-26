"""Public synthetic Muse lifecycle; supervisor handoff is not vendor output."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from helpers import ServiceFixture
from taskalong.api import RunService
from taskalong.errors import TaskAlongError
from taskalong.store import Store
from taskalong.validation import canonical_bytes, digest, seal_versioned
from dataclasses import replace


class MuseHandoffTests(ServiceFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.service.close()
        with Store.maintenance(self.state) as store:
            for version in range(2, 10):
                store.upgrade(operation_key="muse-format-" + str(version), target_version=version,
                    backup_dir=self.root / ("backup-" + str(version)),
                    restore_dir=self.root / ("restore-" + str(version)))
        self.service = RunService(self.state)
        self.muse = self.root / "original-muse-plain-fixture"
        fixture = Path(__file__).parent / "fixtures" / "fake_muse_handoff.py"
        self.muse.write_text(fixture.read_text().replace("#!/usr/bin/env python3", "#!" + sys.executable, 1)
            .replace("MODE_PATH = None", "MODE_PATH = " + repr(str(self.mode_file)))
            .replace("COUNT_PATH = None", "COUNT_PATH = " + repr(str(self.root / "muse-invocations.jsonl"))))
        self.muse.chmod(0o700)
        task = self.spec(attempt_seconds=15, total_seconds=60)
        config = self.service.configure_muse_capture({
            "config_id": "original-muse-plain-fixture", "qualification": "synthetic",
            "projection": "muse-plain-fixture/1", "transport": "operator_registered_original_fixture",
            "executable": {"path": str(self.muse), "sha256": hashlib.sha256(self.muse.read_bytes()).hexdigest()},
            "build": "1.4.10-R6427.1", "requested_model": "synthetic-muse-model",
            "permission_profile": "synthetic-profile", "max_model_steps": 1,
            "inference_destination_id": "synthetic-local-muse", "check_profile_digest": self.profile["digest"],
            "checks_digest": digest(task["checks"]), "review_config_digest": task["review"]["config_digest"],
            "command_sandbox_digest": digest(self.service._store.setting("command_sandbox"))})
        self.task = seal_versioned("task-spec", task | {"schema_version": "2.9",
            "execution": {"driver_config_digest": config["digest"]},
            "permissions": task["permissions"] | {"inference_destination_id": "synthetic-local-muse"}}, version="2.9")

    def test_public_run_uses_capture_once_and_handoff_only_reaches_independent_verification(self):
        run, _ = self.submit(self.task)
        self.start(run, key="muse-start")
        finished = self.wait(run["run_id"])
        self.assertEqual(finished["state"], "blocked")
        self.assertIn("required_review_missing", {x["code"] for x in finished["blockers"]})
        self.assertIsNone(finished["acceptance_id"])
        self.assertIsNone(finished["active_attempt_id"])
        attempt = self.service._store.detail("attempts", finished["attempts"][-1]["attempt_id"])
        handoff = json.loads(self.service._store.get_blob(attempt["execution_handoff"]["sha256"]))
        self.assertEqual(handoff["kind"], "execution_handoff")
        self.assertEqual(handoff["producer_role"], "supervisor")
        self.assertIsNone(handoff["observed_model"])
        self.assertIsNone(handoff["observed_session"])
        self.assertEqual(handoff["attempt_id"], attempt["attempt_id"])
        self.assertEqual(handoff["packet_digest"], attempt["packet"]["digest"])
        evidence = [self.service._store.detail("evidence", x) for x in finished["evidence_ids"]]
        self.assertTrue(any(x["type"] == "command" and x["result"] == "passed" for x in evidence))
        self.service.start(run["run_id"], operation_key="muse-start", expected_revision=0)
        with RunService(self.state) as reopened:
            reopened.start(run["run_id"], operation_key="muse-start", expected_revision=0)
        self.assertEqual(len((self.root / "muse-invocations.jsonl").read_text().splitlines()), 1)
        view = self.service.result(run["run_id"])
        self.assertEqual(view["outcome"], "execution_handoff_ready")
        self.assertFalse(view["independently_accepted"])

    def completed(self, mode="good"):
        self.set_mode(mode)
        run, _ = self.submit(self.task)
        self.start(run)
        return self.wait(run["run_id"])

    def test_completed_handoff_survives_cancel_result_and_reconcile_without_replay(self):
        run = self.completed()
        attempt_id = run["attempts"][-1]["attempt_id"]
        before = self.service._store.detail("attempts", attempt_id)
        budget = dict(run["budget_consumed"])
        pending = self.service.cancel(run["run_id"], operation_key="cancel-completed",
            expected_revision=run["revision"])
        self.assertEqual(pending["state"], "cancel_pending")
        self.assertIsNone(pending["active_attempt_id"])
        self.assertEqual(pending["pending_effect_ids"], [])
        view = self.service.result(run["run_id"])
        self.assertEqual(view["outcome"], "pending")
        self.assertFalse(view["independently_accepted"])
        operations = self.service._store.db.execute("SELECT count(*) FROM operations").fetchone()[0]
        with self.assertRaises(TaskAlongError) as refused:
            self.service.verify(run["run_id"], operation_key="verify-during-cancel",
                expected_revision=pending["revision"])
        self.assertEqual(refused.exception.code, "workspace_not_quiescent")
        self.assertEqual(self.service._store.db.execute("SELECT count(*) FROM operations").fetchone()[0], operations)
        cancelled = self.service.reconcile(run["run_id"], operation_key="reconcile-cancel",
            expected_revision=pending["revision"])
        self.assertEqual(cancelled["state"], "cancelled")
        self.assertEqual(self.service.result(run["run_id"])["outcome"], "cancelled")
        self.assertEqual(self.service._store.detail("attempts", attempt_id), before)
        self.assertEqual(cancelled["budget_consumed"], budget)
        self.assertEqual(len((self.root / "muse-invocations.jsonl").read_text().splitlines()), 1)

    def test_completed_missing_handoff_still_refuses_result_and_cancel_reconciliation(self):
        run = self.completed()
        attempt = self.service._store.detail("attempts", run["attempts"][-1]["attempt_id"])
        attempt["execution_handoff"] = None
        with self.service._store.transaction() as db:
            db.execute("UPDATE attempts SET document=? WHERE attempt_id=?",
                (canonical_bytes(attempt).decode(), attempt["attempt_id"]))
        pending = self.service.cancel(run["run_id"], operation_key="cancel-missing-handoff",
            expected_revision=run["revision"])
        for action in (lambda: self.service.result(run["run_id"]),
                lambda: self.service.reconcile(run["run_id"], operation_key="reconcile-missing-handoff",
                    expected_revision=pending["revision"])):
            with self.assertRaises(TaskAlongError) as refused:
                action()
            self.assertEqual(refused.exception.code, "muse_handoff_missing")
        self.assertEqual(self.service.inspect(run["run_id"])["state"], "cancel_pending")

    def test_completed_tampered_handoff_still_refuses_cancel_reconciliation(self):
        run = self.completed()
        attempt = self.service._store.detail("attempts", run["attempts"][-1]["attempt_id"])
        (self.state / "blobs" / attempt["execution_handoff"]["sha256"]).write_bytes(b"tampered")
        pending = self.service.cancel(run["run_id"], operation_key="cancel-tampered-handoff",
            expected_revision=run["revision"])
        for action in (lambda: self.service.result(run["run_id"]),
                lambda: self.service.reconcile(run["run_id"], operation_key="reconcile-tampered-handoff",
                    expected_revision=pending["revision"])):
            with self.assertRaises(TaskAlongError):
                action()
        self.assertEqual(self.service.inspect(run["run_id"])["state"], "cancel_pending")

    def test_pending_verifier_effect_prevents_completed_run_cancellation(self):
        run = self.completed()
        self.service._store.mutate(run["run_id"], "test.verifying", "pending-effect", run["revision"], {},
            lambda current, db: current.update(state="verifying", blockers=[]), fence=run["lease_generation"])
        self.service._workflow._capture_prepare(run["run_id"], "test-pending", "pending-effect")
        current = self.service.inspect(run["run_id"])
        pending = self.service.cancel(run["run_id"], operation_key="cancel-pending-effect",
            expected_revision=current["revision"])
        self.assertEqual(self.service.result(run["run_id"])["outcome"], "pending")
        with self.assertRaises(TaskAlongError) as refused:
            self.service.reconcile(run["run_id"], operation_key="reconcile-pending-effect",
                expected_revision=pending["revision"])
        self.assertEqual(refused.exception.code, "effect_unreconciled")
        after = self.service.inspect(run["run_id"])
        self.assertEqual(after["state"], "cancel_pending")
        self.assertEqual(after["pending_effect_ids"], pending["pending_effect_ids"])
        self.assertEqual(len((self.root / "muse-invocations.jsonl").read_text().splitlines()), 1)

    def test_accepted_retirement_preserves_history_but_refuses_current_lease_operations(self):
        import shutil
        from taskalong.muse_handoff import configuration
        from test_cancel_resume import CancelResumeTests
        reviewer = shutil.which("review-sensei") or str(Path(sys.executable).parent / "review-sensei")
        if not Path(reviewer).is_file():
            self.skipTest("released reviewer environment missing; full installed qualification requires this boundary")
        fixtures = Path(__file__).parent / "fixtures" / "reviewsensei"
        selected = self.service.configure_review(fixtures / "approved.yml",
            fixture_response=fixtures / "clean.json", executable=reviewer)
        config = configuration(self.service._store, self.task["execution"]["driver_config_digest"])
        config["review_config_digest"] = selected["config_digest"]
        config.pop("digest")
        config = self.service.configure_muse_capture(config)
        self.task = seal_versioned("task-spec", self.task | {
            "execution": {"driver_config_digest": config["digest"]},
            "review": self.task["review"] | {"config_digest": selected["config_digest"]}}, version="2.9")
        accepted = self.completed()
        self.assertEqual(accepted["state"], "accepted")
        before = self.service.result(accepted["run_id"])
        self.assertEqual(before["outcome"], "accepted")
        retired = CancelResumeTests.retire_when_quiescent(self, accepted, "retire-muse")
        self.assertEqual(self.service.inspect(accepted["run_id"]), retired)
        self.assertEqual(retired["acceptance_id"], accepted["acceptance_id"])
        for action, code in ((lambda: self.service.result(accepted["run_id"]), "lease_retired"),
                (lambda: self.service.start(accepted["run_id"], operation_key="retired-start",
                    expected_revision=retired["revision"]), "invalid_run_state"),
                (lambda: self.service.verify(accepted["run_id"], operation_key="retired-verify",
                    expected_revision=retired["revision"]), "lease_retired")):
            with self.assertRaises(TaskAlongError) as refused:
                action()
            self.assertEqual(refused.exception.code, code)
        self.assertEqual(self.service.inspect(accepted["run_id"]), retired)
        self.assertEqual(len((self.root / "muse-invocations.jsonl").read_text().splitlines()), 1)

    def test_incorrect_code_is_not_accepted_even_with_valid_local_handoff(self):
        run = self.completed("bad")
        self.assertNotEqual(run["state"], "accepted")
        self.assertIsNone(run["acceptance_id"])
        attempt = self.service._store.detail("attempts", run["attempts"][-1]["attempt_id"])
        self.assertIsNotNone(attempt["execution_handoff"])
        evidence = [self.service._store.detail("evidence", x) for x in run["evidence_ids"]]
        self.assertTrue(any(x["type"] == "command" and x["result"] == "failed" for x in evidence))

    def test_out_of_scope_bytes_prevent_handoff_and_verification(self):
        run = self.completed("out-of-scope")
        self.assertEqual(run["state"], "blocked")
        self.assertIn("scope_violation", {x["code"] for x in run["blockers"]})
        attempt = self.service._store.detail("attempts", run["attempts"][-1]["attempt_id"])
        self.assertIsNone(attempt.get("execution_handoff"))
        self.assertEqual(run["evidence_ids"], [])
        self.assertEqual(attempt["status"], "failed")
        self.assertTrue(attempt["termination_confirmed"])
        self.assertEqual(run["blockers"][0]["effect_outcome"], "known")
        self.assertEqual(len((self.root / "muse-invocations.jsonl").read_text().splitlines()), 1)

    def test_actual_local_cancel_creates_no_execution_handoff(self):
        self.set_mode("hang")
        run, _ = self.submit(self.task)
        self.start(run)
        running = self.wait(run["run_id"], predicate=lambda r: r["state"] == "running"
                            and (self.root / "muse-invocations.jsonl").exists())
        self.service.cancel(run["run_id"], operation_key="cancel-muse", expected_revision=running["revision"])
        cancelled = self.wait(run["run_id"], states=("cancelled",))
        attempt = self.service._store.detail("attempts", cancelled["attempts"][-1]["attempt_id"])
        self.assertIsNone(attempt.get("execution_handoff"))
        self.assertTrue(attempt["termination_confirmed"])
        self.assertIsNone(cancelled["acceptance_id"])

    def test_tampered_capture_fails_readback_and_fresh_verification_without_redispatch(self):
        run = self.completed()
        attempt = self.service._store.detail("attempts", run["attempts"][-1]["attempt_id"])
        ref = attempt["muse_capture"]["refs"]["stdout.bin"]
        path = self.state / "blobs" / ref["sha256"]
        path.write_bytes(b"tampered")
        with self.assertRaises(TaskAlongError):
            self.service.result(run["run_id"])
        with self.assertRaises(TaskAlongError):
            self.service.verify(run["run_id"], operation_key="verify-tampered", expected_revision=run["revision"])
        self.assertEqual(len((self.root / "muse-invocations.jsonl").read_text().splitlines()), 1)

    def test_resealed_mismatched_handoff_is_not_authoritative_store_evidence(self):
        run = self.completed()
        attempt = self.service._store.detail("attempts", run["attempts"][-1]["attempt_id"])
        handoff = json.loads(self.service._store.get_blob(attempt["execution_handoff"]["sha256"]))
        handoff["driver_config_digest"] = "c" * 64
        forged = seal_versioned("execution-handoff", handoff, version="2.9")
        attempt["execution_handoff"] = self.service._store.put_blob(canonical_bytes(forged))
        with self.service._store.transaction() as db:
            db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (canonical_bytes(attempt).decode(), attempt["attempt_id"]))
        with self.assertRaises(TaskAlongError):
            self.service.result(run["run_id"])
        self.assertIsNone(self.service.inspect(run["run_id"])["acceptance_id"])

    def foreground(self, fault):
        """Inject a supervisor boundary fault after public start, with real capture."""
        from taskalong import workflow, muse_handoff
        run, _ = self.submit(self.task)
        with patch.object(self.service._workflow, "_launch_supervisor", lambda *_: None):
            self.start(run)
        current = self.service.inspect(run["run_id"])
        with patch.object(muse_handoff, "create_handoff", fault):
            workflow.drive_run(self.state, run["run_id"], current["active_attempt_id"])
        return self.service.inspect(run["run_id"])

    def test_expired_authority_prevents_handoff_after_capture(self):
        from taskalong import muse_handoff
        create = muse_handoff.create_handoff
        def stale(*args):
            with patch("taskalong.store.now", return_value="2099-01-01T00:00:00Z"):
                return create(*args)
        run = self.foreground(stale)
        attempt = self.service._store.detail("attempts", run["attempts"][-1]["attempt_id"])
        self.assertIsNone(attempt.get("execution_handoff"))
        self.assertEqual(run["evidence_ids"], [])
        self.assertNotEqual(run["state"], "accepted")

    def test_stale_lease_proof_prevents_handoff_after_capture(self):
        from taskalong import muse_handoff
        create = muse_handoff.create_handoff
        def stale(store, *args):
            require = store.require_fence
            def mismatch(run, generation, **kwargs):
                return require(run, generation + 1, **kwargs)
            with patch.object(store, "require_fence", mismatch):
                return create(store, *args)
        run = self.foreground(stale)
        attempt = self.service._store.detail("attempts", run["attempts"][-1]["attempt_id"])
        self.assertIsNone(attempt.get("execution_handoff"))
        self.assertEqual(run["evidence_ids"], [])

    def test_missing_capture_file_prevents_handoff_and_independent_checks(self):
        from taskalong.executors.muse_fixture import MuseFixtureDriver
        from taskalong.workflow import drive_run
        run, _ = self.submit(self.task)
        with patch.object(self.service._workflow, "_launch_supervisor", lambda *_: None):
            self.start(run)
        current = self.service.inspect(run["run_id"])
        original = MuseFixtureDriver.run
        def lose(driver, *args, **kwargs):
            result = original(driver, *args, **kwargs)
            (result["_muse_capture"].directory / "stdout.bin").unlink()
            return result
        with patch.object(MuseFixtureDriver, "run", lose):
            drive_run(self.state, run["run_id"], current["active_attempt_id"])
        stopped = self.service.inspect(run["run_id"])
        attempt = self.service._store.detail("attempts", stopped["attempts"][-1]["attempt_id"])
        self.assertIsNone(attempt.get("execution_handoff"))
        self.assertEqual(stopped["evidence_ids"], [])
        self.assertIsNone(stopped["acceptance_id"])

    def test_workspace_change_between_handoff_observation_and_finish_refuses_transition(self):
        from taskalong import muse_handoff
        from taskalong.workflow import drive_run
        run, _ = self.submit(self.task)
        with patch.object(self.service._workflow, "_launch_supervisor", lambda *_: None):
            self.start(run)
        current = self.service.inspect(run["run_id"])
        original = muse_handoff.validate_handoff
        def drift(store, observed_run, spec, attempt, manager, workspace, **options):
            if options.get("before_finish"):
                (Path(workspace["path"]) / "arithmetic.py").write_text("def add(a,b): return 999\n")
            return original(store, observed_run, spec, attempt, manager, workspace, **options)
        with patch.object(muse_handoff, "validate_handoff", drift):
            drive_run(self.state, run["run_id"], current["active_attempt_id"])
        stopped = self.service.inspect(run["run_id"])
        attempt = self.service._store.detail("attempts", stopped["attempts"][-1]["attempt_id"])
        self.assertIsNone(attempt.get("execution_handoff"))
        self.assertEqual(stopped["evidence_ids"], [])
        self.assertIsNone(stopped["candidate"])

    def test_cancel_between_handoff_creation_and_finish_cannot_commit_completion(self):
        from taskalong import muse_handoff
        create = muse_handoff.create_handoff
        def cancelled_after_creation(store, run_id, *args):
            handoff = create(store, run_id, *args)
            current = self.service.inspect(run_id)
            self.service.cancel(run_id, operation_key="cancel-before-finish",
                expected_revision=current["revision"])
            with self.assertRaises(TaskAlongError):
                create(store, run_id, *args)
            return handoff
        stopped = self.foreground(cancelled_after_creation)
        attempt = self.service._store.detail("attempts", stopped["attempts"][-1]["attempt_id"])
        self.assertEqual(stopped["state"], "cancelled")
        self.assertTrue(attempt["termination_confirmed"])
        self.assertNotEqual(attempt["status"], "completed")
        self.assertIsNone(attempt.get("execution_handoff"))
        self.assertIsNotNone(attempt.get("muse_capture"))
        self.assertIsNone(stopped["acceptance_id"])
        self.assertIsNone(stopped["candidate"])
        self.assertEqual(stopped["evidence_ids"], [])
        self.assertEqual(stopped["budget_consumed"]["attempts"], 1)
        self.assertEqual(stopped["budget_consumed"]["output_bytes"], attempt["process"]["output_bytes"])
        self.assertEqual(len((self.root / "muse-invocations.jsonl").read_text().splitlines()), 1)

    def test_unknown_termination_retains_quarantine_and_never_manufactures_handoff(self):
        from taskalong.executors.muse_fixture import MuseFixtureDriver
        from taskalong.workflow import drive_run
        run, _ = self.submit(self.task)
        with patch.object(self.service._workflow, "_launch_supervisor", lambda *_: None):
            self.start(run)
        current = self.service.inspect(run["run_id"])
        original = MuseFixtureDriver.run
        def lose(driver, *args, **kwargs):
            result = original(driver, *args, **kwargs)
            self.assertTrue(result["process"]["termination_confirmed"])
            result["process"] = result["process"] | {"termination_confirmed": False, "unaccounted_descendants": True}
            result.update(state="unknown", error="muse_termination_unconfirmed")
            return result
        with patch.object(MuseFixtureDriver, "run", lose):
            drive_run(self.state, run["run_id"], current["active_attempt_id"])
        stopped = self.service.inspect(run["run_id"])
        attempt = self.service._store.detail("attempts", stopped["attempts"][-1]["attempt_id"])
        self.assertEqual(stopped["state"], "blocked")
        self.assertIsNotNone(stopped["active_attempt_id"])
        self.assertIsNone(attempt.get("execution_handoff"))
        self.assertTrue(stopped["pending_effect_ids"])
        self.assertFalse(attempt["termination_confirmed"])
        self.assertEqual(stopped["blockers"][0]["effect_outcome"], "uncertain")
        self.service.start(run["run_id"], operation_key="start", expected_revision=0)
        self.assertEqual(len((self.root / "muse-invocations.jsonl").read_text().splitlines()), 1)
        pending = self.service.cancel(run["run_id"], operation_key="cancel-unknown",
            expected_revision=stopped["revision"])
        # Root disappearance is not complete descendant-cessation proof.
        with patch("taskalong.process.receipt_is_alive", return_value=False):
            reconciled = self.service.reconcile(run["run_id"], operation_key="reconcile-unknown-cancel",
                expected_revision=pending["revision"])
        self.assertEqual(reconciled["state"], "blocked")
        self.assertIsNotNone(reconciled["active_attempt_id"])
        self.assertEqual(reconciled["pending_effect_ids"], stopped["pending_effect_ids"])
        self.assertFalse(self.service._store.detail("attempts", attempt["attempt_id"])["termination_confirmed"])
        self.run_ids.remove(run["run_id"])
        # Only the observation was fault-injected. The real fixture had already
        # ceased, as asserted above; teardown does not reconcile the quarantine.

    def test_failed_handoff_validation_preserves_uncertain_cessation_outcome(self):
        from taskalong.executors.muse_fixture import MuseFixtureDriver
        from taskalong.workflow import drive_run
        run, _ = self.submit(self.task)
        with patch.object(self.service._workflow, "_launch_supervisor", lambda *_: None):
            self.start(run)
        current = self.service.inspect(run["run_id"])
        original = MuseFixtureDriver.run
        def contradictory(driver, *args, **kwargs):
            result = original(driver, *args, **kwargs)
            self.assertTrue(result["process"]["termination_confirmed"])
            result["process"] = result["process"] | {"termination_confirmed": False, "unaccounted_descendants": True}
            # Even a contradictory completed claim must fail closed when the
            # authoritative handoff validation observes uncertain cessation.
            return result
        with patch.object(MuseFixtureDriver, "run", contradictory):
            drive_run(self.state, run["run_id"], current["active_attempt_id"])
        stopped = self.service.inspect(run["run_id"])
        attempt = self.service._store.detail("attempts", stopped["attempts"][-1]["attempt_id"])
        self.assertEqual(attempt["status"], "failed")
        self.assertFalse(attempt["termination_confirmed"])
        self.assertIsNone(attempt.get("execution_handoff"))
        self.assertEqual(stopped["blockers"][0]["effect_outcome"], "uncertain")
        self.assertTrue(stopped["pending_effect_ids"])
        self.assertIsNotNone(stopped["active_attempt_id"])
        self.assertEqual(stopped["evidence_ids"], [])
        self.assertEqual(len((self.root / "muse-invocations.jsonl").read_text().splitlines()), 1)
        self.run_ids.remove(run["run_id"])
        # The real fixture stopped; only the returned observation was faulted.

    def test_incomplete_capture_persistence_cannot_manufacture_handoff(self):
        from taskalong.executors.muse_fixture import MuseFixtureDriver
        from taskalong.workflow import drive_run
        run, _ = self.submit(self.task)
        with patch.object(self.service._workflow, "_launch_supervisor", lambda *_: None):
            self.start(run)
        current = self.service.inspect(run["run_id"])
        original_run, original_put = MuseFixtureDriver.run, Store.put_blob
        ceased = []
        def observed(driver, *args, **kwargs):
            result = original_run(driver, *args, **kwargs)
            self.assertTrue(result["process"]["termination_confirmed"])
            ceased.append(True)
            return result
        def failed_write(store, data, **options):
            if options.get("media_type") == "application/octet-stream":
                raise OSError("controlled durable capture failure")
            return original_put(store, data, **options)
        with patch.object(MuseFixtureDriver, "run", observed), patch.object(Store, "put_blob", failed_write):
            drive_run(self.state, run["run_id"], current["active_attempt_id"])
        stopped = self.service.inspect(run["run_id"])
        attempt = self.service._store.detail("attempts", stopped["attempts"][-1]["attempt_id"])
        self.assertEqual(ceased, [True])
        self.assertIsNone(attempt.get("execution_handoff"))
        self.assertIsNone(attempt.get("muse_capture"))
        self.assertEqual(stopped["evidence_ids"], [])
        self.assertIsNone(stopped["acceptance_id"])
        self.assertTrue(stopped["pending_effect_ids"])
        self.service.start(run["run_id"], operation_key="start", expected_revision=0)
        self.assertEqual(len((self.root / "muse-invocations.jsonl").read_text().splitlines()), 1)
        self.run_ids.remove(run["run_id"])
        # The real fixture ceased. Only durable retention failed; this test
        # does not resolve the deliberately retained Store quarantine.


if __name__ == "__main__":
    unittest.main()
