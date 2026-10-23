"""Cancellation, explicit continuation, retained work and persisted budgets."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.store import Store, encode, identifier
from helpers import ServiceFixture, git


class CancelResumeTests(ServiceFixture, unittest.TestCase):
    def cancelled_run(self):
        self.set_mode("hang")
        run, _ = self.submit()
        self.start(run)
        running = self.wait(run["run_id"], predicate=lambda item: item["state"] == "running" and bool(self.invocations()))
        self.service.cancel(run["run_id"], operation_key="cancel-for-retirement", expected_revision=running["revision"])
        return self.wait(run["run_id"], states=("cancelled",))

    def retire_when_quiescent(self, run, key="retire"):
        deadline = time.monotonic() + 5
        while True:
            try:
                return self.service.retire_workspace(run["run_id"], operation_key=key, expected_revision=run["revision"])
            except TaskAlongError as exc:
                # Retry only a proven no-effect guard conflict during the
                # completed supervisor's final return, never uncertainty.
                if exc.code not in {"supervisor_owned", "operation_in_progress"} or time.monotonic() >= deadline:
                    raise
                time.sleep(0.025)

    def test_retirement_admits_fresh_task_preserving_original_workspace_and_history(self):
        cancelled = self.cancelled_run()
        old_path = self.root / "workspaces" / cancelled["run_id"]
        old_head = git(old_path, "rev-parse", "HEAD")
        old_bytes = (old_path / "arithmetic.py").read_bytes()
        old_events = self.service.events(cancelled["run_id"])
        marker = self.repo / ".git" / "taskalong" / "workspaces" / (cancelled["workspace_id"] + ".json")
        old_marker = marker.read_bytes()
        next_run, _ = self.submit(key="next-task")
        with self.assertRaises(TaskAlongError) as occupied:
            self.start(next_run, key="before-retirement")
        self.assertEqual(occupied.exception.code, "workspace_occupied")
        retired = self.retire_when_quiescent(cancelled)
        self.assertEqual(retired["state"], "cancelled")
        self.assertTrue(retired["extensions"]["taskalong:workspace_retirement"]["preserved"])
        self.assertEqual(retired["evidence_ids"], cancelled["evidence_ids"])
        self.assertEqual(self.service.events(cancelled["run_id"])[:-1], old_events)
        self.assertEqual(self.service.events(cancelled["run_id"])[-1]["type"], "workspace.retired")
        self.set_mode("good")
        self.start(self.service.inspect(next_run["run_id"]), key="after-retirement")
        next_finished = self.wait(next_run["run_id"])
        self.assertIn("required_review_missing", {item["code"] for item in next_finished["blockers"]})
        self.assertGreater(next_finished["lease_generation"], cancelled["lease_generation"])
        self.assertNotEqual(next_finished["workspace_id"], cancelled["workspace_id"])
        self.assertEqual((old_path / "arithmetic.py").read_bytes(), old_bytes)
        self.assertEqual(git(old_path, "rev-parse", "HEAD"), old_head)
        self.assertEqual(git(self.repo, "rev-parse", "taskalong/" + cancelled["run_id"]), old_head)
        self.assertEqual(marker.read_bytes(), old_marker)
        self.assertEqual(self.service.retire_workspace(cancelled["run_id"], operation_key="retire", expected_revision=0), retired)
        with Store(self.state) as private:
            self.assertEqual(private.retired_lease(retired)["workspace"]["path"], str(old_path))
            with self.assertRaises(TaskAlongError) as old_lease:
                private.lease(retired)
            self.assertEqual(old_lease.exception.code, "lease_retired")
            with self.assertRaises(TaskAlongError):
                private.require_fence(retired, retired["lease_generation"])
        for method, kwargs in ((self.service.resume, {"mode": "restart"}), (self.service.verify, {}), (self.service.publish, {"intent_digest": "f" * 64})):
            with self.subTest(method=method.__name__), self.assertRaises(TaskAlongError):
                method(retired["run_id"], operation_key="retired-" + method.__name__, expected_revision=retired["revision"], **kwargs)
        self.assertEqual(len(self.invocations()), 2)

    def test_cli_retirement_result_is_versioned_idempotent_and_preserves_workspace(self):
        cancelled = self.cancelled_run()
        command = [sys.executable, "-m", "taskalong", "--state-dir", str(self.state), "retire-workspace", cancelled["run_id"],
                   "--expected-revision", str(cancelled["revision"]), "--key", "cli-retire", "--json"]
        deadline = time.monotonic() + 5
        while True:
            result = subprocess.run(command, cwd=self.root, env=dict(os.environ), capture_output=True, text=True, timeout=15)
            document = json.loads(result.stdout)
            if result.returncode != 4 or document["errors"][0]["code"] not in {"supervisor_owned", "operation_in_progress"} or time.monotonic() >= deadline:
                break
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual((document["kind"], document["schema_version"], document["command"], document["state"]), ("command_result", "1.0", "retire-workspace", "cancelled"))
        again = subprocess.run(command, cwd=self.root, env=dict(os.environ), capture_output=True, text=True, timeout=15)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(json.loads(again.stdout), document)
        self.assertTrue((self.root / "workspaces" / cancelled["run_id"]).is_dir())

    def test_retirement_rejects_running_and_pending_cancellation(self):
        self.set_mode("hang")
        run, _ = self.submit()
        self.start(run)
        running = self.wait(run["run_id"], states=("running",))
        with self.assertRaises(TaskAlongError) as active:
            self.service.retire_workspace(run["run_id"], operation_key="retire-running", expected_revision=running["revision"])
        self.assertEqual(active.exception.code, "retirement_not_terminal")
        pending = self.service.cancel(run["run_id"], operation_key="cancel-pending", expected_revision=running["revision"])
        with self.assertRaises(TaskAlongError) as request:
            self.service.retire_workspace(run["run_id"], operation_key="retire-pending", expected_revision=pending["revision"])
        self.assertIn(request.exception.code, {"retirement_not_terminal", "revision_conflict"})
        cancelled = self.wait(run["run_id"], states=("cancelled",))
        self.assertNotIn("taskalong:workspace_retirement", cancelled["extensions"])

    def test_retirement_never_invents_missing_cessation_or_ignores_unknown_effects(self):
        cancelled = self.cancelled_run()
        # Remove an actual receipt's proof. This defensive negative fixture
        # never fabricates a successful process or acceptance receipt.
        with Store(self.state) as private:
            attempt_id = cancelled["attempts"][-1]["attempt_id"]
            original = private.detail("attempts", attempt_id)
            with private.transaction() as db:
                db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode({**original, "termination_confirmed": False}), attempt_id))
        with self.assertRaises(TaskAlongError) as missing:
            self.retire_when_quiescent(cancelled, "missing-proof")
        self.assertEqual(missing.exception.code, "retirement_cessation_unconfirmed")
        self.assertEqual(missing.exception.effect_outcome, "uncertain")
        with Store(self.state) as private:
            with private.transaction() as db:
                db.execute("UPDATE attempts SET document=? WHERE attempt_id=?", (encode(original), attempt_id))
                effect = {"effect_id": identifier(), "run_id": cancelled["run_id"], "operation_key": "unknown-fixture-effect", "kind": "fixture.unknown", "request_digest": "a" * 64, "phase": "unknown", "request": {}, "response": None}
                db.execute("INSERT INTO effects VALUES (?,?,?,?,?,?,?)", (effect["effect_id"], cancelled["run_id"], effect["operation_key"], effect["kind"], effect["request_digest"], effect["phase"], encode(effect)))
        with self.assertRaises(TaskAlongError) as uncertain:
            self.retire_when_quiescent(cancelled, "pending-proof")
        self.assertEqual(uncertain.exception.code, "retirement_effects_pending")
        self.assertEqual(self.service.inspect(cancelled["run_id"]), cancelled)

    def test_accepted_retirement_preserves_independent_acceptance_and_allows_new_task(self):
        # Reuse the real installed, pinned reviewer boundary. Missing optional
        # local tooling is a skip here; full installed qualification requires it.
        from test_recovery_regressions import RecoveryRegressions
        spec = RecoveryRegressions.configure_released_review(self)
        run, _ = self.submit(spec)
        self.start(run)
        accepted = self.wait(run["run_id"])
        self.assertEqual(accepted["state"], "accepted")
        candidate = dict(accepted["candidate"])
        evidence_ids = list(accepted["evidence_ids"])
        acceptance_id = accepted["acceptance_id"]
        with Store(self.state) as private:
            acceptance = private.detail("acceptances", acceptance_id)
        retired = self.retire_when_quiescent(accepted, "retire-accepted")
        self.assertEqual(retired["state"], "accepted")
        self.assertEqual(retired["candidate"], candidate)
        self.assertEqual(retired["evidence_ids"], evidence_ids)
        self.assertEqual(retired["acceptance_id"], acceptance_id)
        with Store(self.state) as private:
            self.assertEqual(private.detail("acceptances", acceptance_id), acceptance)
        # The new local task uses the same explicit reviewer configuration, but
        # a different immutable task identity and an entirely fresh workspace.
        next_spec = self.spec()
        next_spec["review"] = dict(spec["review"])
        from taskalong.validation import seal
        next_run, _ = self.submit(seal("task-spec", next_spec), key="after-accepted")
        self.start(next_run, key="new-start-after-accepted")
        finished = self.wait(next_run["run_id"])
        self.assertEqual(finished["state"], "accepted")
        self.assertGreater(finished["lease_generation"], retired["lease_generation"])
        self.assertNotEqual(finished["workspace_id"], retired["workspace_id"])
        with self.assertRaises(TaskAlongError) as revoked:
            self.service.verify(retired["run_id"], operation_key="retired-reverify", expected_revision=retired["revision"])
        self.assertEqual(revoked.exception.code, "lease_retired")

    def test_cancel_before_dispatch_reconciles_without_starting_a_worker(self):
        run, _ = self.submit()
        requested = self.service.cancel(run["run_id"], operation_key="cancel-created", expected_revision=run["revision"])
        stopped = self.service.reconcile(run["run_id"], operation_key="reconcile-cancel", expected_revision=requested["revision"])
        self.assertEqual(stopped["state"], "cancelled")
        self.assertIsNone(stopped["active_attempt_id"])
        self.assertFalse(stopped["attempts"])
        self.assertFalse(stopped["pending_effect_ids"])
        self.assertFalse(self.invocations())
        repeated = self.service.reconcile(run["run_id"], operation_key="reconcile-cancel", expected_revision=0)
        self.assertEqual(repeated, stopped)
        confirmations = [e for e in self.service.events(run["run_id"]) if e["type"] == "cancel.confirmed"]
        self.assertEqual(len(confirmations), 1)
        self.assertTrue(confirmations[0]["payload"]["local_cessation"])

    def test_uncertain_review_cancellation_never_confirms_local_cessation(self):
        run, _ = self.submit()
        self.start(run)
        stopped = self.wait(run["run_id"])
        self.assertIn("required_review_missing", {b["code"] for b in stopped["blockers"]})
        config = self.root / "uncertain-review.yml"
        config.write_text("synthetic review configuration\n")
        self.service.configure_review(config, fixture_response=config, executable=self.executable)

        def uncertain_review(*args, **kwargs):
            current = self.service.inspect(run["run_id"])
            self.service.cancel(run["run_id"], operation_key="cancel-review", expected_revision=current["revision"])
            raise TaskAlongError("review_process_unreconciled", "Synthetic missing cessation receipt.", exit_code=5, effect_outcome="uncertain")

        with patch("taskalong.integrations.reviewsensei.ReviewSenseiAdapter.review", uncertain_review):
            observed = self.service.verify(run["run_id"], operation_key="verify-uncertain", expected_revision=stopped["revision"])
        self.assertEqual(observed["state"], "blocked")
        self.assertTrue(observed["pending_effect_ids"])
        self.assertIsNone(observed["acceptance_id"])
        self.assertEqual(observed["blockers"][0]["effect_outcome"], "uncertain")
        self.assertFalse([e for e in self.service.events(run["run_id"]) if e["type"] == "cancel.confirmed"])
        for effect_id in observed["pending_effect_ids"]:
            effect = self.service._store.detail("effects", effect_id)
            self.assertEqual(effect["kind"], "verifier.capture")
            self.assertEqual(effect["phase"], "unknown")
        with self.assertRaises(TaskAlongError) as caught:
            self.service.reconcile(run["run_id"], operation_key="reconcile-unknown", expected_revision=observed["revision"])
        self.assertEqual(caught.exception.effect_outcome, "uncertain")

    def test_cancel_is_requested_then_confirmed_and_terminal_run_cannot_resume(self):
        self.set_mode("hang")
        run, _ = self.submit()
        self.start(run)
        running = self.wait(run["run_id"], predicate=lambda item: item["state"] == "running" and len(self.invocations()) == 1)
        requested = self.service.cancel(run["run_id"], operation_key="cancel-once", expected_revision=running["revision"])
        self.assertEqual(requested["state"], "cancel_pending")
        repeated = self.service.cancel(run["run_id"], operation_key="cancel-once", expected_revision=0)
        self.assertEqual(repeated["revision"], requested["revision"])
        finished = self.wait(run["run_id"], states=("cancelled",))
        self.assertIsNone(finished["active_attempt_id"])
        with self.assertRaises(TaskAlongError) as caught:
            self.service.resume(run["run_id"], mode="restart", operation_key="terminal-restart", expected_revision=finished["revision"])
        self.assertEqual(caught.exception.exit_code, 3)
        self.assertEqual(len(self.invocations()), 1)
        events = self.service.events(run["run_id"])
        self.assertEqual(sum(item["type"] == "cancel.requested" for item in events), 1)
        self.assertEqual(sum(item["type"] == "cancel.confirmed" for item in events), 1)

    def test_stopped_malformed_result_restarts_explicitly_with_new_attempt_and_fence(self):
        self.set_mode("duplicate-result")
        run, _ = self.submit()
        self.start(run)
        failed = self.wait(run["run_id"])
        self.assertEqual(failed["state"], "blocked")
        self.assertIsNone(failed["active_attempt_id"])
        self.assertIsNone(failed["acceptance_id"])
        before = failed["budget_consumed"]
        self.set_mode("good")
        resumed = self.service.resume(run["run_id"], mode="restart", operation_key="explicit-restart", expected_revision=failed["revision"])
        finished = self.wait(run["run_id"])
        self.assertEqual(finished["state"], "blocked")
        self.assertIn("required_review_missing", {item["code"] for item in finished["blockers"]})
        self.assertEqual(len(finished["attempts"]), 2)
        self.assertEqual(finished["attempts"][1]["mode"], "restart")
        self.assertNotEqual(finished["attempts"][0]["attempt_id"], finished["attempts"][1]["attempt_id"])
        self.assertEqual(finished["lease_generation"], failed["lease_generation"] + 1)
        self.assertGreater(finished["budget_consumed"]["active_seconds"], before["active_seconds"])
        self.assertEqual(finished["budget_consumed"]["attempts"], 2)
        self.assertEqual(before["input_tokens"], 19)
        self.assertEqual(before["output_tokens"], 7)
        self.assertEqual(finished["budget_consumed"]["input_tokens"], 38)
        self.assertEqual(finished["budget_consumed"]["output_tokens"], 14)
        self.assertIsNone(finished["budget_consumed"]["cost_usd"])
        self.assertEqual(len(self.invocations()), 2)

    def test_repeated_failed_attempts_cannot_reset_persisted_budget(self):
        self.set_mode("duplicate-result")
        run, _ = self.submit(self.spec(attempt_seconds=5, total_seconds=10))
        self.start(run)
        failed = self.wait(run["run_id"])
        self.service.resume(run["run_id"], mode="restart", operation_key="second-attempt", expected_revision=failed["revision"])
        exhausted = self.wait(run["run_id"])
        self.assertEqual(exhausted["budget_consumed"]["attempts"], 2)
        with self.assertRaises(TaskAlongError) as caught:
            self.service.resume(run["run_id"], mode="restart", operation_key="third-attempt", expected_revision=exhausted["revision"])
        self.assertEqual(caught.exception.code, "budget_exhausted")
        self.assertEqual(len(self.invocations()), 2)

    def test_unknown_or_overflowing_usage_never_becomes_a_known_run_total(self):
        for first_mode, second_mode in (("duplicate-result", "unknown-usage"),
                                        ("unknown-usage-invalid-result", "good"),
                                        ("max-usage-invalid-result", "good")):
            with self.subTest(first=first_mode, second=second_mode):
                # Each sequence owns a separate repository/store and actual
                # fixture processes; no usage or completed-store call is mocked.
                fixture = type("UsageFixture", (ServiceFixture, unittest.TestCase), {})()
                fixture.setUp()
                try:
                    fixture.set_mode(first_mode)
                    run, _ = fixture.submit()
                    fixture.start(run)
                    first = fixture.wait(run["run_id"])
                    self.assertIsNone(first["active_attempt_id"])
                    fixture.set_mode(second_mode)
                    fixture.service.resume(run["run_id"], mode="restart", operation_key="usage-restart", expected_revision=first["revision"])
                    final = fixture.wait(run["run_id"])
                    self.assertEqual(final["budget_consumed"]["attempts"], 2)
                    self.assertIsNone(final["budget_consumed"]["input_tokens"])
                    self.assertIsNone(final["budget_consumed"]["output_tokens"])
                    self.assertIsNone(final["budget_consumed"]["cost_usd"])
                    # A repeated operation key cannot count the same attempt a
                    # second time, even with an old expected revision.
                    fixture.service.resume(run["run_id"], mode="restart", operation_key="usage-restart", expected_revision=0)
                    self.assertEqual(fixture.service.inspect(run["run_id"])["budget_consumed"], final["budget_consumed"])
                    self.assertEqual(len(fixture.invocations()), 2)
                finally:
                    fixture.tearDown()


if __name__ == "__main__":
    unittest.main()
