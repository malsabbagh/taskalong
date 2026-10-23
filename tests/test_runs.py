"""Public lifecycle and detached execution through the real service and CLI."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from taskalong.api import RunService
from taskalong.errors import TaskAlongError
from helpers import ServiceFixture, git


class RunTests(ServiceFixture, unittest.TestCase):
    def test_completed_worker_and_real_checks_stop_at_required_review(self):
        run, spec = self.submit()
        self.start(run)
        finished = self.wait(run["run_id"])
        self.assertEqual(finished["state"], "blocked")
        self.assertIn("required_review_missing", {item["code"] for item in finished["blockers"]})
        self.assertIsNone(finished["acceptance_id"])
        self.assertIsNone(finished["active_attempt_id"])
        self.assertEqual(len(finished["attempts"]), 1)
        self.assertEqual(len(self.invocations()), 1)
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.base)
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")
        evidence = self.export(run["run_id"])["evidence"]
        self.assertEqual({item["type"] for item in evidence}, {"scope", "command"})
        self.assertTrue(all(item["result"] == "passed" for item in evidence))
        self.assertTrue(all(item["subject"]["candidate_commit"] == finished["candidate"]["commit"] for item in evidence))
        events = self.service.events(run["run_id"])
        self.assertEqual([item["seq"] for item in events], list(range(1, len(events) + 1)))
        self.assertEqual(sum(item["type"] == "executor.started" for item in events), 1)

    def test_repeated_start_key_returns_prior_receipt_without_another_execution(self):
        run, _ = self.submit()
        first = self.start(run, key="same-start")
        second = self.service.start(run["run_id"], operation_key="same-start", expected_revision=999999)
        self.assertEqual(first["run_id"], second["run_id"])
        self.assertEqual(first["attempts"], second["attempts"])
        finished = self.wait(run["run_id"])
        with RunService(self.state) as fresh:
            fresh.start(run["run_id"], operation_key="same-start", expected_revision=0)
        self.assertEqual(len(self.invocations()), 1)
        self.assertEqual(len(finished["attempts"]), 1)

    def test_portable_permissions_do_not_replace_operator_authority(self):
        run, _ = self.submit(authorize=False)
        with self.assertRaises(TaskAlongError) as caught:
            self.start(run)
        self.assertEqual(caught.exception.exit_code, 3)
        self.assertEqual(self.service.inspect(run["run_id"])["state"], "created")
        self.assertEqual(self.invocations(), [])

    def test_status_and_events_never_launch_a_created_run(self):
        run, _ = self.submit()
        for _ in range(3):
            with RunService(self.state) as fresh:
                self.assertEqual(fresh.inspect(run["run_id"])["state"], "created")
                self.assertTrue(fresh.events(run["run_id"]))
        self.assertEqual(self.invocations(), [])

    def test_actual_cli_client_death_does_not_cancel_its_detached_supervisor(self):
        self.barrier_file.touch()
        run, _ = self.submit()
        # Run the actual CLI dispatcher. SIGKILL happens before this outer
        # process can report a normal exit, while the provider is held at a
        # separate synthetic barrier. The supervisor must remain independent.
        program = "import os,signal,sys; from taskalong.cli import main; code=main(sys.argv[1:]); sys.stdout.flush(); os.kill(os.getpid(),signal.SIGKILL)"
        client = subprocess.run([sys.executable, "-c", program, "--state-dir", str(self.state), "start", run["run_id"],
                                 "--expected-revision", str(run["revision"]), "--key", "outer-killed", "--json"],
                                cwd=self.root, env=dict(os.environ), capture_output=True, text=True, timeout=15)
        self.assertEqual(client.returncode, -9, client.stderr)
        self.assertEqual(json.loads(client.stdout)["kind"], "command_result")
        running = self.wait(run["run_id"], states=("running",))
        self.assertEqual(running["state"], "running")
        self.release_file.touch()
        finished = self.wait(run["run_id"])
        self.assertEqual(finished["state"], "blocked")
        self.assertEqual(len(finished["attempts"]), 1)
        self.assertEqual(len(self.invocations()), 1)
        self.assertIsNone(finished["active_attempt_id"])


if __name__ == "__main__":
    unittest.main()
