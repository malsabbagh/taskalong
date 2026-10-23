"""Shared durable-driver contract; each driver supplies an explicit fixture.

Add future qualified driver fixture classes to this runner. Binary discovery
does not add a case or a registry entry. These cases prove synthetic protocol
behavior only, never vendor runtime isolation or provider cancellation.
"""
import unittest

from taskalong.errors import TaskAlongError
from taskalong.validation import seal_versioned
from test_execution_bindings import BindingFixture


class DurableDriverContract:
    def configured_task(self):
        self.service.configure_execution(**self.configuration)
        return self.submit(self.task)[0]

    def test_start_observe_and_result_keep_worker_and_acceptance_separate(self):
        run = self.configured_task()
        self.start(run)
        stopped = self.wait(run["run_id"])
        self.assertEqual(len(self.invocations()), 1)
        self.assertEqual(len(stopped["attempts"]), 1)
        view = self.service.result(run["run_id"])
        self.assertEqual(view["outcome"], "worker_completed")
        self.assertFalse(view["independently_accepted"])
        self.assertFalse(view["production_dispatch_allowed"])

    def test_cancel_owned_worker_prevents_acceptance(self):
        self.barrier_file.touch()
        run = self.configured_task()
        self.start(run)
        running = self.wait(run["run_id"], states=("running",))
        # A durable process receipt precedes gate release; prove the target
        # actually began before exercising cancellation of a running fixture.
        running = self.wait(run["run_id"], predicate=lambda observed: bool(self.invocations()))
        self.service.cancel(run["run_id"], operation_key="contract-cancel", expected_revision=running["revision"])
        stopped = self.wait(run["run_id"])
        self.assertEqual(stopped["state"], "cancelled")
        self.assertEqual(len(self.invocations()), 1)
        self.assertIsNone(stopped["acceptance_id"])
        self.assertEqual(stopped["evidence_ids"], [])
        self.assertEqual(self.service.result(run["run_id"])["outcome"], "cancelled")

    def test_unsupported_native_resume_never_restarts(self):
        run = self.configured_task()
        with self.assertRaises(TaskAlongError) as failure:
            self.service.resume(run["run_id"], mode="native", operation_key="contract-native", expected_revision=run["revision"])
        self.assertEqual(failure.exception.code, "native_resume_unsupported")
        self.assertEqual(self.invocations(), [])
        self.assertEqual(self.service.inspect(run["run_id"])["attempts"], [])

    def test_production_task_cannot_use_fixture_qualification(self):
        self.service.configure_execution(**self.configuration)
        task = seal_versioned("task-spec", self.task | {"qualification":"production"}, version="2.2")
        with self.assertRaises(TaskAlongError) as failure:
            self.service.submit(task, operation_key="contract-production")
        self.assertEqual(failure.exception.code, "execution_identity_mismatch")
        self.assertEqual(self.invocations(), [])


class CodexFixtureContractTests(DurableDriverContract, BindingFixture, unittest.TestCase):
    """Only the explicitly registered fake Codex wire protocol is admitted."""


if __name__ == "__main__":
    unittest.main()
