"""Unavailable E1 execution refuses before legacy replay or effect machinery."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.store import Store
from taskalong.validation import seal_versioned
from taskalong.workflow import Workflow
from test_antigravity_store import upgrade_through
from test_trial_contracts import example_trial_spec


class TrialOperationalRefusalTests(unittest.TestCase):
    def test_valid_submission_refuses_before_replay_repository_or_state_changes(self):
        task = seal_versioned("task-spec", example_trial_spec(), version="2.8")
        with tempfile.TemporaryDirectory() as directory, Store(Path(directory).resolve() / "state") as store:
            before = list(store.db.iterdump())
            with patch.object(store, "operation", side_effect=AssertionError("replay reached")), \
                    patch.object(store, "repository", side_effect=AssertionError("repository reached")), \
                    patch("taskalong.workflow.inspect_repository", side_effect=AssertionError("Git reached")), \
                    patch("subprocess.Popen", side_effect=AssertionError("process reached")):
                with self.assertRaises(TaskAlongError) as failure:
                    Workflow(store).submit(task, operation_key="e1-submit")
            self.assertEqual(failure.exception.code, "trial_runtime_unqualified")
            self.assertEqual(list(store.db.iterdump()), before)

    def test_fabricated_stored_run_cannot_enter_an_old_operational_path(self):
        task = seal_versioned("task-spec", example_trial_spec(), version="2.8")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with Store(root / "state"):
                pass
            with Store.maintenance(root / "state") as store:
                upgrade_through(store, root, 8)
                run = store.create_run(task, "historical-e1")
                workflow = Workflow(store)
                common = {"operation_key": "must-not-replay", "expected_revision": run["revision"]}
                calls = {
                    "start": lambda: workflow.start(run["run_id"], **common),
                    "restart": lambda: workflow.start(run["run_id"], mode="restart", **common),
                    "native": lambda: workflow.start(run["run_id"], mode="native", **common),
                    "verify": lambda: workflow.verify(run["run_id"], **common),
                    "reconcile": lambda: workflow.reconcile(run["run_id"], **common),
                    "cancel": lambda: workflow.cancel(run["run_id"], **common),
                    "retire": lambda: workflow.retire_workspace(run["run_id"], **common),
                    "intent": lambda: workflow.publish_intent(run["run_id"]),
                    "publish": lambda: workflow.publish(run["run_id"], intent_digest="a" * 64, **common),
                    "authorize": lambda: workflow.authorize(run["run_id"], decision_digest=task["digest"], scope=["execute"]),
                }
                before = list(store.db.iterdump())
                with patch.object(store, "guard", side_effect=AssertionError("guard reached")), \
                        patch.object(store, "operation", side_effect=AssertionError("replay reached")), \
                        patch.object(store, "repository", side_effect=AssertionError("repository reached")), \
                        patch("subprocess.Popen", side_effect=AssertionError("process reached")):
                    for name, call in calls.items():
                        with self.subTest(operation=name):
                            with self.assertRaises(TaskAlongError) as failure:
                                call()
                            self.assertEqual(failure.exception.code, "trial_runtime_unqualified")
                self.assertEqual(list(store.db.iterdump()), before)


if __name__ == "__main__":
    unittest.main()
