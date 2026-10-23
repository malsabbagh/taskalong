"""Operation receipts serialize real competing clients without lost updates."""

import concurrent.futures
import threading
import unittest

from taskalong.errors import TaskAlongError
from taskalong.store import Store
from taskalong.validation import seal
from test_store import StoreFixture


class IdempotencyTests(StoreFixture):
    def test_same_submit_key_returns_identity_and_changed_input_conflicts(self):
        self.assertEqual(self.store.create_run(self.spec, "submit"), self.run)
        changed = seal("task-spec", self.spec | {"goal": "A changed task."})
        with self.assertRaises(TaskAlongError) as failure:
            self.store.create_run(changed, "submit")
        self.assertEqual(failure.exception.code, "operation_key_conflict")
        with self.assertRaises(TaskAlongError) as failure:
            self.store.create_run(changed, "other-submit-key")
        self.assertEqual(failure.exception.code, "task_revision_conflict")
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM runs").fetchone()[0], 1)

    def test_prior_receipt_is_checked_before_expected_revision(self):
        changed = self.store.mutate(self.run["run_id"], "prepare", "once", 1,
                                    {"phase": "ready"}, self.change)
        def forbidden_repeat(*_):
            self.fail("An already committed mutation was dispatched again")
        repeated = self.store.mutate(self.run["run_id"], "prepare", "once", 900,
                                     {"phase": "ready"}, forbidden_repeat)
        self.assertEqual(repeated, changed)
        self.assertEqual(len(self.store.events(self.run["run_id"])), 2)
        with self.assertRaises(TaskAlongError) as failure:
            self.store.mutate(self.run["run_id"], "prepare", "once", 2,
                              {"phase": "changed-semantic-input"}, self.change)
        self.assertEqual(failure.exception.code, "operation_key_conflict")

    def test_competing_revision_clients_commit_only_one_state_event_pair(self):
        barrier = threading.Barrier(2)
        def client(index):
            with Store(self.state) as store:
                barrier.wait(timeout=5)
                try:
                    value = store.mutate(self.run["run_id"], "prepare", f"client-{index}", 1,
                                          {"client": index}, self.change)
                    return "committed", value["revision"]
                except TaskAlongError as failure:
                    return failure.code, failure.exit_code
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(client, [1, 2]))
        self.assertEqual(sorted(item[0] for item in results), ["committed", "revision_conflict"])
        self.assertEqual(self.store.run(self.run["run_id"])["revision"], 2)
        self.assertEqual([e["seq"] for e in self.store.events(self.run["run_id"])], [1, 2])

    def test_concurrent_same_key_has_one_effect_owner(self):
        barrier = threading.Barrier(2)
        dispatched = []
        def client(_):
            with Store(self.state) as store:
                barrier.wait(timeout=5)
                def change(run, db):
                    dispatched.append("effect")
                    run["state"] = "ready"
                return store.mutate(self.run["run_id"], "prepare", "shared", 1, {"subject": "same"}, change)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(client, [1, 2]))
        self.assertEqual(results[0], results[1])
        self.assertEqual(dispatched, ["effect"])
        self.assertEqual(len(self.store.events(self.run["run_id"])), 2)

    def test_concurrent_first_clients_share_one_initialized_store(self):
        for round_number in range(8):
            fresh = self.root / ("concurrent-new-store-" + str(round_number))
            barrier = threading.Barrier(6)
            def client(_):
                barrier.wait(timeout=5)
                with Store(fresh) as store:
                    return store.store_uuid
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                identities = list(pool.map(client, range(6)))
            self.assertEqual(len(set(identities)), 1)
            with Store(fresh) as reopened:
                self.assertEqual(reopened.db.execute("PRAGMA user_version").fetchone()[0], 1)
                self.assertEqual(reopened.db.execute("SELECT count(*) FROM metadata").fetchone()[0], 5)
                self.assertEqual(reopened.db.execute(
                    "SELECT value FROM metadata WHERE key = 'application'"
                ).fetchone()[0], "taskalong")

    def test_invalid_keys_are_rejected_before_mutation(self):
        for key in ("", "x" * 129, "bad\nkey", "bad\u0085key", True):
            with self.subTest(key=repr(key)), self.assertRaises(TaskAlongError):
                self.store.mutate(self.run["run_id"], "prepare", key, 1, {}, self.change)
        self.assertEqual(self.store.run(self.run["run_id"]), self.run)


if __name__ == "__main__":
    unittest.main()
