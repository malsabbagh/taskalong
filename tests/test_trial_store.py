"""E1 format fence over generated stores; no production state is opened."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
import sqlite3
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.store import Store
from taskalong.validation import seal_versioned
from test_antigravity_store import upgrade_through
from test_trial_contracts import example_trial_config, example_trial_spec


class TrialStoreFenceTests(unittest.TestCase):
    def test_format8_is_ordered_backed_up_and_excludes_actual_format7_reader(self):
        from taskalong.contracts import RuntimeProfile
        from taskalong.maintenance import verify_backup, verify_restored
        from taskalong.trial import TrialDriverConfig
        from test_contracts import example_profile, example_spec
        config = TrialDriverConfig.from_dict(seal_versioned("driver-config", example_trial_config(), version="2.8"))
        task = seal_versioned("task-spec", example_trial_spec(), version="2.8")
        legacy = RuntimeProfile.from_dict(example_profile())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            state = root / "state"
            with Store(state) as store:
                store.register_profile(legacy.to_dict())
                original = store.create_run(example_spec(), "old-task")
                blob = store.put_blob(b"private checkpoint preserved")
            with Store.maintenance(state) as store:
                with self.assertRaises(TaskAlongError) as order:
                    store.upgrade(operation_key="skip-fence", backup_dir=root / "backup-8",
                                  restore_dir=root / "restore-8", target_version=8)
                self.assertEqual(order.exception.code, "store_migration_order")
                self.assertFalse((root / "backup-8").exists())
                upgrade_through(store, root, 7)
                prior = [tuple(r) for r in store.db.execute("SELECT * FROM store_migrations ORDER BY number")]
                request = dict(operation_key="e1-fence", backup_dir=root / "backup-8",
                               restore_dir=root / "restore-8", target_version=8)
                receipt = store.upgrade(**request)
                self.assertEqual(store.upgrade(**request), receipt)
                self.assertEqual(store.format_version, 8)
                self.assertEqual(store.db.execute("PRAGMA user_version").fetchone()[0], 8)
                self.assertEqual([tuple(r) for r in store.db.execute("SELECT * FROM store_migrations WHERE number<8 ORDER BY number")], prior)
                backup = verify_backup(root / "backup-8", expected_digest=receipt["backup_manifest_digest"])
                restored = verify_restored(root / "backup-8", root / "restore-8", expected_digest=backup["digest"])
                self.assertEqual(backup["database"]["user_version"], 7)
                self.assertTrue(restored["quarantined"])
                self.assertTrue(store.record_document(config, operation_key="config-history")["historical_only"])
                self.assertEqual(store.document_history("driver_config", config.digest), (config,))
                trial_run = store.create_run(task, "trial-task-history")
                self.assertEqual(store.spec(trial_run), task)
                self.assertEqual(store.run(original["run_id"]), original)
                self.assertEqual(store.get_blob(blob["sha256"]), b"private checkpoint preserved")
                with self.assertRaises(sqlite3.IntegrityError):
                    store.db.execute("UPDATE document_history SET identity='changed'")
            fixture = Path(__file__).parent / "fixtures/legacy_store_v7.py"
            self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(),
                             "b14a1c2a3b7ac0d0421549daec1548719cc7218d03335b9ffedaa3a9095484eb")
            spec = importlib.util.spec_from_file_location("taskalong._legacy_store_v7", fixture)
            predecessor = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(predecessor)
            before = {p.name: p.read_bytes() for p in state.glob("state.sqlite3*")}
            with self.assertRaises(TaskAlongError) as old:
                predecessor.Store(state)
            self.assertEqual(old.exception.code, "unsupported_store_version")
            self.assertEqual({p.name: p.read_bytes() for p in state.glob("state.sqlite3*")}, before)
            with Store(state) as store:
                self.assertEqual(store.format_version, 8)
                self.assertEqual(store.run(original["run_id"]), original)
                self.assertEqual(store.spec(trial_run), task)
                self.assertEqual(store.document_history("driver_config", config.digest), (config,))

    def test_interruption_before_migration_keeps_format7_and_reuses_verified_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with Store(root / "state"):
                pass
            with Store.maintenance(root / "state") as store:
                upgrade_through(store, root, 7)
                prior = [tuple(r) for r in store.db.execute("SELECT * FROM store_migrations ORDER BY number")]
                request = dict(operation_key="interrupted-e1-fence", backup_dir=root / "backup-8",
                               restore_dir=root / "restore-8", target_version=8)
                with patch("taskalong.maintenance.restore_backup", side_effect=InterruptedError("controlled interruption")):
                    with self.assertRaises(TaskAlongError) as interrupted:
                        store.upgrade(**request)
                self.assertEqual(interrupted.exception.code, "store_upgrade_failed")
                self.assertEqual(store.format_version, 7)
                self.assertEqual(store.db.execute("PRAGMA user_version").fetchone()[0], 7)
                self.assertEqual([tuple(r) for r in store.db.execute("SELECT * FROM store_migrations ORDER BY number")], prior)
                backup_bytes = (root / "backup-8/backup-manifest.json").read_bytes()
            with Store.maintenance(root / "state") as store:
                receipt = store.upgrade(**request)
                self.assertEqual(receipt["to_version"], 8)
                self.assertEqual((root / "backup-8/backup-manifest.json").read_bytes(), backup_bytes)

    def test_unfenced_task_and_history_refuse_before_any_document_or_operation_write(self):
        from taskalong.trial import TrialDriverConfig
        config = TrialDriverConfig.from_dict(seal_versioned("driver-config", example_trial_config(), version="2.8"))
        task = seal_versioned("task-spec", example_trial_spec(), version="2.8")
        for version in (1, 7):
            with self.subTest(format=version), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                with Store(root / "state"):
                    pass
                if version > 1:
                    with Store.maintenance(root / "state") as store:
                        upgrade_through(store, root, version)
                with Store(root / "state") as store:
                    tables = [r[0] for r in store.db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
                    before = {name: [tuple(r) for r in store.db.execute('SELECT * FROM "' + name + '"')]
                              for name in tables}
                    for label, call in (("task", lambda: store.create_run(task, "unfenced-e1")),
                                        ("history", lambda: store.record_document(config, operation_key="unfenced-e1-history"))):
                        with self.subTest(action=label):
                            with self.assertRaises(TaskAlongError) as failure:
                                call()
                            self.assertEqual(failure.exception.code, "store_upgrade_required")
                    self.assertEqual({name: [tuple(r) for r in store.db.execute('SELECT * FROM "' + name + '"')]
                                      for name in tables}, before)
                    self.assertEqual(store.format_version, version)


if __name__ == "__main__":
    unittest.main()
