"""Cursor executable documents require an explicit backed-up format-6 fence."""
from pathlib import Path
import hashlib
import importlib.util
import tempfile
import unittest

from taskalong.errors import TaskAlongError
from taskalong.executors.config import CursorDriverConfig
from taskalong.store import Store
from taskalong.validation import seal_versioned
from test_contracts import example_profile, example_spec
from test_cursor_protocol import example_cursor_config


def upgrade_through(store, root, target):
    for version in range(store.format_version + 1, target + 1):
        store.upgrade(operation_key="upgrade-" + str(version), backup_dir=root / ("backup-" + str(version)),
                      restore_dir=root / ("restore-" + str(version)), target_version=version)


class CursorStoreFenceTests(unittest.TestCase):
    def test_format6_requires_order_and_a_fresh_restore_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with Store(root / "state"):
                pass
            with Store.maintenance(root / "state") as store:
                with self.assertRaises(TaskAlongError) as order:
                    store.upgrade(operation_key="skip-cursor-fence", backup_dir=root / "backup-6",
                                  restore_dir=root / "restore-6", target_version=6)
                self.assertEqual(order.exception.code, "store_migration_order")
                self.assertEqual(store.format_version, 1)
                self.assertEqual(store.db.execute("SELECT count(*) FROM operations").fetchone()[0], 0)
                self.assertFalse((root / "backup-6").exists())
                upgrade_through(store, root, 5)
                prior = [tuple(row) for row in store.db.execute("SELECT * FROM store_migrations ORDER BY number")]
                restored = root / "restore-6"
                restored.mkdir(mode=0o700)
                sentinel = restored / "foreign.txt"
                sentinel.write_bytes(b"existing restore destination")
                sentinel.chmod(0o600)
                with self.assertRaises(TaskAlongError) as destination:
                    store.upgrade(operation_key="existing-restore", backup_dir=root / "backup-6",
                                  restore_dir=restored, target_version=6)
                self.assertEqual(destination.exception.code, "restore_integrity")
                self.assertEqual(store.format_version, 5)
                self.assertEqual(store.db.execute("PRAGMA user_version").fetchone()[0], 5)
                self.assertEqual([tuple(row) for row in store.db.execute("SELECT * FROM store_migrations ORDER BY number")], prior)
                self.assertEqual(sentinel.read_bytes(), b"existing restore destination")
                self.assertTrue((root / "backup-6").is_dir())

    def test_unfenced_cursor_task_and_history_refuse_without_mutation(self):
        config = CursorDriverConfig.from_dict(seal_versioned("driver-config", example_cursor_config(), version="2.5"))
        task = seal_versioned("task-spec", example_spec() | {"schema_version": "2.5", "execution": {
            "binding_digest": "a" * 64, "driver_config_digest": config.digest}}, version="2.5")
        for version in (1, 5):
            with self.subTest(format_version=version), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                with Store(root / "state"):
                    pass
                if version > 1:
                    with Store.maintenance(root / "state") as store:
                        upgrade_through(store, root, version)
                with Store(root / "state") as store:
                    operations = [tuple(row) for row in store.db.execute("SELECT * FROM operations")]
                    with self.assertRaises(TaskAlongError) as task_failure:
                        store.create_run(task, "unfenced-cursor-task")
                    self.assertEqual(task_failure.exception.code, "store_upgrade_required")
                    with self.assertRaises(TaskAlongError) as history_failure:
                        store.record_document(config, operation_key="unfenced-cursor-config")
                    self.assertEqual(history_failure.exception.code, "store_upgrade_required")
                    self.assertEqual(store.db.execute("SELECT count(*) FROM runs").fetchone()[0], 0)
                    self.assertEqual(store.db.execute("SELECT count(*) FROM task_specs").fetchone()[0], 0)
                    self.assertEqual([tuple(row) for row in store.db.execute("SELECT * FROM operations")], operations)
                    self.assertEqual(store.format_version, version)

    def test_backed_up_format6_preserves_history_and_exact_format5_client_refuses(self):
        from taskalong.contracts import RuntimeProfile
        config = CursorDriverConfig.from_dict(seal_versioned("driver-config", example_cursor_config(), version="2.5"))
        legacy = RuntimeProfile.from_dict(example_profile())
        task = seal_versioned("task-spec", example_spec() | {"task_id": "cursor-task", "schema_version": "2.5", "execution": {
            "binding_digest": "a" * 64, "driver_config_digest": config.digest}}, version="2.5")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            state = root / "state"
            with Store(state) as store:
                original = store.create_run(example_spec(), "original")
                blob = store.put_blob(b"retained synthetic fixture bytes", media_type="text/plain")
                store_uuid = store.store_uuid
            with Store.maintenance(state) as store:
                upgrade_through(store, root, 5)
                store.record_document(legacy, operation_key="legacy-profile")
                prior = [tuple(row) for row in store.db.execute("SELECT * FROM store_migrations ORDER BY number")]
                request = dict(operation_key="cursor-fence", backup_dir=root / "backup-6",
                               restore_dir=root / "restore-6", target_version=6)
                receipt = store.upgrade(**request)
                self.assertEqual((receipt["from_version"], receipt["to_version"]), (5, 6))
                self.assertEqual(store.upgrade(**request), receipt)
                self.assertEqual(store.format_version, 6)
                self.assertEqual(store.db.execute("PRAGMA user_version").fetchone()[0], 6)
                self.assertEqual([tuple(row) for row in store.db.execute("SELECT * FROM store_migrations WHERE number<6 ORDER BY number")], prior)
                self.assertEqual(store.store_uuid, store_uuid)
                self.assertTrue(store.record_document(config, operation_key="cursor-history")["historical_only"])
                self.assertEqual(store.document_history("driver_config", config.digest), (config,))
                self.assertEqual(store.document_history("runtime_profile", legacy.to_dict()["profile_id"]), (legacy,))
                cursor_run = store.create_run(task, "cursor-task")
                self.assertEqual(store.spec(cursor_run), task)
                self.assertEqual(store.run(original["run_id"]), original)
                self.assertEqual(store.get_blob(blob["sha256"]), b"retained synthetic fixture bytes")
            fixture = Path(__file__).parent / "fixtures/legacy_store_v5.py"
            self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(), "17af03e2f2d38628b2d0d123a6f725c4218f9b4013349ce20d8c71a4802eab91")
            spec = importlib.util.spec_from_file_location("taskalong._legacy_store_v5", fixture)
            predecessor = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(predecessor)
            before = (state / "state.sqlite3").read_bytes()
            auxiliary = {p.name: p.read_bytes() for p in state.glob("state.sqlite3-*")}
            with self.assertRaises(TaskAlongError) as old:
                predecessor.Store(state)
            self.assertEqual(old.exception.code, "unsupported_store_version")
            self.assertEqual((state / "state.sqlite3").read_bytes(), before)
            self.assertEqual({p.name: p.read_bytes() for p in state.glob("state.sqlite3-*")}, auxiliary)
            with Store(state) as store:
                self.assertEqual(store.format_version, 6)
                self.assertEqual(store.spec(cursor_run), task)
                self.assertEqual(store.run(original["run_id"]), original)
                self.assertEqual(store.document_history("driver_config", config.digest), (config,))


if __name__ == "__main__":
    unittest.main()
