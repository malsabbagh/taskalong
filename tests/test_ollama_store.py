"""Explicit format-5 maintenance preserves history and excludes format-4 clients."""
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

from taskalong.errors import TaskAlongError
from taskalong.store import Store
from taskalong.validation import seal_versioned
from test_claude_driver import example_driver_config
from test_contracts import example_spec
from test_ollama_profiles import local_profile, route_observation


def ollama_config():
    from taskalong.executors.config import OllamaDriverConfig
    profile = local_profile()
    return OllamaDriverConfig.from_dict(seal_versioned("driver-config", example_driver_config() | {
        "driver_version": "claude-print-ollama-fixture-1", "projection": "claude-ollama-fixture/1",
        "wire_version": "2.4", "credential_ref": None, "provider_profile_digest": profile.digest,
        "fixture_route_observation": route_observation(profile)}, version="2.4"))


def upgrade_to(store, root, target):
    for version in range(store.format_version + 1, target + 1):
        store.upgrade(operation_key="upgrade-" + str(version), backup_dir=root/("backup" + str(version)),
                      restore_dir=root/("restore" + str(version)), target_version=version)


class OllamaStoreFenceTests(unittest.TestCase):
    def test_format5_cannot_skip_migrations_or_overwrite_a_restore_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with Store(root/"state"):
                pass
            with Store.maintenance(root/"state") as store:
                with self.assertRaises(TaskAlongError) as order:
                    store.upgrade(operation_key="skip", backup_dir=root/"backup5", restore_dir=root/"restore5", target_version=5)
                self.assertEqual(order.exception.code, "store_migration_order")
                self.assertEqual(store.format_version, 1)
                self.assertEqual(store.db.execute("SELECT count(*) FROM operations").fetchone()[0], 0)
                self.assertFalse((root/"backup5").exists())
                upgrade_to(store, root, 4)
                previous = [tuple(row) for row in store.db.execute("SELECT * FROM store_migrations ORDER BY number")]
                destination = root/"restore5"
                destination.mkdir(mode=0o700)
                sentinel = destination/"foreign.txt"
                sentinel.write_bytes(b"existing destination belongs to another operation")
                sentinel.chmod(0o600)
                with self.assertRaises(TaskAlongError) as restore:
                    store.upgrade(operation_key="foreign", backup_dir=root/"backup5", restore_dir=destination, target_version=5)
                self.assertEqual(restore.exception.code, "restore_integrity")
                self.assertEqual(store.format_version, 4)
                self.assertEqual(store.db.execute("PRAGMA user_version").fetchone()[0], 4)
                self.assertEqual([tuple(row) for row in store.db.execute("SELECT * FROM store_migrations ORDER BY number")], previous)
                self.assertEqual(sentinel.read_bytes(), b"existing destination belongs to another operation")
                self.assertTrue((root/"backup5").is_dir())

    def test_new_task_cannot_be_persisted_before_the_fence(self):
        task = seal_versioned("task-spec", example_spec() | {"schema_version": "2.4", "execution": {
            "binding_digest": "a" * 64, "driver_config_digest": ollama_config().digest}}, version="2.4")
        for version in (1, 4):
            with self.subTest(format_version=version), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                with Store(root/"state"):
                    pass
                if version > 1:
                    with Store.maintenance(root/"state") as store:
                        upgrade_to(store, root, version)
                with Store(root/"state") as store:
                    self.assertEqual(store.format_version, version)
                    operations = [tuple(row) for row in store.db.execute("SELECT * FROM operations")]
                    with self.assertRaises(TaskAlongError) as early:
                        store.create_run(task, "early")
                    self.assertEqual(early.exception.code, "store_upgrade_required")
                    self.assertEqual(store.db.execute("SELECT count(*) FROM runs").fetchone()[0], 0)
                    self.assertEqual(store.db.execute("SELECT count(*) FROM task_specs").fetchone()[0], 0)
                    self.assertEqual([tuple(row) for row in store.db.execute("SELECT * FROM operations")], operations)

    def test_backed_up_history_requires_format5_and_actual_format4_client_refuses(self):
        config = ollama_config()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            state = root/"state"
            with Store(state) as store:
                original = store.create_run(example_spec(), "original")
                blob = store.put_blob(b"original private fixture data", media_type="text/plain")
            with Store.maintenance(state) as store:
                upgrade_to(store, root, 4)
                with self.assertRaises(TaskAlongError) as early:
                    store.record_document(config, operation_key="unfenced")
                self.assertEqual(early.exception.code, "store_upgrade_required")
                previous = [tuple(row) for row in store.db.execute("SELECT * FROM store_migrations ORDER BY number")]
                request = dict(operation_key="ollama-fence", backup_dir=root/"backup5", restore_dir=root/"restore5", target_version=5)
                receipt = store.upgrade(**request)
                self.assertEqual((receipt["from_version"], receipt["to_version"]), (4, 5))
                self.assertEqual(store.upgrade(**request), receipt)
                self.assertEqual([tuple(row) for row in store.db.execute("SELECT * FROM store_migrations WHERE number<5 ORDER BY number")], previous)
                self.assertTrue(store.record_document(config, operation_key="fenced")["historical_only"])
                self.assertEqual(store.document_history("driver_config", config.digest), (config,))
                from taskalong.executors.config import DriverConfig
                legacy = DriverConfig.from_dict(seal_versioned("driver-config", example_driver_config(), version="2.3"))
                store.record_document(legacy, operation_key="legacy-on-new-format")
                self.assertEqual(store.document_history("driver_config", legacy.digest), (legacy,))
                self.assertEqual(store.run(original["run_id"]), original)
                self.assertEqual(store.get_blob(blob["sha256"]), b"original private fixture data")
            # Exact accepted M5 implementation, rather than a model of its fence.
            fixture = Path(__file__).parent/"fixtures/legacy_store_v4.py"
            self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(), "b620efd82da709431ed7fc09e7c9ab1396fbc09bf5ab1302666055d6c12a4c20")
            spec = importlib.util.spec_from_file_location("taskalong._legacy_store_v4", fixture)
            predecessor = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(predecessor)
            before = (state/"state.sqlite3").read_bytes()
            auxiliary = {item.name: item.read_bytes() for item in state.glob("state.sqlite3-*")}
            with self.assertRaises(TaskAlongError) as old:
                predecessor.Store(state)
            self.assertEqual(old.exception.code, "unsupported_store_version")
            self.assertEqual((state/"state.sqlite3").read_bytes(), before)
            self.assertEqual({item.name: item.read_bytes() for item in state.glob("state.sqlite3-*")}, auxiliary)
            with Store(state) as store:
                self.assertEqual(store.format_version, 5)
                self.assertEqual(store.run(original["run_id"]), original)
                self.assertEqual(store.document_history("driver_config", config.digest), (config,))


if __name__ == "__main__":
    unittest.main()
