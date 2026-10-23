"""Durable private storage behavior through the actual SQLite store."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.store import Store, identifier, _private
from taskalong.validation import digest, seal, validate
from test_contracts import example_spec


class StoreFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.state = self.root / "state"
        self.store = Store(self.state)
        self.spec = example_spec()
        self.run = self.store.create_run(self.spec, "submit")

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def change(self, run, db):
        run["state"] = "ready"


class StoreTests(StoreFixture):
    def test_new_store_has_explicit_taskalong_application_marker(self):
        row = self.store.db.execute("SELECT value FROM metadata WHERE key='application'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "taskalong")

    def test_foreign_or_untagged_store_is_rejected_without_database_mutation(self):
        for label, application in (("untagged", None), ("foreign", "synthetic.other")):
            with self.subTest(application=label):
                state = self.root / label
                with Store(state) as store:
                    store.db.execute("DELETE FROM metadata WHERE key='application'")
                    if application is not None:
                        store.db.execute("INSERT INTO metadata VALUES ('application', ?)", (application,))
                    expected = dict(store.db.execute("SELECT key,value FROM metadata"))
                database = state / "state.sqlite3"
                before = database.read_bytes()
                with self.assertRaises(TaskAlongError) as failure:
                    with Store(state):
                        pass
                self.assertEqual(failure.exception.code, "unsupported_store_application")
                self.assertEqual(database.read_bytes(), before)
                with sqlite3.connect(database) as connection:
                    self.assertEqual(dict(connection.execute("SELECT key,value FROM metadata")), expected)
                    self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)

    def test_sensitive_submission_is_rejected_before_persistence(self):
        from taskalong.workflow import Workflow
        credential = "ghp_" + "x" * 30
        for change in ({"goal": credential}, {"extensions": {"org:metadata": {"api_key": "synthetic credential"}}}):
            with self.subTest(field=next(iter(change))), self.assertRaises(TaskAlongError) as failure:
                Workflow(self.store).submit(self.spec | change, operation_key="never-retain-sensitive")
            self.assertEqual(failure.exception.code, "sensitive_input")
        stored = "".join(row[0] for row in self.store.db.execute("SELECT document FROM task_specs"))
        self.assertNotIn(credential, stored)
        self.assertNotIn("synthetic credential", stored)
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM runs").fetchone()[0], 1)

    def test_state_event_and_receipt_commit_together(self):
        observed = self.store.mutate(self.run["run_id"], "prepare", "prepare-once", 1,
                                     {"subject": self.spec["digest"]}, self.change,
                                     events=[("run.ready", {}), ("effect.prepared", {"effect": "synthetic"})])
        self.assertEqual(observed["revision"], 2)
        self.assertEqual(observed["state"], "ready")
        events = self.store.events(self.run["run_id"])
        self.assertEqual([item["seq"] for item in events], [1, 2, 3])
        self.assertEqual([item["run_revision"] for item in events], [1, 2, 2])
        self.assertEqual(self.store.operation("prepare", self.run["run_id"], "prepare-once", {"subject": self.spec["digest"]}), observed)
        with Store(self.state) as reopened:
            self.assertEqual(reopened.run(self.run["run_id"]), observed)
            self.assertEqual(reopened.events(self.run["run_id"]), events)

    def test_failed_mutation_rolls_back_state_and_all_inserted_records(self):
        def failure(run, db):
            run["state"] = "ready"
            self.store._event(db, run, "run.ready")
            raise TaskAlongError("synthetic_failure", "Expected transactional failure.", exit_code=1)
        with self.assertRaises(TaskAlongError):
            self.store.mutate(self.run["run_id"], "failing", "one", 1, {}, failure)
        self.assertEqual(self.store.run(self.run["run_id"]), self.run)
        self.assertEqual(len(self.store.events(self.run["run_id"])), 1)
        self.assertIsNone(self.store.operation("failing", self.run["run_id"], "one", {}))

    def test_private_modes_missing_blob_tamper_and_symlink_are_fail_closed(self):
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.store.db_path.stat().st_mode & 0o777, 0o600)
        receipt = self.store.put_blob(b"private synthetic result")
        path = self.store.blob_root / receipt["sha256"]
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.store.get_blob(receipt["sha256"]), b"private synthetic result")
        path.write_bytes(b"tampered")
        with self.assertRaises(TaskAlongError) as failure:
            self.store.get_blob(receipt["sha256"])
        self.assertEqual(failure.exception.code, "blob_integrity")
        path.unlink()
        with self.assertRaises(TaskAlongError) as failure:
            self.store.get_blob(receipt["sha256"])
        self.assertEqual(failure.exception.code, "blob_missing")
        (self.root / "outside").write_bytes(b"not an artifact")
        path.symlink_to(self.root / "outside")
        with self.assertRaises(TaskAlongError):
            self.store.get_blob(receipt["sha256"])
        self.assertEqual((self.root / "outside").read_bytes(), b"not an artifact")

    def test_insecure_existing_control_path_is_preserved_and_rejected(self):
        insecure = self.root / "insecure"
        insecure.mkdir(mode=0o755)
        with self.assertRaises(TaskAlongError):
            Store(insecure)
        self.assertEqual(insecure.stat().st_mode & 0o777, 0o755)
        linked = self.root / "linked"
        linked.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(TaskAlongError):
            Store(linked)
        self.assertTrue(linked.is_symlink())
        self.assertEqual(self.store.run(self.run["run_id"]), self.run)

    def test_unlinked_private_inode_snapshot_is_allowed_only_for_optional_ephemeral_files(self):
        path = self.root / "synthetic.sqlite3-wal"
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        try:
            os.write(descriptor, b"new synthetic metadata fixture")
            path.unlink()
            snapshot = os.fstat(descriptor)
            self.assertEqual(snapshot.st_nlink, 0)
            self.assertEqual(snapshot.st_uid, os.getuid())
            original_lstat = Path.lstat
            def observed(selected):
                return snapshot if selected == path else original_lstat(selected)
            with patch.object(Path, "lstat", autospec=True, side_effect=observed) as metadata:
                _private(path, directory=False, optional_ephemeral=True)
                self.assertEqual(metadata.call_count, 1, "Private-path validation must use one inode snapshot")
            with patch.object(Path, "lstat", autospec=True, side_effect=observed):
                with self.assertRaises(TaskAlongError) as blocked:
                    _private(path, directory=False)
                self.assertEqual(blocked.exception.code, "unsafe_state_path")
        finally:
            os.close(descriptor)

    def test_store_reopens_when_optional_wal_or_shm_snapshot_was_unlinked(self):
        # A real private inode is unlinked while held open. Replay only that
        # kernel-produced lstat image; SQLite itself opens the actual database.
        original_lstat = Path.lstat
        for suffix in ("-wal", "-shm"):
            with self.subTest(suffix=suffix):
                directory = self.root / ("ephemeral-" + suffix[1:])
                with Store(directory) as initial:
                    expected_uuid = initial.store_uuid
                path = directory / ("state.sqlite3" + suffix)
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                try:
                    path.unlink()
                    snapshot = os.fstat(descriptor)
                    self.assertEqual(snapshot.st_nlink, 0)
                    observed_count = []
                    def observed(selected):
                        if selected == path and not observed_count:
                            observed_count.append(selected)
                            return snapshot
                        return original_lstat(selected)
                    with patch.object(Path, "lstat", autospec=True, side_effect=observed):
                        with Store(directory) as reopened:
                            self.assertEqual(reopened.store_uuid, expected_uuid)
                            self.assertEqual(reopened.db.execute("PRAGMA user_version").fetchone()[0], 1)
                    self.assertEqual(len(observed_count), 1)
                finally:
                    os.close(descriptor)

    def test_optional_ephemeral_guard_still_rejects_unsafe_real_files(self):
        target = self.root / "private-target"
        target.write_bytes(b"original synthetic target")
        target.chmod(0o600)
        linked = self.root / "hardlinked-wal"
        os.link(target, linked)
        symlink = self.root / "symlinked-wal"
        symlink.symlink_to(target)
        insecure = self.root / "shared-wal"
        insecure.write_bytes(b"insecure synthetic metadata")
        insecure.chmod(0o644)
        directory = self.root / "directory-wal"
        directory.mkdir(mode=0o700)
        for path, expected_code in ((linked, "unsafe_state_path"), (symlink, "unsafe_state_path"),
                                    (insecure, "unsafe_state_permissions"), (directory, "unsafe_state_path")):
            with self.subTest(path=path.name), self.assertRaises(TaskAlongError) as rejected:
                _private(path, directory=False, optional_ephemeral=True)
            self.assertEqual(rejected.exception.code, expected_code)
        self.assertEqual(target.read_bytes(), b"original synthetic target")
        self.assertEqual(target.stat().st_nlink, 2)
        self.assertTrue(symlink.is_symlink())
        self.assertEqual(insecure.stat().st_mode & 0o777, 0o644)
        self.assertTrue(directory.is_dir())
        ordinary = self.root / "ordinary-private-file"
        ordinary.write_bytes(b"bounded private regular file")
        ordinary.chmod(0o600)
        _private(ordinary, directory=False)
        _private(ordinary, directory=False, optional_ephemeral=True)

    def test_future_store_is_not_downgraded_or_rewritten(self):
        other = self.root / "future"
        with Store(other) as store:
            store.db.execute("PRAGMA user_version=27")
        db = other / "state.sqlite3"
        before = hashlib.sha256(db.read_bytes()).hexdigest()
        with self.assertRaises(TaskAlongError) as failure:
            Store(other)
        self.assertEqual(failure.exception.code, "unsupported_store_version")
        self.assertEqual(hashlib.sha256(db.read_bytes()).hexdigest(), before)
        connection = sqlite3.connect(db)
        self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 27)
        connection.close()

    def test_future_metadata_format_is_preserved_and_rejected(self):
        other = self.root / "future-metadata"
        with Store(other) as store:
            store.db.execute("UPDATE metadata SET value='27' WHERE key='format_version'")
        db = other / "state.sqlite3"
        before = hashlib.sha256(db.read_bytes()).hexdigest()
        with self.assertRaises(TaskAlongError) as failure:
            Store(other)
        self.assertEqual(failure.exception.exit_code, 70)
        self.assertEqual(hashlib.sha256(db.read_bytes()).hexdigest(), before)

    def test_missing_required_metadata_blocks_without_reinitialization(self):
        other = self.root / "missing-metadata"
        with Store(other) as store:
            store.db.execute("DELETE FROM metadata WHERE key='store_uuid'")
        with self.assertRaises(TaskAlongError) as failure:
            Store(other)
        self.assertEqual(failure.exception.exit_code, 70)
        connection = sqlite3.connect(other / "state.sqlite3")
        self.assertIsNone(connection.execute("SELECT value FROM metadata WHERE key='store_uuid'").fetchone())
        connection.close()

    def test_transaction_triggers_prevent_mutating_immutable_history(self):
        for sql, parameters in (
            ("UPDATE task_specs SET document='{}' WHERE task_id=?", (self.spec["task_id"],)),
            ("DELETE FROM task_specs WHERE task_id=?", (self.spec["task_id"],)),
            ("UPDATE events SET document='{}' WHERE run_id=?", (self.run["run_id"],)),
            ("DELETE FROM events WHERE run_id=?", (self.run["run_id"],)),
        ):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                self.store.db.execute(sql, parameters)
        self.assertEqual(self.store.spec(self.run), self.spec)
        self.assertEqual(len(self.store.events(self.run["run_id"])), 1)

    def test_event_cursor_is_ordered_finite_and_validated(self):
        self.store.mutate(self.run["run_id"], "prepare", "once", 1, {}, self.change,
                          events=[("run.ready", {}), ("effect.prepared", {})])
        self.assertEqual([e["seq"] for e in self.store.events(self.run["run_id"], after_seq=1, limit=1)], [2])
        self.assertEqual(self.store.events(self.run["run_id"], after_seq=3), [])
        for cursor, limit in ((True, 5), (-1, 5), (0, 1001), (0, False)):
            with self.assertRaises(TaskAlongError):
                self.store.events(self.run["run_id"], cursor, limit)

    def test_backup_api_includes_committed_wal_state_and_remains_private(self):
        self.store.mutate(self.run["run_id"], "prepare", "once", 1, {}, self.change)
        backup = self.store.backup(self.root / "backup.sqlite3")
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        connection = sqlite3.connect(backup)
        self.assertEqual(connection.execute("SELECT state FROM runs WHERE run_id=?", (self.run["run_id"],)).fetchone()[0], "ready")
        self.assertEqual(connection.execute("SELECT count(*) FROM events").fetchone()[0], 2)
        connection.close()
        with self.assertRaises(TaskAlongError):
            self.store.backup(backup)

    def test_run_and_event_public_documents_match_versioned_schema(self):
        self.assertEqual(validate("task-run", self.run), self.run)
        for event in self.store.events(self.run["run_id"]):
            self.assertEqual(validate("run-event", event), event)


if __name__ == "__main__":
    unittest.main()
