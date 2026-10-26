"""Explicit Muse format fence and additive resource compatibility."""
import hashlib
import importlib.util
from importlib import resources
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator
from taskalong.errors import TaskAlongError
from taskalong.store import Store
from taskalong.validation import schema, schema_names, seal_versioned
from test_antigravity_store import upgrade_through
from test_contracts import example_spec


class MuseStoreTests(unittest.TestCase):
    def test_format9_is_explicit_backed_up_and_actual_format8_client_refuses(self):
        from taskalong.maintenance import verify_backup, verify_restored
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            state = root / "state"
            with Store(state) as store:
                original = store.create_run(example_spec(), "retained-v1")
                blob = store.put_blob(b"retained original")
            with Store.maintenance(state) as store:
                with self.assertRaises(TaskAlongError) as failure:
                    store.upgrade(operation_key="skip", target_version=9,
                        backup_dir=root / "skip-backup", restore_dir=root / "skip-restore")
                self.assertEqual(failure.exception.code, "store_migration_order")
                self.assertFalse((root / "skip-backup").exists())
                upgrade_through(store, root, 8)
                request = dict(operation_key="muse-fence", target_version=9,
                    backup_dir=root / "backup-9", restore_dir=root / "restore-9")
                receipt = store.upgrade(**request)
                self.assertEqual(store.upgrade(**request), receipt)
                self.assertEqual(store.format_version, 9)
                backup = verify_backup(root / "backup-9", expected_digest=receipt["backup_manifest_digest"])
                self.assertEqual(backup["database"]["user_version"], 8)
                self.assertTrue(verify_restored(root / "backup-9", root / "restore-9",
                    expected_digest=backup["digest"])["quarantined"])
            fixture = Path(__file__).parent / "fixtures/legacy_store_v8.py"
            self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(),
                "c3c8c18e9eb8b5cbb041bf322ff3ba09fa433c6f04f56a2dea82dcb84bae081e")
            spec = importlib.util.spec_from_file_location("taskalong._legacy_store_v8", fixture)
            predecessor = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(predecessor)
            before = {p.name: p.read_bytes() for p in state.glob("state.sqlite3*")}
            with self.assertRaises(TaskAlongError) as failure:
                predecessor.Store(state)
            self.assertEqual(failure.exception.code, "unsupported_store_version")
            self.assertEqual({p.name: p.read_bytes() for p in state.glob("state.sqlite3*")}, before)
            with Store(state) as store:
                self.assertEqual(store.run(original["run_id"]), original)
                self.assertEqual(store.get_blob(blob["sha256"]), b"retained original")

    def test_unfenced_muse_submission_refuses_without_writing(self):
        task = example_spec()
        task = seal_versioned("task-spec", task | {"schema_version": "2.9",
            "execution": {"driver_config_digest": "a" * 64}}, version="2.9")
        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory).resolve() / "state") as store:
                tables = [row[0] for row in store.db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
                def rows():
                    return {name: [tuple(row) for row in store.db.execute('SELECT * FROM "' + name + '"')]
                            for name in tables}
                before = rows()
                with self.assertRaises(TaskAlongError) as failure:
                    store.create_run(task, "unfenced-muse")
                self.assertEqual(failure.exception.code, "store_upgrade_required")
                self.assertEqual(rows(), before)
                self.assertEqual(store.format_version, 1)

    def test_additive_schemas_are_valid_and_earlier_resources_are_byte_identical(self):
        names = {"capture-config", "task-spec", "worker-packet", "packet-projection",
                 "execution-handoff", "result-view", "capabilities-view"}
        self.assertEqual(set(schema_names(version="2.9")), names)
        for name in names:
            Draft202012Validator.check_schema(schema(name, version="2.9"))
        # Frozen original resource inventory is generated from the base commit,
        # independently of the new reader and schemas.
        import json
        root = resources.files("taskalong.resources")
        for name, expected in json.loads((Path(__file__).parent / "fixtures/pre-muse-resources.json").read_bytes()).items():
            raw = root.joinpath(name.removeprefix("src/taskalong/resources/")).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), expected, name)


class MuseResultViewSchemaTests(unittest.TestCase):
    def view(self, *, state="created", outcome="pending", accepted=False, **changes):
        value = {"run_id": "00000000-0000-4000-8000-000000000001", "revision": 1,
            "state": state, "outcome": outcome, "independently_accepted": accepted,
            "acceptance_digest": None, "execution_handoff_digest": None,
            "canonical_packet_digest": None, "evidence_artifacts": [],
            "production_dispatch_allowed": False}
        return value | changes

    def seal(self, value):
        return seal_versioned("result-view", value, version="2.9")

    def test_valid_pending_handoff_accepted_cancelled_and_retained_assessments(self):
        refs = {name: "a" * 64 for name in ("acceptance_digest",
            "execution_handoff_digest", "canonical_packet_digest")}
        values = [self.view(), self.view(state="running"),
            self.view(state="blocked", outcome="execution_handoff_ready", **refs),
            self.view(state="accepted", outcome="accepted", accepted=True, **refs),
            self.view(state="cancelled", outcome="cancelled"),
            self.view(state="cancelled", outcome="cancelled", **refs),
            self.view(state="cancel_pending", **refs)]
        for value in values:
            with self.subTest(state=value["state"], outcome=value["outcome"]):
                self.assertEqual(self.seal(value)["acceptance_digest"], value["acceptance_digest"])

    def test_acceptance_state_outcome_and_boolean_must_agree(self):
        from itertools import product
        for state, outcome, accepted in product((False, True), repeat=3):
            if state == outcome == accepted:
                continue
            value = self.view(state="accepted" if state else "blocked",
                outcome="accepted" if outcome else "pending", accepted=accepted,
                acceptance_digest="a" * 64, execution_handoff_digest="b" * 64,
                canonical_packet_digest="c" * 64)
            with self.subTest(state=state, outcome=outcome, accepted=accepted):
                with self.assertRaises(TaskAlongError):
                    self.seal(value)

    def test_accepted_requires_all_three_digests(self):
        value = self.view(state="accepted", outcome="accepted", accepted=True,
            acceptance_digest="a" * 64, execution_handoff_digest="b" * 64,
            canonical_packet_digest="c" * 64)
        for field in ("acceptance_digest", "execution_handoff_digest", "canonical_packet_digest"):
            for missing in (False, True):
                changed = value | {field: None}
                if missing:
                    del changed[field]
                with self.subTest(field=field, missing=missing):
                    with self.assertRaises(TaskAlongError):
                        self.seal(changed)

    def test_handoff_ready_requires_handoff_and_packet_digests(self):
        value = self.view(state="blocked", outcome="execution_handoff_ready",
            execution_handoff_digest="b" * 64, canonical_packet_digest="c" * 64)
        for field in ("execution_handoff_digest", "canonical_packet_digest"):
            for missing in (False, True):
                changed = value | {field: None}
                if missing:
                    del changed[field]
                with self.subTest(field=field, missing=missing):
                    with self.assertRaises(TaskAlongError):
                        self.seal(changed)


if __name__ == "__main__":
    unittest.main()
