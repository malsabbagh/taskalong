"""Format-11 fence preserves accepted M10 and all predecessor private history.

The pinned reader and resource inventory come from accepted M10 commit
b7e50ef8109912a2d45f7067c1d241a1a9759b47. No live executor is registered or run.
"""
import copy
import hashlib
import importlib.util
from importlib import resources
import json
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator

from taskalong.errors import TaskAlongError
from taskalong.execution import read_task_spec
from taskalong.maintenance import verify_backup, verify_restored
from taskalong.muse_handoff import MuseConfiguration
from taskalong.store import Store
from taskalong.trial import TrialDriverConfig
from taskalong.validation import canonical_bytes, schema, schema_names, seal_versioned
from test_antigravity_store import upgrade_through
from test_contracts import example_spec
from test_trial_contracts import example_trial_config, example_trial_spec


PINNED_READER_SHA256 = "a5161ba52757250fa8a0076d831cc39a8c48f688da722b83cc394a8747e1842b"


def ordered_task():
    value = example_spec()
    value.update(schema_version="2.7", task_id="retained-m10-task",
        steps=[{"step_id":"A", "goal":"Correct the declared arithmetic file.",
            "scope":copy.deepcopy(value["scope"]), "inputs":[], "required":True}],
        final_verification={"max_passes":1, "total_active_seconds":110,
                            "max_output_bytes":524288})
    value["budget"].update(total_active_seconds=170, attempt_output_bytes=65536)
    return seal_versioned("task-spec", value, version="2.7")


def artifact_task():
    value = ordered_task()
    value.update(schema_version="2.10", task_id="unfenced-artifact-task",
        execution={"routes":[{"route_id":"codex", "binding_digest":"a"*64,
            "configuration_digest":"b"*64, "disclosure_destination_id":"fixture"}],
            "check_route_id":"codex"})
    value["permissions"].pop("inference_destination_id")
    value["permissions"]["disclosure_destination_ids"] = ["fixture"]
    value["steps"][0].update(route_id="codex", outputs=[],
        import_scope={"files":[], "operations":["modify"]})
    return seal_versioned("task-spec", value, version="2.10")


def retained_muse():
    return MuseConfiguration.from_dict(seal_versioned("capture-config", {
        "config_id":"retained-muse", "qualification":"synthetic",
        "projection":"muse-plain-fixture/1",
        "transport":"operator_registered_original_fixture",
        "executable":{"path":"/opt/example/original-fixture", "sha256":"a"*64},
        "build":"1.4.10-R6427.1", "requested_model":"synthetic-muse-model",
        "permission_profile":"synthetic-profile", "max_model_steps":1,
        "inference_destination_id":"synthetic-local-muse", "check_profile_digest":"b"*64,
        "checks_digest":"c"*64, "review_config_digest":"d"*64,
        "command_sandbox_digest":"e"*64, "extensions":{},
    }, version="2.9"))


class ArtifactStoreTests(unittest.TestCase):
    def test_all_78_inherited_resources_and_explicit_closed_handoff_family(self):
        inventory = json.loads((Path(__file__).parent / "fixtures/pre-artifact-resources.json").read_bytes())
        self.assertEqual(len(inventory), 78)
        root = resources.files("taskalong.resources")
        for path, expected in inventory.items():
            raw = root.joinpath(path.removeprefix("src/taskalong/resources/")).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), expected, path)
        names = {"task-spec", "task-run", "step-receipt", "result-view", "output-manifest",
                 "resolved-inputs", "import-journal", "file-set-patch", "worker-packet", "packet-projection"}
        self.assertEqual(set(schema_names(version="2.10")), names)
        for name in names:
            document = schema(name, version="2.10")
            Draft202012Validator.check_schema(document)
            self.assertIs(document["additionalProperties"], False)
            self.assertEqual(document["properties"]["schema_version"], {"const":"2.10"})

    def test_handoff_task_refuses_before_explicit_format11_without_state_changes(self):
        task = artifact_task()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with Store(root / "state"):
                pass
            with Store.maintenance(root / "state") as store:
                upgrade_through(store, root, 10)
            with Store(root / "state") as store:
                operations = [tuple(row) for row in store.db.execute("SELECT * FROM operations")]
                with self.assertRaises(TaskAlongError) as error:
                    store.create_run(task, "never-admit-unfenced-artifact")
                self.assertEqual(error.exception.code, "store_upgrade_required")
                self.assertEqual(store.format_version, 10)
                self.assertEqual(store.db.execute("SELECT count(*) FROM runs").fetchone()[0], 0)
                self.assertEqual(store.db.execute("SELECT count(*) FROM task_specs").fetchone()[0], 0)
                self.assertEqual([tuple(row) for row in store.db.execute("SELECT * FROM operations")], operations)

    def test_format11_is_sequential_exclusive_and_requires_fresh_verified_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with Store(root / "state"):
                pass
            with Store.maintenance(root / "state") as store:
                with self.assertRaises(TaskAlongError) as order:
                    store.upgrade(operation_key="skip-to-artifact", target_version=11,
                        backup_dir=root / "skip-backup", restore_dir=root / "skip-restore")
                self.assertEqual(order.exception.code, "store_migration_order")
                self.assertEqual(store.format_version, 1)
                self.assertFalse((root / "skip-backup").exists())
                upgrade_through(store, root, 10)
            with Store(root / "state") as opened:
                with self.assertRaises(TaskAlongError) as overlap:
                    Store.maintenance(root / "state")
                self.assertEqual(overlap.exception.code, "maintenance_busy")
                self.assertEqual(opened.format_version, 10)
            with Store.maintenance(root / "state") as store:
                restored = root / "existing-restore"
                restored.mkdir(mode=0o700)
                sentinel = restored / "foreign.txt"
                sentinel.write_bytes(b"Retain unrelated synthetic bytes")
                sentinel.chmod(0o600)
                with self.assertRaises(TaskAlongError) as occupied:
                    store.upgrade(operation_key="occupied-artifact-restore", target_version=11,
                        backup_dir=root / "occupied-backup", restore_dir=restored)
                self.assertEqual(occupied.exception.code, "restore_integrity")
                self.assertEqual(store.format_version, 10)
                self.assertEqual(sentinel.read_bytes(), b"Retain unrelated synthetic bytes")

    def test_backed_up_10_to_11_preserves_history_and_actual_format10_reader_refuses(self):
        trial_config = TrialDriverConfig.from_dict(seal_versioned(
            "driver-config", example_trial_config(), version="2.8"))
        trial_spec = seal_versioned("task-spec", example_trial_spec(), version="2.8")
        muse = retained_muse()
        task = ordered_task()
        fixture = Path(__file__).parent / "fixtures/legacy_store_v10.py"
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(), PINNED_READER_SHA256)
        loader = importlib.util.spec_from_file_location("taskalong._artifact_predecessor_10", fixture)
        predecessor = importlib.util.module_from_spec(loader)
        loader.loader.exec_module(predecessor)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            state = root / "state"
            with Store(state) as store:
                legacy = store.create_run(example_spec(), "retained-v1-run")
                artifact = store.put_blob(b"Original private predecessor bytes", media_type="text/plain")
            with Store.maintenance(state) as store:
                upgrade_through(store, root, 8)
                store.record_document(trial_config, operation_key="retained-e1-config")
                trial = store.create_run(trial_spec, "retained-e1-intent")
                upgrade_through(store, root, 9)
                store.record_document(muse, operation_key="retained-muse-config")
                upgrade_through(store, root, 10)
                ordered = store.create_run(task, "retained-m10-plan")
                # Historical schema data is retained as an inert private blob;
                # it is deliberately not a fabricated successful attempt.
                receipt = seal_versioned("step-receipt", {
                    "run_id":ordered["run_id"], "spec_digest":task["digest"], "step_id":"A",
                    "step_index":0, "attempt_id":"22222222-2222-4222-8222-222222222222",
                    "lease_generation":1, "packet_digest":"1"*64, "result_digest":"2"*64,
                    "process_digest":"3"*64, "checkpoint_digest":"4"*64,
                    "starting_snapshot_digest":"5"*64, "final_snapshot_digest":"6"*64,
                    "reservation_digest":"7"*64, "predecessor_digest":None,
                }, version="2.7")
                receipt_blob = store.put_blob(canonical_bytes(receipt))
                before_events = store.events(ordered["run_id"])
                before_e1 = store.document_history("driver_config", trial_config.digest)
                before_muse = store.document_history("capture_config", muse.digest)
                store_uuid = store.store_uuid
            # The literal pinned predecessor is usable before the fence.
            with predecessor.Store(state) as old:
                self.assertEqual(old.format_version, 10)
                self.assertEqual(old.run(ordered["run_id"]), ordered)
                self.assertEqual(old.get_blob(receipt_blob["sha256"]), canonical_bytes(receipt))
            with Store.maintenance(state) as store:
                request = dict(operation_key="artifact-format11", target_version=11,
                    backup_dir=root / "artifact-backup", restore_dir=root / "artifact-restore")
                result = store.upgrade(**request)
                self.assertEqual(store.upgrade(**request), result)
                self.assertEqual(store.format_version, 11)
                self.assertEqual(store.store_uuid, store_uuid)
                backup = verify_backup(request["backup_dir"], expected_digest=result["backup_manifest_digest"])
                self.assertEqual(backup["database"]["user_version"], 10)
                restore = verify_restored(request["backup_dir"], request["restore_dir"], expected_digest=backup["digest"])
                self.assertTrue(restore["quarantined"])
                for run in (legacy, trial, ordered):
                    self.assertEqual(store.run(run["run_id"]), run)
                self.assertEqual(store.spec(ordered), task)
                self.assertEqual(store.spec(trial), trial_spec)
                self.assertEqual(store.events(ordered["run_id"]), before_events)
                self.assertEqual(store.document_history("driver_config", trial_config.digest), before_e1)
                self.assertEqual(store.document_history("capture_config", muse.digest), before_muse)
                from taskalong.trial_control import register_trial_document
                retained=register_trial_document(store,trial_config,operation_key="format11-e1-public-history")
                self.assertTrue(retained["historical_only"])
                self.assertEqual(store.get_blob(artifact["sha256"]), b"Original private predecessor bytes")
                self.assertEqual(store.get_blob(receipt_blob["sha256"]), canonical_bytes(receipt))
            before = {p.name:p.read_bytes() for p in state.glob("state.sqlite3*")}
            with self.assertRaises(TaskAlongError) as refusal:
                predecessor.Store(state)
            self.assertEqual(refusal.exception.code, "unsupported_store_version")
            self.assertEqual({p.name:p.read_bytes() for p in state.glob("state.sqlite3*")}, before)
            with Store(state) as store:
                self.assertEqual(store.run(ordered["run_id"]), ordered)
                self.assertEqual(store.get_blob(receipt_blob["sha256"]), canonical_bytes(receipt))

    def test_existing_27_task_bytes_and_no_selector_meaning_remain_unchanged(self):
        task = ordered_task()
        original = canonical_bytes(task)
        self.assertEqual(read_task_spec(task).to_bytes(), original)
        read_task_spec(artifact_task())
        self.assertEqual(read_task_spec(task).to_bytes(), original)
        for mutation in ("selector", "output", "route"):
            changed = copy.deepcopy(task)
            if mutation == "selector":
                changed["steps"][0]["inputs"] = [{"kind":"step_output", "from_step_id":"A",
                    "output_id":"note", "expected_kind":"utf8_text", "max_bytes":10}]
            elif mutation == "output":
                changed["steps"][0]["outputs"] = []
            else:
                changed["steps"][0]["route_id"] = "claude"
            with self.subTest(mutation=mutation), self.assertRaises(TaskAlongError) as refusal:
                seal_versioned("task-spec", changed, version="2.7")
            self.assertEqual(refusal.exception.code, "schema_validation")
        with self.assertRaises(TaskAlongError) as unknown:
            read_task_spec(artifact_task() | {"schema_version":"2.11"})
        self.assertEqual(unknown.exception.code, "unknown_schema_version")


if __name__ == "__main__":
    unittest.main()
