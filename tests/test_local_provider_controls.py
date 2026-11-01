"""Disposable owner evidence only; no processes, provider calls or real State."""
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from taskalong import local_provider_controls as controls
from taskalong.artifact_io import stage_regular
from taskalong.errors import TaskAlongError
from taskalong.local_provider_capture import PrivateCapture
from taskalong.store import Store
from taskalong.validation import canonical_bytes, digest, loads


class ProviderControlsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name).resolve()
        self.store = Store(self.parent / "state")
        self.addCleanup(self.store.close)
        self.receipt = {"invocation_id": "synthetic", "pid": 123, "pgid": 123,
                        "supervisor_pid": 124, "started_unix_ms": 100, "executable_sha256": "e" * 64}

    def write(self, root, name, value):
        raw = canonical_bytes(value)
        stage_regular(root, name, raw, expected_sha256=hashlib.sha256(raw).hexdigest())

    def run_record(self, *, legacy=False, state="running", run_id="owner-1", **changes):
        root = self.parent / run_id
        root.mkdir(mode=0o700)
        control = root if legacy else root / "control"
        if not legacy:
            control.mkdir(mode=0o700)
        value = {"format": "local-provider-run/1" if legacy else "configured-provider-run/1",
                 "provider": "muse" if legacy else "codex", "run_id": run_id, "revision": 3,
                 "state": state, "output": str(root), "configuration_digest": "a" * 64,
                 "bundle_digest" if legacy else "request_digest": "b" * 64,
                 "controller_submissions": 1, "automatic_retry_allowed": False,
                 "patch_applied": False, "acceptance_allowed": False, "remote_usage": "unknown",
                 "process_receipt": self.receipt}
        if not legacy:
            value["control_root"] = str(control)
        value.update(changes)
        value["digest"] = digest(value)
        self.write(root, "events/0003.json", value)
        self.store.set_setting("provider-run:" + run_id, value)
        return value, root, control

    def cancel(self, run_id="owner-1", key="cancel", revision=3):
        return controls.request_cancel(self.store, run_id, operation_key=key, expected_revision=revision)

    def reconcile(self, run_id="owner-1", key="reconcile", revision=3):
        return controls.reconcile(self.store, run_id, operation_key=key, expected_revision=revision)

    def assert_code(self, code, action):
        with self.assertRaises(TaskAlongError) as caught:
            action()
        self.assertEqual(caught.exception.code, code)

    def test_new_and_actual_legacy_shapes_bind_marker_to_authenticated_owner(self):
        for legacy in (False, True):
            with self.subTest(legacy=legacy):
                run_id = "legacy" if legacy else "new"
                record, root, control = self.run_record(legacy=legacy, run_id=run_id)
                old_event = (root / "events/0003.json").read_bytes()
                result = self.cancel(run_id, "cancel-" + run_id)
                self.assertEqual(result["status"], "requested")
                marker = loads((control / "cancel-request.json").read_bytes())
                self.assertEqual(marker["binding"], controls._binding(record))
                self.assertEqual(marker["intent_digest"], result["intent_digest"])
                self.assertEqual(marker["digest"], digest(marker))
                self.assertEqual((control / "cancel-request.json").stat().st_mode & 0o777, 0o400)
                self.assertEqual(self.store.setting("provider-run:" + run_id), record)
                self.assertEqual((root / "events/0003.json").read_bytes(), old_event)
                self.assertNotIn(str(root), str(result))

    def test_intent_is_committed_and_complete_stage_precedes_marker_visibility(self):
        record, root, control = self.run_record()
        original = controls._publish
        def observe(directory, stage):
            slot = self.store.setting("provider-control:cancel:owner-1")
            self.assertIsNotNone(slot)
            self.assertIsNotNone(self.store.setting(slot["operation"]))
            self.assertFalse((control / "cancel-request.json").exists())
            self.assertEqual(loads((control / stage).read_bytes())["binding"], controls._binding(record))
            original(directory, stage)
        with patch.object(controls, "_publish", side_effect=observe):
            self.assertEqual(self.cancel()["status"], "requested")

    def test_legacy_successor_format_two_retains_same_local_control_contract(self):
        _, _, control = self.run_record(legacy=True, format="local-provider-run/2",
                                         manual_successor={"opaque_retained_lineage": True})
        self.assertEqual(self.cancel()["status"], "requested")
        self.assertTrue((control / "cancel-request.json").exists())

    def test_exact_duplicate_after_owner_revision_advances_returns_prior_receipt(self):
        record, _, _ = self.run_record()
        first = self.cancel()
        updated = {**record, "revision": 4, "state": "failed"}
        updated["digest"] = digest(updated)
        self.store.set_setting("provider-run:owner-1", updated)
        with patch.object(controls, "_publish", side_effect=AssertionError("replayed")):
            self.assertEqual(self.cancel(), first)
        self.assert_code("provider_control_key_conflict", lambda: self.cancel(revision=4))
        self.assert_code("provider_control_key_conflict", lambda: self.cancel("other"))
        self.assert_code("provider_control_key_conflict", lambda: self.reconcile(key="cancel"))

    def test_stale_revision_and_new_key_refuse_without_replay(self):
        _, _, control = self.run_record()
        self.assert_code("revision_conflict", lambda: self.cancel(revision=2))
        self.assertFalse((control / "cancel-request.json").exists())
        self.cancel()
        self.assert_code("provider_control_already_requested", lambda: self.cancel(key="again"))

    def test_terminal_blocked_and_not_started_records_are_observations(self):
        for state in ("completed", "proposal_ready", "failed", "blocked", "preflight", "prepared"):
            with self.subTest(state=state):
                record, _, control = self.run_record(state=state, run_id=state)
                result = self.cancel(state, state)
                self.assertEqual(result["status"], "observation_only")
                self.assertFalse((control / "cancel-request.json").exists())
                self.assertEqual(self.store.setting("provider-run:" + state), record)

    def test_no_process_or_capture_is_unknown_and_never_mutates_owner(self):
        record, root, _ = self.run_record()
        inspected = controls.inspect_run(self.store, "owner-1")
        self.assertEqual(inspected["stored_state"], "running")
        self.assertEqual(inspected["local_termination"], "unknown")
        self.assertEqual(inspected["capture"]["status"], "unknown")
        self.assertEqual(inspected["remote_usage"], "unknown")
        reconciled = self.reconcile()
        self.assertEqual(reconciled["observation"]["local_termination"], "unknown")
        self.assertEqual(self.store.setting("provider-run:owner-1"), record)
        self.assertEqual(list((root / "events").iterdir()), [root / "events/0003.json"])
        self.assertIsNone(controls.inspect_run(self.store, "missing"))

    def test_capture_closure_and_bound_process_exit_are_separate_observations(self):
        _, root, control = self.run_record()
        process = {"receipt": self.receipt, "root_exit_observed": True, "root_exit_code": 0,
                   "group_termination_confirmed": True}
        self.write(root, "process.json", process)
        sink = PrivateCapture(control / "capture")
        try:
            sink.write("stdout", b"private output")
            sink.finalize()
        finally:
            sink.close()
        observed = controls.inspect_run(self.store, "owner-1")
        self.assertEqual(observed["local_termination"], "observed")
        self.assertEqual(observed["stored_state"], "running")
        self.assertEqual(observed["capture"]["status"], "closed")
        self.assertEqual(observed["descendant_cessation"], "unknown")

    def test_process_receipt_conflict_prevents_marker(self):
        _, root, control = self.run_record()
        self.write(root, "process.json", {"receipt": {**self.receipt, "pid": 999},
                                         "root_exit_observed": True, "root_exit_code": 0})
        self.assert_code("provider_control_process_conflict", self.cancel)
        self.assertFalse((control / "cancel-request.json").exists())

    def test_owner_state_and_event_disagreement_or_orphan_later_event_refuse(self):
        record, root, _ = self.run_record()
        self.write(root, "events/0004.json", {**record, "revision": 4})
        self.assert_code("provider_control_history_changed", self.cancel)

    def test_self_sealed_state_without_matching_owner_event_is_insufficient(self):
        record, _, _ = self.run_record()
        record["remote_usage"] = "not_sent"
        record["digest"] = digest(record)
        self.store.set_setting("provider-run:owner-1", record)
        self.assert_code("provider_control_history_changed", self.cancel)

    def test_invalid_flags_types_and_non_muse_legacy_refuse(self):
        for field, value in (("automatic_retry_allowed", True), ("patch_applied", 0),
                             ("acceptance_allowed", None), ("controller_submissions", True),
                             ("request_digest", "bad"), ("revision", True), ("state", [])):
            with self.subTest(field=field):
                run_id = "bad-" + field
                self.run_record(run_id=run_id, **{field: value})
                self.assert_code("provider_control_invalid", lambda: self.cancel(run_id, run_id))
        self.run_record(legacy=True, run_id="legacy-bad", provider="codex")
        self.assert_code("provider_control_invalid", lambda: self.cancel("legacy-bad", "legacy-bad"))

    def test_invalid_process_identity_types_refuse_before_intent(self):
        self.run_record(process_receipt={**self.receipt, "pid": True})
        self.assert_code("provider_control_invalid", self.cancel)
        self.assertIsNone(self.store.setting("provider-control:cancel:owner-1"))

    def test_missing_or_symlinked_or_nonprivate_roots_never_recreated(self):
        record, root, control = self.run_record()
        control.rmdir()
        self.assertRaises((TaskAlongError, OSError), self.cancel)
        self.assertFalse(control.exists())
        elsewhere = self.parent / "elsewhere"
        elsewhere.mkdir(mode=0o700)
        control.symlink_to(elsewhere, target_is_directory=True)
        self.assertRaises((TaskAlongError, OSError), self.cancel)
        self.assertEqual(list(elsewhere.iterdir()), [])
        control.unlink()
        control.mkdir(mode=0o755)
        self.assertRaises(TaskAlongError, self.cancel)
        self.assertEqual(self.store.setting("provider-run:owner-1"), record)

    def test_failed_stage_preserves_intent_partial_bytes_and_never_replays(self):
        record, _, control = self.run_record()
        def fail_stage(root, name, *args, **kwargs):
            (root / name).write_bytes(b"partial")
            raise OSError("synthetic partial write")
        with patch.object(controls, "stage_regular", side_effect=fail_stage):
            first = self.cancel()
        self.assertEqual(first["status"], "publication_unknown")
        stage = next(control.glob(".cancel-stage-*"))
        self.assertEqual(stage.read_bytes(), b"partial")
        with patch.object(controls, "stage_regular", side_effect=AssertionError("replayed")):
            self.assertEqual(self.cancel(), first)
            result = self.reconcile()
        self.assertEqual(result["observation"]["cancel_request"], "intent_retained_publication_unknown")
        self.assertEqual(stage.read_bytes(), b"partial")
        self.assertEqual(self.store.setting("provider-run:owner-1"), record)

    def test_sql_receipt_failure_after_publication_is_reconciled_without_replay(self):
        _, _, control = self.run_record()
        original = controls._insert
        def fail_receipt(db, name, value):
            if name.endswith(":receipt"):
                raise sqlite3.OperationalError("synthetic receipt failure")
            original(db, name, value)
        with patch.object(controls, "_insert", side_effect=fail_receipt):
            self.assertEqual(self.cancel()["status"], "publication_unknown")
        self.assertTrue((control / "cancel-request.json").exists())
        with patch.object(controls, "_publish", side_effect=AssertionError("replayed")):
            self.assertEqual(self.cancel()["status"], "publication_unknown")
        self.assertEqual(self.reconcile()["observation"]["cancel_request"], "published")

    def test_no_overwrite_of_preexisting_marker_or_pending_stage(self):
        _, _, control = self.run_record()
        self.write(control, "cancel-request.json", {"foreign": True})
        before = (control / "cancel-request.json").read_bytes()
        self.assertEqual(self.cancel()["status"], "publication_unknown")
        self.assertEqual((control / "cancel-request.json").read_bytes(), before)
        self.assert_code("provider_control_marker_conflict", self.reconcile)


if __name__ == "__main__":
    unittest.main()
