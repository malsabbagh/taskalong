"""Completed High evidence in disposable State; never a live provider or account."""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from taskalong import artifact_io, muse_experimental as muse, muse_native_lifecycle as lifecycle
from taskalong import muse_result_recovery as recovery, muse_successor as successor, supervised_pilot as pilot
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes
import test_muse_high_successor as high_fixtures
from test_muse_interrupted_recovery import passive_journal_rows
from test_muse_native_lifecycle import SESSION, RUN, TASK, SECOND, row as task_row, status_details


class HistoricalStatusGuard(lifecycle.NativeModelTaskGuard):
    """Reproduce the old rejection, without bypassing a production admission."""
    def _status_descriptor(self, row, payload, event):
        if type(event) is dict and event.get("details", {}).get("phase") == "stream_succeeded":
            return None
        return super()._status_descriptor(row, payload, event)


@unittest.skipUnless(os.name == "posix", "Private local recovery requires POSIX")
class HighCompleteResultTests(unittest.TestCase):
    def setUp(self):
        self.fixture = high_fixtures.interrupted_fixture()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.service = self.fixture.root, self.fixture.service
        self.store = self.service._store
        self.parent = self.fixture.original
        self.max_config = self.store.setting("provider:muse")

    def complete_high(self, *, mutate=None, over_limit=False, replacement=None):
        proof = self.service.provider_successor_plan(predecessor=self.parent["run_id"], reason="interrupted-high")
        self.over_limit, self.mutate = over_limit, mutate
        self.replacement = replacement
        with patch.object(lifecycle, "NativeModelTaskGuard", HistoricalStatusGuard), \
                patch.object(muse, "run_foreground_experiment", side_effect=self.completed_owner):
            self.high = self.service.provider_successor(predecessor=self.parent["run_id"], reason="interrupted-high",
                key="synthetic-completed-high", plan_digest=proof["digest"], output=str(self.root / "completed-high"))
        self.assertEqual(self.high["state"], "failed")
        self.assertEqual(self.high["error"], "provider_native_lifecycle_stop")
        self.assertEqual(self.high["process"]["root_exit_code"], 0)
        self.assertTrue(self.high["process"]["cancelled"])
        self.assertEqual(self.high["process"]["private_capture"]["status"], "closed")
        self.high_root = Path(self.high["output"])
        self.high_bytes = canonical_bytes(self.high)
        self.high_files = self.files(self.high_root)
        self.high_journal_bytes = self.high_journal.read_bytes()
        self.parent_claim = self.store.setting("provider-claim:muse:" + self.parent["bundle_digest"])
        self.high_claim = self.store.setting("provider-claim:muse:" + self.high["bundle_digest"])
        self.reservation = copy.deepcopy(self.high["manual_successor"])
        return self.high

    def completed_owner(self, argv, **options):
        self.assertEqual(argv[argv.index("--reasoning-effort") + 1], "high")
        previous = self.fixture.c.mode; self.fixture.c.mode = "success"
        try: result = self.fixture.c.owner(argv, **options)
        finally: self.fixture.c.mode = previous
        linked = json.loads(result.stdout.splitlines()[0])
        self.session = linked["stream"]["id"]
        self.native_run = linked["payload"]["run_stream"]["id"]
        output = Path(argv[argv.index("--workspace") + 1]).parent
        manifest = json.loads((output / "bundle/bundle.json").read_bytes())
        content = "Synthetic recovered replacement.\n" * 8 if self.replacement is None else self.replacement
        self.response = {"bundle_digest": manifest["digest"], "changes": {"source.py": content}}
        if self.over_limit:
            self.response["changes"]["source.py"] = "\n"
            overhead = len(canonical_bytes(self.response))
            self.response["changes"]["source.py"] = "x" * (1048576 - overhead + 1) + "\n"
        self.committed = json.dumps(self.response, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if self.over_limit: self.assertEqual(len(self.committed.encode()), 1048577)
        rows = self.fixture.rows(linked, repeated=False)[:2]
        for kind in ("proposed", "accepted", "scheduled", "side_effect_intent", "started"):
            value = task_row(len(rows) + 1, kind)
            value["stream"]["id"] = self.session
            value["payload"]["command_id"] = self.native_run
            value["payload"]["run_stream"]["id"] = self.native_run
            rows.append(value)
        base = rows[1]
        chunk_size = 8192 if self.over_limit else 53
        for offset in range(0, len(self.committed), chunk_size):
            rows.append(base | {"sequence": len(rows) + 1, "payload_type": "run.output.delta", "payload": {
                "kind": "run_output_delta", "command_id": self.native_run,
                "run_stream": {"kind": "run", "id": self.native_run}, "text": self.committed[offset:offset + chunk_size]}})
        status = task_row(len(rows) + 1, "status")
        status["stream"]["id"] = self.session
        status["payload"]["command_id"] = self.native_run
        status["payload"]["run_stream"]["id"] = self.native_run
        status["payload"]["event"].update(message="Synthetic successful stream.", details=status_details("stream_succeeded"))
        rows.append(status)
        completed = copy.deepcopy(status)
        completed.update(sequence=len(rows) + 1, payload_type="task.lifecycle.completed")
        completed["payload"]["event"] = {"kind": "completed", "task_id": TASK}
        rows.append(completed)
        if self.mutate is not None: self.mutate(rows)
        for index, row in enumerate(rows, 1): row["sequence"] = index
        rows.append(base | {"sequence": len(rows) + 1, "payload_type": "run.terminal.completed", "payload": {
            "kind": "run_terminal", "run_stream": {"kind": "run", "id": self.native_run},
            "terminal": "completed", "text": self.committed}})
        raw = b"".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode() + b"\n" for row in rows)
        options["_on_output_chunk"]("stdout", raw)
        for line in raw.splitlines(): options["on_stdout_line"](line)

        def bound(value):
            if type(value) is dict: return {key: bound(item) for key, item in value.items()}
            if type(value) is list: return [bound(item) for item in value]
            if value == SESSION: return self.session
            if value == RUN: return self.native_run
            if value == "synthetic-model": return self.max_config["model"]
            return value
        journal = [bound(row) for row in passive_journal_rows()[:-1]]
        journal.append({"payload": {"kind": "run", "run_id": self.native_run, "event": {
            "kind": "model_request_configured", "toolset": {"active_tools": []}, "reminder_roster": {"agents": []}}}})
        for row in rows:
            if row["payload"].get("kind") == "task_lifecycle":
                event = copy.deepcopy(row["payload"]["event"])
                journal.append({"payload": {"kind": "task", "run_id": self.native_run,
                    "task_id": event["task_id"], "event": event}})
        journal.extend([{"payload": {"kind": "run", "run_id": self.native_run, "event": {
            "kind": "assistant_message_committed", "text": self.committed}}},
            {"payload": {"kind": "run", "run_id": self.native_run, "event": {
                "kind": "terminal", "terminal": "completed", "reason": None}}},
            {"payload_type": "session.end", "payload": {"kind": "session_end", "record": {
                "session_id": self.session, "reason": "normal"}}}])
        for index, row in enumerate(journal, 1):
            row.update(schema_version=1, sequence=index, stream={"kind": "session", "id": self.session},
                record_type="event", durability="durable")
            row.setdefault("payload_schema_version", 1)
            row.setdefault("payload_type", "runtime.session")
        self.high_journal = self.fixture.c.journals[-1]
        self.high_journal.write_bytes(b"".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode() + b"\n" for row in journal))
        info = result.to_dict() | {"root_exit_code": 0, "timed_out": False, "cancelled": True,
            "output_limited": False, "output_bytes": len(raw)}
        return SimpleNamespace(stdout=b"" if options.get("_retain_output") is False else raw, stderr=b"",
            root_exit_code=0, timed_out=False, cancelled=True, output_limited=False,
            failure_code=None, to_dict=lambda: info)

    @staticmethod
    def files(root):
        return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}

    @contextmanager
    def offline(self):
        real_open, real_path_open = artifact_io._open, Path.open
        def opening(path, *args, **kwargs):
            if isinstance(path, (str, bytes, os.PathLike)) and Path(os.fsdecode(path)).name == "auth.json":
                raise AssertionError("No native authentication contents")
            return real_open(path, *args, **kwargs)
        def path_open(path, *args, **kwargs):
            if path.name == "auth.json": raise AssertionError("No native authentication contents")
            return real_path_open(path, *args, **kwargs)
        with patch.object(muse, "run_foreground_experiment", side_effect=AssertionError("No native call")), \
                patch.object(muse, "_preflight", side_effect=AssertionError("No native preflight")), \
                patch.object(muse, "_observe_file", side_effect=AssertionError("No installed native probe")), \
                patch.object(subprocess, "Popen", side_effect=AssertionError("No process")), \
                patch.object(socket, "socket", side_effect=AssertionError("No network")), \
                patch.object(os, "kill", side_effect=AssertionError("No PID probe")), \
                patch.object(os, "killpg", side_effect=AssertionError("No group probe")), \
                patch.object(artifact_io, "_open", side_effect=opening), patch.object(Path, "open", path_open):
            yield

    def plan(self):
        return self.service.provider_result_recovery_plan(run_id=self.high["run_id"])

    def execute(self, proof, *, key="recover-high", output=None):
        return self.service.recover_provider_result(run_id=self.high["run_id"], key=key,
            plan_digest=proof["digest"], output=str(output or self.root / "recovered-high"))

    def assert_preserved(self):
        self.fixture.c.assert_original()
        self.assertEqual(canonical_bytes(self.service.result(self.high["run_id"])), self.high_bytes)
        self.assertEqual(self.files(self.high_root), self.high_files)
        self.assertEqual(self.high_journal.read_bytes(), self.high_journal_bytes)
        self.assertEqual(self.store.setting("provider-claim:muse:" + self.parent["bundle_digest"]), self.parent_claim)
        self.assertEqual(self.store.setting("provider-claim:muse:" + self.high["bundle_digest"]), self.high_claim)
        self.assertEqual(self.store.setting("provider-successor:muse:" + self.parent["run_id"]), self.reservation)

    def journal(self, transform):
        rows = [json.loads(line) for line in self.high_journal.read_bytes().splitlines()]
        rows = transform(rows)
        for index, row in enumerate(rows, 1): row["sequence"] = index
        self.high_journal.write_bytes(b"".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode() + b"\n" for row in rows))

    def test_complete_high_plan_and_recovery_are_model_free_and_preserve_both_histories(self):
        self.complete_high()
        with self.offline():
            proof = self.plan()
            self.assertEqual(proof["format"], "muse-result-recovery-plan/2")
            self.assertTrue(proof["model_free"])
            self.assertEqual(proof["requested_effort"], "high")
            self.assertIsNone(proof["journal"]["reported_effort"])
            self.assertEqual(proof["bundle_digest"], self.high["bundle_digest"])
            self.assertEqual(proof["configuration_digest"], self.high["configuration_digest"])
            self.assertEqual(proof["response_sha256"], hashlib.sha256(self.committed.encode()).hexdigest())
            self.assertEqual(proof["original_capture_status"], "closed")
            result = self.execute(proof)
        self.assertEqual(result["state"], "recovered_proposal_ready")
        self.assertEqual(result["new_controller_submissions"], 0)
        self.assertEqual(result["remote_usage"], "unknown")
        self.assertFalse(result["acceptance_allowed"])
        self.assertEqual((self.root / "recovered-high/proposal/response.json").read_bytes(), canonical_bytes(self.response))
        self.assertEqual((self.root / "recovered-high/snapshot-bundle/provider-submission.json").read_bytes(),
                         (Path(self.high["bundle"]) / "provider-submission.json").read_bytes())
        self.assert_preserved()

    def test_same_key_observes_once_and_changed_key_or_output_cannot_restage(self):
        self.complete_high()
        with self.offline(), patch.object(pilot, "stage", wraps=pilot.stage) as stage:
            proof = self.plan(); result = self.execute(proof)
            self.assertEqual(stage.call_count, 1)
            with patch.object(recovery, "_material", side_effect=AssertionError("No repeated recovery")):
                self.assertEqual(self.execute(proof), result)
            self.assertEqual(stage.call_count, 1)
            for changes in ({"key": "other"}, {"output": self.root / "other-output"}):
                with self.subTest(changes=changes), self.assertRaises(TaskAlongError): self.execute(proof, **changes)
            self.assertEqual(stage.call_count, 1)
        self.assert_preserved()

    def test_unicode_escaped_response_above_legacy_cap_stages_and_observes_exact_bytes(self):
        content = "é" * 32768 + '"\\\t\n' * 1024
        self.assertGreater(len(content.encode()), 65536)
        self.complete_high(replacement=content)
        encoded = canonical_bytes(self.response)
        self.assertGreater(len(encoded), 65536)
        self.assertLess(len(encoded), 1048576)
        with self.offline(), patch.object(pilot, "stage", wraps=pilot.stage) as stage:
            proof = self.plan(); result = self.execute(proof)
            self.assertEqual(proof["response_bytes"], len(encoded))
            self.assertEqual(proof["response_sha256"], hashlib.sha256(encoded).hexdigest())
            self.assertEqual(self.execute(proof), result)
            self.assertEqual(stage.call_count, 1)
        response = (self.root / "recovered-high/proposal/response.json").read_bytes()
        self.assertEqual(response, encoded)
        self.assertEqual(hashlib.sha256(response).hexdigest(), proof["response_sha256"])
        self.assert_preserved()

    def test_recovery_output_cannot_overlap_original_max_parent_bundle_or_anchor(self):
        self.complete_high()
        protected = (Path(self.parent["output"]), Path(self.parent["bundle"]), successor._anchor(self.parent))
        with self.offline():
            proof = self.plan()
            for root in protected:
                output = root / "recovery-must-not-appear"
                with self.subTest(root=root.name), self.assertRaises(TaskAlongError) as caught:
                    self.execute(proof, output=output)
                self.assertEqual(caught.exception.code, "provider_result_recovery_output_overlap")
                self.assertFalse(output.exists())
        self.assertIsNone(self.store.setting("provider-result-recovery:muse:" + self.high["run_id"]))
        self.assert_preserved()

    def test_recovery_does_not_require_current_configuration_or_installed_binary(self):
        self.complete_high()
        self.store.set_setting("provider:muse", {"disabled": True})
        self.fixture.c.binary.unlink()
        with self.offline(): self.assertTrue(self.plan()["model_free"])
        self.assert_preserved()

    def test_malformed_success_status_and_additional_capture_model_task_refuse(self):
        def malformed(rows):
            status = next(row for row in rows if row["payload_type"] == "task.lifecycle.status")
            status["payload"]["event"]["details"]["facets"][0]["attempt"] = False
        self.complete_high(mutate=malformed)
        with self.offline(), self.assertRaises(TaskAlongError): self.plan()

    def test_additional_completed_model_task_in_capture_refuses(self):
        def additional(rows):
            for kind in ("proposed", "side_effect_intent", "started", "completed"):
                value = task_row(len(rows) + 1, kind, SECOND)
                value["stream"]["id"] = self.session
                value["payload"]["command_id"] = self.native_run
                value["payload"]["run_stream"]["id"] = self.native_run
                rows.append(value)
        self.complete_high(mutate=additional)
        with self.offline(), self.assertRaises(TaskAlongError): self.plan()

    def test_reclosed_short_capture_chain_without_accepted_scheduled_refuses(self):
        def missing(rows):
            rows[:] = [row for row in rows if row["payload_type"] not in {"task.lifecycle.accepted", "task.lifecycle.scheduled"}]
        self.complete_high(mutate=missing)
        with self.offline(), self.assertRaises(TaskAlongError): self.plan()

    def test_reclosed_short_journal_chain_without_accepted_scheduled_refuses(self):
        self.complete_high()
        self.journal(lambda rows: [row for row in rows if not (row["payload"].get("kind") == "task"
            and row["payload"]["event"]["kind"] in {"accepted", "scheduled"})])
        with self.offline(), self.assertRaises(TaskAlongError): self.plan()

    def test_coherently_different_journal_task_identity_cannot_match_capture(self):
        self.complete_high()
        def changed(rows):
            for row in rows:
                payload = row["payload"]
                if payload.get("kind") == "task":
                    payload["task_id"] = SECOND
                    payload["event"]["task_id"] = SECOND
                    if "task_stream" in payload: payload["task_stream"]["id"] = SECOND
                    if "task_stream" in payload["event"]: payload["event"]["task_stream"]["id"] = SECOND
            return rows
        self.journal(changed)
        with self.offline(), self.assertRaises(TaskAlongError): self.plan()

    def test_zero_or_additional_journal_model_chains_refuse(self):
        self.complete_high(); original = self.high_journal.read_bytes()
        for variant in ("zero", "second"):
            self.high_journal.write_bytes(original)
            def changed(rows):
                if variant == "zero": return [row for row in rows if row["payload"].get("kind") != "task"]
                extra = []
                for kind in ("proposed", "side_effect_intent", "started", "completed"):
                    event = task_row(1, kind, SECOND)["payload"]["event"]
                    extra.append({"payload_type": "runtime.session", "payload_schema_version": 1,
                        "payload": {"kind": "task", "run_id": self.native_run, "task_id": SECOND, "event": event}})
                position = next(n for n,row in enumerate(rows) if row["payload"].get("event", {}).get("kind") == "assistant_message_committed")
                return rows[:position] + extra + rows[position:]
            self.journal(changed)
            with self.subTest(variant=variant), self.offline(), self.assertRaises(TaskAlongError): self.plan()

    def test_missing_commit_foreign_identity_and_mismatched_commit_refuse(self):
        self.complete_high(); original = self.high_journal.read_bytes()
        for variant in ("missing", "foreign", "different"):
            self.high_journal.write_bytes(original)
            def changed(rows):
                selected = next(row for row in rows if row["payload"].get("event", {}).get("kind") == "assistant_message_committed")
                if variant == "missing": return [row for row in rows if row is not selected]
                if variant == "foreign": selected["payload"]["event"]["details"] = {"run_id": SECOND}
                else: selected["payload"]["event"]["text"] = self.committed.replace("Synthetic", "Different", 1)
                return rows
            self.journal(changed)
            with self.subTest(variant=variant), self.offline(), self.assertRaises(TaskAlongError): self.plan()

    def test_closed_capture_tampering_cannot_be_recovered(self):
        self.complete_high()
        with (self.high_root / "capture/stdout.bin").open("ab") as stream: stream.write(b"unbound tail\n")
        with self.offline(), self.assertRaises(TaskAlongError): self.plan()

    def test_parent_child_claim_and_amendment_lineage_tampering_refuse(self):
        self.complete_high()
        for identity in (self.parent["bundle_digest"], self.high["bundle_digest"]):
            key = "provider-claim:muse:" + identity; original = self.store.setting(key)
            self.store.set_setting(key, original | {"run_id": SECOND})
            with self.subTest(identity=identity), self.offline(), self.assertRaises(TaskAlongError): self.plan()
            self.store.set_setting(key, original)
        key = "provider-successor-root:muse:" + self.parent["run_id"]
        enrollment = self.store.setting(key); enrollment["effort_amendment"]["to_effort"] = "max"
        self.store.set_setting(key, enrollment)
        with self.offline(), self.assertRaises(TaskAlongError): self.plan()

    def test_original_proposal_cap_still_refuses_canonical_overflow(self):
        self.complete_high(over_limit=True)
        with self.offline(), self.assertRaises(TaskAlongError): self.plan()

    def test_staged_output_tampering_never_repairs_or_restages(self):
        self.complete_high()
        with self.offline(): proof = self.plan(); self.execute(proof)
        path = self.root / "recovered-high/proposal/response.json"
        path.chmod(0o600); path.write_bytes(path.read_bytes() + b" "); path.chmod(0o400)
        with self.offline(), patch.object(pilot, "stage", side_effect=AssertionError("No repair")), self.assertRaises(TaskAlongError):
            self.execute(proof)
        self.assert_preserved()


if __name__ == "__main__":
    unittest.main()
