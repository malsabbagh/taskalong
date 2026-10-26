"""Core-owned closed patch imports through the existing ordered lifecycle."""
import copy
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import unittest
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, loads, seal_versioned
from test_artifact_handoff import HandoffFixture

FIXED = "def add(a, b):\n    return a + b\n"
BEFORE = b"def add(a, b):\n    return a - b\n"


class ArtifactImportTests(HandoffFixture, unittest.TestCase):
    def patch_task(self, *, overlap=False, out_of_scope=False):
        task = self.handoff_task()
        envelope = seal_versioned("file-set-patch", {"files":[{
            "path":"arithmetic.py" if out_of_scope else "second.py", "operation":"modify",
            "before_sha256":hashlib.sha256(BEFORE).hexdigest(), "before_bytes":len(BEFORE),
            "after_sha256":hashlib.sha256(FIXED.encode()).hexdigest(), "after_bytes":len(FIXED.encode()),
            "mode":"100644", "payload_output_id":"note"}]}, version="2.10")
        self.executables[self.direction[0]].with_suffix(".mode.json").write_text(json.dumps({
            "mode":"good", "payload":FIXED, "patch":envelope}))
        first, second = task["steps"]
        first["scope"]["files"].append("handoff/change.json")
        task["scope"]["files"].append("handoff/change.json")
        first["outputs"][0]["max_bytes"] = 4096
        declared = copy.deepcopy(first["outputs"][0]) | {"output_id":"patch", "artifact_kind":"file_set_patch",
            "path":"handoff/change.json", "max_bytes":4096}
        first["outputs"].append(declared)
        second["inputs"] = [{"kind":"step_output", "from_step_id":"A", "output_id":"patch",
            "expected_kind":"file_set_patch", "max_bytes":4096}]
        second["import_scope"] = {"files":["second.py"], "operations":["modify"]}
        if overlap:
            # A second output identity is an equally authorized artifact, but
            # must not create a second writer for the same literal destination.
            first["outputs"].append(declared | {"output_id":"second-patch","path":"handoff/second-change.json"})
            first["scope"]["files"].append("handoff/second-change.json")
            task["scope"]["files"].append("handoff/second-change.json")
            second["inputs"].append(second["inputs"][0] | {"output_id":"second-patch"})
        return seal_versioned("task-spec", task, version="2.10")

    def test_core_patch_has_explicit_before_after_edge_and_worker_delta(self):
        first, _ = self.first(self.patch_task())
        self.advance(first)
        final = self.wait(first["run_id"], timeout=35)
        self.assertEqual([s["status"] for s in final["steps"]], ["completed","completed"], final)
        attempts = [self.service._store.detail("attempts", a["attempt_id"]) for a in final["attempts"]]
        journal = loads(self.service._store.get_blob(attempts[1]["import_journal_blob_sha256"]))
        preceding = loads(self.service._store.get_blob(final["steps"][0]["receipt_digest"]))
        self.assertEqual(journal["before_content_digest"], preceding["final_snapshot_digest"])
        self.assertNotEqual(journal["before_content_digest"], journal["after_content_digest"])
        self.assertEqual(journal["after_content_digest"], attempts[1]["starting_snapshot_digest"])
        self.assertEqual((Path(attempts[1]["workspace"]["path"])/"second.py").read_text(), FIXED)
        worker = loads(self.service._store.get_blob(attempts[1]["result_artifact"]["sha256"]))
        self.assertEqual(worker["changed_files"], [], "The core import must not be attributed to worker edits")
        self.assertEqual(len(self.invocations()),2)
        if self.review_executable:
            self.assertEqual(final["state"],"accepted",final)
        # Settled import effects remain eligible for ordinary exclusive complete
        # maintenance; merely setting an effect phase to observed is insufficient.
        self.service.close()
        from taskalong.api import RunService
        from taskalong.store import Store
        from taskalong.maintenance import verify_backup
        with Store.maintenance(self.state) as maintenance:
            backed=maintenance.backup(self.root/"completed-handoff-backup",complete=True)
            self.assertEqual(verify_backup(self.root/"completed-handoff-backup",expected_digest=backed["digest"])["database"]["user_version"],11)
        self.service=RunService(self.state)

    def test_patch_outside_import_scope_cannot_launch_target_or_write(self):
        first, _ = self.first(self.patch_task(out_of_scope=True))
        self.advance(first)
        stopped = self.wait(first["run_id"], states=("blocked",), timeout=20)
        self.assertIn("artifact_import_scope",{b["code"] for b in stopped["blockers"]})
        self.assertEqual(len(self.invocations()),1)
        self.assertIsNone(stopped["acceptance_id"])

    def test_patch_payload_and_envelope_total_obeys_selector_limit(self):
        task = self.patch_task()
        envelope_bytes = canonical_bytes(loads(self.executables[self.direction[0]].with_suffix(".mode.json").read_bytes())["patch"])
        task["steps"][1]["inputs"][0]["max_bytes"] = len(envelope_bytes)
        task = seal_versioned("task-spec",task,version="2.10")
        first,_ = self.first(task)
        self.advance(first)
        stopped = self.wait(first["run_id"], states=("blocked",), timeout=20)
        self.assertIn("artifact_size_limit",{b["code"] for b in stopped["blockers"]})
        self.assertEqual(len(self.invocations()),1)

    def test_patch_parser_rejects_duplicate_destinations_and_unknown_fields(self):
        task = self.patch_task()
        value = loads(self.executables[self.direction[0]].with_suffix(".mode.json").read_bytes())["patch"]
        for change in (value | {"files":value["files"]*2}, value | {"shell":"never execute"}):
            with self.assertRaises(TaskAlongError):
                seal_versioned("file-set-patch",change,version="2.10")

    def test_patch_cannot_disclose_a_source_only_referenced_payload(self):
        task = self.patch_task()
        source = next(r for r in task["execution"]["routes"] if r["route_id"] == self.direction[0])
        task["steps"][0]["outputs"][0]["allowed_target_binding_digests"] = [source["binding_digest"]]
        task["steps"][0]["outputs"][0]["allowed_disclosure_destination_ids"] = [source["disclosure_destination_id"]]
        task = seal_versioned("task-spec",task,version="2.10")
        first,_ = self.first(task)
        self.advance(first)
        stopped = self.wait(first["run_id"],states=("blocked",),timeout=20)
        self.assertIn("artifact_disclosure_forbidden",{b["code"] for b in stopped["blockers"]})
        self.assertEqual(len(self.starts()),1)
        target = Path(self.service._store.lease(stopped)["workspace"]["path"])/"second.py"
        self.assertEqual(target.read_bytes(),BEFORE)

    def test_failed_target_retry_preserves_import_without_reapplying(self):
        first,_ = self.first(self.patch_task())
        self.set_driver_mode(self.direction[1],"failed")
        self.advance(first)
        stopped = self.wait(first["run_id"],timeout=25)
        self.assertEqual(stopped["steps"][1]["status"],"failed",stopped)
        first_target=self.service._store.detail("attempts",stopped["attempts"][-1]["attempt_id"])
        self.assertTrue(first_target["import_committed"])
        self.set_driver_mode(self.direction[1],"good")
        self.service.retry(stopped["run_id"],expected_step_id="B",operation_key="retry-import",expected_revision=stopped["revision"])
        final=self.wait(first["run_id"],timeout=35)
        self.assertEqual([s["status"] for s in final["steps"]],["completed","completed"],final)
        retry=self.service._store.detail("attempts",final["attempts"][-1]["attempt_id"])
        self.assertEqual(retry["resolved_inputs_blob_sha256"],first_target["resolved_inputs_blob_sha256"])
        self.assertEqual(retry["import_journal_blob_sha256"],first_target["import_journal_blob_sha256"])
        imports=self.service._store.db.execute("SELECT count(*) FROM operations WHERE run_id=? AND command='artifact.import.commit'",(final["run_id"],)).fetchone()[0]
        self.assertEqual(imports,2,"One empty first-step import and exactly one second-step import")
        self.assertEqual(final["reservation_totals"]["attempts"],3)

    def test_cancellation_during_import_blocks_target_and_settles_only_known_writes(self):
        first,_ = self.first(self.patch_task())
        with patch.object(self.service._workflow,"_launch_supervisor",lambda *a:None):
            prepared=self.advance(first)
        from taskalong.workflow import drive_run
        from taskalong.artifact_io import apply_regular
        def cancel_after_write(*args,**kwargs):
            apply_regular(*args,**kwargs)
            current=self.service._store.run(first["run_id"])
            self.service.cancel(first["run_id"],operation_key="cancel-import",expected_revision=current["revision"])
        with patch("taskalong.artifact_io.apply_regular",side_effect=cancel_after_write):
            drive_run(self.state,first["run_id"],prepared["active_attempt_id"])
        stopped=self.service.inspect(first["run_id"])
        self.assertEqual(stopped["state"],"cancel_pending",stopped)
        self.assertEqual(len(self.starts()),1)
        reserved=stopped["reservation_totals"]
        final=self.service.reconcile(first["run_id"],operation_key="settle-cancelled-import",expected_revision=stopped["revision"])
        self.assertEqual(final["state"],"cancelled",final)
        self.assertIsNone(final["steps"][1]["receipt_digest"])
        self.assertEqual(final["reservation_totals"],reserved)
        self.assertEqual(final["pending_effect_ids"],[])
        self.assertEqual(len(self.starts()),1)

    def test_sigkill_between_files_recovers_exact_journal_once(self):
        task = self.patch_task()
        settings=loads(self.executables[self.direction[0]].with_suffix(".mode.json").read_bytes())
        extra=copy.deepcopy(settings["patch"]["files"][0]) | {"path":"extra.txt","operation":"add","before_sha256":None,"before_bytes":None}
        settings["patch"]=seal_versioned("file-set-patch",settings["patch"] | {"files":settings["patch"]["files"]+[extra]},version="2.10")
        self.executables[self.direction[0]].with_suffix(".mode.json").write_text(json.dumps(settings))
        task["scope"]["files"].append("extra.txt")
        task["steps"][1]["import_scope"]={"files":["second.py","extra.txt"],"operations":["add","modify"]}
        task["budget"].update(attempt_seconds=45,total_active_seconds=220)
        task=seal_versioned("task-spec",task,version="2.10")
        first,_=self.first(task)
        with patch.object(self.service._workflow,"_launch_supervisor",lambda *a:None):
            prepared=self.advance(first)
        reader,writer=os.pipe()
        program=r'''
import os,signal,sys
from taskalong._supervisor import run_guard
from taskalong.workflow import drive_run
from taskalong import artifact_io
state,run,attempt,fd=sys.argv[1:];fd=int(fd)
original=artifact_io.apply_regular
count=0
def barrier(*args,**kwargs):
    global count
    original(*args,**kwargs);count+=1
    if count==1:
        os.write(fd,b'W');signal.pause()
artifact_io.apply_regular=barrier
with run_guard(state,run):drive_run(state,run,attempt)
'''
        child=subprocess.Popen([sys.executable,"-B","-c",program,str(self.state),first["run_id"],prepared["active_attempt_id"],str(writer)],
            pass_fds=(writer,),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        os.close(writer)
        try:
            ready,_,_=select.select([reader],[],[],15)
            self.assertTrue(ready,"Import did not reach its durable between-file barrier")
            self.assertEqual(os.read(reader,1),b"W")
            self.assertEqual(len(self.starts()),1)
            workspace=Path(self.service._store.lease(self.service._store.run(first["run_id"]))["workspace"]["path"])
            first_mtime=(workspace/"second.py").stat().st_mtime_ns
            self.assertEqual((workspace/"second.py").read_text(),FIXED)
            self.assertFalse((workspace/"extra.txt").exists())
            child.send_signal(signal.SIGKILL);child.communicate(timeout=5)
            self.assertEqual(child.returncode,-signal.SIGKILL)
            current=self.service._store.run(first["run_id"])
            reservations=copy.deepcopy(current["reservation_totals"])
            original_attempt=self.service._store.detail("attempts",prepared["active_attempt_id"])
            self.assertIsNotNone(original_attempt["import_journal_blob_sha256"])
            self.assertFalse(original_attempt.get("import_committed",False))
            from taskalong.api import RunService
            self.service.close();self.service=RunService(self.state)
            self.service.reconcile(first["run_id"],operation_key="recover-exact-import",expected_revision=current["revision"])
            final=self.wait(first["run_id"],timeout=35)
            self.assertEqual([s["status"] for s in final["steps"]],["completed","completed"],final)
            recovered=self.service._store.detail("attempts",prepared["active_attempt_id"])
            self.assertEqual(recovered["import_journal_blob_sha256"],original_attempt["import_journal_blob_sha256"])
            self.assertEqual(recovered["attempt_id"],original_attempt["attempt_id"])
            self.assertEqual((workspace/"extra.txt").read_text(),FIXED)
            self.assertEqual((workspace/"second.py").stat().st_mtime_ns,first_mtime)
            self.assertEqual(final["reservation_totals"]["attempts"],reservations["attempts"])
            self.assertEqual(len(self.starts()),2)
        finally:
            os.close(reader)
            if child.poll() is None:
                child.kill();child.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
