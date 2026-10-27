"""Shared public synthetic Codex/Claude handoff contract, in both directions.

The providers are original external fixtures. Store transactions, route
admission, process ownership, immutable resolution and acceptance are real.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from helpers import ServiceFixture, git
from taskalong.api import RunService
from taskalong.errors import TaskAlongError
from taskalong.store import Store
from taskalong.validation import canonical_bytes, digest, loads, seal, seal_versioned
from test_antigravity_store import upgrade_through
from test_claude_driver import ClaudeBindingFixture, fixture_driver_context
from test_execution_bindings import BindingFixture
from test_qualification import policy_for, reference

PAYLOAD = b"Synthetic reviewed handoff bytes.\n"


def remeasure(configuration, check):
    """Issue exact synthetic evidence after a fixture check-binding change."""
    value = copy.deepcopy(configuration)
    binding = seal_versioned("execution-binding", value["binding"] | {
        "check_binding_digest":check["digest"]}, version="2.0")
    policies = [copy.deepcopy(check) if p["kind"] == "check_binding" else p for p in value["policies"]]
    context = value["context"]
    if "driver_config" in value:
        config = value["driver_config"]
        config = seal_versioned("driver-config", config | {"policy_digests":config["policy_digests"] | {
            "check_binding":check["digest"]}}, version="2.3")
        value["driver_config"] = config
        context["effective_context_digest"] = digest({"policies":sorted(policies,key=lambda p:p["digest"]),
                                                     "driver_config_digest":config["digest"]})
    else:
        context["effective_context_digest"] = digest(sorted(policies,key=lambda p:p["digest"]))
    subject = {key:binding[key] for key in ("installation_digest", "provider_profile_digest",
        "instruction_bundle_digest", "tool_policy_digest", "worker_sandbox_digest", "check_binding_digest")} | {
        "binding_digest":binding["digest"], "runtime_closure_digest":value["installation"]["runtime_closure_digest"],
        "backend_id":"synthetic-fixture", "provider":value["provider"]["provider"],
        "model_digest":value["provider"]["model"]["resolved_digest"], "native_resume_compatibility_digest":None,
        **context}
    receipt = value["receipts"][0]
    old_ref = receipt["results"][0]["evidence_refs"][0]
    observation = loads(value["evidence"].pop(old_ref["sha256"]))
    raw = canonical_bytes(observation | {"subject":subject})
    ref = reference(raw)
    value["evidence"][ref["sha256"]] = raw
    receipt = seal_versioned("qualification-receipt", receipt | {"subject":subject,
        "results":[{"capability":"start","outcome":"supported","evidence_refs":[ref]}]}, version="2.1")
    value.update(binding=binding, policies=policies, context=context, receipts=[receipt], trust=policy_for(receipt))
    return value


class HandoffFixture(ClaudeBindingFixture):
    """Use existing trusted fixture builders with original two-protocol bytes."""
    direction = ("codex", "claude")

    def setUp(self):
        source = (Path(__file__).parent / "fixtures/fake_handoff_driver.py").read_text().replace(
            "#!/usr/bin/env python3", "#!" + sys.executable, 1)
        original_service = ServiceFixture.setUp
        original_binding = BindingFixture.setUp

        def handoff_service(instance):
            original_service(instance)
            instance.executable.write_text(source)
            instance.executable.chmod(0o700)
            instance.profile = seal("runtime-profile", instance.profile | {"profile_id":"handoff-seed",
                "executable_sha256":hashlib.sha256(instance.executable.read_bytes()).hexdigest()})
            instance.service.register_profile(instance.profile)

        def capture_codex(instance):
            original_binding(instance)
            instance.codex_configuration = copy.deepcopy(instance.configuration)
            instance.codex_executable = instance.executable

        def handoff_claude(executable):
            executable.write_text(source)
            executable.chmod(0o700)
            return fixture_driver_context(executable)

        # These patches customize test fixture construction only. No product
        # state, authority, journal, process owner or admission result is mocked.
        with patch.object(ServiceFixture, "setUp", handoff_service), \
             patch.object(BindingFixture, "setUp", capture_codex), \
             patch("test_claude_driver.fixture_driver_context", side_effect=handoff_claude):
            super().setUp()
        self.claude_executable = self.executable
        self.claude_configuration = copy.deepcopy(self.configuration)
        self.executables = {"codex":self.codex_executable,"claude":self.claude_executable}
        for executable in self.executables.values():
            executable.with_suffix(".mode.json").write_text('{"mode":"good"}')
        (self.repo / "second.py").write_text("def add(a, b):\n    return a - b\n")
        git(self.repo, "add", "second.py")
        git(self.repo, "commit", "-m", "Second synthetic handoff file")
        self.base = git(self.repo, "rev-parse", "HEAD")
        self.checks = [{"id":"unit", "argv":[sys.executable,"-B","-c",
            "from arithmetic import add; from second import add as second; assert add(2,3)==5 and second(3,4)==7"],
            "cwd":".","timeout_seconds":5,"expected_exit_code":0,"criterion_ids":["addition"],"required":True}]
        self.review_executable = os.environ.get("TASKALONG_REVIEW_EXECUTABLE")
        self.review_digest = self.task["review"]["config_digest"]
        if self.review_executable:
            configured = self.service.configure_review(Path(__file__).parent/"fixtures/reviewsensei/approved.yml",
                fixture_response=Path(__file__).parent/"fixtures/reviewsensei/clean.json", executable=self.review_executable)
            self.review_digest = configured["config_digest"]
        check = seal_versioned("check-binding", self.check | {"checks_digest":digest(self.checks),
            "review_config_digest":self.review_digest}, version="2.2")
        self.configurations = {"codex":remeasure(self.codex_configuration,check),
                               "claude":remeasure(self.claude_configuration,check)}
        self.service.close()
        with Store.maintenance(self.state) as store:
            upgrade_through(store,self.root,11)
        self.service = RunService(self.state)
        for configuration in self.configurations.values():
            self.service.configure_execution(**configuration)

    def routes(self):
        return [{"route_id":name,"binding_digest":configuration["binding"]["digest"],
            "configuration_digest":configuration["driver_config"]["digest"] if "driver_config" in configuration
                else configuration["runtime_profile_digest"],
            "disclosure_destination_id":configuration["provider"]["profile_id"] if "driver_config" in configuration
                else self.profile["inference_destination_id"]}
            for name,configuration in self.configurations.items()]

    def handoff_task(self, *, empty=False):
        source,target = self.direction
        routes = {r["route_id"]:r for r in self.routes()}
        task = self.spec(attempt_seconds=15,total_seconds=160)
        task.update(schema_version="2.10",checks=self.checks,scope={"files":["arithmetic.py","second.py","handoff/note.txt"],
            "operations":["add","modify"]},execution={"routes":list(routes.values()),"check_route_id":"codex"},
            final_verification={"max_passes":1,"total_active_seconds":100,"max_output_bytes":524288})
        task["permissions"].pop("inference_destination_id")
        task["permissions"]["disclosure_destination_ids"] = [r["disclosure_destination_id"] for r in routes.values()]
        task["review"]["config_digest"] = self.review_digest
        task["budget"].update(max_attempts=4,attempt_output_bytes=65536)
        output = {"output_id":"note","artifact_kind":"utf8_text","path":"handoff/note.txt",
            "max_bytes":0 if empty else len(PAYLOAD),"classification":"synthetic_fixture",
            "allowed_target_binding_digests":[routes[target]["binding_digest"]],
            "allowed_disclosure_destination_ids":[routes[target]["disclosure_destination_id"]]}
        task["steps"] = [
            {"step_id":"A","goal":"Create a reviewed synthetic artifact and fix the first file.",
             "scope":{"files":["arithmetic.py","handoff/note.txt"],"operations":["add","modify"]},
             "inputs":[],"required":True,"route_id":source,"outputs":[output],
             "import_scope":{"files":[],"operations":["modify"]}},
            {"step_id":"B","goal":"Consume exact staged synthetic bytes and fix the second file.",
             "scope":{"files":["second.py"],"operations":["modify"]},"required":True,"route_id":target,
             "inputs":[{"kind":"step_output","from_step_id":"A","output_id":"note",
                 "expected_kind":"utf8_text","max_bytes":output["max_bytes"]}],"outputs":[],
             "import_scope":{"files":[],"operations":["modify"]}}]
        return seal_versioned("task-spec",task,version="2.10")

    def invocations(self):
        path = self.root/"handoff-invocations.jsonl"
        return [loads(line) for line in path.read_bytes().splitlines()] if path.exists() else []

    def starts(self):
        path = self.root/"handoff-starts.jsonl"
        return [loads(line) for line in path.read_bytes().splitlines()] if path.exists() else []

    def set_driver_mode(self, name, mode):
        self.executables[name].with_suffix(".mode.json").write_text(json.dumps({"mode":mode}))

    def producer_stopped(self, task=None):
        run,task = self.submit(task or self.handoff_task())
        self.start(run)
        stopped = self.wait(run["run_id"],predicate=lambda r:not r["active_attempt_id"] and r["state"] in {"ready","blocked","cancelled"})
        return stopped,task

    def first(self, task=None):
        stopped,task = self.producer_stopped(task)
        self.assertEqual(stopped["steps"][0]["status"],"completed",stopped)
        self.assertEqual(stopped["steps"][1]["status"],"pending",stopped)
        return stopped,task

    def advance(self, first, *, key="handoff-advance"):
        return self.service.advance(first["run_id"],expected_step_id="B",predecessor_digest=first["steps"][0]["receipt_digest"],
            operation_key=key,expected_revision=first["revision"])


class SharedHandoffContract:
    def assert_no_target(self, run_id):
        self.assertEqual(len(self.invocations()),1)
        self.assertEqual(len(self.starts()),1)
        observed = self.service._store.run(run_id)
        self.assertIsNone(observed["acceptance_id"])
        self.assertEqual(observed["steps"][1]["receipt_digest"],None)
        return observed

    def test_finish_identity_guards_same_step_retry_before_and_during_commit(self):
        first,_=self.first()
        self.set_driver_mode(self.direction[1],"failed")
        self.advance(first)
        failed=self.wait(first["run_id"],timeout=25)
        self.assertEqual(failed["steps"][1]["status"],"failed",failed)
        older=failed["steps"][1]["attempt_ids"][0]
        self.set_driver_mode(self.direction[1],"good")
        with patch.object(self.service._workflow,"_launch_supervisor",lambda *a:None):
            prepared=self.service.retry(first["run_id"],expected_step_id="B",operation_key="finish-identity-retry",expected_revision=failed["revision"])
        from taskalong import workflow, steps
        from taskalong.store import encode
        captured=[]
        finish=workflow._finish_attempt
        def retain_result(store,run_id,attempt_id,result,worker,**kwargs):
            captured.append((result,worker))
            return store.run(run_id)
        with patch("taskalong.workflow._finish_attempt",side_effect=retain_result):
            workflow.drive_run(self.state,first["run_id"],prepared["active_attempt_id"])
        self.assertEqual(len(captured),1)
        result,worker=captured[0]
        self.assertTrue(result["process"]["termination_confirmed"])
        attempt_id=prepared["active_attempt_id"]
        current=self.service._store.run(first["run_id"])
        item=self.service._store.detail("attempts",attempt_id)
        receipt=steps.completed_receipt
        def replace(value):
            self.service._store.db.execute("UPDATE attempts SET document=? WHERE attempt_id=?",(encode(value),attempt_id))
        try:
            for field,value in (("step_index",-1),("step_index",True),("step_index",0),("step_id","A"),("attempt_id",older)):
                for during_commit in (False,True):
                    with self.subTest(field=field,value=value,during_commit=during_commit):
                        replace(item)
                        def corrupt_after_receipt(*args,**kwargs):
                            ref=receipt(*args,**kwargs)
                            replace(item | {field:value})
                            return ref
                        if not during_commit:
                            replace(item | {field:value})
                        blobs=self.service._store.db.execute("SELECT count(*) FROM blobs").fetchone()[0]
                        with patch("taskalong.steps.completed_receipt",side_effect=corrupt_after_receipt if during_commit else AssertionError("No receipt may precede identity validation")):
                            with self.assertRaises(TaskAlongError) as error:
                                finish(self.service._store,first["run_id"],attempt_id,result,worker)
                        self.assertEqual(error.exception.code,"step_identity_mismatch")
                        self.assertEqual(self.service._store.run(first["run_id"]),current)
                        if not during_commit:
                            self.assertEqual(self.service._store.db.execute("SELECT count(*) FROM blobs").fetchone()[0],blobs)
        finally:
            replace(item)
            finish(self.service._store,first["run_id"],attempt_id,result,worker)
        finished=self.service._store.run(first["run_id"])
        self.assertEqual(finished["steps"][1]["status"],"completed")
        self.assertEqual(finished["reservation_totals"]["attempts"],3)

    def test_two_driver_handoff_binds_exact_bytes_and_fresh_sessions(self):
        task = self.handoff_task()
        immutable = canonical_bytes(task)
        first,_ = self.first(task)
        self.assertIsNone(first["candidate"])
        self.assertIsNone(first["acceptance_id"])
        self.assertEqual(len(self.invocations()),1)
        self.advance(first)
        final = self.wait(first["run_id"],timeout=35)
        self.assertEqual([s["status"] for s in final["steps"]],["completed","completed"],final)
        self.assertEqual(len(final["attempts"]),2)
        self.assertEqual(len(self.starts()),2)
        self.assertEqual(final["reservation_totals"]["attempts"],2)
        self.assertEqual(canonical_bytes(self.service._store.spec(final)),immutable)
        observations = self.invocations()
        self.assertEqual([o["driver"] for o in observations],list(self.direction))
        self.assertNotEqual(observations[0]["session"],observations[1]["session"])
        self.assertNotEqual(observations[0]["attempt_id"],observations[1]["attempt_id"])
        self.assertTrue(all(not o["credential_environment_present"] for o in observations))
        self.assertEqual(observations[1]["staged"],[{"sha256":hashlib.sha256(PAYLOAD).hexdigest(),"bytes":len(PAYLOAD)}])
        attempts = [self.service._store.detail("attempts",a["attempt_id"]) for a in final["attempts"]]
        self.assertGreater(attempts[1]["lease_generation"],attempts[0]["lease_generation"])
        self.assertNotIn(observations[0]["session"].encode(),canonical_bytes(attempts[1]["packet"]))
        self.assertNotIn(b"fixture-auth",canonical_bytes(attempts[1]["packet"]))
        self.assertEqual(attempts[0]["thread_id"],observations[0]["session"] if self.direction[0] == "codex" else None)
        self.assertIsNotNone(final["execution_chain_digest"])
        result = self.service.result(final["run_id"])
        self.assertLess(result["observed_usage"]["worker_duration_ms"],final["reservation_totals"]["active_seconds"]*1000)
        self.assertLess(result["observed_usage"]["captured_output_bytes"],final["reservation_totals"]["output_bytes"])
        if self.review_executable:
            self.assertEqual(final["state"],"accepted",final)
            self.assertTrue(result["independently_accepted"])
        else:
            self.assertEqual(final["state"],"blocked",final)
            self.assertIn("required_review_missing",{b["code"] for b in final["blockers"]})
            self.assertFalse(result["independently_accepted"])
            self.assertTrue(any(e["type"] == "command" and e["result"] == "passed"
                for e in self.export(final["run_id"])["evidence"]))

    def test_empty_declared_text_is_present_and_consumed(self):
        self.set_driver_mode(self.direction[0],"empty")
        first,_ = self.first(self.handoff_task(empty=True))
        self.advance(first)
        final = self.wait(first["run_id"],timeout=35)
        self.assertEqual([s["status"] for s in final["steps"]],["completed","completed"],final)
        self.assertEqual(self.invocations()[1]["staged"],[{"sha256":hashlib.sha256(b"").hexdigest(),"bytes":0}])

    def test_selector_missing_wrong_kind_and_unauthorized_target_refuse_before_workers(self):
        for change in ("missing","kind","target"):
            with self.subTest(change=change):
                task = self.handoff_task()
                if change == "missing":
                    task["steps"][1]["inputs"][0]["output_id"] = "not-declared"
                elif change == "kind":
                    task["steps"][1]["inputs"][0]["expected_kind"] = "file_set_patch"
                else:
                    task["steps"][0]["outputs"][0]["allowed_target_binding_digests"] = [task["execution"]["routes"][0]["binding_digest"]]
                    if self.direction[1] == "codex":
                        task["steps"][0]["outputs"][0]["allowed_target_binding_digests"] = [task["execution"]["routes"][1]["binding_digest"]]
                with self.assertRaises(TaskAlongError):
                    seal_versioned("task-spec",task,version="2.10")
                self.assertEqual(self.invocations(),[])

    def test_duplicate_outputs_selectors_and_unknown_modes_fail_closed(self):
        for change in ("duplicate-output","duplicate-selector","self","forward","version","production"):
            with self.subTest(change=change):
                task = self.handoff_task()
                if change == "duplicate-output":
                    task["steps"][0]["outputs"].append(copy.deepcopy(task["steps"][0]["outputs"][0]))
                elif change == "duplicate-selector":
                    task["steps"][1]["inputs"].append(copy.deepcopy(task["steps"][1]["inputs"][0]))
                elif change in {"self","forward"}:
                    task["steps"][0]["inputs"] = copy.deepcopy(task["steps"][1]["inputs"])
                    task["steps"][0]["inputs"][0]["from_step_id"] = "A" if change == "self" else "B"
                elif change == "version":
                    task["schema_version"] = "2.11"
                else:
                    task["qualification"] = "production"
                with self.assertRaises(TaskAlongError):
                    seal_versioned("task-spec",task,version="2.10")
                self.assertEqual(self.invocations(),[])

    def test_missing_declared_output_blocks_the_producer_receipt(self):
        self.set_driver_mode(self.direction[0],"missing-note")
        stopped,_ = self.producer_stopped()
        self.assertEqual(stopped["steps"][0]["status"],"failed",stopped)
        self.assertIsNone(stopped["steps"][0]["receipt_digest"])
        self.assertIsNone(stopped["steps"][0]["output_manifest_blob_sha256"])
        self.assert_no_target(stopped["run_id"])

    def test_producer_partial_retry_admits_only_successful_attempt_outputs(self):
        self.set_driver_mode(self.direction[0],"failed-after-edits")
        failed,_ = self.producer_stopped()
        self.assertEqual(failed["steps"][0]["status"],"failed",failed)
        self.assertIsNone(failed["steps"][0]["receipt_digest"])
        failed_attempt_id = failed["steps"][0]["attempt_ids"][0]
        workspace = Path(self.service._store.lease(failed)["workspace"]["path"])
        partial = {path:(workspace/path).read_bytes() for path in ("arithmetic.py","handoff/note.txt")}
        self.set_driver_mode(self.direction[0],"good")
        self.service.retry(failed["run_id"],expected_step_id="A",operation_key="retry-producer",
                           expected_revision=failed["revision"])
        first = self.wait(failed["run_id"],predicate=lambda r:not r["active_attempt_id"] and r["state"] in {"ready","blocked"})
        self.assertEqual(first["steps"][0]["status"],"completed",first)
        self.assertEqual(first["reservation_totals"]["attempts"],2)
        self.assertEqual(len(first["steps"][0]["attempt_ids"]),2)
        self.assertEqual({path:(workspace/path).read_bytes() for path in partial},partial)
        receipt = loads(self.service._store.get_blob(first["steps"][0]["receipt_digest"]))
        manifest = loads(self.service._store.get_blob(first["steps"][0]["output_manifest_blob_sha256"]))
        self.assertNotEqual(receipt["attempt_id"],failed_attempt_id)
        self.assertEqual(manifest["attempt_id"],receipt["attempt_id"])
        self.assertEqual(manifest["producer_receipt_blob_sha256"],first["steps"][0]["receipt_digest"])
        self.assertIsNone(self.service._store.detail("attempts",failed_attempt_id).get("output_manifest_blob_sha256"))
        self.advance(first)
        final = self.wait(first["run_id"],timeout=35)
        self.assertEqual([s["status"] for s in final["steps"]],["completed","completed"],final)
        self.assertEqual(final["reservation_totals"]["attempts"],3)
        self.assertEqual(len(self.starts()),3)

    def test_changed_source_blob_blocks_target_without_replacing_history(self):
        first,_ = self.first()
        manifest = loads(self.service._store.get_blob(first["steps"][0]["output_manifest_blob_sha256"]))
        artifact = manifest["outputs"][0]["artifact"]
        (self.service._store.blob_root/artifact["sha256"]).write_bytes(b"tampered synthetic handoff")
        with self.assertRaises(TaskAlongError):
            self.advance(first)
        observed = self.assert_no_target(first["run_id"])
        self.assertEqual(observed["steps"][0],first["steps"][0])
        self.assertEqual(observed["reservation_totals"],first["reservation_totals"])
        self.run_ids.remove(first["run_id"])

    def test_embedded_receipt_digest_cannot_replace_blob_address(self):
        first,_ = self.first()
        receipt = loads(self.service._store.get_blob(first["steps"][0]["receipt_digest"]))
        self.assertNotEqual(receipt["digest"],first["steps"][0]["receipt_digest"])
        changed = self.service._store.run(first["run_id"])
        changed["steps"][0]["receipt_digest"] = receipt["digest"]
        # Deliberately corrupt one private persisted reference. No successful
        # core mutation or proof validation is replaced by this negative fixture.
        self.service._store.db.execute("UPDATE runs SET document=? WHERE run_id=?",
            (canonical_bytes(changed).decode(),first["run_id"]))
        with self.assertRaises(TaskAlongError):
            self.advance(first)
        self.assert_no_target(first["run_id"])
        self.run_ids.remove(first["run_id"])

    def test_resealed_manifest_cannot_forge_the_finish_operation(self):
        first,_ = self.first()
        store = self.service._store
        run = store.run(first["run_id"])
        aid = run["steps"][0]["attempt_ids"][0]
        attempt = store.detail("attempts",aid)
        manifest = loads(store.get_blob(run["steps"][0]["output_manifest_blob_sha256"]))
        substituted = store.put_blob(b"Another synthetic reviewed note.\n",media_type="text/plain")
        manifest["outputs"][0]["artifact"] = substituted
        manifest = seal_versioned("output-manifest",manifest,version="2.10")
        fake = store.put_blob(canonical_bytes(manifest))["sha256"]
        run["steps"][0]["output_manifest_blob_sha256"] = fake
        attempt["output_manifest_blob_sha256"] = fake
        with store.transaction() as db:
            db.execute("UPDATE runs SET document=? WHERE run_id=?",(canonical_bytes(run).decode(),run["run_id"]))
            db.execute("UPDATE attempts SET document=? WHERE attempt_id=?",(canonical_bytes(attempt).decode(),aid))
        with self.assertRaises(TaskAlongError) as error:
            self.advance(first)
        self.assertEqual(error.exception.code,"artifact_proof_forged")
        self.assert_no_target(first["run_id"])
        self.run_ids.remove(first["run_id"])

    def test_changed_workspace_base_cannot_admit_target(self):
        first,_ = self.first()
        workspace = Path(self.service._store.lease(first)["workspace"]["path"])
        git(workspace,"add","arithmetic.py","handoff/note.txt")
        git(workspace,"commit","-m","Unapproved synthetic worker commit")
        with self.assertRaises(TaskAlongError):
            self.advance(first)
        self.assert_no_target(first["run_id"])

    def test_staged_bytes_changed_after_packet_compile_prevent_gate_release(self):
        from taskalong import artifact_handoff
        from taskalong._supervisor import run_guard
        from taskalong.workflow import drive_run
        first,_ = self.first()
        with patch.object(self.service._workflow,"_launch_supervisor") as launch:
            prepared = self.advance(first)
            launch.assert_called_once()
        compile_packet = artifact_handoff.compile_packet
        altered = []

        def compile_then_change(store,run,attempt,fields,admission):
            compiled = compile_packet(store,run,attempt,fields,admission)
            wire = compiled[1]
            entry = wire["extensions"]["taskalong:handoff"]["staged_inputs"][0]
            target = Path(attempt["workspace"]["path"])/entry["path"]
            target.chmod(0o600)
            target.write_bytes(b"Changed staged synthetic bytes.")
            altered.append(True)
            return compiled

        with patch.object(artifact_handoff,"compile_packet",side_effect=compile_then_change), \
             run_guard(self.state,first["run_id"]):
            drive_run(self.state,first["run_id"],prepared["active_attempt_id"])
        self.assertEqual(altered,[True])
        final = self.assert_no_target(first["run_id"])
        self.assertNotEqual(final["steps"][1]["status"],"completed")

    def test_unknown_owner_cessation_at_finish_keeps_output_unadmitted(self):
        from taskalong import workflow
        from taskalong._supervisor import run_guard
        run,task = self.submit(self.handoff_task())
        with patch.object(self.service._workflow,"_launch_supervisor"):
            prepared = self.start(run)
        finish = workflow._finish_attempt
        actual_receipts = []

        def unknown_finish(store,run_id,attempt_id,result,worker,**options):
            self.assertIs(result["process"].get("termination_confirmed"),True)
            actual_receipts.append(copy.deepcopy(result["process"]))
            unknown = copy.deepcopy(result)
            unknown["process"].update(termination_confirmed=False,unaccounted_descendants=True)
            return finish(store,run_id,attempt_id,unknown,worker,**options)

        with patch.object(workflow,"_finish_attempt",side_effect=unknown_finish), run_guard(self.state,run["run_id"]):
            workflow.drive_run(self.state,run["run_id"],prepared["active_attempt_id"])
        observed = self.service._store.run(run["run_id"])
        self.assertEqual(len(actual_receipts),1)
        self.assertEqual(observed["state"],"blocked")
        self.assertIsNotNone(observed["active_attempt_id"])
        self.assertTrue(observed["pending_effect_ids"])
        self.assertIsNone(observed["steps"][0]["receipt_digest"])
        self.assertIsNone(observed["steps"][0]["output_manifest_blob_sha256"])
        with self.assertRaises(TaskAlongError):
            self.service.advance(run["run_id"],expected_step_id="B",predecessor_digest="0"*64,
                operation_key="after-unknown",expected_revision=observed["revision"])
        self.assert_no_target(run["run_id"])
        # The injected uncertainty tests core admission; the real fixture was
        # already stopped/reaped as independently asserted above. Avoid asking
        # generic cleanup to settle the intentionally corrupted observation.
        self.run_ids.remove(run["run_id"])

    def test_released_review_independently_accepts_both_required_steps(self):
        if not self.review_executable:
            self.skipTest("released reviewer required; core-only handoff smoke separately refuses acceptance")
        first,_ = self.first()
        self.advance(first)
        final = self.wait(first["run_id"],timeout=35)
        self.assertEqual(final["state"],"accepted",final)
        self.assertTrue(self.service.result(final["run_id"])["independently_accepted"])


class CodexToClaudeHandoffTests(SharedHandoffContract,HandoffFixture,unittest.TestCase):
    direction = ("codex","claude")


class ClaudeToCodexHandoffTests(SharedHandoffContract,HandoffFixture,unittest.TestCase):
    direction = ("claude","codex")


if __name__ == "__main__":
    unittest.main()
