"""Public CLI regressions adopted from the independent issue #10 audit.

The ordinary sequence uses external CLI processes. Explicit fault injections
observe real crash boundaries or corrupt retained evidence and are labelled.
No provider call or fabricated successful process receipt is used.
"""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from ordered_cli_probe import CLIProbe, canonical, sha
from ordered_fault_barriers import install_exit_barrier, remove_barrier, require_boundary

HERE = Path(__file__).resolve().parent


class OrderedCLITests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="m10-independent-")).resolve()
        self.probe = CLIProbe(self.root, python=os.environ.get("M10_PYTHON"),
                              source=os.environ.get("M10_SOURCE"))
        self.binding = json.loads(Path(os.environ.get("M10_BINDING", HERE / "fixtures/ordered_binding.json")).read_bytes())
        self.probe.prepare_format(10)
        self.run_id = None
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Independent Synthetic Operator")
        self.git("config", "user.email", "synthetic@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        for name in ("a.py", "b.py", "outside.py"):
            (self.repo / name).write_text("def value():\n    return 1\n")
        (self.repo / "input.txt").write_text("frozen input\n")
        check = "from pathlib import Path\nimport a,b\nPath(" + repr(str(self.root / "checks.jsonl")) + ").open('a').write('check\\n')\nassert a.value()==2 and b.value()==2\n"
        (self.repo / "check.py").write_text(check)
        self.git("add", ".")
        self.git("commit", "-m", "Independent M10 fixture baseline")
        self.base = self.git("rev-parse", "HEAD")
        self.probe.write_json("identity.json", {"runtime": self.probe.identity(), "source": os.environ.get("M10_SOURCE"),
            "binding": self.binding})
        worker = self.root / "worker"
        worker.write_text((HERE / "fixtures/ordered_codex.py").read_text().replace("#!/usr/bin/env python3", "#!" + self.probe.python, 1))
        worker.chmod(0o700)
        self.controls = {"a.py": "good", "b.py": "good"}
        self.control()
        launcher = self.root / "command-launcher"
        launcher.write_text("#!" + self.probe.python + "\nimport os,sys\nargs=sys.argv[sys.argv.index('--')+1:]\nos.execv(args[0],args)\n")
        launcher.chmod(0o700)
        self.registration = self.probe.call("register-repository", self.repo,
            "--workspace-root", self.root / "workspaces")["data"]
        profile = {"profile_id": "independent-m10-fixture", "qualification": "synthetic",
            "adapter": "codex-cli", "executable_path": str(worker),
            "executable_sha256": sha(worker.read_bytes()), "runtime_version": "0.163.0",
            "model": "synthetic", "reasoning_effort": "low", "service_tier": None,
            "inference_destination_id": "independent-local-fixture", "permission_policy": {},
            "permission_policy_digest": sha(canonical({})), "toolchain_read_roots": [],
            "credential_source_ref": None, "qualification_receipt_ids": []}
        self.profile = self.probe.call("register-profile", "--profile",
            self.probe.write_json("profile.json", profile))["data"]
        self.probe.call("configure-sandbox", "--executable", launcher)
        self.review_config = self.root / "review.yml"
        self.review_config.write_text("schema: 1\n")
        if (os.environ.get("M10_REVIEW") or os.environ.get("TASKALONG_REVIEW_EXECUTABLE")):
            response = self.probe.write_json("review-response.json", {"summary": "Independent synthetic review.", "comments": []})
            self.probe.call("configure-review", "--config", self.review_config,
                "--fixture-response", response, "--executable", (os.environ.get("M10_REVIEW") or os.environ["TASKALONG_REVIEW_EXECUTABLE"]),
                "--python-executable", self.probe.python)

    def tearDown(self):
        if not getattr(self, "run_id", None):
            return
        # Only the public owner control path stops a fixture worker. Do not
        # signal a stored PID or delete an owned workspace during cleanup.
        for name in ("a.py", "b.py"):
            (self.root / (name + ".release")).touch()
        observed = self.probe.call("status", self.run_id, ok=None)
        run = observed["data"] if observed["ok"] else self.probe.private_fault_snapshot(self.run_id)
        if run.get("active_attempt_id"):
            self.probe.mutation("cancel", run, "cleanup-" + str(uuid.uuid4()), ok=None)
            self.probe.wait(self.run_id, lambda r: not r.get("active_attempt_id"), timeout=20)
        print("Independent scratch retained:", self.root)

    def git(self, *args):
        return subprocess.check_output(["git", "-c", "core.hooksPath=/dev/null", "-C", str(self.repo), *args],
            env=self.probe.env, text=True, timeout=15).strip()

    def control(self):
        self.probe.write_json("control.json", self.controls)

    def spec(self):
        return {"schema_version": "2.7", "task_id": "independent-" + str(uuid.uuid4()),
            "revision": 1, "goal": "Change a and b in authorized order.",
            "non_goals": ["No providers, publication, other files or dependencies."],
            "repository": {"registration_id": self.registration["registration_id"],
                           "base_commit": self.base, "base_ref": "main"},
            "scope": {"files": ["a.py", "b.py"], "operations": ["modify"]},
            "criteria": [{"id": "both", "description": "Both modules return two.", "check_ids": ["final"]}],
            "checks": [{"id": "final", "argv": [self.probe.python, "-B", "check.py"],
                "cwd": ".", "timeout_seconds": 5, "expected_exit_code": 0, "criterion_ids": ["both"], "required": True}],
            "execution": {"adapter": "codex-cli", "profile_id": self.profile["profile_id"], "profile_digest": self.profile["digest"]},
            "permissions": {"local_edit": True, "local_commit": True,
                "inference_destination_id": "independent-local-fixture", "allowed_effects": ["execute", "verify", "commit_candidate"]},
            "budget": {"max_attempts": 4, "attempt_seconds": 10, "total_active_seconds": 160,
                "max_output_bytes": 8_388_608, "attempt_output_bytes": 524_288, "hard_cost_usd": None, "hard_tokens": None},
            "final_verification": {"max_passes": 1, "total_active_seconds": 100, "max_output_bytes": 2_097_152},
            "review": {"required": True, "integration": "reviewsensei", "contract": "0.8.8/v1",
                "config_digest": sha(self.review_config.read_bytes()), "require_full_coverage": True},
            "publication": None, "qualification": "synthetic",
            "steps": [{"step_id": name, "goal": "Change " + name.lower() + ".py from one to two.",
                "scope": {"files": [name.lower() + ".py"], "operations": ["modify"]},
                "inputs": [], "required": True} for name in ("A", "B")]}

    def steps(self, run):
        return run[self.binding["steps_field"]]

    def predecessor(self, run):
        return self.steps(run)[0][self.binding["receipt_digest_field"]]

    def task_file(self, name, document):
        # Public versioned task files are sealed documents. Compute the public
        # canonical digest independently, never import the candidate's sealer.
        value = copy.deepcopy({key: item for key, item in document.items() if key != "digest"})
        value.update(kind="task_spec", extensions=value.get("extensions", {}))
        # Existing sealed-document set normalization applies only to these
        # public fields. The ordered step list is deliberately left untouched.
        for key in ("files", "operations"):
            value["scope"][key] = sorted(set(value["scope"][key]))
        value["permissions"]["allowed_effects"] = sorted(set(value["permissions"]["allowed_effects"]))
        for criterion in value["criteria"]:
            criterion["check_ids"] = sorted(set(criterion["check_ids"]))
        for check in value["checks"]:
            check["criterion_ids"] = sorted(set(check["criterion_ids"]))
        value["digest"] = sha(canonical(value))
        return self.probe.write_json(name, value)

    def prepare(self, spec=None):
        task = spec or self.spec()
        path = self.task_file("task.json", task)
        self.probe.call("validate", "--spec", path)
        self.assertEqual(self.probe.invocations(), [])
        run = self.probe.call("submit", "--spec", path, "--key", "submit")["data"]
        self.run_id = run["run_id"]
        self.probe.call("authorize", self.run_id, "--decision-digest", run["spec_digest"],
                        "--scope", "execute", "verify", "commit_candidate")
        return self.probe.status(self.run_id)

    def complete_a(self):
        run = self.prepare()
        receipt = self.probe.mutation("start", run, "start-A")
        # Replay original request even if revision has advanced in background.
        replay = self.probe.mutation("start", run, "start-A")
        self.assertEqual(replay, receipt)
        ready = self.probe.wait(self.run_id,
            lambda r: self.steps(r)[0]["status"] == "completed" and not r.get("active_attempt_id"))
        self.assertEqual(self.steps(ready)[1]["status"], "pending")
        self.assertNotEqual(ready["state"], "accepted")
        self.assertEqual(len(self.probe.invocations()), 1)
        self.assertFalse((self.root / "checks.jsonl").exists(), "Premature final check")
        view = self.probe.call("result", self.run_id)["data"]
        self.assertIn("advance", view["next_actions"], "Missing valid next action")
        return ready

    def advance(self, run, key="advance-B", ok=True):
        return self.probe.mutation("advance", run, key, "--step-id", "B",
            "--predecessor-digest", self.predecessor(run), ok=ok)

    def test_rejects_invalid_complete_plan_before_launch(self):
        cases = {}
        valid = self.spec()
        for label, change in (("empty", []), ("too-many", valid["steps"] * 5),
                              ("duplicate", [valid["steps"][0]] * 2)):
            cases[label] = valid | {"steps": change}
        for missing in ("step_id", "goal", "scope", "required"):
            value = copy.deepcopy(valid)
            del value["steps"][1][missing]
            cases["missing-" + missing] = value
        for label, change in (("scope-expansion", {"scope": {"files": ["outside.py"], "operations": ["modify"]}}),
                              ("step-model", {"model": "unsupported"}),
                              ("future-input", {"inputs": [{"step_id": "A", "output": "future"}]})):
            value = copy.deepcopy(valid)
            value["steps"][1].update(change)
            cases[label] = value
        value = copy.deepcopy(valid)
        value["budget"]["max_attempts"] = 1
        cases["insufficient-attempts"] = value
        for label, value in cases.items():
            with self.subTest(case=label):
                path = self.task_file(label + ".json", value)
                result = self.probe.call("validate", "--spec", path, ok=False)
                self.assertTrue(result["errors"])
                self.assertTrue(result["errors"][0].get("message"))
                self.probe.call("submit", "--spec", path, "--key", label, ok=False)
                self.assertEqual(self.probe.invocations(), [])

    def test_one_and_eight_step_endpoints_validate_before_launch(self):
        for count in (1, 8):
            with self.subTest(count=count):
                value = self.spec()
                step = value["steps"][0]
                value["steps"] = [copy.deepcopy(step) | {"step_id": "step-" + str(n)} for n in range(count)]
                value["budget"]["max_attempts"] = max(2, count)
                value["budget"]["total_active_seconds"] = 200
                value["budget"]["max_output_bytes"] = 8_388_608
                path = self.task_file("endpoint-" + str(count) + ".json", value)
                self.probe.call("validate", "--spec", path)
                self.assertEqual(self.probe.invocations(), [])

    def test_changed_declared_input_rejects_before_worker(self):
        value = self.spec()
        value["steps"][0]["inputs"] = [{"path": "input.txt", "sha256": sha((self.repo / "input.txt").read_bytes())}]
        run = self.prepare(value)
        (self.repo / "input.txt").write_text("changed bytes\n")
        before = copy.deepcopy(run)
        self.probe.mutation("start", run, "changed-input", ok=False)
        self.assertEqual(self.probe.invocations(), [])
        self.assertEqual(self.probe.status(self.run_id)["budget_consumed"], before["budget_consumed"])

    def test_interstep_reopen_preserves_results_and_rejects_premature_verify(self):
        ready = self.complete_a()
        before = copy.deepcopy(ready)
        for _ in range(3):
            self.assertEqual(self.probe.status(self.run_id), before)
        self.probe.mutation("verify", ready, "premature-verify", ok=False)
        after = self.probe.status(self.run_id)
        self.assertEqual(self.steps(after), self.steps(before))
        self.assertEqual(after["budget_consumed"], before["budget_consumed"])
        self.assertEqual(len(self.probe.invocations()), 1)
        self.assertFalse((self.root / "checks.jsonl").exists())

    def test_cancel_between_steps_prevents_advance_and_final_checks(self):
        ready = self.complete_a()
        cancelled = self.probe.mutation("cancel", ready, "cancel-between", ok=None)["data"]
        if cancelled["state"] == "cancel_pending":
            self.probe.mutation("reconcile", cancelled, "settle-between-cancel", ok=None)
            cancelled = self.probe.status(self.run_id)
        self.advance(cancelled, ok=False)
        self.probe.mutation("verify", self.probe.status(self.run_id), "verify-cancelled", ok=False)
        self.assertEqual(len(self.probe.invocations()), 1)
        self.assertFalse((self.root / "checks.jsonl").exists())

    def test_scope_violation_cannot_complete_first_step(self):
        self.controls["a.py"] = "out-of-scope"
        self.control()
        run = self.prepare()
        self.probe.mutation("start", run, "scope-start")
        stopped = self.probe.wait(self.run_id, lambda r: not r.get("active_attempt_id") and r["state"] in {"blocked", "failed"})
        self.assertNotEqual(self.steps(stopped)[0]["status"], "completed")
        self.assertEqual(self.steps(stopped)[1]["status"], "pending")
        self.assertFalse((self.root / "checks.jsonl").exists())

    def test_stale_workspace_checkpoint_rejects_advance_without_charging(self):
        ready = self.complete_a()
        totals = copy.deepcopy(ready["reservation_totals"])
        workspace = Path(self.probe.invocations()[0]["cwd"])
        (workspace / "a.py").write_text("def value():\n    return 99\n")
        self.advance(ready, ok=False)
        stopped = self.probe.status(self.run_id)
        self.assertEqual(stopped["reservation_totals"], totals)
        self.assertEqual(len(self.probe.invocations()), 1)
        self.assertNotEqual(stopped["state"], "accepted")

    def test_changed_completed_receipt_blob_rejects_advance(self):
        """Supplemental stored-artifact corruption; public CLI rejection oracle."""
        ready = self.complete_a()
        totals = copy.deepcopy(ready["reservation_totals"])
        artifact = self.probe.state / "blobs" / self.predecessor(ready)
        self.assertTrue(artifact.is_file())
        artifact.write_bytes(artifact.read_bytes() + b"\ncorrupted completed result\n")
        self.advance(ready, ok=False)
        self.assertEqual(len(self.probe.invocations()), 1)
        self.assertEqual(self.probe.private_fault_snapshot(self.run_id)["reservation_totals"], totals)

    def test_failed_final_check_prevents_overall_acceptance(self):
        value = self.spec()
        value["checks"][0]["argv"] = [self.probe.python, "-c",
            "from pathlib import Path; Path(" + repr(str(self.root / "checks.jsonl")) + ").open('a').write('failed-check\\n'); raise SystemExit(1)"]
        run = self.prepare(value)
        self.probe.mutation("start", run, "start-A")
        ready = self.probe.wait(self.run_id,
            lambda r: self.steps(r)[0]["status"] == "completed" and not r.get("active_attempt_id"))
        self.assertFalse((self.root / "checks.jsonl").exists())
        self.advance(ready)
        final = self.probe.wait(self.run_id,
            lambda r: (self.root / "checks.jsonl").exists() and r["state"] in {"blocked", "failed", "accepted"})
        self.assertNotEqual(final["state"], "accepted")
        view = self.probe.call("result", self.run_id)["data"]
        self.assertFalse(view["independently_accepted"])
        self.assertNotEqual(view["outcome"], "accepted")
        self.assertTrue(view["stop_reason"])
        self.assertEqual(len(self.probe.invocations()), 2)

    def test_attempt_exhaustion_prevents_another_retry(self):
        value = self.spec()
        value["budget"]["max_attempts"] = 2
        self.controls["b.py"] = "failed"
        self.control()
        run = self.prepare(value)
        self.probe.mutation("start", run, "start-A")
        ready = self.probe.wait(self.run_id,
            lambda r: self.steps(r)[0]["status"] == "completed" and not r.get("active_attempt_id"))
        self.advance(ready)
        failed = self.probe.wait(self.run_id,
            lambda r: self.steps(r)[1]["status"] == "failed" and not r.get("active_attempt_id"))
        before = copy.deepcopy(failed["reservation_totals"])
        self.probe.mutation("retry", failed, "exhausted-retry", "--step-id", "B", ok=False)
        self.assertEqual(len(self.probe.invocations()), 2)
        self.assertEqual(self.probe.status(self.run_id)["reservation_totals"], before)

    def test_reopen_after_durable_step_completion_keeps_completed_work(self):
        """Supplemental controlled supervisor exit after real completion commit."""
        run = self.prepare()
        marker, previous = install_exit_barrier(self.probe, "_finish_attempt", event="return")
        try:
            self.probe.mutation("start", run, "crash-after-A-commit")
            require_boundary(marker)
        finally:
            remove_barrier(self.probe, previous)
        ready = self.probe.wait(self.run_id,
            lambda r: self.steps(r)[0]["status"] == "completed" and not r.get("active_attempt_id"))
        saved = copy.deepcopy(self.steps(ready)[0])
        totals = copy.deepcopy(ready["reservation_totals"])
        # Reconcile may be an observation or report no recovery needed. It may
        # never turn a completed A into a new attempt or implicitly start B.
        self.probe.mutation("reconcile", ready, "recover-between", ok=None)
        after = self.probe.status(self.run_id)
        self.assertEqual(self.steps(after)[0], saved)
        self.assertEqual(self.steps(after)[1]["status"], "pending")
        self.assertEqual(after["reservation_totals"], totals)
        self.assertEqual(len(self.probe.invocations()), 1)
        self.assertFalse((self.root / "checks.jsonl").exists())

    def test_lost_cessation_proof_never_admits_advance_or_verification(self):
        """Supplemental removal of durable proof, never a manufactured success."""
        ready = self.complete_a()
        before = copy.deepcopy(ready["reservation_totals"])
        attempt = self.steps(ready)[0]["attempt_ids"][-1]
        program = """import json,sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db:
    row=db.execute('SELECT document FROM attempts WHERE attempt_id=?',(sys.argv[2],)).fetchone()
    value=json.loads(row[0]); value['termination_confirmed']=False
    if isinstance(value.get('process'),dict): value['process']['termination_confirmed']=False
    db.execute('UPDATE attempts SET document=? WHERE attempt_id=?',(json.dumps(value),sys.argv[2]))
"""
        result = subprocess.run([self.probe.python, "-c", program,
            str(self.probe.state / "state.sqlite3"), attempt], cwd=self.probe.cwd,
            env=self.probe.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.advance(ready, ok=False)
        observed = self.probe.call("status", self.run_id, ok=None)
        now = observed["data"] if observed["ok"] else self.probe.private_fault_snapshot(self.run_id)
        self.probe.mutation("verify", now, "verify-without-cessation", ok=False)
        self.assertEqual(self.probe.private_fault_snapshot(self.run_id)["reservation_totals"], before)
        self.assertEqual(len(self.probe.invocations()), 1)
        self.assertFalse((self.root / "checks.jsonl").exists())

    def test_failed_second_step_retry_keeps_first_result_and_charges(self):
        self.controls["b.py"] = "failed"
        self.control()
        ready = self.complete_a()
        first = copy.deepcopy(self.steps(ready)[0])
        self.advance(ready)
        failed = self.probe.wait(self.run_id,
            lambda r: self.steps(r)[1]["status"] == "failed" and not r.get("active_attempt_id"))
        self.assertEqual(self.steps(failed)[0], first)
        self.assertFalse((self.root / "checks.jsonl").exists())
        before = copy.deepcopy(failed["reservation_totals"])
        self.controls["b.py"] = "barrier"
        self.control()
        response = self.probe.mutation("retry", failed, "retry-B", "--step-id", "B")
        self.assertEqual(self.probe.mutation("retry", failed, "retry-B", "--step-id", "B"), response)
        running = self.probe.wait(self.run_id,
            lambda r: len(self.probe.invocations()) == 3 and bool(r.get("active_attempt_id")))
        self.assertEqual([call["selected"] for call in self.probe.invocations()], ["a.py", "b.py", "b.py"])
        self.assertEqual(self.steps(running)[0], first)
        self.assertEqual(running["reservation_totals"]["attempts"], before["attempts"] + 1)
        self.assertGreater(running["reservation_totals"]["active_seconds"], before["active_seconds"])
        self.assertGreater(running["reservation_totals"]["output_bytes"], before["output_bytes"])
        self.probe.mutation("cancel", running, "stop-retry", ok=None)
        self.probe.wait(self.run_id, lambda r: not r.get("active_attempt_id"))
        self.assertFalse((self.root / "checks.jsonl").exists())

    def test_active_cancellation_blocks_later_launches_and_checks(self):
        self.controls["a.py"] = "barrier"
        self.control()
        run = self.prepare()
        self.probe.mutation("start", run, "start-barrier")
        active = self.probe.wait(self.run_id,
            lambda r: len(self.probe.invocations()) == 1 and bool(r.get("active_attempt_id")))
        before = copy.deepcopy(active["reservation_totals"])
        cancelled = self.probe.mutation("cancel", active, "cancel-active", ok=None)
        settled = self.probe.wait(self.run_id,
            lambda r: not r.get("active_attempt_id") and r["state"] in {"cancelled", "blocked", "cancel_pending"})
        self.assertEqual(settled["reservation_totals"], before)
        self.probe.mutation("verify", settled, "verify-after-active-cancel", ok=False)
        self.assertEqual(len(self.probe.invocations()), 1)
        self.assertFalse((self.root / "checks.jsonl").exists())

    def test_two_step_happy_path_keeps_first_work_and_advances_once(self):
        if not (os.environ.get("M10_REVIEW") or os.environ.get("TASKALONG_REVIEW_EXECUTABLE")):
            self.skipTest("Full acceptance needs owner-supplied installed fixture ReviewSensei executable")
        ready = self.complete_a()
        prior_step = copy.deepcopy(self.steps(ready)[0])
        response = self.advance(ready)
        self.assertEqual(self.advance(ready), response)
        final = self.probe.wait(self.run_id, lambda r: r["state"] in {"accepted", "blocked", "failed"})
        self.assertEqual(final["state"], "accepted", final)
        self.assertEqual(self.steps(final)[0], prior_step)
        self.assertTrue(all(step["status"] == "completed" for step in self.steps(final)))
        calls = self.probe.invocations()
        self.assertEqual([call["selected"] for call in calls], ["a.py", "b.py"])
        self.assertEqual(calls[0]["cwd"], calls[1]["cwd"])
        self.assertIn("return 2", calls[1]["a_before"])
        self.assertTrue((self.root / "checks.jsonl").exists())
        self.probe.call("result", self.run_id)


if __name__ == "__main__":
    unittest.main()
