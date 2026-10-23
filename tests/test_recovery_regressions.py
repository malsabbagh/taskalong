"""Independent regressions for effect and cancellation boundaries.

Crash barriers observe actual function entry after the preceding real effect.
They do not replace a core method or return a fabricated successful receipt.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import time
import unittest

from taskalong.api import RunService
from taskalong.errors import TaskAlongError
from taskalong.store import Store
from taskalong.validation import seal
from helpers import ServiceFixture, git


class RecoveryRegressions(ServiceFixture, unittest.TestCase):
    def wait_file(self, path, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return
            time.sleep(0.025)
        self.fail("The real process did not reach the requested recovery barrier")

    def cli_start(self, run, key, *, environment=None):
        return subprocess.run([sys.executable, "-m", "taskalong", "--state-dir", str(self.state),
                               "start", run["run_id"], "--expected-revision", str(run["revision"]),
                               "--key", key, "--json"], cwd=self.root,
                              env=environment or dict(os.environ), capture_output=True,
                              text=True, timeout=15)

    def trace_environment(self, function_name, *, mode="kill", command=None, event_kind="call"):
        """Inject trusted test observation into client/supervisor, never worker."""
        directory = self.root / ("trace-" + function_name)
        directory.mkdir()
        marker = directory / "reached"
        release = directory / "release"
        program = (
            "import os,sys,time\n"
            f"marker={str(marker)!r}; release={str(release)!r}\n"
            "def observe(frame,event,arg):\n"
            f"    if event != {event_kind!r} or frame.f_code.co_name != {function_name!r}: return observe\n"
            "    if '/taskalong/' not in frame.f_code.co_filename.replace('\\\\','/'): return observe\n"
        )
        if command is not None:
            program += f"    if frame.f_locals.get('command') != {command!r}: return observe\n"
        program += ("    sys.settrace(None)\n"
                    "    with open(marker,'w') as stream:\n"
                    "        stream.write('observed'); stream.flush(); os.fsync(stream.fileno())\n")
        if mode == "kill":
            program += "    os.kill(os.getpid(),9)\n"
        else:
            program += ("    end=time.monotonic()+30\n"
                        "    while not os.path.exists(release) and time.monotonic()<end: time.sleep(0.01)\n")
        program += "    return None\nsys.settrace(observe)\n"
        (directory / "sitecustomize.py").write_text(program)
        environment = dict(os.environ)
        # The trace directory contains only this barrier. The installed test
        # interpreter still resolves TaskAlong from its ordinary installation.
        previous = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = str(directory) + (os.pathsep + previous if previous else "")
        return environment, marker, release

    def test_cancel_before_spawn_receipt_cannot_be_overwritten_as_running(self):
        self.set_mode("hang")
        run, _ = self.submit()
        environment, marker, release = self.trace_environment("on_spawn", mode="pause")
        client = self.cli_start(run, "cancel-startup-boundary", environment=environment)
        self.assertEqual(client.returncode, 0, client.stderr)
        try:
            self.wait_file(marker)
            before = self.service.inspect(run["run_id"])
            self.assertEqual(before["state"], "ready")
            requested = self.service.cancel(run["run_id"], operation_key="cancel-before-spawn-receipt",
                                            expected_revision=before["revision"])
            self.assertEqual(requested["state"], "cancel_pending")
        finally:
            release.touch()
        finished = self.wait(run["run_id"])
        self.assertEqual(finished["state"], "cancelled")
        self.assertIsNone(finished["active_attempt_id"])
        self.assertEqual(len(finished["attempts"]), 1)
        self.assertLessEqual(len(self.invocations()), 1)
        events = self.service.events(run["run_id"])
        self.assertEqual(sum(event["type"] == "cancel.requested" for event in events), 1)
        self.assertEqual(sum(event["type"] == "cancel.confirmed" for event in events), 1)
        self.assertNotIn("acceptance.recorded", {event["type"] for event in events})

    def test_concurrent_same_key_clients_dispatch_one_attempt(self):
        self.barrier_file.touch()
        run, _ = self.submit()
        reader, writer = os.pipe()
        program = ("import os,sys; fd=int(sys.argv[1]); os.read(fd,1); os.close(fd); "
                   "from taskalong.cli import main; raise SystemExit(main(sys.argv[2:]))")
        clients = []
        try:
            for _ in range(2):
                clients.append(subprocess.Popen([sys.executable, "-c", program, str(reader),
                    "--state-dir", str(self.state), "start", run["run_id"], "--key", "shared-start",
                    "--expected-revision", str(run["revision"]), "--json"],
                    pass_fds=(reader,), cwd=self.root, env=dict(os.environ),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
            os.close(reader)
            reader = -1
            os.write(writer, b"GO")
            outputs = [client.communicate(timeout=15) for client in clients]
            self.assertIn(0, [client.returncode for client in clients])
            self.assertTrue(all(client.returncode in {0, 4} for client in clients), outputs)
            for client, (output, _) in zip(clients, outputs):
                document = json.loads(output)
                if client.returncode == 0:
                    self.assertEqual(document["data"]["run_id"], run["run_id"])
                    self.assertEqual(len(document["data"]["attempts"]), 1)
                else:
                    self.assertEqual(document["errors"][0]["code"], "operation_in_progress")
            running = self.wait(run["run_id"], states=("running",))
            repeated = self.service.start(run["run_id"], operation_key="shared-start", expected_revision=999999)
            self.assertEqual(repeated["run_id"], run["run_id"])
            self.assertEqual(len(repeated["attempts"]), 1)
            self.release_file.touch()
            finished = self.wait(run["run_id"])
            self.assertEqual(len(finished["attempts"]), 1)
            self.assertEqual(len(self.invocations()), 1)
            self.assertEqual(sum(event["type"] == "executor.started" for event in self.service.events(run["run_id"])), 1)
            self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.base)
        finally:
            if reader >= 0:
                os.close(reader)
            os.close(writer)
            self.release_file.touch(exist_ok=True)
            for client in clients:
                if client.poll() is None:
                    client.kill()
                    client.communicate(timeout=5)

    def test_killed_client_after_worktree_creation_recovers_proven_no_dispatch(self):
        run, _ = self.submit()
        environment, marker, _ = self.trace_environment("_workspace_ready")
        client = self.cli_start(run, "allocation-crash", environment=environment)
        self.assertEqual(client.returncode, -signal.SIGKILL, client.stderr)
        self.wait_file(marker)
        before = self.service.inspect(run["run_id"])
        self.assertEqual(before["state"], "ready")
        self.assertEqual(self.invocations(), [])
        with Store(self.state) as private:
            attempt = private.detail("attempts", before["active_attempt_id"])
            self.assertEqual(attempt["spawn_phase"], "not_dispatched")
            self.assertNotIn("supervisor_launch", attempt)
            workspace_id = attempt["workspace"]["workspace_id"]
        self.service.reconcile(run["run_id"], operation_key="recover-allocation", expected_revision=before["revision"])
        finished = self.wait(run["run_id"])
        self.assertEqual(finished["workspace_id"], workspace_id)
        self.assertEqual(len(finished["attempts"]), 1)
        self.assertEqual(len(self.invocations()), 1)
        self.assertIsNone(finished["active_attempt_id"])
        self.assertEqual(git(self.repo, "worktree", "list", "--porcelain").count("branch refs/heads/taskalong/" + run["run_id"]), 1)
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.base)

    def test_killed_supervisor_after_candidate_cas_reconciles_exact_candidate(self):
        run, _ = self.submit()
        environment, marker, _ = self.trace_environment("_candidate_observed")
        client = self.cli_start(run, "freeze-crash", environment=environment)
        self.assertEqual(client.returncode, 0, client.stderr)
        self.wait_file(marker)
        before = self.service.inspect(run["run_id"])
        self.assertIsNone(before["active_attempt_id"])
        self.assertIsNone(before["candidate"])
        with Store(self.state) as private:
            effects = [private.detail("effects", value) for value in before["pending_effect_ids"]]
            self.assertEqual([effect["kind"] for effect in effects], ["candidate.freeze"])
            workspace = private.lease(before)["workspace"]
        exact_commit = git(workspace["path"], "rev-parse", "HEAD")
        self.assertNotEqual(exact_commit, self.base)
        recovered = self.service.reconcile(run["run_id"], operation_key="recover-candidate", expected_revision=before["revision"])
        self.assertEqual(recovered["candidate"]["commit"], exact_commit)
        self.assertEqual(recovered["pending_effect_ids"], [])
        with Store(self.state) as private:
            effect = private.detail("effects", effects[0]["effect_id"])
            self.assertEqual(effect["phase"], "observed")
            self.assertEqual(effect["response"], recovered["candidate"])
        again = self.service.reconcile(run["run_id"], operation_key="recover-candidate", expected_revision=0)
        self.assertEqual(again["candidate"]["commit"], exact_commit)
        self.assertEqual(git(workspace["path"], "rev-list", "--count", self.base + "..HEAD"), "1")
        self.assertEqual(len(self.invocations()), 1)
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.base)

    def assert_resume_marker_crash_recovers(self, event_kind, *, fault=None, barrier="advance_generation"):
        self.set_mode("duplicate-result")
        run, _ = self.submit(self.spec(attempt_seconds=30, total_seconds=60))
        self.start(run)
        stopped = self.wait(run["run_id"])
        self.assertEqual(stopped["state"], "blocked")
        self.assertIsNone(stopped["active_attempt_id"])
        self.set_mode("good")
        environment, marker, _ = self.trace_environment(barrier, event_kind=event_kind)
        client = subprocess.run([sys.executable, "-m", "taskalong", "--state-dir", str(self.state),
                                 "resume", run["run_id"], "--mode", "native", "--key", "resume-window",
                                 "--expected-revision", str(stopped["revision"]), "--json"],
                                cwd=self.root, env=environment, capture_output=True, text=True, timeout=15)
        self.assertEqual(client.returncode, -signal.SIGKILL, client.stderr)
        self.wait_file(marker)
        prepared = self.service.inspect(run["run_id"])
        self.assertEqual(prepared["state"], "ready")
        self.assertEqual(prepared["lease_generation"], stopped["lease_generation"] + 1)
        self.assertEqual(len(self.invocations()), 1, "A prepared second attempt must not have dispatched")
        with Store(self.state) as private:
            attempt = private.detail("attempts", prepared["active_attempt_id"])
            self.assertEqual(attempt["spawn_phase"], "not_dispatched")
            self.assertNotIn("supervisor_launch", attempt)
            old_workspace = attempt["workspace"]
            effect = private.detail("effects", attempt["workspace_effect_id"])
            self.assertEqual(effect["kind"], "workspace.reacquire")
        marker_path = Path(old_workspace["common_dir"]) / "taskalong" / "workspaces" / (old_workspace["workspace_id"] + ".json")
        owned_marker = json.loads(marker_path.read_text())
        expected_generation = stopped["lease_generation"] if barrier == "advance_generation" and event_kind == "call" else prepared["lease_generation"]
        self.assertEqual(owned_marker["generation"], expected_generation)
        if fault == "changed_content":
            changed = Path(old_workspace["path"]) / "arithmetic.py"
            changed.write_text("def add(a, b):\n    return 999\n")
            from taskalong.errors import TaskAlongError
            with self.assertRaises(TaskAlongError) as rejected:
                self.service.reconcile(run["run_id"], operation_key="recover-changed-resume",
                                       expected_revision=prepared["revision"])
            self.assertEqual(rejected.exception.code, "checkpoint_stale")
            self.assertEqual(changed.read_text(), "def add(a, b):\n    return 999\n")
            self.assertEqual(len(self.invocations()), 1)
            self.assertEqual(len(self.service.inspect(run["run_id"])["attempts"]), 2)
            return
        if fault == "foreign_generation":
            owned_marker["generation"] = owned_marker["lease_generation"] = prepared["lease_generation"] + 1
            marker_path.write_text(json.dumps(owned_marker))
            from taskalong.errors import TaskAlongError
            with self.assertRaises(TaskAlongError):
                self.service.reconcile(run["run_id"], operation_key="recover-foreign-generation",
                                       expected_revision=prepared["revision"])
            self.assertEqual(json.loads(marker_path.read_text())["generation"], prepared["lease_generation"] + 1)
            self.assertEqual(len(self.invocations()), 1)
            self.assertEqual(self.service.inspect(run["run_id"])["lease_generation"], prepared["lease_generation"])
            return
        recovered = self.service.reconcile(run["run_id"], operation_key="recover-resume-window",
                                           expected_revision=prepared["revision"])
        with Store(self.state) as private:
            current = private.run(run["run_id"])
            lease = private.lease(current)
            self.assertEqual(lease["workspace"]["generation"], current["lease_generation"])
        finished = self.wait(run["run_id"])
        self.assertEqual(finished["state"], "blocked")
        self.assertIn("required_review_missing", {reason["code"] for reason in finished["blockers"]})
        self.assertEqual(finished["workspace_id"], stopped["workspace_id"])
        self.assertEqual(finished["lease_generation"], stopped["lease_generation"] + 1)
        self.assertEqual(len(finished["attempts"]), 2)
        self.assertEqual([item["mode"] for item in self.invocations()], ["start", "native_resume"])
        self.assertIsNone(finished["active_attempt_id"])
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.base)

    def test_crash_before_resume_marker_advance_recovers_reserved_generation(self):
        self.assert_resume_marker_crash_recovers("call")

    def test_crash_after_resume_marker_advance_recovers_exact_new_marker(self):
        self.assert_resume_marker_crash_recovers("return")

    def test_crash_after_resume_workspace_receipt_finishes_same_effect(self):
        self.assert_resume_marker_crash_recovers("call", barrier="_observe_effect")

    def test_resume_recovery_after_client_death_rejects_changed_stopped_source(self):
        self.assert_resume_marker_crash_recovers("return", fault="changed_content")

    def test_resume_recovery_never_adopts_or_resets_a_foreign_generation(self):
        self.assert_resume_marker_crash_recovers("return", fault="foreign_generation")

    def test_small_positive_output_remainder_rejects_resume_before_prepare(self):
        self.set_mode("duplicate-result")
        spec = self.spec()
        spec["budget"]["max_output_bytes"] = 1800
        spec = seal("task-spec", spec)
        run, _ = self.submit(spec)
        self.start(run)
        stopped = self.wait(run["run_id"])
        remaining = spec["budget"]["max_output_bytes"] - stopped["budget_consumed"]["output_bytes"]
        self.assertGreater(remaining, 0)
        self.assertLess(remaining, 1024)
        self.assertIsNone(stopped["active_attempt_id"])
        from taskalong.errors import TaskAlongError
        with self.assertRaises(TaskAlongError) as rejected:
            self.service.resume(run["run_id"], mode="restart", operation_key="insufficient-output-remainder",
                                expected_revision=stopped["revision"])
        self.assertEqual(rejected.exception.code, "budget_exhausted")
        after = self.service.inspect(run["run_id"])
        self.assertEqual(after["revision"], stopped["revision"])
        self.assertEqual(after["lease_generation"], stopped["lease_generation"])
        self.assertEqual(after["budget_consumed"]["attempts"], 1)
        self.assertEqual(len(self.invocations()), 1)

    def test_native_resume_rejects_changed_stopped_content_before_dispatch(self):
        self.set_mode("duplicate-result")
        run, _ = self.submit()
        self.start(run)
        before = self.wait(run["run_id"])
        self.assertEqual(before["state"], "blocked")
        self.assertIsNone(before["active_attempt_id"])
        with Store(self.state) as private:
            workspace = private.lease(before)["workspace"]
            stopped = private.detail("attempts", before["attempts"][-1]["attempt_id"])
            self.assertTrue(stopped["checkpoint"]["content_digest"])
            self.assertTrue(stopped["thread_id"])
        (Path(workspace["path"]) / "arithmetic.py").write_text("def add(a, b):\n    return 999\n")
        self.set_mode("good")
        from taskalong.errors import TaskAlongError
        with self.assertRaises(TaskAlongError) as blocked:
            self.service.resume(run["run_id"], mode="native", operation_key="stale-native",
                                expected_revision=before["revision"])
        self.assertEqual(blocked.exception.code, "checkpoint_stale")
        after = self.service.inspect(run["run_id"])
        self.assertEqual(after["revision"], before["revision"])
        self.assertEqual(after["lease_generation"], before["lease_generation"])
        self.assertEqual(len(self.invocations()), 1)

    def test_exact_stopped_checkpoint_resumes_native_under_fresh_attempt(self):
        self.set_mode("duplicate-result")
        run, _ = self.submit()
        self.start(run)
        stopped = self.wait(run["run_id"])
        self.assertEqual(stopped["state"], "blocked")
        self.set_mode("good")
        self.service.resume(run["run_id"], mode="native", operation_key="exact-native",
                            expected_revision=stopped["revision"])
        finished = self.wait(run["run_id"])
        self.assertEqual(finished["state"], "blocked")
        self.assertIn("required_review_missing", {reason["code"] for reason in finished["blockers"]})
        self.assertEqual(len(finished["attempts"]), 2)
        self.assertEqual(finished["attempts"][-1]["mode"], "native_resume")
        self.assertEqual(finished["lease_generation"], stopped["lease_generation"] + 1)
        self.assertEqual([item["mode"] for item in self.invocations()], ["start", "native_resume"])
        self.assertEqual(finished["budget_consumed"]["attempts"], 2)

    def configure_released_review(self, *, hold_invocation=False):
        executable = os.environ.get("TASKALONG_REVIEW_EXECUTABLE")
        python = os.environ.get("TASKALONG_REVIEW_PYTHON", sys.executable)
        if not executable:
            try:
                if importlib.metadata.version("review-sensei") == "0.8.8":
                    executable = shutil.which("review-sensei")
            except importlib.metadata.PackageNotFoundError:
                pass
        if not executable:
            self.skipTest("released reviewer environment missing; full installed qualification requires this boundary")
        config = self.root / "review.yml"
        response = self.root / "review-response.json"
        config.write_text("schema: 1\n")
        response.write_text('{"summary":"Independent synthetic fixture review.","comments":[]}\n')
        if hold_invocation:
            marker = self.root / "review-entered"
            release = self.root / "review-release"
            wrapper = self.root / "review-barrier"
            wrapper.write_text("#!" + sys.executable + "\nimport os,sys,time\n"
                "if '--diff' in sys.argv:\n"
                f"    open({str(marker)!r},'w').close()\n"
                "    end=time.monotonic()+30\n"
                f"    while not os.path.exists({str(release)!r}) and time.monotonic()<end: time.sleep(0.02)\n"
                f"os.execv({str(executable)!r},[{str(executable)!r},*sys.argv[1:]])\n")
            wrapper.chmod(0o700)
            executable = str(wrapper)
            self.addCleanup(lambda: release.touch(exist_ok=True) if release.parent.exists() else None)
        self.service.configure_review(config, fixture_response=response, executable=executable, python_executable=python)
        specification = self.spec()
        specification["review"]["config_digest"] = hashlib.sha256(config.read_bytes()).hexdigest()
        return seal("task-spec", specification)

    def test_cancel_during_real_review_cannot_become_acceptance(self):
        spec = self.configure_released_review(hold_invocation=True)
        run, _ = self.submit(spec)
        self.start(run)
        self.wait_file(self.root / "review-entered")
        before = self.service.inspect(run["run_id"])
        self.assertEqual(before["state"], "verifying")
        requested = self.service.cancel(run["run_id"], operation_key="cancel-review", expected_revision=before["revision"])
        self.assertEqual(requested["state"], "cancel_pending")
        (self.root / "review-release").touch()
        finished = self.wait(run["run_id"])
        self.assertEqual(finished["state"], "cancelled")
        self.assertIsNone(finished["acceptance_id"])
        self.assertNotIn("acceptance.recorded", {event["type"] for event in self.service.events(run["run_id"])})

    def test_cancel_immediately_before_acceptance_transaction_stays_cancelled(self):
        spec = self.configure_released_review()
        run, _ = self.submit(spec)
        environment, marker, release = self.trace_environment("mutate", mode="pause", command="verify")
        client = self.cli_start(run, "acceptance-boundary", environment=environment)
        self.assertEqual(client.returncode, 0, client.stderr)
        try:
            self.wait_file(marker)
            before = self.service.inspect(run["run_id"])
            self.assertEqual(before["state"], "verifying")
            self.service.cancel(run["run_id"], operation_key="cancel-before-accept", expected_revision=before["revision"])
        finally:
            release.touch()
        finished = self.wait(run["run_id"])
        self.assertEqual(finished["state"], "cancelled")
        self.assertIsNone(finished["acceptance_id"])
        self.assertNotIn("acceptance.recorded", {event["type"] for event in self.service.events(run["run_id"])})

    def test_stale_block_transaction_cannot_reopen_confirmed_cancellation(self):
        run, _ = self.submit()
        self.start(run)
        stopped = self.wait(run["run_id"])
        self.assertIn("required_review_missing", {item["code"] for item in stopped["blockers"]})
        cancellation = {}

        def observe(frame, event, arg):
            if (event != "call" or frame.f_code.co_name != "mutate"
                    or frame.f_locals.get("command") != "block"
                    or frame.f_locals.get("run_id") != run["run_id"]):
                return observe
            # Observe the real call after _block's initial state read. Run the
            # public operator operations before allowing that same mutation to
            # continue; no store method or successful receipt is substituted.
            sys.settrace(None)
            current = self.service.inspect(run["run_id"])
            self.assertEqual(current["state"], "verifying")
            self.assertIsNone(current["active_attempt_id"])
            self.assertFalse(current["pending_effect_ids"])
            requested = self.service.cancel(run["run_id"], operation_key="stale-block-cancel",
                                            expected_revision=current["revision"])
            cancellation["run"] = self.service.reconcile(run["run_id"], operation_key="stale-block-reconcile",
                                                         expected_revision=requested["revision"])
            self.assertEqual(cancellation["run"]["state"], "cancelled")
            cancellation["events"] = self.service.events(run["run_id"])
            return None

        deadline = time.monotonic() + 5
        while True:
            current = self.service.inspect(run["run_id"])
            previous_trace = sys.gettrace()
            try:
                sys.settrace(observe)
                finished = self.service.verify(run["run_id"], operation_key="stale-block-verify",
                                               expected_revision=current["revision"])
                break
            except TaskAlongError as exc:
                # Only the preceding supervisor's proven no-effect guard
                # conflict may be retried with the same verification intent.
                if exc.code != "operation_in_progress" or time.monotonic() >= deadline:
                    raise
            finally:
                sys.settrace(previous_trace)
            time.sleep(0.025)
        self.assertTrue(cancellation)
        self.assertEqual(finished, cancellation["run"])
        self.assertEqual(self.service.inspect(run["run_id"]), cancellation["run"])
        self.assertEqual(self.service.events(run["run_id"]), cancellation["events"])
        confirmations = [event for event in cancellation["events"] if event["type"] == "cancel.confirmed"]
        self.assertEqual(len(confirmations), 1)
        self.assertTrue(confirmations[0]["payload"]["local_cessation"])

    def test_completed_worker_late_cancel_records_confirmation_atomically(self):
        run, _ = self.submit()
        environment, marker, release = self.trace_environment("mutate", mode="pause", command="executor.finish")
        client = self.cli_start(run, "late-completed-cancel", environment=environment)
        self.assertEqual(client.returncode, 0, client.stderr)
        try:
            self.wait_file(marker)
            before = self.service.inspect(run["run_id"])
            requested = self.service.cancel(run["run_id"], operation_key="cancel-after-worker-return",
                                            expected_revision=before["revision"])
            self.assertEqual(requested["state"], "cancel_pending")
        finally:
            release.touch()
        finished = self.wait(run["run_id"], states=("cancelled",))
        self.assertIsNone(finished["active_attempt_id"])
        self.assertFalse(finished["pending_effect_ids"])
        events = self.service.events(run["run_id"])
        confirmations = [event for event in events if event["type"] == "cancel.confirmed"]
        self.assertEqual(len(confirmations), 1)
        self.assertTrue(confirmations[0]["payload"]["termination_confirmed"])
        self.assertTrue(confirmations[0]["payload"]["local_cessation"])
        self.assertEqual(events[-1]["type"], "cancel.confirmed")
        self.assertNotIn("executor.completed", {event["type"] for event in events})
        self.assertNotIn("acceptance.recorded", {event["type"] for event in events})


    def _foreground_verify_interruption(self, stage):
        spec = self.configure_released_review()
        run, _ = self.submit(spec)
        self.start(run)
        accepted = self.wait(run["run_id"])
        self.assertEqual(accepted["state"], "accepted")
        if stage == "review":
            self.configure_released_review(hold_invocation=True)
            marker = self.root / "review-entered"
            release = self.root / "review-release"
        else:
            marker = self.root / "check-entered"
            release = self.root / "check-release"
            self.sandbox.write_text("#!" + sys.executable + "\nimport os,sys,time\nfrom pathlib import Path\n"
                + "argv=sys.argv[sys.argv.index('--')+1:]\n"
                + f"Path({str(marker)!r}).write_text('owned check entered')\n"
                + "end=time.monotonic()+30\n"
                + f"while not Path({str(release)!r}).exists() and time.monotonic()<end: time.sleep(.02)\n"
                + "os.execv(argv[0],argv)\n")
            self.service.configure_command_sandbox(self.sandbox)
            if stage == "uncertain_check":
                entered = self.root / "escaped-entered"
                finished = self.root / "escaped-finished"
                source = self.sandbox.read_text()
                fork = ("child=os.fork()\nif child == 0:\n    os.setsid()\n"
                        + f"    Path({str(entered)!r}).touch()\n"
                        + f"    while not Path({str(release)!r}).exists(): time.sleep(.02)\n"
                        + f"    Path({str(finished)!r}).touch()\n    os._exit(0)\n"
                        + f"while not Path({str(entered)!r}).exists(): time.sleep(.01)\n")
                ready = f"Path({str(marker)!r}).write_text('owned check entered')\n"
                source = source.replace(ready, "")
                source = source.replace("end=time.monotonic()+30\n", fork + ready + "end=time.monotonic()+30\n")
                self.sandbox.write_text(source)
                self.service.configure_command_sandbox(self.sandbox)
        self.addCleanup(lambda: release.touch(exist_ok=True) if release.parent.exists() else None)
        deadline = time.monotonic() + 5
        while True:
            current = self.service.inspect(run["run_id"])
            command = [sys.executable, "-m", "taskalong", "--state-dir", str(self.state), "verify", run["run_id"],
                       "--key", "foreground-interrupt-" + stage, "--expected-revision", str(current["revision"]), "--json"]
            process = subprocess.Popen(command, cwd=self.root, env=dict(os.environ), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            until = time.monotonic() + 20
            while not marker.exists() and process.poll() is None and time.monotonic() < until:
                time.sleep(.02)
            if marker.exists():
                break
            stdout, stderr = process.communicate(timeout=5)
            error = json.loads(stdout)
            if (process.returncode != 4 or error["errors"][0]["code"] != "operation_in_progress"
                    or time.monotonic() >= deadline):
                self.fail("The foreground verifier did not reach its real subprocess barrier: " + stderr + stdout)
            time.sleep(.025)
        try:
            self.assertIsNone(process.poll())
            process.send_signal(signal.SIGINT)  # Only this exact Popen-owned client.
            stdout, stderr = process.communicate(timeout=10)
        finally:
            release.touch()
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
        self.assertEqual(process.returncode, 130, stderr + stdout)
        stopped = self.service.inspect(run["run_id"])
        self.assertEqual(stopped["state"], "blocked")
        if stage == "uncertain_check":
            self.wait_file(finished)
            self.assertTrue(stopped["pending_effect_ids"])
            self.assertIsNone(stopped["acceptance_id"])
            self.assertEqual(stopped["blockers"][0]["effect_outcome"], "uncertain")
            for effect_id in stopped["pending_effect_ids"]:
                self.assertEqual(self.service._store.detail("effects", effect_id)["phase"], "unknown")
            with self.assertRaises(TaskAlongError) as unknown:
                self.service.reconcile(run["run_id"], operation_key="uncertain-interrupt-reconcile",
                                       expected_revision=stopped["revision"])
            self.assertEqual(unknown.exception.effect_outcome, "uncertain")
            self.assertFalse([e for e in self.service.events(run["run_id"]) if e["type"] == "cancel.confirmed"])
            return
        self.assertFalse(stopped["pending_effect_ids"])
        self.assertIsNone(stopped["acceptance_id"])
        self.assertEqual(stopped["blockers"][0]["code"], "verification_interrupted")
        self.assertEqual(stopped["blockers"][0]["effect_outcome"], "known")
        self.assertEqual(json.loads(stdout)["errors"][0]["code"], "verification_interrupted")
        self.assertLess(stopped["budget_consumed"]["output_bytes"], spec["budget"]["max_output_bytes"])
        recovered = self.service.verify(run["run_id"], operation_key="fresh-after-interrupt-" + stage,
                                        expected_revision=stopped["revision"])
        self.assertEqual(recovered["state"], "accepted")
        self.assertFalse(recovered["pending_effect_ids"])
        self.assertEqual(len(self.invocations()), 1)
        self.assertFalse([e for e in self.service.events(run["run_id"]) if e["type"] == "cancel.confirmed"])

    def test_foreground_check_interrupt_preserves_receipt_and_allows_fresh_verification(self):
        self._foreground_verify_interruption("check")

    def test_foreground_review_interrupt_preserves_receipt_and_allows_fresh_verification(self):
        self._foreground_verify_interruption("review")


    def test_foreground_interrupt_keeps_escaped_descendant_capture_unknown(self):
        self._foreground_verify_interruption("uncertain_check")


    def test_foreground_interrupt_before_dispatch_retains_known_zero_capture(self):
        spec = self.configure_released_review()
        run, _ = self.submit(spec)
        self.start(run)
        accepted = self.wait(run["run_id"])
        self.assertEqual(accepted["state"], "accepted")
        environment, marker, release = self.trace_environment("run_bounded", mode="pause")
        command = [sys.executable, "-m", "taskalong", "--state-dir", str(self.state), "verify", run["run_id"],
                   "--key", "interrupt-before-dispatch", "--expected-revision", str(accepted["revision"]), "--json"]
        process = subprocess.Popen(command, cwd=self.root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.wait_file(marker)
            process.send_signal(signal.SIGINT)
            # The handler only sets local intent while the trusted trace barrier
            # still prevents target dispatch. Then allow the real gate to run.
            time.sleep(.05)
            release.touch()
            stdout, stderr = process.communicate(timeout=10)
        finally:
            release.touch()
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
        self.assertEqual(process.returncode, 130, stderr + stdout)
        stopped = self.service.inspect(run["run_id"])
        self.assertEqual(stopped["state"], "blocked")
        self.assertFalse(stopped["pending_effect_ids"])
        self.assertEqual(stopped["budget_consumed"]["output_bytes"], accepted["budget_consumed"]["output_bytes"])
        self.assertEqual(stopped["blockers"][0]["effect_outcome"], "known")
        recovered = self.service.verify(run["run_id"], operation_key="verify-after-predispatch-interrupt", expected_revision=stopped["revision"])
        self.assertEqual(recovered["state"], "accepted")


if __name__ == "__main__":
    unittest.main()
