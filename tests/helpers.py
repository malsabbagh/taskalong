"""New local synthetic fixtures for public service/process lifecycle tests.

The external fake provider and command transport are test boundaries. They do
not replace core transactions, ownership, checks, evidence, or acceptance. The
command fixture deliberately makes no real sandbox-containment claim.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch
import uuid

from taskalong.api import RunService
from taskalong.errors import TaskAlongError
from taskalong.validation import digest, seal


def git(path, *arguments):
    result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(path), *arguments],
                            capture_output=True, check=True, timeout=15)
    return result.stdout.decode().strip()


class ServiceFixture:
    """Mixin creating only a new repository, store and external test executables."""

    def setUp(self):
        env = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        # A source test runner may have supplied a relative PYTHONPATH. Its
        # detached children use an external CWD. Preserve it as an absolute
        # developer-test path; installed qualification supplies no PYTHONPATH.
        if os.environ.get("PYTHONPATH"):
            env["PYTHONPATH"] = os.pathsep.join(str(Path(item).resolve()) for item in os.environ["PYTHONPATH"].split(os.pathsep) if item)
        self.environment = patch.dict(os.environ, env)
        self.environment.start()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.state = self.root / "state"
        self.repo = self.root / "primary"
        self.repo.mkdir()
        git(self.repo, "init", "-b", "main")
        git(self.repo, "config", "user.name", "Synthetic Operator")
        git(self.repo, "config", "user.email", "synthetic@example.invalid")
        git(self.repo, "config", "commit.gpgsign", "false")
        (self.repo / "arithmetic.py").write_text("def add(a, b):\n    return a - b\n")
        (self.repo / "test_arithmetic.py").write_text("import unittest\nfrom arithmetic import add\nclass ArithmeticTests(unittest.TestCase):\n    def test_addition(self):\n        self.assertEqual(add(2, 3), 5)\n")
        git(self.repo, "add", "arithmetic.py", "test_arithmetic.py")
        git(self.repo, "commit", "-m", "Synthetic failing arithmetic baseline")
        self.base = git(self.repo, "rev-parse", "HEAD")
        self.mode_file = self.root / "fixture-mode.json"
        self.mode_file.write_text(json.dumps({"mode": "good"}))
        self.release_file = self.root / "fixture-release"
        self.barrier_file = self.root / "fixture-barrier-enabled"
        self.executable = self.root / "fake-codex"
        fixture = Path(__file__).parent / "fixtures" / "fake_codex.py"
        lines = fixture.read_text().replace("#!/usr/bin/env python3", "#!" + sys.executable, 1).splitlines()
        source = []
        for line in lines:
            if line.startswith("    mode = "):
                source.append("    mode = json.loads(Path(" + repr(str(self.mode_file)) + ").read_text())['mode']")
            else:
                source.append(line)
            if 'print(json.dumps({"type": "thread.started"' in line:
                source.extend(["    while Path(" + repr(str(self.barrier_file)) + ").exists() and not Path(" + repr(str(self.release_file)) + ").exists():",
                               "        time.sleep(0.05)"])
        # A restarted fixture truthfully reports a retained partial edit relative
        # to the task's base even when its second attempt need not change it.
        text = "\n".join(source).replace("if after != before:", "if after != before or 'return a + b' in after:") + "\n"
        self.executable.write_text(text)
        self.executable.chmod(0o700)
        self.sandbox = self.root / "synthetic-command-launcher"
        self.sandbox.write_text("#!" + sys.executable + "\nimport os,sys\nargv=sys.argv[sys.argv.index('--')+1:]\nos.execv(argv[0],argv)\n")
        self.sandbox.chmod(0o700)
        self.service = RunService(self.state)
        self.registration = self.service.register_repository(self.repo, self.root / "workspaces")
        self.profile = seal("runtime-profile", {"profile_id": "public-service-fixture", "qualification": "synthetic",
            "adapter": "codex-cli", "executable_path": str(self.executable),
            "executable_sha256": hashlib.sha256(self.executable.read_bytes()).hexdigest(), "runtime_version": "0.163.0",
            "model": "synthetic", "reasoning_effort": "low", "service_tier": None,
            "inference_destination_id": "synthetic-local-fixture", "permission_policy": {},
            "permission_policy_digest": digest({}), "toolchain_read_roots": [],
            "credential_source_ref": None, "qualification_receipt_ids": []})
        self.service.register_profile(self.profile)
        self.service.configure_command_sandbox(self.sandbox)
        self.run_ids = []

    def tearDown(self):
        # Cancellation goes through the public control plane; test cleanup never
        # signals a numeric PID recovered from the store or removes a worktree.
        self.release_file.touch(exist_ok=True)
        for run_id in self.run_ids:
            observed = self.service.inspect(run_id)
            if observed.get("active_attempt_id") and observed["state"] not in {"cancelled", "failed", "draft_published", "accepted", "cancel_pending"}:
                try:
                    self.service.cancel(run_id, operation_key="fixture-cleanup:" + str(uuid.uuid4()), expected_revision=observed["revision"])
                except TaskAlongError:
                    pass
            deadline = time.monotonic() + 12
            while self.service.inspect(run_id).get("active_attempt_id") and time.monotonic() < deadline:
                time.sleep(0.05)
        self.service.close()
        self.temporary.cleanup()
        self.environment.stop()

    def set_mode(self, mode):
        self.mode_file.write_text(json.dumps({"mode": mode}))

    def spec(self, *, check_argv=None, attempt_seconds=10, total_seconds=20, goal=None):
        return seal("task-spec", {"task_id": "service-" + str(uuid.uuid4()), "revision": 1,
            "goal": goal or "Correct the local synthetic arithmetic function.", "non_goals": ["No other files, dependencies, provider calls or publication."],
            "repository": {"registration_id": self.registration["registration_id"], "base_commit": self.base, "base_ref": "main"},
            "scope": {"files": ["arithmetic.py"], "operations": ["modify"]},
            "criteria": [{"id": "addition", "description": "The function adds two integers.", "check_ids": ["unit"]}],
            "checks": [{"id": "unit", "argv": check_argv or [sys.executable, "-m", "unittest", "-q", "test_arithmetic"],
                        "cwd": ".", "timeout_seconds": 5, "expected_exit_code": 0, "criterion_ids": ["addition"], "required": True}],
            "execution": {"adapter": "codex-cli", "profile_id": self.profile["profile_id"], "profile_digest": self.profile["digest"]},
            "permissions": {"local_edit": True, "local_commit": True, "inference_destination_id": "synthetic-local-fixture", "allowed_effects": ["execute", "verify", "commit_candidate"]},
            "budget": {"max_attempts": 2, "attempt_seconds": attempt_seconds, "total_active_seconds": total_seconds,
                       "max_output_bytes": 1048576, "hard_cost_usd": None, "hard_tokens": None},
            "review": {"required": True, "integration": "reviewsensei", "contract": "0.8.8/v1", "config_digest": "c" * 64, "require_full_coverage": True},
            "publication": None, "qualification": "synthetic"})

    def submit(self, spec=None, *, key="submit", authorize=True):
        spec = spec or self.spec()
        run = self.service.submit(spec, operation_key=key)
        self.run_ids.append(run["run_id"])
        if authorize:
            self.service.authorize(run["run_id"], decision_digest=spec["digest"], scope=["execute", "verify", "commit_candidate"], qualification="synthetic")
        return self.service.inspect(run["run_id"]), spec

    def start(self, run=None, *, key="start"):
        if run is None:
            run, _ = self.submit()
        return self.service.start(run["run_id"], operation_key=key, expected_revision=run["revision"])

    def wait(self, run_id, *, states=("blocked", "accepted", "cancelled", "failed"), predicate=None, timeout=20):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            with RunService(self.state) as fresh:
                last = fresh.inspect(run_id)
            if predicate(last) if predicate is not None else last["state"] in states:
                return last
            time.sleep(0.05)
        self.fail("Run did not reach the expected public state: " + repr(last))

    def invocations(self):
        path = self.root / "fake-codex-invocations.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def export(self, run_id, name="export"):
        directory = self.root / name
        self.service.export(run_id, output=directory)
        return json.loads((directory / "manifest.json").read_text())
