"""Public workspace behavior against real temporary Git repositories."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid
from pathlib import Path

from taskalong.errors import TaskAlongError
from taskalong.workspace import WorkspaceManager, inspect_repository, repository_guard


def git(path, *args):
    result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(path), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode().strip()


class WorkspaceFixture:
    def setUp(self):
        fixture_git_environment = patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"})
        fixture_git_environment.start()
        self.addCleanup(fixture_git_environment.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.repo = self.root / "primary"
        self.repo.mkdir()
        git(self.repo, "init", "--initial-branch=main")
        git(self.repo, "config", "user.name", "Synthetic Operator")
        git(self.repo, "config", "user.email", "operator@example.invalid")
        git(self.repo, "config", "commit.gpgsign", "false")
        (self.repo / "calc.py").write_text("def add_one(value):\n    return value\n")
        git(self.repo, "add", "calc.py")
        git(self.repo, "commit", "-m", "Synthetic baseline")
        self.base = git(self.repo, "rev-parse", "HEAD")
        self.store = str(uuid.uuid4())
        self.run_id = str(uuid.uuid4())
        self.manager = WorkspaceManager(self.repo, self.store)
        self.intent = self.manager.prepare(self.run_id, self.root / "owned" / self.run_id, self.base)

    def workspace(self):
        return self.manager.create(self.intent)


class WorkspaceTests(WorkspaceFixture, unittest.TestCase):
    def test_allocation_retains_primary_and_has_exact_marker(self):
        workspace = self.workspace()
        self.assertEqual(workspace["state"], "owned")
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.base)
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")
        self.assertEqual(git(workspace["path"], "rev-parse", "HEAD"), self.base)
        self.assertEqual(self.manager.validate(workspace, 1)["workspace_id"], workspace["workspace_id"])
        # Repeated identical dispatch reconciles rather than creating a second branch.
        self.assertEqual(self.manager.create(self.intent)["workspace_id"], workspace["workspace_id"])

    def test_alternate_state_store_cannot_bypass_common_directory_owner(self):
        self.workspace()
        other = WorkspaceManager(self.repo, str(uuid.uuid4()))
        with self.assertRaises(TaskAlongError) as caught:
            other.prepare(str(uuid.uuid4()), self.root / "other", self.base)
        self.assertEqual(caught.exception.code, "repository_store_conflict")

    def test_guard_contention_is_not_expiry_or_takeover(self):
        with repository_guard(self.manager.repository, self.store):
            with self.assertRaises(TaskAlongError) as caught:
                with repository_guard(self.manager.repository, self.store):
                    pass
        self.assertEqual(caught.exception.code, "repository_busy")

    def test_guard_accepts_a_fresh_absolute_common_directory(self):
        alternate = self.root / "fresh"
        alternate.mkdir()
        git(alternate, "init", "--initial-branch=main")
        common = alternate / ".git"
        store = str(uuid.uuid4())
        with repository_guard(common, store):
            self.assertTrue((common / "taskalong" / "store.json").is_file())

    def test_guard_inode_is_not_unlinked_after_release(self):
        lock = Path(self.manager.repository["common_dir"]) / "taskalong" / "control.lock"
        before = lock.stat().st_ino
        with repository_guard(self.manager.repository, self.store):
            pass
        self.assertEqual(lock.stat().st_ino, before)

    def test_dirty_primary_is_preserved_and_rejected(self):
        (self.repo / "calc.py").write_text("private uncommitted work\n")
        with self.assertRaises(TaskAlongError) as caught:
            WorkspaceManager(self.repo, self.store)
        self.assertEqual(caught.exception.code, "dirty_repository")
        self.assertEqual((self.repo / "calc.py").read_text(), "private uncommitted work\n")

    def test_occupied_destination_is_never_adopted(self):
        path = Path(self.intent["path"])
        path.mkdir(parents=True)
        (path / "foreign.txt").write_text("foreign data\n")
        with self.assertRaises(TaskAlongError) as caught:
            self.manager.create(self.intent)
        self.assertEqual(caught.exception.code, "workspace_occupied")
        self.assertEqual((path / "foreign.txt").read_text(), "foreign data\n")

    def test_existing_branch_is_not_overwritten(self):
        git(self.repo, "branch", self.intent["branch"], self.base)
        with self.assertRaises(TaskAlongError) as caught:
            self.manager.create(self.intent)
        self.assertEqual(caught.exception.code, "branch_occupied")
        self.assertEqual(git(self.repo, "rev-parse", self.intent["branch"]), self.base)

    def test_foreign_marker_and_stale_generation_block(self):
        workspace = self.workspace()
        with self.assertRaises(TaskAlongError):
            self.manager.validate({**workspace, "run_id": str(uuid.uuid4())})
        changed = self.manager.advance_generation(workspace, 1, 2)
        self.assertEqual(changed["generation"], 2)
        with self.assertRaises(TaskAlongError):
            self.manager.validate(workspace, 1)
        self.assertEqual(self.manager.validate(changed, 2)["generation"], 2)

    def test_reconcile_exact_prepared_marker_preserves_workspace(self):
        workspace = self.workspace()
        marker = Path(workspace["common_dir"]) / "taskalong" / "workspaces" / (workspace["workspace_id"] + ".json")
        # Synthetic crash image: worktree creation finished but marker's final
        # owned receipt did not. Its original allocation tuple remains exact.
        data = json.loads(marker.read_text())
        data["state"] = "prepared"
        marker.write_text(json.dumps(data))
        self.assertEqual(self.manager.reconcile(self.intent)["state"], "owned")
        self.assertTrue(Path(workspace["path"]).exists())

    def test_actual_caller_death_after_creation_reconciles_without_second_worktree(self):
        intent_path = self.root / "allocation-intent.json"
        intent_path.write_text(json.dumps(self.intent))
        program = "import json,os,signal,sys; from taskalong.workspace import WorkspaceManager; i=json.load(open(sys.argv[1])); WorkspaceManager(i['repository_path'],i['store_uuid']).create(i); os.kill(os.getpid(),signal.SIGKILL)"
        result = subprocess.run([sys.executable, "-c", program, str(intent_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, -9, result.stderr.decode())
        recovered = self.manager.reconcile(self.intent)
        self.assertEqual(recovered["workspace_id"], self.intent["workspace_id"])
        listing = git(self.repo, "worktree", "list", "--porcelain")
        self.assertEqual(listing.count("branch refs/heads/" + self.intent["branch"]), 1)

    def test_unmarked_worktree_is_never_recovered_by_name(self):
        workspace = self.workspace()
        marker = Path(workspace["common_dir"]) / "taskalong" / "workspaces" / (workspace["workspace_id"] + ".json")
        marker.unlink()
        with self.assertRaises(TaskAlongError) as caught:
            self.manager.reconcile(self.intent)
        self.assertEqual(caught.exception.code, "workspace_unowned")
        self.assertTrue(Path(workspace["path"]).exists())

    def test_executable_hook_blocks_without_execution(self):
        canary = self.root / "hook-ran"
        hook = self.repo / ".git" / "hooks" / "post-checkout"
        hook.write_text("#!/bin/sh\ntouch " + str(canary) + "\n")
        hook.chmod(0o700)
        with self.assertRaises(TaskAlongError) as caught:
            WorkspaceManager(self.repo, self.store)
        self.assertEqual(caught.exception.code, "repository_policy_unsupported")
        self.assertFalse(canary.exists())

    def test_filters_and_required_signing_are_explicit_blocks(self):
        git(self.repo, "config", "filter.unapproved.smudge", "false")
        with self.assertRaises(TaskAlongError) as caught:
            WorkspaceManager(self.repo, self.store)
        self.assertEqual(caught.exception.code, "repository_policy_unsupported")
        git(self.repo, "config", "--remove-section", "filter.unapproved")
        git(self.repo, "config", "commit.gpgsign", "true")
        with self.assertRaises(TaskAlongError) as caught:
            WorkspaceManager(self.repo, self.store)
        self.assertEqual(caught.exception.code, "signing_policy_unsupported")

    def test_sha256_git_repository_is_rejected(self):
        alternate = self.root / "sha256"
        alternate.mkdir()
        result = subprocess.run(["git", "-C", str(alternate), "init", "--object-format=sha256"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            self.skipTest("Installed Git lacks SHA-256 repository support")
        with self.assertRaises(TaskAlongError) as caught:
            inspect_repository(alternate)
        self.assertEqual(caught.exception.code, "unsupported_git_object_format")


if __name__ == "__main__":
    unittest.main()
