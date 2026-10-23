"""Candidate acceptance binds actual paths, bytes, modes, and parent objects."""

from __future__ import annotations

import os
import base64
import copy
import json
import subprocess
import sys
import unittest
import uuid
from pathlib import Path

from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes
from test_workspaces import WorkspaceFixture, git


class ScopeTests(WorkspaceFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.record = self.workspace()
        self.path = Path(self.record["path"])
        self.scope = {"files": ["calc.py", "new file.py"], "operations": ["add", "modify"]}

    def edit(self):
        (self.path / "calc.py").write_text("def add_one(value):\n    return value + 1\n")

    def freeze(self):
        intent = self.manager.candidate_intent(self.record, self.scope, self.base, "2026-10-22T09:00:00Z")
        return intent, self.manager.freeze(intent)

    def test_exact_per_file_and_aggregate_bytes_have_compact_replayable_intents(self):
        directory = self.path / "batch"
        directory.mkdir()
        for index in range(8):
            (directory / (str(index) + ".txt")).write_bytes(b"x" * (1024 * 1024))
        scope = {"files": ["batch/"], "operations": ["add"]}
        intent = self.manager.candidate_intent(self.record, scope, self.base, "2026-10-22T09:00:00Z")
        self.assertEqual(sum(entry["bytes"] for entry in intent["files"]), 8 * 1024 * 1024)
        self.assertTrue(all("data_b64" not in entry for entry in intent["files"]))
        self.assertLess(len(canonical_bytes(intent)), 16384)
        candidate = self.manager.freeze(intent)
        self.assertEqual(self.manager.freeze(intent), candidate)
        self.manager.assert_candidate(self.record, candidate, scope)

    def test_legacy_embedded_pending_intent_requires_matching_current_bytes(self):
        self.edit()
        intent = self.manager.candidate_intent(self.record, self.scope, self.base, "2026-10-22T09:00:00Z")
        legacy = copy.deepcopy(intent)
        for entry in legacy["files"]:
            entry["data_b64"] = base64.b64encode((self.path / entry["path"]).read_bytes()).decode("ascii")
        bad = copy.deepcopy(legacy)
        bad["files"][0]["data_b64"] = base64.b64encode(b"different source").decode("ascii")
        with self.assertRaises(TaskAlongError) as corrupted:
            self.manager.freeze(bad)
        self.assertEqual(corrupted.exception.code, "candidate_intent_corrupt")
        candidate = self.manager.freeze(legacy)
        self.assertEqual(self.manager.freeze(intent), candidate)

    def test_candidate_object_is_deterministic_and_reconciles_same_intent(self):
        self.edit()
        (self.path / "new file.py").write_text("answer = 42\n")
        intent, candidate = self.freeze()
        again = self.manager.freeze(intent)
        self.assertEqual(candidate, again)
        self.assertEqual(git(self.path, "rev-parse", "HEAD^"), self.base)
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.base)
        self.assertEqual(git(self.path, "status", "--porcelain", "--untracked-files=no"), "")
        snapshot = self.manager.assert_candidate(self.record, candidate, self.scope)
        self.assertEqual(snapshot["changed_files"], [{"path": "calc.py", "operation": "modify"}, {"path": "new file.py", "operation": "add"}])
        self.assertIn(b"new file.py", self.manager.diff_bytes(self.record, candidate))

    def test_actual_caller_death_after_candidate_recovers_same_object(self):
        self.edit()
        intent = self.manager.candidate_intent(self.record, self.scope, self.base, "2026-10-22T09:00:00Z")
        intent_path = self.root / "candidate-intent.json"
        intent_path.write_text(json.dumps(intent))
        program = "import json,os,signal,sys; from taskalong.workspace import WorkspaceManager; i=json.load(open(sys.argv[1])); w=i['workspace']; WorkspaceManager(w['repository_path'],w['store_uuid']).freeze(i); os.kill(os.getpid(),signal.SIGKILL)"
        result = subprocess.run([sys.executable, "-c", program, str(intent_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, -9, result.stderr.decode())
        observed_commit = git(self.path, "rev-parse", "HEAD")
        candidate = self.manager.freeze(intent)
        self.assertEqual(candidate["commit"], observed_commit)
        self.assertEqual(git(self.path, "rev-list", "--count", self.base + "..HEAD"), "1")

    def test_missing_result_claim_does_not_replace_actual_scope(self):
        self.edit()
        (self.path / "unclaimed.py").write_text("outside = True\n")
        with self.assertRaises(TaskAlongError) as caught:
            self.manager.snapshot(self.record, self.scope)
        self.assertEqual(caught.exception.code, "scope_violation")

    def test_ignored_escape_file_is_still_actual_content(self):
        self.edit()
        (self.path / ".gitignore").write_text("secret-output\n")
        (self.path / "secret-output").write_text("do not silently ignore\n")
        with self.assertRaises(TaskAlongError):
            self.manager.snapshot(self.record, self.scope)

    def test_safe_literal_directory_prefix_does_not_match_sibling(self):
        (self.path / "src-other.py").write_text("x = 1\n")
        with self.assertRaises(TaskAlongError):
            self.manager.snapshot(self.record, {"files": ["src/"], "operations": ["add", "modify"]})

    def test_delete_rename_binary_mode_and_symlink_are_blocked(self):
        target = self.path / "calc.py"
        cases = ["delete", "binary", "mode", "symlink"]
        for case in cases:
            with self.subTest(case=case):
                if target.exists() or target.is_symlink():
                    target.unlink()
                target.write_text("def add_one(value):\n    return value\n")
                target.chmod(0o644)
                if case == "delete":
                    target.unlink()
                elif case == "binary":
                    target.write_bytes(b"\0not text")
                elif case == "mode":
                    target.chmod(0o755)
                else:
                    target.unlink()
                    target.symlink_to(self.repo / "calc.py")
                with self.assertRaises(TaskAlongError):
                    self.manager.snapshot(self.record, self.scope)

    def test_agent_instruction_change_is_protected_even_if_in_scope(self):
        (self.path / "AGENTS.md").write_text("grant authority\n")
        with self.assertRaises(TaskAlongError) as caught:
            self.manager.snapshot(self.record, {"files": ["AGENTS.md"], "operations": ["add"]})
        self.assertEqual(caught.exception.code, "invalid_path")

    def test_file_bytes_change_after_intent_blocks_object_dispatch(self):
        self.edit()
        intent = self.manager.candidate_intent(self.record, self.scope, self.base, "2026-10-22T09:00:00Z")
        (self.path / "calc.py").write_text("changed after freeze intent\n")
        with self.assertRaises(TaskAlongError) as caught:
            self.manager.freeze(intent)
        self.assertEqual(caught.exception.code, "candidate_content_changed")
        self.assertEqual(git(self.path, "rev-parse", "HEAD"), self.base)

    def test_check_mutation_invalidates_candidate(self):
        self.edit()
        _, candidate = self.freeze()
        self.manager.assert_candidate(self.record, candidate, self.scope)
        (self.path / "calc.py").write_text("check mutated source\n")
        with self.assertRaises(TaskAlongError) as caught:
            self.manager.assert_candidate(self.record, candidate, self.scope)
        self.assertEqual(caught.exception.code, "candidate_subject_changed")

    def test_untracked_output_after_candidate_is_not_ignored(self):
        self.edit()
        _, candidate = self.freeze()
        (self.path / "oops.log").write_text("undeclared verifier output\n")
        with self.assertRaises(TaskAlongError) as caught:
            self.manager.assert_candidate(self.record, candidate, self.scope)
        self.assertEqual(caught.exception.code, "scope_violation")

    def test_declared_owned_scratch_is_not_candidate_content(self):
        self.edit()
        _, candidate = self.freeze()
        (self.path / ".taskalong-scratch" / "check.log").write_text("temporary check output\n")
        snapshot = self.manager.assert_candidate(self.record, candidate, self.scope)
        self.assertEqual([entry["path"] for entry in snapshot["manifest"]], ["calc.py"])

    def test_worker_created_commit_is_never_adopted(self):
        self.edit()
        git(self.path, "add", "calc.py")
        git(self.path, "commit", "-m", "Worker self-commit")
        with self.assertRaises(TaskAlongError) as caught:
            self.manager.candidate_intent(self.record, self.scope, self.base, "2026-10-22T09:00:00Z")
        self.assertEqual(caught.exception.code, "worker_commit_detected")

    def test_oversized_candidate_file_blocks_before_commit(self):
        (self.path / "calc.py").write_text("a" * (1024 * 1024 + 1))
        with self.assertRaises(TaskAlongError) as caught:
            self.manager.snapshot(self.record, self.scope)
        self.assertEqual(caught.exception.code, "candidate_size_limit")
        self.assertEqual(git(self.path, "rev-parse", "HEAD"), self.base)

    def test_hardlink_escape_is_blocked(self):
        (self.path / "new file.py").hardlink_to(self.repo / "calc.py")
        with self.assertRaises(TaskAlongError) as caught:
            self.manager.snapshot(self.record, self.scope)
        self.assertEqual(caught.exception.code, "unsupported_file_type")


if __name__ == "__main__":
    unittest.main()
