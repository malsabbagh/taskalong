"""Actual independently run checks and evidence/privacy through RunService."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

from taskalong.errors import TaskAlongError
from helpers import ServiceFixture, git


class EvidenceTests(ServiceFixture, unittest.TestCase):
    def test_large_supported_source_reaches_independent_verification(self):
        # Regression for source base64 exceeding the control-document limit.
        # The executable provider, worktree, store and verifier remain real.
        original = (self.repo / "arithmetic.py").read_bytes()
        supported_bytes = 819234
        payload = original + b"#" + b"x" * (supported_bytes - len(original) - 2) + b"\n"
        self.assertEqual(len(payload), supported_bytes)
        (self.repo / "arithmetic.py").write_bytes(payload)
        git(self.repo, "add", "arithmetic.py")
        git(self.repo, "commit", "-m", "Synthetic bounded large source baseline")
        self.base = git(self.repo, "rev-parse", "HEAD")
        run, _ = self.submit()
        self.start(run)
        finished = self.wait(run["run_id"])
        self.assertEqual(finished["state"], "blocked")
        self.assertIn("required_review_missing", {item["code"] for item in finished["blockers"]})
        self.assertIsNotNone(finished["candidate"])
        evidence = self.export(run["run_id"])["evidence"]
        self.assertEqual({record["type"] for record in evidence}, {"scope", "command"})
        self.assertTrue(all(record["result"] == "passed" for record in evidence))

    def test_nonzero_command_issues_failed_evidence_and_cannot_accept_worker_claim(self):
        run, _ = self.submit(self.spec(check_argv=[sys.executable, "-c", "raise SystemExit(7)"]))
        self.start(run)
        finished = self.wait(run["run_id"])
        self.assertEqual(finished["state"], "blocked")
        self.assertIsNone(finished["acceptance_id"])
        evidence = self.export(run["run_id"])["evidence"]
        commands = [item for item in evidence if item["type"] == "command"]
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0]["result"], "failed")
        self.assertEqual(commands[0]["subject"]["candidate_commit"], finished["candidate"]["commit"])
        self.assertTrue(commands[0]["artifacts"])

    def test_check_mutating_candidate_blocks_and_preserves_actual_bytes(self):
        mutation = "from pathlib import Path; Path('arithmetic.py').write_text('def add(a, b):\\n    return 0\\n')"
        run, _ = self.submit(self.spec(check_argv=[sys.executable, "-c", mutation]))
        self.start(run)
        finished = self.wait(run["run_id"])
        self.assertEqual(finished["state"], "blocked")
        self.assertIn("check_mutated_candidate", {item["code"] for item in finished["blockers"]})
        self.assertIsNone(finished["acceptance_id"])
        candidate_source = self.root / "workspaces" / run["run_id"] / "arithmetic.py"
        self.assertIn("return 0", candidate_source.read_text())
        self.assertEqual(len(self.invocations()), 1)

    def test_worker_fabricated_acceptance_is_rejected_before_independent_evidence(self):
        self.set_mode("self-acceptance")
        run, _ = self.submit()
        self.start(run)
        finished = self.wait(run["run_id"])
        self.assertEqual(finished["state"], "blocked")
        self.assertIsNone(finished["acceptance_id"])
        self.assertIsNone(finished["candidate"])
        self.assertEqual(self.export(run["run_id"])["evidence"], [])

    def test_stale_worker_packet_binding_never_advances_to_verification(self):
        self.set_mode("wrong-packet")
        run, _ = self.submit()
        self.start(run)
        finished = self.wait(run["run_id"])
        self.assertEqual(finished["state"], "blocked")
        self.assertIsNone(finished["candidate"])
        self.assertIsNone(finished["acceptance_id"])
        self.assertEqual(self.export(run["run_id"])["evidence"], [])
        self.assertEqual(len(self.invocations()), 1)

    def test_export_omits_task_text_and_command_output_bytes(self):
        task_secret = "DO_NOT_EXPORT_SYNTHETIC_TASK_PROSE"
        output_secret = "DO_NOT_EXPORT_SYNTHETIC_COMMAND_OUTPUT"
        run, _ = self.submit(self.spec(goal=task_secret, check_argv=[sys.executable, "-c", "print('" + output_secret + "')"]))
        self.start(run)
        finished = self.wait(run["run_id"])
        self.service.export(run["run_id"], output=self.root / "redacted-export")
        raw = (self.root / "redacted-export" / "manifest.json").read_text()
        self.assertNotIn(task_secret, raw)
        self.assertNotIn(output_secret, raw)
        self.assertNotIn(str(self.root), raw)
        self.assertIn('"raw_content_included":false', raw)
        self.assertTrue(finished["evidence_ids"])


if __name__ == "__main__":
    unittest.main()
