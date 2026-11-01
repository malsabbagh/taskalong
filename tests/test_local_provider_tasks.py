"""Task preparation checks source truth and output scope before inference."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.local_provider_tasks import prepare_task, render_prompt, validate_plan, verify_task
from taskalong.validation import digest


@unittest.skipUnless(os.name == "posix", "Current owned Git observation is POSIX-only")
class ProviderTaskTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
        self.environment.start()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Synthetic Operator")
        self.git("config", "user.email", "synthetic@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        (self.root / "target.py").write_text("answer = 1\n")
        (self.root / "reference.txt").write_text("Public reference only.\n")
        self.git("add", ".")
        self.git("commit", "-m", "Synthetic source baseline")
        self.base = self.git("rev-parse", "HEAD")

    def tearDown(self):
        self.temp.cleanup()
        self.environment.stop()

    def git(self, *args):
        p = subprocess.run(["git", "-c", "core.hooksPath=" + os.devnull, "-C", str(self.root), *args],
                           capture_output=True, check=True, timeout=15)
        return p.stdout.decode().strip()

    def plan(self, **kw):
        args = {"base_commit": self.base, "task": "Create the declared module using the public reference.",
                "provider": "muse", "model": "example-model", "reasoning_effort": "high",
                "read_paths": ["reference.txt"], "writable_paths": ["new.py", "target.py"]}
        return prepare_task(self.root, **(args | kw))

    def test_new_outputs_are_explicit_and_references_are_read_only(self):
        plan = self.plan()
        self.assertEqual(set(plan["writable_outputs"]), {"new.py", "target.py"})
        self.assertIsNone(plan["writable_outputs"]["new.py"])
        self.assertEqual(plan["writable_outputs"]["target.py"]["content"], "answer = 1\n")
        self.assertEqual(set(plan["read_context"]), {"reference.txt"})
        self.assertEqual(verify_task(plan, repository=self.root), plan)
        prompt = render_prompt(plan)
        self.assertNotIn(str(self.root).encode(), prompt)
        self.assertIn(b"read-only reference", prompt)
        self.assertNotIn("live_dispatch_allowed", plan)

    def test_missing_outputs_and_scope_aliases_fail_before_any_runtime(self):
        for kw in ({"writable_paths": []}, {"writable_paths": ["target.py", "TARGET.py"]},
                   {"writable_paths": ["reference.txt"]}, {"writable_paths": ["a", "a/b.py"]},
                   {"writable_paths": ["../escape"]}, {"read_paths": [".env"]},
                   {"writable_paths": ["new.py", "new.py"]}):
            with self.subTest(kw=kw), self.assertRaises(TaskAlongError):
                self.plan(**kw)

    def test_dirty_source_and_different_base_are_not_resigned(self):
        plan = self.plan()
        (self.root / "target.py").write_text("answer = 2\n")
        with self.assertRaises(TaskAlongError):
            verify_task(plan, repository=self.root)
        self.git("add", "target.py")
        self.git("commit", "-m", "Changed source")
        with self.assertRaises(TaskAlongError):
            verify_task(plan, repository=self.root)
        with self.assertRaises(TaskAlongError):
            self.plan(base_commit="0" * 40)

    def test_validly_resealed_fake_snapshot_still_fails_source_verification(self):
        plan = self.plan()
        snapshot = plan["writable_outputs"]["target.py"]
        snapshot["content"] = "answer = 8\n"
        import hashlib
        snapshot["sha256"] = hashlib.sha256(snapshot["content"].encode()).hexdigest()
        snapshot["bytes"] = len(snapshot["content"].encode())
        from taskalong.local_provider_tasks import _intent
        plan["intent_digest"] = _intent(plan)
        plan["digest"] = digest(plan)
        validate_plan(plan)  # Integrity alone intentionally does not establish truth.
        with self.assertRaises(TaskAlongError):
            verify_task(plan, repository=self.root)

    def test_artifact_format_does_not_allocate_a_new_intent(self):
        old = self.plan()
        new = self.plan(artifact_format="unified-diff/1")
        self.assertEqual(old["intent_digest"], new["intent_digest"])
        self.assertNotEqual(old["digest"], new["digest"])
        self.assertIn(b"unified diff", render_prompt(new))

    def test_untracked_existing_output_and_symlink_targets_fail(self):
        (self.root / "new.py").write_text("Do not overwrite.\n")
        with self.assertRaises(TaskAlongError):
            self.plan()
        (self.root / "new.py").unlink()
        (self.root / "new.py").symlink_to(self.root / "target.py")
        with self.assertRaises(TaskAlongError):
            self.plan()
        self.assertEqual((self.root / "target.py").read_text(), "answer = 1\n")

    def test_new_output_with_regular_file_ancestor_is_not_absent(self):
        with self.assertRaises(TaskAlongError):
            self.plan(writable_paths=["target.py/new.py"])
        self.assertTrue((self.root / "target.py").is_file())

    def test_git_filemode_setting_cannot_hide_changed_source_mode(self):
        plan = self.plan()
        self.git("config", "core.filemode", "false")
        (self.root / "target.py").chmod(0o755)
        with self.assertRaises(TaskAlongError):
            self.plan()
        with self.assertRaises(TaskAlongError):
            verify_task(plan, repository=self.root)

    def test_invalid_unicode_paths_have_safe_typed_errors(self):
        for key in ("read_paths", "writable_paths"):
            with self.subTest(key=key), self.assertRaises(TaskAlongError):
                self.plan(**{key: ["\ud800"]})

    def test_unselected_assets_symlinks_and_untracked_private_files_are_not_inputs(self):
        (self.root / "asset.bin").write_bytes(b"\x00\xff")
        (self.root / "alias").symlink_to("asset.bin")
        self.git("add", "asset.bin", "alias")
        self.git("commit", "-m", "Unselected assets")
        self.base = self.git("rev-parse", "HEAD")
        (self.root / "untracked-note").write_text("Never sent.\n")
        plan = self.plan()
        self.assertNotIn(b"Never sent", render_prompt(plan))
        with self.assertRaises(TaskAlongError):
            self.plan(read_paths=["alias"])
        with self.assertRaises(TaskAlongError):
            self.plan(read_paths=["asset.bin"])

    def test_plan_shape_and_snapshot_tampering_are_closed(self):
        original = self.plan()
        for patch_value in ({"read_context": 1}, {"writable_outputs": []}, {"context_policy": []},
                            {"artifact_format": "guess"}, {"production_dispatch_allowed": True}):
            with self.subTest(patch_value=patch_value), self.assertRaises(TaskAlongError):
                validate_plan(original | patch_value)
        bad = copy.deepcopy(original)
        bad["writable_outputs"]["target.py"]["git_mode"] = []
        with self.assertRaises(TaskAlongError):
            validate_plan(bad)
        with self.assertRaises(TaskAlongError):
            self.plan(task="\ud800")
        self.assertEqual(json.loads(json.dumps(original)), original)


if __name__ == "__main__":
    unittest.main()
