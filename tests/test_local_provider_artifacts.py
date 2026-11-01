"""Synthetic integrity fixtures exercise pure proposal validation, not source proof."""
import copy
import difflib
from dataclasses import FrozenInstanceError
import hashlib
import os
import random
from pathlib import Path
import subprocess
import tempfile
import unittest

from taskalong.errors import TaskAlongError
from taskalong.local_provider_artifacts import validate_response
from taskalong.local_provider_tasks import FORMAT, _intent
from taskalong.validation import canonical_bytes, digest, loads


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def snapshot(text, mode="100644"):
    raw = text.encode()
    return {"content": text, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "git_blob": blob(raw), "git_mode": mode}


def synthetic_plan(outputs=None, *, kind="file-replacements/1", reads=None):
    """Intentionally fake source identities; only a source observer authenticates them."""
    outputs = {"target.txt": snapshot("old\n"), "new.txt": None} if outputs is None else outputs
    plan = {"format": FORMAT, "repository_identity": "a" * 64, "base_commit": "b" * 40,
            "base_tree": "c" * 40, "task": "Synthetic proposal validation only.", "provider": "synthetic",
            "backend": None, "model": "synthetic", "reasoning_effort": "high", "context_policy": "include",
            "artifact_format": kind, "read_context": reads or {}, "writable_outputs": outputs,
            "snapshot_provenance": "observed-selected-git", "manual_application_required": True,
            "automatic_retry_allowed": False}
    plan["intent_digest"] = _intent(plan)
    plan["digest"] = digest(plan)
    return plan


class ProviderArtifactTests(unittest.TestCase):
    def response(self, plan, changes):
        key = "changes" if plan["artifact_format"] == "file-replacements/1" else "patch"
        return {"bundle_digest": plan["digest"], key: changes}

    def artifact(self, plan, changes, **kw):
        return validate_response(plan, self.response(plan, changes), **kw)

    def rejected(self, plan, changes, **kw):
        with self.assertRaises(TaskAlongError):
            self.artifact(plan, changes, **kw)

    def test_replacement_new_edit_delete_empty_and_no_final_lf_preimages(self):
        plan = synthetic_plan({"edit.txt": snapshot("old\n", "100755"), "delete.txt": snapshot("last"),
                               "empty-delete.txt": snapshot(""), "empty-new.txt": None, "new.txt": None})
        changes = {"edit.txt": "new\n", "delete.txt": None, "empty-delete.txt": None,
                   "empty-new.txt": "", "new.txt": "created\n"}
        artifact = self.artifact(plan, changes)
        manifest = artifact.to_dict()
        entries = {f["path"]: f for f in manifest["files"]}
        self.assertEqual(entries["edit.txt"]["after"]["mode"], "100755")
        self.assertEqual(entries["empty-new.txt"]["after"],
                         {"sha256": hashlib.sha256(b"").hexdigest(), "bytes": 0, "mode": "100644"})
        self.assertIsNone(entries["empty-new.txt"]["before"])
        self.assertIsNone(entries["empty-delete.txt"]["after"])
        self.assertIn(b"-last\n\\ No newline at end of file\n", artifact.patch_bytes)
        self.assertEqual(manifest["patch_sha256"], hashlib.sha256(artifact.patch_bytes).hexdigest())
        self.assertEqual(manifest["response_sha256"], hashlib.sha256(canonical_bytes(self.response(plan, changes))).hexdigest())
        self.assertEqual(manifest["plan_digest"], plan["digest"])
        self.assertEqual(manifest["intent_digest"], plan["intent_digest"])
        self.assertTrue(manifest["manual_application_required"])
        for flag in ("execution_allowed", "acceptance_allowed", "production_dispatch_allowed", "source_truth_verified"):
            self.assertFalse(manifest[flag])
        self.git_check(plan, artifact.patch_bytes)

    def git_check(self, plan, patch):
        """Check disposable synthetic files only; never apply a proposal."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for path, snap in plan["writable_outputs"].items():
                if snap is not None:
                    dest = root / path
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(snap["content"].encode())
                    dest.chmod(int(snap["git_mode"], 8) & 0o777)
            environment = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
            for args, data in ((["init", "-q"], None), (["apply", "--check", "--whitespace=nowarn", "-"], patch)):
                p = subprocess.run(["git", "-c", "core.hooksPath=" + os.devnull, "-C", tmp, *args],
                                   input=data, capture_output=True, timeout=15, env=environment)
                self.assertEqual(p.returncode, 0, p.stderr.decode())

    def test_immutable_artifact_and_fresh_metadata(self):
        artifact = self.artifact(synthetic_plan(), {"new.txt": "hello\n"})
        first = artifact.to_dict()
        first["files"][0]["after"]["mode"] = "100755"
        self.assertEqual(artifact.to_dict()["files"][0]["after"]["mode"], "100644")
        with self.assertRaises(FrozenInstanceError):
            artifact.patch_bytes = b"different"

    def test_replacements_reject_noops_non_lf_controls_and_read_only_paths(self):
        plan = synthetic_plan(reads={"reference.txt": snapshot("reference\n")})
        for changes in ({}, {"target.txt": "old\n"}, {"new.txt": None}, {"reference.txt": "changed\n"},
                        {"target.txt": "missing LF"}, {"target.txt": "CRLF\r\n"},
                        {"target.txt": "null\0\n"}, {"target.txt": "\ud800"},
                        {"TARGET.txt": "alias\n"}, {"target.txt": "valid\n", "TARGET.txt": "alias\n"},
                        {"../escape": "bad\n"}, {".git/config": "bad\n"},
                        {"target.txt": 2}, {"target.txt": False}, {"target.txt": ["x"]}):
            with self.subTest(changes=changes):
                self.rejected(plan, changes)

    def test_closed_response_shape_digest_and_strict_json(self):
        plan = synthetic_plan()
        response = self.response(plan, {"new.txt": "ok\n"})
        for bad in (response | {"extra": True}, response | {"bundle_digest": "0" * 64},
                    {"changes": {}}, [], response | {"changes": {1: "x"}},
                    response | {"changes": {"new.txt": float("nan")}}):
            with self.subTest(bad=bad), self.assertRaises(TaskAlongError):
                validate_response(plan, bad)
        with self.assertRaises(TaskAlongError):
            loads('{"bundle_digest":"a","changes":{"new.txt":"one","new.txt":"two"}}')

    def test_plan_alias_and_hostile_unicode_fail_with_typed_errors(self):
        for outputs in ({"a": None, "A": None}, {"a": None, "a/b": None},
                        {".git/config": None}, {"\ud800": None}):
            with self.subTest(outputs=outputs), self.assertRaises(TaskAlongError):
                plan = synthetic_plan(outputs)
                self.artifact(plan, {"a": "new\n"})
        plan = synthetic_plan()
        plan["writable_outputs"]["target.txt"]["content"] = "\ud800"
        self.rejected(plan, {"new.txt": "ok\n"})

    def test_bounds_are_explicit_and_canonical_bytes_count(self):
        plan = synthetic_plan()
        response = self.response(plan, {"new.txt": "é\n"})
        size = len(canonical_bytes(response))
        artifact = validate_response(plan, response, max_proposal_bytes=size)
        self.rejected(plan, {"new.txt": "é\n"}, max_proposal_bytes=size - 1)
        self.rejected(plan, {"new.txt": "é\n"}, max_patch_bytes=len(artifact.patch_bytes) - 1)
        self.assertEqual(validate_response(plan, response, max_patch_bytes=len(artifact.patch_bytes)), artifact)
        for value in (0, -1, True, 1.5, 1048577):
            for key in ("max_proposal_bytes", "max_patch_bytes"):
                with self.subTest(key=key, value=value):
                    self.rejected(plan, {"new.txt": "ok\n"}, **{key: value})

    def test_small_unified_patch_changes_a_large_preimage(self):
        text = "unchanged long source line\n" * 5000 + "old\n"
        plan = synthetic_plan({"large.txt": snapshot(text)}, kind="unified-diff/1")
        patch = "--- a/large.txt\n+++ b/large.txt\n@@ -5001 +5001 @@ final line\n-old\n+new\n"
        artifact = self.artifact(plan, patch)
        self.assertGreater(len(text.encode()), 65536)
        self.assertLess(len(artifact.patch_bytes), 1024)
        after = artifact.to_dict()["files"][0]["after"]
        self.assertEqual(after["sha256"], hashlib.sha256((text[:-4] + "new\n").encode()).hexdigest())
        self.git_check(plan, artifact.patch_bytes)

    def test_diff_insert_delete_multiple_hunks_and_no_final_lf(self):
        plan = synthetic_plan({"target.txt": snapshot("a\nb\nc\nd\ne")}, kind="unified-diff/1")
        patch = ("--- a/target.txt\n+++ b/target.txt\n@@ -1,2 +1,3 @@\n a\n+inserted\n b\n"
                 "@@ -4,2 +5,1 @@\n d\n-e\n\\ No newline at end of file\n")
        artifact = self.artifact(plan, patch)
        self.assertEqual(artifact.to_dict()["files"][0]["after"]["sha256"], hashlib.sha256(b"a\ninserted\nb\nc\nd\n").hexdigest())
        self.git_check(plan, artifact.patch_bytes)
        no_lf = "--- a/target.txt\n+++ b/target.txt\n@@ -5 +5 @@\n-e\n\\ No newline at end of file\n+end\n\\ No newline at end of file\n"
        artifact = self.artifact(plan, no_lf)
        self.assertEqual(artifact.to_dict()["files"][0]["after"]["sha256"], hashlib.sha256(b"a\nb\nc\nd\nend").hexdigest())
        self.git_check(plan, artifact.patch_bytes)

    def test_diff_new_delete_and_empty_git_metadata(self):
        plan = synthetic_plan({"new.txt": None, "gone.txt": snapshot("gone\n"), "empty.txt": None,
                               "empty-gone.txt": snapshot("")}, kind="unified-diff/1")
        patch = ("--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+new\n"
                 "--- a/gone.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n"
                 "diff --git a/empty.txt b/empty.txt\nnew file mode 100644\nindex 0000000..e69de29\n"
                 "diff --git a/empty-gone.txt b/empty-gone.txt\ndeleted file mode 100644\nindex e69de29..0000000\n")
        artifact = self.artifact(plan, patch)
        self.assertEqual(len(artifact.to_dict()["files"]), 4)
        self.git_check(plan, artifact.patch_bytes)

    def test_diff_new_no_final_lf_and_zero_count_insertions(self):
        plan = synthetic_plan({"new.txt": None, "target.txt": snapshot("middle\n"),
                               "gone.txt": snapshot("last")}, kind="unified-diff/1")
        patch = ("--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+last\n\\ No newline at end of file\n"
                 "--- a/target.txt\n+++ b/target.txt\n@@ -0,0 +1 @@\n+first\n"
                 "@@ -1,0 +3 @@\n+end\n"
                 "--- a/gone.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-last\n\\ No newline at end of file\n")
        artifact = self.artifact(plan, patch)
        entries = {entry["path"]: entry for entry in artifact.to_dict()["files"]}
        self.assertEqual(entries["new.txt"]["after"]["sha256"], hashlib.sha256(b"last").hexdigest())
        self.assertEqual(entries["target.txt"]["after"]["sha256"],
                         hashlib.sha256(b"first\nmiddle\nend\n").hexdigest())
        self.assertIsNone(entries["gone.txt"]["after"])
        self.git_check(plan, artifact.patch_bytes)

    def test_generated_git_headers_round_trip_preserves_content_and_modes(self):
        outputs = {"target.txt": snapshot("old", "100755"), "new.txt": None, "gone.txt": snapshot("")}
        replacements = self.artifact(synthetic_plan(outputs), {"target.txt": "new\n", "new.txt": "", "gone.txt": None})
        plan = synthetic_plan(outputs, kind="unified-diff/1")
        artifact = self.artifact(plan, replacements.patch_bytes.decode())
        self.assertEqual(artifact.patch_bytes, replacements.patch_bytes)
        self.git_check(plan, artifact.patch_bytes)

    def test_diff_counts_context_positions_overlap_and_noop_rejected(self):
        plan = synthetic_plan({"target.txt": snapshot("a\nb\nc\n")}, kind="unified-diff/1")
        header = "--- a/target.txt\n+++ b/target.txt\n"
        for hunks in ("@@ -1,2 +1 @@\n-a\n+x\n", "@@ -1 +1 @@\n-wrong\n+x\n",
                      "@@ -0 +1 @@\n-a\n+x\n", "@@ -1 +2 @@\n-a\n+x\n",
                      "@@ -1 +1 @@\n-a\n+x\n@@ -1 +1 @@\n-a\n+y\n",
                      "@@ -2 +2 @@\n-b\n+x\n@@ -1 +1 @@\n-a\n+y\n",
                      "@@ -1,2 +1,2 @@\n a\n-b\n+x\n@@ -2 +2 @@\n-b\n+y\n",
                      "@@ -1 +1 @@\n a\n", "@@ -1 +1 @@\n-a\n+a\n",
                      "@@ -1 +1 @@\n-a\n+x\n\\ No newline at end of file\n",
                      "@@ -1,0 +1 @@\n+x\n", "@@ -1 +1 @@\n-a\n+x\n+overflow\n",
                      "@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+x\n",
                      "@@ -1,9999999 +1 @@\n-a\n+x\n"):
            with self.subTest(hunks=hunks):
                self.rejected(plan, header + hunks)

    def test_seeded_conventional_diffs_reconstruct_independently_known_results(self):
        rng = random.Random(41)
        for case in range(80):
            before = "".join(rng.choice(["a\n", "b\n", "é\n", "\n"])
                             for _ in range(rng.randrange(30)))
            after = before.splitlines(keepends=True)
            for _ in range(rng.randrange(1, 6)):
                offset = rng.randrange(len(after) + 1)
                after[offset:offset + rng.randrange(3)] = [rng.choice(["x\n", "y\n", "\n"])
                                                           for _ in range(rng.randrange(3))]
            after = "".join(after)
            if before == after:
                continue
            patch = "".join(difflib.unified_diff(before.splitlines(keepends=True),
                              after.splitlines(keepends=True), fromfile="a/target.txt", tofile="b/target.txt"))
            plan = synthetic_plan({"target.txt": snapshot(before)}, kind="unified-diff/1")
            with self.subTest(case=case):
                artifact = self.artifact(plan, patch)
                self.assertEqual(artifact.to_dict()["files"][0]["after"]["sha256"],
                                 hashlib.sha256(after.encode()).hexdigest())
                again = self.artifact(plan, artifact.patch_bytes.decode())
                self.assertEqual(again.patch_bytes, artifact.patch_bytes)
                if case % 17 == 0:
                    self.git_check(plan, artifact.patch_bytes)

    def test_diff_rejects_phantom_empty_lines_and_misplaced_newline_markers(self):
        plan = synthetic_plan({"new.txt": None}, kind="unified-diff/1")
        self.rejected(plan, "--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+\n\\ No newline at end of file\n")
        self.rejected(plan, "--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n\\ No newline at end of file\n+x\n")

    def test_diff_metadata_path_binary_partial_and_trailing_payload_rejected_atomically(self):
        plan = synthetic_plan(reads={"reference.txt": snapshot("reference\n")}, kind="unified-diff/1")
        valid = "--- a/target.txt\n+++ b/target.txt\n@@ -1 +1 @@\n-old\n+new\n"
        bad_patches = [valid + "trailing garbage\n", valid + "\n", valid + "--- a/new.txt\n",
                       valid + valid, valid.replace("target.txt", "../escape"),
                       valid.replace("target.txt", "reference.txt"), valid.replace("target.txt", "TARGET.txt"),
                       valid.replace("+++ b/target.txt", "+++ b/new.txt"),
                       "diff --git a/target.txt b/new.txt\n" + valid,
                       "diff --git a/target.txt b/target.txt\nold mode 100644\nnew mode 100755\n" + valid,
                       "diff --git a/target.txt b/target.txt\nnew file mode 100755\n" + valid,
                       "diff --git a/target.txt b/target.txt\nindex 1111111..2222222 100644\n" + valid,
                       "diff --git a/target.txt b/target.txt\nindex 1111111..2222222 120000\n" + valid,
                       "diff --git a/target.txt b/target.txt\nGIT binary patch\nliteral 0\n",
                       "diff --git a/target.txt b/target.txt\nsimilarity index 100%\nrename from target.txt\nrename to new.txt\n",
                       valid.replace("--- a/target.txt\n", "--- a/target.txt\t2026-01-01\n"),
                       valid.rstrip("\n"), "", valid + "\\ No newline at end of file\n\\ No newline at end of file\n"]
        original = copy.deepcopy(plan)
        for patch in bad_patches:
            with self.subTest(patch=patch):
                self.rejected(plan, patch)
                self.assertEqual(plan, original)
        self.rejected(plan, valid, max_proposal_bytes=30)
        self.rejected(plan, valid, max_patch_bytes=30)


if __name__ == "__main__":
    unittest.main()
