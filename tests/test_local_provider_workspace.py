"""Disposable owned Git snapshots only; no native provider, account or State."""
import copy
import errno
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong import local_provider_workspace as owned
from taskalong.local_provider_tasks import prepare_task
from taskalong.validation import canonical_bytes, digest
from test_local_provider_artifacts import snapshot, synthetic_plan


@unittest.skipUnless(os.name == "posix" and shutil.which("git", path=os.defpath), "Existing POSIX Git required")
class OwnedProviderWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.workspace = self.root / "owned workspace é"
        self.control = self.root / "control space λ"
        self.workspace.mkdir(mode=0o700)
        self.control.mkdir(mode=0o700)
        self.plan = synthetic_plan({"src/target.py": snapshot("old, no final LF"),
            "src/new.py": None, "tools/script.sh": snapshot("Never execute this snapshot.\n", "100755")},
            reads={"docs/reference.txt": snapshot("Synthetic public reference.\n")})

    def prepare(self, plan=None):
        return owned.prepare_owned_workspace(self.plan if plan is None else plan,
            workspace=self.workspace, control_root=self.control)

    def verify(self, receipt, plan=None):
        return owned.verify_owned_workspace(self.plan if plan is None else plan,
            workspace=self.workspace, receipt=receipt)

    def git(self, root, *args):
        executable = shutil.which("git", path=os.defpath)
        result = subprocess.run([executable, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
            "-C", str(root), *args], capture_output=True, timeout=15,
            env=owned._env(self.control), check=True)
        return result.stdout

    def overwrite(self, relative, data, mode=0o400):
        path = self.workspace / relative
        path.chmod(0o600)
        path.write_bytes(data)
        path.chmod(mode)

    def test_exact_selected_files_form_a_distinct_private_git_snapshot(self):
        receipt = self.prepare()
        self.assertIsNone(self.verify(receipt))
        files = {str(path.relative_to(self.workspace)) for path in self.workspace.rglob("*")
                 if path.is_file() and ".git" not in path.relative_to(self.workspace).parts}
        self.assertEqual(files, {"docs/reference.txt", "src/target.py", "tools/script.sh"})
        self.assertFalse((self.workspace / "src/new.py").exists())
        self.assertEqual((self.workspace / "src/target.py").read_bytes(), b"old, no final LF")
        self.assertEqual(stat.S_IMODE((self.workspace / "src/target.py").stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE((self.workspace / "tools/script.sh").stat().st_mode), 0o500)
        self.assertEqual(self.git(self.workspace, "rev-parse", "--is-inside-work-tree").strip(), b"true")
        self.assertEqual(self.git(self.workspace, "rev-parse", "HEAD").strip().decode(), receipt["head"])
        self.assertEqual(self.git(self.workspace, "rev-parse", "HEAD^{tree}").strip().decode(), receipt["tree"])
        self.assertEqual(self.git(self.workspace, "status", "--porcelain=v1"), b"")
        self.assertNotEqual(receipt["source_base_commit"], receipt["head"])
        self.assertEqual(receipt["source_base_commit"], self.plan["base_commit"])
        self.assertEqual(receipt["plan_digest"], self.plan["digest"])
        self.assertEqual(receipt["digest"], digest(receipt))
        self.assertLess(len(canonical_bytes(receipt)), 65536)
        self.assertEqual(receipt["files"]["docs/reference.txt"]["role"], "read_context")
        self.assertEqual(receipt["files"]["src/new.py"]["snapshot"], None)
        # Root may persist the receipt beside its already-existing control files.
        (self.control / "workspace.json").write_bytes(canonical_bytes(receipt))
        self.assertIsNone(self.verify(receipt))

    def test_aggregate_git_setup_deadline_refuses_before_another_child(self):
        with patch.object(owned, "_clock", side_effect=(0, 121)), \
                patch.object(owned, "run_bounded") as child, self.assertRaises(TaskAlongError):
            self.prepare()
        child.assert_not_called()

    def test_git_setup_and_validation_share_the_same_aggregate_deadline(self):
        clock = [0]
        calls = []
        real = owned.run_bounded
        def child(*args, **kwargs):
            calls.append(kwargs["timeout_seconds"])
            result = real(*args, **kwargs)
            clock[0] += 14
            return result
        with patch.object(owned, "_clock", side_effect=lambda: clock[0]), \
                patch.object(owned, "run_bounded", side_effect=child), self.assertRaises(TaskAlongError):
            self.prepare()
        self.assertLessEqual(len(calls), 9)
        self.assertLess(calls[-1], 15)

    def test_last_hash_cannot_bless_prior_git_config_changed_during_inventory(self):
        receipt = self.prepare()
        script = (self.workspace / "tools/script.sh").stat()
        config = self.workspace / ".git/config"
        real_read = os.read
        changed = []
        def reading(fd, maximum):
            data = real_read(fd, maximum)
            info = os.fstat(fd)
            if data and (info.st_dev, info.st_ino) == (script.st_dev, script.st_ino) and not changed:
                config.chmod(0o600)
                config.write_text("[core]\n hooksPath = /outside/hostile\n")
                config.chmod(0o400)
                changed.append(True)
            return data
        with patch.object(owned.os, "read", side_effect=reading), self.assertRaises(TaskAlongError):
            self.verify(receipt)
        self.assertEqual(changed, [True])

    def test_cleanup_closes_all_descriptors_once_and_preserves_primary_failure(self):
        descriptors = [os.open(os.devnull, os.O_RDONLY) for _ in range(3)]
        original = tuple(descriptors)
        attempted = []
        real_close = os.close
        first = OSError(errno.EIO, "Synthetic close completed then failed")
        primary = TaskAlongError("synthetic_workspace_failure", "Synthetic invalid snapshot.")
        def closing(fd):
            attempted.append(fd)
            real_close(fd)
            if len(attempted) == 1:
                raise first
        with patch.object(owned.os, "close", side_effect=closing), self.assertRaises(TaskAlongError) as caught:
            try:
                raise primary
            finally:
                owned._close_all_once(descriptors)
        self.assertIs(caught.exception, primary)
        self.assertIs(caught.exception.__cause__, first)
        self.assertEqual(attempted, list(reversed(original)))
        self.assertEqual(descriptors, [])
        for fd in original:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_unsupported_quoted_unicode_paths_refuse_before_git(self):
        for path in ('"leading.txt', 'dir/with"quote.txt', 'unicode-é.txt'):
            with self.subTest(path=path), patch.object(owned, "run_bounded") as child, self.assertRaises(TaskAlongError):
                self.prepare(synthetic_plan({path: snapshot("Public snapshot.\n")}))
            child.assert_not_called()

    def test_null_only_plan_has_an_empty_committed_snapshot(self):
        plan = synthetic_plan({"new/only.py": None})
        receipt = self.prepare(plan)
        self.assertIsNone(self.verify(receipt, plan))
        self.assertEqual(self.git(self.workspace, "ls-tree", "-r", "HEAD"), b"")
        self.assertFalse((self.workspace / "new").exists())

    def test_actual_source_repository_is_observed_but_never_copied_or_changed(self):
        source = self.root / "toy source"
        source.mkdir(mode=0o700)
        self.git(source, "init", "--template=", "-b", "main")
        (source / "selected.txt").write_text("selected synthetic source\n")
        (source / "unselected.txt").write_text("Unselected synthetic extra.\n")
        self.git(source, "add", "--", "selected.txt", "unselected.txt")
        self.git(source, "commit", "-m", "Synthetic source")
        head = self.git(source, "rev-parse", "HEAD").strip().decode()
        before = {str(path.relative_to(source)): path.read_bytes() for path in source.rglob("*") if path.is_file()}
        with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}):
            plan = prepare_task(source, base_commit=head, task="Synthetic owned snapshot.", provider="codex",
                model="synthetic-model", reasoning_effort="high", read_paths=["selected.txt"], writable_paths=["new.txt"])
        receipt = self.prepare(plan)
        self.assertIsNone(self.verify(receipt, plan))
        after = {str(path.relative_to(source)): path.read_bytes() for path in source.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        self.assertFalse((self.workspace / "unselected.txt").exists())
        self.assertNotEqual(receipt["head"], head)
        self.assertEqual(receipt["source_base_commit"], head)
        self.assertEqual(stat.S_IMODE((source / "selected.txt").stat().st_mode), 0o644)

    def test_global_config_hooks_templates_filters_and_ambient_git_env_are_ignored(self):
        marker = self.root / "must-not-run"
        evil = self.root / "evil"
        evil.mkdir(mode=0o700)
        script = evil / "git"
        script.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\nexit 91\n")
        script.chmod(0o700)
        hooks = evil / "hooks"
        hooks.mkdir()
        shutil.copyfile(script, hooks / "pre-commit")
        (hooks / "pre-commit").chmod(0o700)
        template = evil / "template"
        template.mkdir()
        (template / "unexpected").write_text("Never copy this template.\n")
        config = evil / "global-config"
        config.write_text(f'[core]\n hooksPath = {hooks}\n fsmonitor = {script}\n[filter "hostile"]\n clean = {script}\n[commit]\n gpgSign = true\n[gpg]\n program = {script}\n[init]\n templateDir = {template}\n')
        env = {"PATH": str(evil), "HOME": str(evil), "XDG_CONFIG_HOME": str(evil),
            "GIT_DIR": str(evil), "GIT_WORK_TREE": str(evil), "GIT_INDEX_FILE": str(evil / "index"),
            "GIT_OBJECT_DIRECTORY": str(evil), "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(evil),
            "GIT_CONFIG_GLOBAL": str(config), "GIT_CONFIG_SYSTEM": str(config), "GIT_TEMPLATE_DIR": str(template),
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.hooksPath", "GIT_CONFIG_VALUE_0": str(hooks),
            "GIT_CONFIG_PARAMETERS": "'core.fsmonitor=bad'", "GIT_SSH_COMMAND": str(script)}
        plan = synthetic_plan({"-literal.txt": snapshot("raw LF\n"), ".gitattributes": snapshot("* filter=hostile text eol=crlf\n"), "new.txt": None})
        with patch.dict(os.environ, env):
            receipt = self.prepare(plan)
            self.assertIsNone(self.verify(receipt, plan))
        self.assertFalse(marker.exists())
        self.assertFalse((self.workspace / ".git/hooks").exists())
        self.assertFalse((self.workspace / ".git/unexpected").exists())
        self.assertFalse((self.workspace / ".git/objects/info/alternates").exists())
        self.assertNotIn(b"remote", (self.workspace / ".git/config").read_bytes())
        self.assertEqual(self.git(self.workspace, "show", "HEAD:-literal.txt"), b"raw LF\n")
        self.assertEqual(self.git(self.workspace, "show", "-s", "--format=%an:%ae", "HEAD").strip(),
                         b"TaskAlong Snapshot:snapshot@example.invalid")
        self.assertFalse((evil / "index").exists())

    def test_initial_extra_files_gitfiles_and_symlinks_refuse_before_git(self):
        for kind in ("extra", "gitfile", "symlink"):
            with self.subTest(kind=kind):
                path = self.workspace / ("extra" if kind == "extra" else ".git")
                if kind == "symlink":
                    path.symlink_to(self.control, target_is_directory=True)
                else:
                    path.write_text("gitdir: " + str(self.control) + "\n")
                with patch.object(owned, "run_bounded", side_effect=AssertionError("Git must not start")), self.assertRaises(TaskAlongError):
                    self.prepare()
                path.unlink()
        alias = self.root / "alias"
        alias.symlink_to(self.workspace, target_is_directory=True)
        with self.assertRaises(TaskAlongError):
            owned.prepare_owned_workspace(self.plan, workspace=alias, control_root=self.control)
        with self.assertRaises(TaskAlongError):
            owned.prepare_owned_workspace(self.plan, workspace=self.workspace, control_root=self.workspace)

    def test_file_content_mode_inode_and_read_only_reference_tampering_refuse(self):
        for kind in ("content", "reference", "mode", "inode", "hardlink", "extra", "new-output", "empty-dir"):
            with self.subTest(kind=kind):
                self.workspace = self.root / ("work-" + kind)
                self.workspace.mkdir(mode=0o700)
                receipt = self.prepare()
                target = self.workspace / "src/target.py"
                if kind in ("content", "reference"):
                    self.overwrite("docs/reference.txt" if kind == "reference" else "src/target.py", b"changed\n")
                elif kind == "mode":
                    target.chmod(0o600)
                elif kind in ("inode", "hardlink"):
                    target.parent.chmod(0o700)
                    replacement = self.root / ("replacement-" + kind)
                    replacement.write_bytes(target.read_bytes())
                    replacement.chmod(0o400)
                    target.unlink()
                    if kind == "hardlink":
                        os.link(replacement, target)
                    else:
                        replacement.rename(target)
                    target.parent.chmod(0o500)
                else:
                    self.workspace.chmod(0o700)
                    if kind == "new-output":
                        (self.workspace / "src").chmod(0o700)
                        (self.workspace / "src/new.py").write_text("unexpected\n")
                    elif kind == "empty-dir":
                        (self.workspace / "unexpected").mkdir(mode=0o700)
                    else:
                        (self.workspace / "unexpected").write_text("unexpected\n")
                with patch.object(owned, "run_bounded", side_effect=AssertionError("Changed state must precede Git")), self.assertRaises(TaskAlongError):
                    self.verify(receipt)

    def test_git_metadata_tampering_and_external_git_directory_refuse_before_git(self):
        for kind in ("config", "head", "object", "symlink", "replacement"):
            with self.subTest(kind=kind):
                self.workspace = self.root / ("git-" + kind)
                self.workspace.mkdir(mode=0o700)
                receipt = self.prepare()
                if kind == "config":
                    self.overwrite(".git/config", b'[remote "forbidden"]\n url=/outside\n')
                elif kind == "head":
                    self.overwrite(".git/HEAD", b"ref: refs/heads/foreign\n")
                elif kind == "object":
                    name = next(path for path in receipt["inventory"] if path.startswith(".git/objects/") and receipt["inventory"][path]["kind"] == "file")
                    self.overwrite(name, b"invalid object")
                else:
                    self.workspace.chmod(0o700)
                    old = self.root / ("old-git-" + kind)
                    (self.workspace / ".git").chmod(0o700)
                    (self.workspace / ".git").rename(old)
                    if kind == "symlink":
                        (self.workspace / ".git").symlink_to(old, target_is_directory=True)
                    else:
                        shutil.copytree(old, self.workspace / ".git")
                with patch.object(owned, "run_bounded", side_effect=AssertionError("Changed Git metadata must not be interpreted")), self.assertRaises(TaskAlongError):
                    self.verify(receipt)

    def test_tampered_receipts_and_changed_plan_are_not_authority(self):
        receipt = self.prepare()
        broken = copy.deepcopy(receipt)
        broken["digest"] = "0" * 64
        with self.assertRaises(TaskAlongError):
            self.verify(broken)
        for change in ({"unknown": True}, {"head": "0" * 40},
                       {"plan_digest": "0" * 64}, {"git": {"path": "/outside", "sha256": "0" * 64}}):
            value = copy.deepcopy(receipt) | change
            value["digest"] = digest(value)
            with self.subTest(change=change), self.assertRaises(TaskAlongError):
                self.verify(value)
        changed = copy.deepcopy(self.plan)
        changed["task"] = "A different synthetic task."
        from taskalong.local_provider_tasks import _intent
        changed["intent_digest"] = _intent(changed)
        changed["digest"] = digest(changed)
        forged = copy.deepcopy(receipt)
        forged.update(plan_digest=changed["digest"], intent_digest=changed["intent_digest"])
        forged["digest"] = digest(forged)
        with self.assertRaises(TaskAlongError):
            self.verify(forged, changed)
        self.assertIsNone(self.verify(receipt))

    def test_git_binary_identity_is_rechecked_without_executing_a_changed_tool(self):
        receipt = self.prepare()
        identity = copy.deepcopy(receipt["git"])
        identity["sha256"] = "0" * 64
        with patch.object(owned, "_git_identity", return_value=identity), \
                patch.object(owned, "run_bounded", side_effect=AssertionError("Changed tool must not start")), self.assertRaises(TaskAlongError):
            self.verify(receipt)

    def test_partial_preparation_is_preserved_and_never_replayed(self):
        with patch.object(owned, "run_bounded", side_effect=owned.ProcessBoundaryError("Synthetic local Git failure")), self.assertRaises(TaskAlongError):
            self.prepare()
        self.assertEqual((self.workspace / "src/target.py").read_bytes(), b"old, no final LF")
        with patch.object(owned, "run_bounded", side_effect=AssertionError("Partial workspace must not be retried")), self.assertRaises(TaskAlongError):
            self.prepare()


if __name__ == "__main__":
    unittest.main()
