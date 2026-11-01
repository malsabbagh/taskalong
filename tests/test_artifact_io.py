"""Descriptor artifact boundaries on real disposable synthetic filesystem data."""
import hashlib
import errno
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from taskalong import artifact_io
from taskalong.artifact_io import apply_regular, read_regular, stage_regular
from taskalong.errors import TaskAlongError


class ArtifactIOTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.path = self.root / "value"
        self.payload = b"Synthetic approved artifact.\n"
        self.path.write_bytes(self.payload)
        self.path.chmod(0o600)
        self.sha = hashlib.sha256(self.payload).hexdigest()

    def read(self, **options):
        return read_regular(self.root, "value", max_bytes=len(self.payload),
                            expected_sha256=self.sha, expected_bytes=len(self.payload), **options)

    def test_parent_cleanup_attempts_all_descriptors_once_after_close_errors(self):
        for missing_root in (False, True):
            with self.subTest(missing_root=missing_root):
                real_open, real_close = artifact_io._open, os.close
                opened, attempted = [], []
                first = OSError(errno.EIO, "Synthetic close completed then failed")
                second = OSError(errno.EINTR, "Synthetic later close error")
                def opening(*args, **kwargs):
                    fd = real_open(*args, **kwargs)
                    opened.append(fd)
                    return fd
                def closing(fd):
                    attempted.append(fd)
                    real_close(fd)
                    if len(attempted) == 1:
                        raise first
                    if len(attempted) == 2:
                        raise second
                root = self.root / "missing" if missing_root else self.root
                with patch.object(artifact_io, "_open", side_effect=opening), \
                        patch.object(artifact_io.os, "close", side_effect=closing), \
                        self.assertRaises(OSError) as failure:
                    with artifact_io._parent(root, "value", private=True):
                        pass
                if missing_root:
                    self.assertIsInstance(failure.exception, FileNotFoundError)
                    self.assertIs(failure.exception.__cause__, first)
                else:
                    self.assertIs(failure.exception, first)
                self.assertGreater(len(opened), 1)
                self.assertEqual(attempted, list(reversed(opened)))
                self.assertEqual(len(attempted), len(set(attempted)))
                for fd in opened:
                    with self.assertRaises(OSError) as closed:
                        os.fstat(fd)
                    self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_body_failure_retains_type_and_outcome_when_cleanup_also_fails(self):
        primary = TaskAlongError("synthetic_validation_failure", "Synthetic evidence invalid.",
                                exit_code=4, effect_outcome="uncertain")
        real_close = os.close
        attempted = []
        cleanup = OSError(errno.EIO, "Synthetic cleanup failure")
        def closing(fd):
            attempted.append(fd)
            real_close(fd)
            if len(attempted) == 1:
                raise cleanup
        with patch.object(artifact_io.os, "close", side_effect=closing), \
                self.assertRaises(TaskAlongError) as failure:
            with artifact_io._parent(self.root, "value", private=True):
                raise primary
        self.assertIs(failure.exception, primary)
        self.assertIs(failure.exception.__cause__, cleanup)
        self.assertEqual(failure.exception.effect_outcome, "uncertain")
        self.assertEqual(failure.exception.code, "synthetic_validation_failure")
        self.assertGreater(len(attempted), 1)
        self.assertEqual(len(attempted), len(set(attempted)))
        for fd in attempted:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_add_absence_is_observational_and_refuses_existing_entries(self):
        artifact_io.require_absent(self.root,"missing/parent/leaf")
        self.assertFalse((self.root/"missing").exists())
        self.rejects(lambda:artifact_io.require_absent(self.root,"value"))
        (self.root/"link").symlink_to(self.root/"missing")
        self.rejects(lambda:artifact_io.require_absent(self.root,"link"))
        self.rejects(lambda:artifact_io.require_absent(self.root,"link/leaf"))
        self.rejects(lambda:artifact_io.require_absent(self.root/"absent-root","leaf"))

    def test_fresh_add_exclusive_creation_refuses_entry_after_absence_check(self):
        artifact_io.require_absent(self.root,"new")
        target=self.root/"new"
        target.write_bytes(self.payload)
        target.chmod(0o644)
        before=target.stat().st_mtime_ns
        self.rejects(lambda:apply_regular(self.root,"new",self.payload,before_sha256=None,before_bytes=None))
        self.assertEqual(target.read_bytes(),self.payload)
        self.assertEqual(target.stat().st_mtime_ns,before)

    def test_os_controlled_alias_prefixes_preserve_private_store_readback(self):
        from taskalong.store import Store
        selected = self.root
        for alias, destination in ((Path("/tmp"),Path("/private/tmp")),(Path("/var"),Path("/private/var"))):
            if alias.is_symlink() and self.root.is_relative_to(destination):
                selected = alias / self.root.relative_to(destination)
                break
        self.assertEqual(read_regular(selected,"value",max_bytes=len(self.payload),expected_sha256=self.sha),self.payload)
        with Store(selected/"state") as store:
            reference=store.put_blob(self.payload,media_type="text/plain")
            self.assertEqual(store.get_blob(reference["sha256"]),self.payload)

    def rejects(self, action, *, uncertain=False):
        with self.assertRaises(TaskAlongError) as failure:
            action()
        self.assertEqual(failure.exception.code, "artifact_file_invalid")
        self.assertEqual(failure.exception.effect_outcome, "uncertain" if uncertain else "not_sent")
        self.assertNotIn(str(self.root), failure.exception.message)
        return failure.exception

    def test_exact_owned_private_bytes_and_empty_text(self):
        self.assertEqual(self.read(private=True), self.payload)
        self.path.write_bytes(b"")
        self.assertEqual(read_regular(self.root, "value", max_bytes=0,
            expected_bytes=0, expected_sha256=hashlib.sha256(b"").hexdigest(), private=True), b"")

    def test_expected_size_and_hash_are_independent_constraints(self):
        self.rejects(lambda: read_regular(self.root, "value", max_bytes=100, expected_bytes=1))
        self.rejects(lambda: read_regular(self.root, "value", max_bytes=100, expected_sha256="0" * 64))
        self.assertEqual(read_regular(self.root, "value", max_bytes=len(self.payload)), self.payload)
        self.rejects(lambda: read_regular(self.root, "value", max_bytes=len(self.payload) - 1))

    def test_invalid_argument_types_and_paths_refuse(self):
        for relative in ("../value", "/value", "a/../value", "a//value", "a\\value",
                         ".git/config", "AGENTS.md", ".env", "value/", "", None):
            with self.subTest(relative=relative):
                self.rejects(lambda: read_regular(self.root, relative, max_bytes=100))
        for maximum in (-1, True, "100", 2**53):
            with self.subTest(maximum=maximum):
                self.rejects(lambda: read_regular(self.root, "value", max_bytes=maximum))
        for options in ({"expected_bytes":True}, {"expected_bytes":-1},
                        {"expected_bytes":101}, {"expected_sha256":"A" * 64}, {"private":1}):
            with self.subTest(options=options):
                self.rejects(lambda: read_regular(self.root, "value", max_bytes=100, **options))

    def test_missing_safe_platform_primitive_refuses_without_open(self):
        with patch.object(artifact_io.os, "O_NOFOLLOW", create=True) as missing:
            # Absence, not a value of zero, is the unsupported condition.
            del artifact_io.os.O_NOFOLLOW
            with patch.object(artifact_io, "_open") as opened:
                self.rejects(self.read)
                opened.assert_not_called()

    def test_static_symlink_hardlink_fifo_and_directory_refuse(self):
        outside = self.root / "outside"
        outside.write_bytes(self.payload)
        outside.chmod(0o600)
        self.path.unlink()
        self.path.symlink_to(outside)
        self.rejects(self.read)
        self.path.unlink()
        os.link(outside, self.path)
        self.rejects(self.read)
        self.path.unlink()
        os.mkfifo(self.path, mode=0o600)
        self.rejects(self.read)
        self.path.unlink()
        self.path.mkdir(mode=0o700)
        self.rejects(self.read)

    def test_symlinked_parent_and_symlinked_root_refuse(self):
        (self.root / "alias").symlink_to(self.root, target_is_directory=True)
        self.rejects(lambda: read_regular(self.root, "alias/value", max_bytes=100))
        self.rejects(lambda: read_regular(self.root / "alias", "value", max_bytes=100))

    def test_private_file_and_root_permissions_are_checked(self):
        self.path.chmod(0o644)
        self.assertEqual(self.read(), self.payload)
        self.rejects(lambda: self.read(private=True))
        self.path.chmod(0o600)
        self.root.chmod(0o755)
        self.rejects(lambda: self.read(private=True))

    def test_staged_consumption_requires_exact_read_only_mode(self):
        self.path.chmod(0o400)
        self.assertEqual(self.read(private=True,expected_mode=0o400),self.payload)
        self.path.chmod(0o600)
        with patch.object(artifact_io,"_read") as reader:
            self.rejects(lambda:self.read(private=True,expected_mode=0o400))
            reader.assert_not_called()
        # Private-only remains a separate, intentionally less restrictive check.
        self.assertEqual(self.read(private=True),self.payload)

    def test_exact_mode_is_rechecked_after_read_and_invalid_modes_refuse(self):
        self.path.chmod(0o400)
        original = artifact_io._read
        changed = []

        def chmod_after_read(descriptor,size):
            raw = original(descriptor,size)
            if not changed:
                self.path.chmod(0o600)
                changed.append(True)
            return raw

        with patch.object(artifact_io,"_read",side_effect=chmod_after_read):
            self.rejects(lambda:self.read(private=True,expected_mode=0o400))
        for mode in (False,-1,0o10000,"400",[]):
            with self.subTest(mode=mode):
                self.rejects(lambda:self.read(expected_mode=mode))

    def test_matching_symlink_swap_before_leaf_open_is_never_followed(self):
        outside = self.root / "outside"
        outside.write_bytes(self.payload)
        outside.chmod(0o600)
        original = artifact_io._open
        substituted = []

        def replace(name, flags, *arguments, **options):
            if name == "value" and options.get("dir_fd") is not None:
                self.path.unlink()
                self.path.symlink_to(outside)
                substituted.append(True)
            return original(name, flags, *arguments, **options)

        with patch.object(artifact_io, "_open", side_effect=replace), patch.object(artifact_io, "_read") as reader:
            self.rejects(self.read)
            reader.assert_not_called()
        self.assertEqual(substituted, [True])
        self.assertEqual(outside.read_bytes(), self.payload)

    def test_matching_hardlink_swap_before_leaf_open_refuses(self):
        outside = self.root / "outside"
        outside.write_bytes(self.payload)
        outside.chmod(0o600)
        original = artifact_io._open

        def replace(name, flags, *arguments, **options):
            if name == "value" and options.get("dir_fd") is not None:
                self.path.unlink()
                os.link(outside, self.path)
            return original(name, flags, *arguments, **options)

        with patch.object(artifact_io, "_open", side_effect=replace), patch.object(artifact_io, "_read") as reader:
            self.rejects(self.read)
            reader.assert_not_called()

    def test_replacement_after_descriptor_open_cannot_supply_alternate_bytes(self):
        original = artifact_io._read
        observed = []

        def replace(descriptor, size):
            if not observed:
                self.path.unlink()
                self.path.write_bytes(b"different synthetic bytes")
            raw = original(descriptor, size)
            observed.append(raw)
            return raw

        with patch.object(artifact_io, "_read", side_effect=replace):
            self.rejects(self.read)
        self.assertEqual(b"".join(observed), self.payload)

    def test_same_size_write_and_new_hardlink_during_read_refuse(self):
        original = artifact_io._read
        for alteration in (lambda: self.path.write_bytes(b"x" * len(self.payload)),
                           lambda: os.link(self.path, self.root / "alias")):
            with self.subTest(alteration=alteration):
                self.path.write_bytes(self.payload)
                altered = []

                def changed(descriptor, size):
                    raw = original(descriptor, size)
                    if not altered:
                        alteration()
                        altered.append(True)
                    return raw

                with patch.object(artifact_io, "_read", side_effect=changed):
                    self.rejects(self.read)

    def test_growing_file_read_is_bounded_to_cap_plus_one(self):
        original = artifact_io._read
        requests = []
        altered = []

        def grow(descriptor, size):
            if not altered:
                with self.path.open("ab") as output:
                    output.write(b"x" * 1000)
                altered.append(True)
            requests.append(size)
            return original(descriptor, size)

        with patch.object(artifact_io, "_read", side_effect=grow):
            self.rejects(self.read)
        self.assertEqual(sum(requests), len(self.payload) + 1)

    def test_directory_replacement_during_read_refuses(self):
        folder = self.root / "inputs"
        folder.mkdir(mode=0o700)
        self.path.rename(folder / "value")
        original = artifact_io._read
        altered = []

        def replace(descriptor, size):
            raw = original(descriptor, size)
            if not altered:
                folder.rename(self.root / "retained")
                folder.mkdir(mode=0o700)
                (folder / "value").write_bytes(self.payload)
                altered.append(True)
            return raw

        with patch.object(artifact_io, "_read", side_effect=replace):
            self.rejects(lambda: read_regular(self.root, "inputs/value", max_bytes=100))

    def test_staging_creates_private_fresh_copies_and_empty_text(self):
        stage_regular(self.root, "inputs/0000", self.payload, expected_sha256=self.sha)
        target = self.root / "inputs" / "0000"
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o700)
        self.assertNotEqual(target.stat().st_ino, self.path.stat().st_ino)
        self.assertEqual(read_regular(self.root, "inputs/0000", max_bytes=100, private=True), self.payload)
        stage_regular(self.root, "inputs/0001", b"", expected_sha256=hashlib.sha256(b"").hexdigest())
        self.assertEqual(read_regular(self.root, "inputs/0001", max_bytes=0, private=True), b"")

    def test_staging_cannot_overwrite_existing_file_or_follow_links(self):
        self.rejects(lambda: stage_regular(self.root, "value", self.payload, expected_sha256=self.sha))
        self.assertEqual(self.path.read_bytes(), self.payload)
        alias = self.root / "alias"
        alias.symlink_to(self.path)
        self.rejects(lambda: stage_regular(self.root, "alias", self.payload, expected_sha256=self.sha))
        self.assertTrue(alias.is_symlink())
        parent = self.root / "inputs"
        parent.symlink_to(self.root, target_is_directory=True)
        self.rejects(lambda: stage_regular(self.root, "inputs/other", self.payload, expected_sha256=self.sha))
        self.assertFalse((self.root / "other").exists())

    def test_staging_wrong_hash_mode_and_mutable_data_refuse_before_effects(self):
        for data, sha, mode in ((self.payload, "0" * 64, 0o400), (self.payload, self.sha, 0o644),
                                (bytearray(self.payload), self.sha, 0o400)):
            with self.subTest(mode=mode, data_type=type(data)):
                self.rejects(lambda: stage_regular(self.root, "inputs/0000", data,
                    expected_sha256=sha, mode=mode))
                self.assertFalse((self.root / "inputs").exists())

    def test_staging_partial_write_reports_uncertainty_and_preserves_bytes(self):
        original = artifact_io._write
        calls = []

        def interrupted(descriptor, payload):
            if calls:
                raise OSError("synthetic private detail must not escape")
            calls.append(True)
            return original(descriptor, payload[:3])

        with patch.object(artifact_io, "_write", side_effect=interrupted):
            error = self.rejects(lambda: stage_regular(self.root, "partial", self.payload,
                expected_sha256=self.sha), uncertain=True)
        self.assertEqual((self.root / "partial").read_bytes(), self.payload[:3])
        self.assertNotIn("synthetic private detail", error.message)

    def test_patch_exact_modify_and_empty_replacement_preserve_inode_and_mode(self):
        self.path.chmod(0o644)
        before = self.path.stat()
        apply_regular(self.root, "value", b"short", before_sha256=self.sha,
                      before_bytes=len(self.payload))
        self.assertEqual(self.path.read_bytes(), b"short")
        self.assertEqual(self.path.stat().st_ino, before.st_ino)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o644)
        apply_regular(self.root, "value", b"", before_sha256=hashlib.sha256(b"short").hexdigest(),
                      before_bytes=5)
        self.assertEqual(self.path.read_bytes(), b"")

    def test_patch_fresh_add_and_executable_modification(self):
        apply_regular(self.root, "new/added", self.payload, before_sha256=None, before_bytes=None)
        self.assertEqual((self.root / "new/added").read_bytes(), self.payload)
        self.assertEqual(stat.S_IMODE((self.root / "new/added").stat().st_mode), 0o644)
        self.path.chmod(0o755)
        apply_regular(self.root, "value", b"replacement", before_sha256=self.sha,
                      before_bytes=len(self.payload), mode="100755")
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o755)

    def test_patch_wrong_before_hash_size_mode_and_add_collision_leave_bytes(self):
        self.path.chmod(0o644)
        cases = ({"before_sha256":"0" * 64,"before_bytes":len(self.payload)},
                 {"before_sha256":self.sha,"before_bytes":1},
                 {"before_sha256":self.sha,"before_bytes":len(self.payload),"mode":"100755"},
                 {"before_sha256":None,"before_bytes":None})
        for options in cases:
            with self.subTest(options=options):
                self.rejects(lambda: apply_regular(self.root, "value", b"after", **options))
                self.assertEqual(self.path.read_bytes(), self.payload)
                self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o644)

    def test_patch_allow_after_requires_exact_bytes_and_mode(self):
        self.path.chmod(0o644)
        with patch.object(artifact_io, "_write") as writer:
            apply_regular(self.root, "value", self.payload, before_sha256="0" * 64,
                          before_bytes=1, allow_after=True)
            writer.assert_not_called()
        with patch.object(artifact_io, "_write") as writer:
            apply_regular(self.root, "value", self.payload, before_sha256=None,
                          before_bytes=None, allow_after=True)
            writer.assert_not_called()
        self.rejects(lambda: apply_regular(self.root, "value", b"different", before_sha256=None,
                                          before_bytes=None, allow_after=True))
        self.assertEqual(self.path.read_bytes(), self.payload)

    def test_patch_invalid_envelope_refuses_before_creating_directories(self):
        for options in ({"before_sha256":None,"before_bytes":0},
                        {"before_sha256":None,"before_bytes":None,"mode":"100755"},
                        {"before_sha256":self.sha,"before_bytes":True},
                        {"before_sha256":self.sha,"before_bytes":len(self.payload),"allow_after":1},
                        {"before_sha256":self.sha,"before_bytes":len(self.payload),"mode":None},
                        {"before_sha256":self.sha,"before_bytes":len(self.payload),"mode":[]}):
            with self.subTest(options=options):
                self.rejects(lambda: apply_regular(self.root, "new/added", self.payload, **options))
                self.assertFalse((self.root / "new").exists())

    def test_patch_path_replacement_during_write_preserves_foreign_entry(self):
        self.path.chmod(0o644)
        original = artifact_io._write
        writes = []
        retained = self.root / "retained"
        foreign = b"foreign synthetic file must not be overwritten"

        def replaced(descriptor, payload):
            if not writes:
                self.path.rename(retained)
                self.path.write_bytes(foreign)
                self.path.chmod(0o644)
            writes.append(True)
            return original(descriptor, payload)

        with patch.object(artifact_io, "_write", side_effect=replaced):
            self.rejects(lambda: apply_regular(self.root, "value", b"approved replacement",
                before_sha256=self.sha, before_bytes=len(self.payload)), uncertain=True)
        self.assertEqual(self.path.read_bytes(), foreign)
        self.assertEqual(retained.read_bytes(), b"approved replacement")

    def test_patch_partial_write_keeps_partial_bytes_and_uncertainty(self):
        self.path.chmod(0o644)
        original = artifact_io._write
        writes = []

        def interrupted(descriptor, payload):
            if writes:
                raise OSError("private write error")
            writes.append(True)
            return original(descriptor, payload[:3])

        with patch.object(artifact_io, "_write", side_effect=interrupted):
            self.rejects(lambda: apply_regular(self.root, "value", b"approved replacement",
                before_sha256=self.sha, before_bytes=len(self.payload)), uncertain=True)
        self.assertEqual(self.path.read_bytes(), b"app" + self.payload[3:])

    def test_patch_symlink_hardlink_and_parent_link_cannot_receive_writes(self):
        self.path.chmod(0o644)
        target = self.root / "outside"
        self.path.rename(target)
        self.path.symlink_to(target)
        self.rejects(lambda: apply_regular(self.root, "value", b"after", before_sha256=self.sha,
                                          before_bytes=len(self.payload)))
        self.assertEqual(target.read_bytes(), self.payload)
        self.path.unlink()
        os.link(target, self.path)
        self.rejects(lambda: apply_regular(self.root, "value", b"after", before_sha256=self.sha,
                                          before_bytes=len(self.payload)))
        self.assertEqual(target.read_bytes(), self.payload)
        (self.root / "alias").symlink_to(self.root, target_is_directory=True)
        self.rejects(lambda: apply_regular(self.root, "alias/added", b"after",
                                          before_sha256=None, before_bytes=None))
        self.assertFalse((self.root / "added").exists())


if __name__ == "__main__":
    unittest.main()
