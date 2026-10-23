"""Distribution audits reject unexpected bytes and unsafe archive members."""
from __future__ import annotations

import importlib.util
import base64
import csv
import gzip
import hashlib
import io
import json
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location("taskalong_distribution_auditor", Path(__file__).resolve().parents[1] / "tools" / "check_dist.py")
auditor = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(auditor)
_QUALIFIER_SPEC = importlib.util.spec_from_file_location("taskalong_installed_qualifier", Path(__file__).resolve().parents[1] / "tools" / "qualify_installed.py")
qualifier = importlib.util.module_from_spec(_QUALIFIER_SPEC)
_QUALIFIER_SPEC.loader.exec_module(qualifier)


class DistributionTests(unittest.TestCase):
    def test_fresh_environment_interpreter_and_pip_start(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "venv"
            python = qualifier.create_environment(target)
            result = subprocess.run(
                [python, "-I", "-c", "import sys,pip;print(sys.prefix);print(pip.__file__)"],
                env=qualifier.clean_environment(), capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            prefix, pip_path = result.stdout.strip().splitlines()
            self.assertEqual(Path(prefix).resolve(), target.resolve())
            self.assertTrue(Path(pip_path).resolve().is_relative_to(target.resolve()))

    def test_sdist_normalization_preserves_payload_and_is_reproducible(self):
        tool = Path(__file__).resolve().parents[1] / "tools" / "normalize_sdist.py"
        payload = b"synthetic package content\n"
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ("first.tar.gz", "second.tar.gz")]
            for index, path in enumerate(paths, 1):
                with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
                    folder = tarfile.TarInfo("taskalong-0.1.0a1")
                    folder.type = tarfile.DIRTYPE
                    folder.uid, folder.uname = index, "synthetic-builder"
                    archive.addfile(folder)
                    item = tarfile.TarInfo("taskalong-0.1.0a1/synthetic.py")
                    item.size, item.mode = len(payload), 0o644
                    item.uid = item.gid = item.mtime = index
                    item.uname, item.gname = "synthetic-builder", "synthetic-group"
                    item.pax_headers = {"atime": str(index), "SCHILY.xattr.user.fixture": "synthetic"}
                    archive.addfile(item, io.BytesIO(payload))
                result = subprocess.run([sys.executable, str(tool), str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(auditor.read_sdist(path), {"synthetic.py": payload})
                with tarfile.open(path, "r:gz") as archive:
                    self.assertEqual(archive.getmember("taskalong-0.1.0a1/synthetic.py").mode, 0o644)
            self.assertEqual(paths[0].read_bytes(), paths[1].read_bytes())
            before = paths[0].read_bytes()
            result = subprocess.run([sys.executable, str(tool), str(paths[0])], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(paths[0].read_bytes(), before)

    def test_invalid_sdist_normalization_keeps_input_and_never_extracts(self):
        tool = Path(__file__).resolve().parents[1] / "tools" / "normalize_sdist.py"
        cases = (("taskalong-0.1.0a1/../../outside", tarfile.REGTYPE),
                 ("taskalong-0.1.0a1/link", tarfile.SYMTYPE),
                 ("unexpected-root/synthetic.py", tarfile.REGTYPE))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "untrusted.tar.gz"
            for name, kind in cases:
                with self.subTest(name=name, kind=kind):
                    with tarfile.open(path, "w:gz") as archive:
                        item = tarfile.TarInfo(name)
                        item.type, item.linkname = kind, "../../outside"
                        archive.addfile(item, io.BytesIO() if item.isfile() else None)
                    before = path.read_bytes()
                    result = subprocess.run([sys.executable, str(tool), str(path)], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(path.read_bytes(), before)
                    self.assertEqual({p.name for p in root.iterdir()}, {path.name})

    def test_sdist_rejects_build_machine_metadata(self):
        cases = ({"uid": 123}, {"gid": 123}, {"uname": "synthetic-builder"},
                 {"gname": "synthetic-group"}, {"mtime": 123},
                 {"pax_headers": {"ctime": "123"}})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "untrusted.tar.gz"
            for fields in cases:
                with self.subTest(fields=tuple(fields)):
                    raw = io.BytesIO()
                    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
                        item = tarfile.TarInfo("taskalong-0.1.0a1/synthetic.py")
                        for key, value in fields.items():
                            setattr(item, key, value)
                        archive.addfile(item, io.BytesIO())
                    path.write_bytes(gzip.compress(raw.getvalue(), mtime=0))
                    with self.assertRaises(auditor.AuditError):
                        auditor.read_sdist(path)

    def test_sdist_rejects_gzip_name_comment_and_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "untrusted.tar.gz"
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode="w") as archive:
                archive.addfile(tarfile.TarInfo("taskalong-0.1.0a1/synthetic.py"), io.BytesIO())
            for filename, mtime in (("synthetic-builder.tar", 0), ("", 123)):
                with self.subTest(filename=filename, mtime=mtime):
                    compressed = io.BytesIO()
                    with gzip.GzipFile(filename=filename, fileobj=compressed, mode="wb", mtime=mtime) as stream:
                        stream.write(raw.getvalue())
                    path.write_bytes(compressed.getvalue())
                    with self.assertRaises(auditor.AuditError):
                        auditor.read_sdist(path)
            compressed = bytearray(gzip.compress(raw.getvalue(), mtime=0))
            compressed[3] |= 16  # A valid optional gzip comment, independent of tar contents.
            path.write_bytes(bytes(compressed[:10]) + b"synthetic-builder\0" + bytes(compressed[10:]))
            with self.assertRaises(auditor.AuditError):
                auditor.read_sdist(path)

    def test_wheel_rejects_comment_and_extra_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "untrusted.whl"
            for field in ("archive-comment", "member-comment", "extra"):
                with self.subTest(field=field):
                    with zipfile.ZipFile(path, "w") as archive:
                        item = zipfile.ZipInfo("taskalong/synthetic.py")
                        if field == "archive-comment":
                            archive.comment = b"synthetic-builder"
                        elif field == "member-comment":
                            item.comment = b"synthetic-builder"
                        else:
                            item.extra = b"\xfe\xca\x04\x00test"
                        archive.writestr(item, b"")
                    with self.assertRaises(auditor.AuditError):
                        auditor.read_wheel(path)

    def test_metadata_rejects_unapproved_contact_and_source_urls(self):
        metadata = (b"Name: taskalong\nVersion: 0.1.0a1\nRequires-Python: >=3.11,<3.15\n"
                    b"Requires-Dist: jsonschema<5,>=4.26\n"
                    b'Requires-Dist: review-sensei==0.8.8; extra == "review"\n'
                    b"Provides-Extra: review\nLicense-Expression: MIT\nLicense-File: LICENSE\n")
        auditor._metadata(metadata)
        for field in ("Author", "Author-email", "Maintainer", "Maintainer-email", "Home-page", "Project-URL", "Download-URL"):
            with self.subTest(field=field), self.assertRaises(auditor.AuditError):
                auditor._metadata(metadata + field.encode() + b": synthetic@example.invalid\n")

    def test_metadata_rejects_missing_substituted_and_duplicate_license_fields(self):
        metadata = (b"Name: taskalong\nVersion: 0.1.0a1\nRequires-Python: >=3.11,<3.15\n"
                    b"Requires-Dist: jsonschema<5,>=4.26\n"
                    b'Requires-Dist: review-sensei==0.8.8; extra == "review"\n'
                    b"Provides-Extra: review\nLicense-Expression: MIT\nLicense-File: LICENSE\n")
        auditor._metadata(metadata)
        cases = (metadata.replace(b"License-Expression: MIT\n", b""),
                 metadata.replace(b"License-Expression: MIT", b"License-Expression: Apache-2.0"),
                 metadata + b"License-Expression: MIT\n",
                 metadata.replace(b"License-File: LICENSE", b"License-File: NOTICE"),
                 metadata + b"License-File: LICENSE\n",
                 metadata + b"License: MIT\n")
        for data in cases:
            with self.subTest(data=data), self.assertRaises(auditor.AuditError):
                auditor._metadata(data)

    def test_archive_paths_are_literal_and_contained(self):
        for path in ("../outside", "/outside", "a/../../b", "a//b", "a\\b", "C:/outside", "a/./b", "a\0b"):
            with self.subTest(path=path), self.assertRaises(auditor.AuditError):
                auditor.checked_name(path)
        self.assertEqual(auditor.checked_name("taskalong/resources/templates/worker.txt"), "taskalong/resources/templates/worker.txt")

    def test_wheel_rejects_symlinks_executables_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "untrusted.whl"
            for mode in (stat.S_IFLNK | 0o777, stat.S_IFREG | 0o755):
                with zipfile.ZipFile(path, "w") as archive:
                    item = zipfile.ZipInfo("taskalong/unsafe")
                    item.external_attr = mode << 16
                    archive.writestr(item, "../../outside")
                with self.assertRaises(auditor.AuditError):
                    auditor.read_wheel(path)
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(zipfile.ZipInfo("taskalong/safe.py"), "first")
                # Duplicate ZIP members have platform-dependent extraction behavior.
                with self.assertWarns(UserWarning):
                    archive.writestr(zipfile.ZipInfo("taskalong/safe.py"), "second")
            with self.assertRaises(auditor.AuditError):
                auditor.read_wheel(path)

    def test_sdist_never_follows_link_or_root_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "untrusted.tar.gz"
            for name, kind in (("taskalong-0.1.0a1/linked", tarfile.SYMTYPE), ("taskalong-0.1.0a1/../outside", tarfile.REGTYPE), ("wrong-root/a", tarfile.REGTYPE)):
                with tarfile.open(path, "w:gz") as archive:
                    item = tarfile.TarInfo(name)
                    item.type = kind
                    item.linkname = "../../outside"
                    item.size = 0
                    archive.addfile(item, io.BytesIO())
                with self.assertRaises(auditor.AuditError):
                    auditor.read_sdist(path)

    def test_exact_inventory_does_not_accept_extra_file(self):
        with self.assertRaises(auditor.AuditError):
            auditor._exact({"taskalong/__init__.py", "taskalong/auth.json"}, {"taskalong/__init__.py"}, "wheel")

    def test_record_tampering_and_self_hash_are_rejected(self):
        body = b"synthetic package bytes"
        module_name = "taskalong/__init__.py"
        record_name = f"{auditor.DIST_INFO}/RECORD"
        encoded = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
        stream = io.StringIO()
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerows([(module_name, "sha256=" + encoded, str(len(body))), (record_name, "", "")])
        files = {module_name: body, record_name: stream.getvalue().encode()}
        auditor._record(files)
        files[module_name] = b"changed bytes"
        with self.assertRaises(auditor.AuditError):
            auditor._record(files)
        files[module_name] = body
        files[record_name] = files[record_name].replace((record_name + ",,").encode(), (record_name + ",sha256=forged,1").encode())
        with self.assertRaises(auditor.AuditError):
            auditor._record(files)

    def test_checked_inventory_exists_and_has_no_patterns(self):
        root = Path(__file__).resolve().parents[1]
        inventory = auditor.load_inventory(root)
        self.assertTrue(inventory["wheel_sources"])
        self.assertTrue(all("*" not in p for p in inventory["sdist_sources"]))
        for forbidden in ("tests/", "tools/", ".agents/", ".codex/", "docs/"):
            self.assertFalse(any(p.startswith(forbidden) for p in inventory["wheel_sources"]))

    def test_rebuilding_input_cannot_relabel_qualified_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "taskalong-0.1.0a1-py3-none-any.whl"
            source.write_bytes(b"first artifact bytes")
            snapshots = root / "private-snapshots"
            snapshots.mkdir(mode=0o700)
            copied, observed_hash = qualifier.snapshot_artifact(source, snapshots)
            source.write_bytes(b"replacement artifact bytes")
            self.assertEqual(copied.read_bytes(), b"first artifact bytes")
            self.assertEqual(observed_hash, hashlib.sha256(copied.read_bytes()).hexdigest())
            self.assertNotEqual(observed_hash, hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(copied.stat().st_mode & 0o777, 0o600)

    def test_harness_lock_and_fixtures_cannot_drift_during_install(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            root.mkdir()
            files = {"tools/qualify_installed.py": b"synthetic harness", "requirements-dev.lock": b"first lock",
                     "tests/test_example.py": b"first test", "tests/fixtures/fake_codex.py": b"first codex",
                     "tests/fixtures/fake_gh.py": b"first gh"}
            for relative, data in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            (root / "distribution-inventory.json").write_text(json.dumps({"sdist_sources": sorted(files)}))
            work = Path(directory) / "first"
            work.mkdir()
            original_digest = qualifier.snapshot_harness(root, work)
            (root / "requirements-dev.lock").write_bytes(b"replacement lock")
            (root / "tests/test_example.py").write_bytes(b"replacement test")
            self.assertEqual((work / "requirements-dev.lock").read_bytes(), b"first lock")
            self.assertEqual((work / "installed-tests/test_example.py").read_bytes(), b"first test")
            replacement = Path(directory) / "second"
            replacement.mkdir()
            self.assertNotEqual(original_digest, qualifier.snapshot_harness(root, replacement))


if __name__ == "__main__":
    unittest.main()
