#!/usr/bin/env python3
"""Audit distributions against the reviewed file-by-file inventory.

This utility reads archives without extracting them. It neither installs packages
nor executes archive members. Its JSON receipt contains names and hashes only.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import stat
import sys
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

NAME = "taskalong"
VERSION = "0.1.0a1"
DIST_INFO = f"{NAME}-{VERSION}.dist-info"
EGG_INFO = f"src/{NAME}.egg-info"
WHEEL_METADATA = {f"{DIST_INFO}/{p}" for p in ("METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD")}
SDIST_GENERATED = {"PKG-INFO", "setup.cfg"} | {f"{EGG_INFO}/{p}" for p in ("PKG-INFO", "SOURCES.txt", "dependency_links.txt", "entry_points.txt", "requires.txt", "top_level.txt")}
WHEEL_METADATA.add(f"{DIST_INFO}/licenses/LICENSE")
APPROVED_LICENSE_SHA256 = "eebd1b34e94e652cda6426b07244e2f851896f40e8a3831e5a678be256ac746b"
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 4 * 1024 * 1024


class AuditError(ValueError):
    """An archive differs from the exact approved package inventory."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_name(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise AuditError("invalid archive member name")
    path = PurePosixPath(value)
    if path.is_absolute() or any(p in ("", ".", "..") for p in value.split("/")) or ":" in value:
        raise AuditError("archive path escape")
    return value


def load_inventory(root: Path) -> dict[str, list[str]]:
    value = json.loads((root / "distribution-inventory.json").read_text(encoding="utf-8"))
    if set(value) != {"format_version", "wheel_sources", "sdist_sources"} or value["format_version"] != 1:
        raise AuditError("unsupported distribution inventory")
    for key in ("wheel_sources", "sdist_sources"):
        paths = value[key]
        if not isinstance(paths, list) or paths != sorted(set(paths)):
            raise AuditError("inventory lists must be unique and sorted")
        for path in paths:
            checked_name(path)
            if any(c in path for c in "*?["):
                raise AuditError("inventory must enumerate files, not patterns")
            source = root / path
            if not source.is_file() or source.is_symlink():
                raise AuditError(f"inventory source missing or symlink: {path}")
            if any(parent.is_symlink() for parent in source.parents if parent != root and root in parent.parents):
                raise AuditError(f"inventory source traverses a symlink: {path}")
    if not set(value["wheel_sources"]).issubset(value["sdist_sources"]):
        raise AuditError("sdist must contain every wheel source")
    if any(not p.startswith("src/taskalong/") for p in value["wheel_sources"]):
        raise AuditError("wheel source outside package")
    return value


def _bounded_file(path: Path) -> None:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise AuditError("archive missing, symlinked, or oversized")


def read_wheel(path: Path) -> dict[str, bytes]:
    _bounded_file(path)
    result: dict[str, bytes] = {}
    with zipfile.ZipFile(path) as archive:
        if archive.comment:
            raise AuditError("unapproved wheel archive metadata")
        for item in archive.infolist():
            if item.comment or item.extra:
                raise AuditError("unapproved wheel member metadata")
            if item.is_dir():
                raise AuditError("wheel directory entries are outside the exact inventory")
            name = checked_name(item.filename)
            mode = item.external_attr >> 16
            if name in result or stat.S_ISLNK(mode) or mode & 0o111 or item.file_size > MAX_MEMBER_BYTES:
                raise AuditError("duplicate, symlink, executable, or oversized wheel member")
            result[name] = archive.read(item)
    if sum(map(len, result.values())) > MAX_ARCHIVE_BYTES:
        raise AuditError("expanded wheel exceeds limit")
    return result


def read_sdist(path: Path) -> dict[str, bytes]:
    _bounded_file(path)
    with path.open("rb") as stream:
        header = stream.read(10)
    if len(header) != 10 or header[:4] != b"\x1f\x8b\x08\x00" or header[4:8] != b"\x00" * 4:
        raise AuditError("sdist gzip metadata is not normalized")
    result: dict[str, bytes] = {}
    directories: set[str] = set()
    expected_root = f"{NAME}-{VERSION}/"
    with tarfile.open(path, "r:gz") as archive:
        for item in archive:
            if (item.uid != 0 or item.gid != 0 or item.uname or item.gname or item.mtime != 0
                    or set(item.pax_headers) - {"path"}):
                raise AuditError("sdist owner or timestamp metadata is not normalized")
            if item.isdir():
                if item.name != expected_root.rstrip("/"):
                    if not item.name.startswith(expected_root):
                        raise AuditError("unexpected sdist directory root")
                    directories.add(checked_name(item.name[len(expected_root):].rstrip("/")))
                continue
            if not item.isfile() or item.issym() or item.islnk() or item.size > MAX_MEMBER_BYTES:
                raise AuditError("non-regular or oversized sdist member")
            if not item.name.startswith(expected_root):
                raise AuditError("unexpected sdist root")
            name = checked_name(item.name[len(expected_root):])
            if name in result:
                raise AuditError("duplicate sdist member")
            # Test-only fake tools may be executable; package sources may not.
            if item.mode & 0o111 and not name.startswith(("tests/fixtures/", "tools/")):
                raise AuditError("unexpected executable sdist member")
            stream = archive.extractfile(item)
            if stream is None:
                raise AuditError("unreadable sdist member")
            result[name] = stream.read(MAX_MEMBER_BYTES + 1)
    if sum(map(len, result.values())) > MAX_ARCHIVE_BYTES:
        raise AuditError("expanded sdist exceeds limit")
    ancestors = {str(parent) for name in result for parent in PurePosixPath(name).parents if str(parent) != "."}
    if not directories.issubset(ancestors):
        raise AuditError("sdist contains a directory outside the exact file inventory")
    return result


def _exact(actual: set[str], expected: set[str], label: str) -> None:
    if actual != expected:
        raise AuditError(f"{label} inventory mismatch: missing={sorted(expected-actual)}, unexpected={sorted(actual-expected)}")


def _metadata(data: bytes) -> None:
    metadata = BytesParser().parsebytes(data)
    if any(metadata.get_all(field) for field in ("Author", "Author-email", "Maintainer", "Maintainer-email",
                                                "Home-page", "Project-URL", "Download-URL")):
        raise AuditError("distribution identity/contact/source metadata is not approved")
    if metadata.get("Name") != NAME or metadata.get("Version") != VERSION:
        raise AuditError("incorrect distribution identity")
    if metadata.get("Requires-Python") != ">=3.11,<3.15" and metadata.get("Requires-Python") != "<3.15,>=3.11":
        raise AuditError("unexpected Python contract")
    if (metadata.get_all("License") or metadata.get_all("License-Expression") != ["MIT"]
            or metadata.get_all("License-File") != ["LICENSE"]):
        raise AuditError("license metadata differs from the approved MIT notice")
    if any("Operating System" in c or "License ::" in c for c in metadata.get_all("Classifier", [])):
        raise AuditError("unqualified platform/license classifier")
    requirements = metadata.get_all("Requires-Dist", [])
    if set(requirements) != {"jsonschema<5,>=4.26", 'review-sensei==0.8.8; extra == "review"'} or len(requirements) != 2:
        raise AuditError("runtime dependency contract differs from the qualified inventory")
    if metadata.get_all("Provides-Extra", []) != ["review"]:
        raise AuditError("unexpected package extras")


def _record(files: dict[str, bytes]) -> None:
    record_name = f"{DIST_INFO}/RECORD"
    rows = list(csv.reader(io.StringIO(files[record_name].decode("utf-8"))))
    if any(len(row) != 3 for row in rows) or len(rows) != len(files):
        raise AuditError("wheel RECORD shape mismatch")
    _exact({row[0] for row in rows}, set(files), "RECORD")
    if len({row[0] for row in rows}) != len(rows):
        raise AuditError("duplicate wheel RECORD entry")
    for name, encoded, size in rows:
        if name == record_name:
            if encoded or size:
                raise AuditError("RECORD self hash must be empty")
            continue
        expected = base64.urlsafe_b64encode(hashlib.sha256(files[name]).digest()).rstrip(b"=").decode("ascii")
        if encoded != f"sha256={expected}" or size != str(len(files[name])):
            raise AuditError("wheel RECORD integrity mismatch")


def audit(path: Path, *, root: Path, inventory: dict | None = None) -> dict:
    inventory = load_inventory(root) if inventory is None else inventory
    if path.name.endswith(".whl"):
        if path.name != f"{NAME}-{VERSION}-py3-none-any.whl":
            raise AuditError("unexpected wheel filename or compatibility tag")
        files = read_wheel(path)
        expected = {p.removeprefix("src/") for p in inventory["wheel_sources"]} | WHEEL_METADATA
        _exact(set(files), expected, "wheel")
        _metadata(files[f"{DIST_INFO}/METADATA"])
        if files[f"{DIST_INFO}/entry_points.txt"].decode("utf-8").strip() != "[console_scripts]\ntaskalong = taskalong.cli:main":
            raise AuditError("unexpected console entry points")
        if files[f"{DIST_INFO}/top_level.txt"].decode().strip() != NAME:
            raise AuditError("unexpected top-level package")
        if b"Root-Is-Purelib: true" not in files[f"{DIST_INFO}/WHEEL"]:
            raise AuditError("wheel must be pure Python")
        if sha256(files[f"{DIST_INFO}/licenses/LICENSE"]) != APPROVED_LICENSE_SHA256:
            raise AuditError("wheel license differs from the approved MIT notice")
        _record(files)
        mappings = {p.removeprefix("src/"): p for p in inventory["wheel_sources"]}
        artifact = "wheel"
    elif path.name.endswith(".tar.gz"):
        if path.name != f"{NAME}-{VERSION}.tar.gz":
            raise AuditError("unexpected sdist filename")
        files = read_sdist(path)
        _exact(set(files), set(inventory["sdist_sources"]) | SDIST_GENERATED, "sdist")
        _metadata(files["PKG-INFO"])
        _metadata(files[f"{EGG_INFO}/PKG-INFO"])
        source_list = files[f"{EGG_INFO}/SOURCES.txt"].decode("utf-8").splitlines()
        _exact(set(source_list), set(inventory["sdist_sources"]) | (SDIST_GENERATED - {"PKG-INFO", "setup.cfg"}), "sdist source mapping")
        mappings = {p: p for p in inventory["sdist_sources"]}
        artifact = "sdist"
    else:
        raise AuditError("unsupported distribution archive")
    if sha256((root / "LICENSE").read_bytes()) != APPROVED_LICENSE_SHA256:
        raise AuditError("source license differs from the approved MIT notice")
    for member, source in mappings.items():
        if files[member] != (root / source).read_bytes():
            raise AuditError(f"archive source differs from checkout: {source}")
    return {"artifact": artifact, "file": path.name, "sha256": sha256(path.read_bytes()), "bytes": path.stat().st_size,
            "members": [{"path": name, "sha256": sha256(data), "bytes": len(data)} for name, data in sorted(files.items())]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        inventory = load_inventory(args.root)
        archives = sorted(args.dist_dir.glob("*.whl")) + sorted(args.dist_dir.glob("*.tar.gz"))
        if len(archives) != 2 or len(list(args.dist_dir.iterdir())) != 2:
            raise AuditError("dist directory must contain exactly one wheel and one sdist")
        receipts = [audit(p, root=args.root, inventory=inventory) for p in archives]
        print(json.dumps({"kind": "distribution_audit", "format_version": 1, "ok": True, "artifacts": receipts}, sort_keys=True))
        return 0
    except (AuditError, OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(json.dumps({"kind": "distribution_audit", "format_version": 1, "ok": False, "error": str(error)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
