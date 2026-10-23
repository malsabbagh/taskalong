#!/usr/bin/env python3
"""Remove build-machine ownership and timestamps from a bounded sdist.

Repack regular files/directories without extraction. Payload bytes and modes are
preserved; Git history and source text are outside this metadata normalization.
Run the exact distribution auditor separately after normalization.
"""
from __future__ import annotations

import argparse
import gzip
import io
import os
from pathlib import Path
import tarfile
import tempfile

from check_dist import AuditError, MAX_ARCHIVE_BYTES, MAX_MEMBER_BYTES, checked_name, read_sdist


def normalize(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise AuditError("sdist must be a regular file")
    with path.open("rb") as stream:
        original = stream.read(MAX_ARCHIVE_BYTES + 1)
    if len(original) > MAX_ARCHIVE_BYTES:
        raise AuditError("compressed sdist exceeds limit")
    entries = []
    names = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(original), mode="r:gz") as archive:
        for item in archive:
            name = checked_name(item.name.rstrip("/") if item.isdir() else item.name)
            if name in names or len(names) >= 4096:
                raise AuditError("duplicate or excessive sdist members")
            names.add(name)
            if not (item.isfile() or item.isdir()) or item.size > MAX_MEMBER_BYTES:
                raise AuditError("non-regular or oversized sdist member")
            data = b""
            if item.isfile():
                source = archive.extractfile(item)
                if source is None:
                    raise AuditError("unreadable sdist member")
                data = source.read(MAX_MEMBER_BYTES + 1)
                total += len(data)
                if len(data) != item.size or total > MAX_ARCHIVE_BYTES:
                    raise AuditError("expanded sdist exceeds limit")
            clean = tarfile.TarInfo(name)
            clean.type = tarfile.DIRTYPE if item.isdir() else tarfile.REGTYPE
            clean.mode = item.mode & 0o777
            clean.size = len(data)
            entries.append((clean, data))
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".normalized-sdist-", dir=path.parent, delete=False) as output:
            temporary = Path(output.name)
            with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for item, data in sorted(entries, key=lambda entry: entry[0].name):
                        archive.addfile(item, io.BytesIO(data) if item.isfile() else None)
            output.flush()
            os.fsync(output.fileno())
        read_sdist(temporary)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="+", type=Path)
    args = parser.parse_args()
    for path in args.archives:
        normalize(path)
    print(f"Normalized {len(args.archives)} source archive(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
