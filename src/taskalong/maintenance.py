"""Private quiescent maintenance; no external-effect rollback or admission."""
from __future__ import annotations

import functools
import hashlib
import ctypes
import errno
from contextlib import closing, contextmanager
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
from importlib.resources import files

from .errors import TaskAlongError
from .store import _private, initialization_guard, now, key_check, encode
from .validation import canonical_bytes, digest, loads, validate, validate_versioned

_BACKUP = "backup-manifest.json"
_RESTORE = "restore-receipt.json"
_QUARANTINE = "taskalong.restore-quarantine"
_MAX_BYTES = 512 * 1024 * 1024
_MAX_FILES = 10000
_SQLITE_AUX = ("state.sqlite3-wal", "state.sqlite3-shm", "state.sqlite3-journal")


def _failure(code, message):
    return TaskAlongError(code, message, exit_code=70)


def _path(value):
    path = Path(os.path.abspath(value))
    for component in (path, *path.parents):
        if component.is_symlink() and component not in (Path("/tmp"), Path("/var")):
            raise _failure("unsafe_state_path", "Maintenance paths cannot traverse symbolic links.")
    # Only OS-controlled aliases survive the component checks above. Normalize
    # them before containment checks; otherwise /var and its canonical spelling
    # can describe the same control directory with different lexical parents.
    return path.resolve(strict=False)


def _overlap(first, second):
    first, second = _path(first), _path(second)
    if first == second or first in second.parents or second in first.parents:
        return True
    # Existing directory identity also catches case aliases on filesystems that
    # preserve spelling while comparing names without case sensitivity.
    try:
        for root, other in ((first,second),(second,first)):
            if root.exists() and any(parent.exists() and root.samefile(parent) for parent in (other,*other.parents)):
                return True
    except OSError as exc:
        raise _failure("maintenance_path_unproven", "Directory separation cannot be proved; preserve the selected paths.") from exc
    return False


def _relative(value):
    # Control captures (including instruction files) are private data. Task-scope
    # protected-name rules must not silently omit them from a complete backup.
    if (type(value) is not str or not value or len(value.encode()) > 4096 or not value.isprintable()
            or value.startswith("/") or "\\" in value or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise _failure("backup_integrity", "A control inventory path is not a bounded literal relative path.")
    return value


def _sync(directory):
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def _file(path, destination=None):
    _private(path, directory=False)
    sha, count = hashlib.sha256(), 0
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    output = None
    try:
        if destination is not None:
            out = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
            output = os.fdopen(out, "wb")
        with os.fdopen(fd, "rb") as source:
            fd = None
            before = os.fstat(source.fileno())
            while chunk := source.read(1024 * 1024):
                count += len(chunk)
                if count > _MAX_BYTES:
                    raise _failure("backup_limits", "Complete maintenance exceeds its bounded byte budget.")
                sha.update(chunk)
                if output is not None:
                    output.write(chunk)
            after = os.fstat(source.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino) or count != after.st_size:
                raise _failure("backup_changed", "A private control file changed during maintenance.")
        if output is not None:
            os.fchmod(output.fileno(), stat.S_IMODE(before.st_mode))
            output.flush()
            os.fsync(output.fileno())
    finally:
        if fd is not None:
            os.close(fd)
        if output is not None:
            output.close()
    return {"size_bytes": count, "sha256": sha.hexdigest(), "mode": stat.S_IMODE(before.st_mode)}


def _coordination(relative):
    return relative in {"initialize.lock", "maintenance.lock"} or (relative.startswith("guards/") and relative.endswith(".lock"))


def _inventory(root, *, destination=None, exclude=()):
    directories, records, omitted = [], [], []
    entries = 0
    def walk(directory, depth=0):
        nonlocal entries
        if depth > 64:
            raise _failure("backup_limits", "Control inventory nesting exceeds its bounded depth.")
        _private(directory, directory=True)
        for path in sorted(directory.iterdir()):
            entries += 1
            if entries > _MAX_FILES:
                raise _failure("backup_limits", "Control inventory exceeds its bounded item count.")
            relative = str(path.relative_to(root))
            if relative in exclude:
                _private(path, directory=False, optional_ephemeral=relative in _SQLITE_AUX)
                continue
            if path.is_dir() and not path.is_symlink():
                _private(path, directory=True)
                directories.append({"path":relative, "mode":stat.S_IMODE(path.stat().st_mode)})
                if destination is not None:
                    (destination / relative).mkdir(mode=0o700)
                walk(path, depth + 1)
                continue
            _private(path, directory=False)
            if _coordination(relative):
                if path.stat().st_size != 0:
                    raise _failure("backup_control_unsupported", "Coordination files must be empty; preserve unexpected metadata.")
                omitted.append(relative)
                continue
            records.append({"path": relative, **_file(path, destination / relative if destination is not None else None)})
            if len(records) > _MAX_FILES or sum(item["size_bytes"] for item in records) > _MAX_BYTES:
                raise _failure("backup_limits", "Complete maintenance exceeds its bounded inventory budget.")
    walk(root)
    return sorted(directories, key=lambda item:item["path"]), sorted(records, key=lambda item:item["path"]), sorted(omitted)


def _rows(rows):
    value, count = hashlib.sha256(), 0
    for row in rows:
        encoded = canonical_bytes(list(row))
        value.update(len(encoded).to_bytes(8, "big"))
        value.update(encoded)
        count += 1
    return {"rows": count, "sha256": value.hexdigest()}


def database_state(db):
    if [tuple(row) for row in db.execute("PRAGMA integrity_check")] != [("ok",)]:
        raise _failure("backup_integrity", "SQLite integrity verification failed.")
    if db.execute("PRAGMA foreign_key_check").fetchall():
        raise _failure("backup_integrity", "SQLite foreign-key verification failed.")
    metadata = dict(db.execute("SELECT key,value FROM metadata"))
    version = db.execute("PRAGMA user_version").fetchone()[0]
    if version not in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11) or metadata.get("format_version") != str(version):
        raise _failure("store_integrity", "Store schema markers disagree.")
    schema = [list(row) for row in db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]
    tables = {}
    for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"):
        quoted = '"' + name.replace('"', '""') + '"'
        columns = [row[1] for row in db.execute("PRAGMA table_info(" + quoted + ")")]
        order = ",".join(str(i + 1) for i in range(len(columns)))
        tables[name] = {"columns": columns, **_rows(db.execute("SELECT * FROM " + quoted + " ORDER BY " + order))}
    return {"user_version": version, "format_version": metadata["format_version"], "store_uuid": metadata["store_uuid"],
            "application": metadata["application"], "schema_sha256": digest(schema), "tables": tables}


@contextmanager
def _read_db(path):
    _private(path, directory=False)
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA query_only=ON")
    try:
        yield db
    finally:
        db.close()


def create_backup(store, destination):
    require_quiescent(store)
    target = _path(destination)
    if _overlap(store.root, target):
        raise _failure("backup_target", "Complete backups must be outside the source control directory.")
    try:
        target.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise _failure("backup_exists", "A complete backup destination must be new; preserve existing artifacts.") from exc
    try:
        if (store.root / _BACKUP).exists() or (store.root / _RESTORE).exists():
            raise _failure("backup_control_unsupported", "Unexpected maintenance metadata requires reconciliation.")
        store.backup(target / "state.sqlite3")
        directories, records, omitted = _inventory(store.root, destination=target,
            exclude=("state.sqlite3", *_SQLITE_AUX))
        records.append({"path":"state.sqlite3", **_file(target / "state.sqlite3")})
        with _read_db(target / "state.sqlite3") as db:
            snapshot = database_state(db)
            available = {item["path"]:item for item in records}
            for sha, size in db.execute("SELECT sha256,bytes FROM blobs"):
                row = available.get("blobs/" + sha)
                if row is None or row["sha256"] != sha or row["size_bytes"] != size:
                    raise _failure("backup_blob_integrity", "A referenced blob is missing or changed; preserve the source and incomplete backup.")
            registered = {row[0] for row in db.execute("SELECT sha256 FROM blobs")}
            for row in db.execute("SELECT document FROM evidence"):
                evidence = validate("evidence", loads(row[0]))
                for reference in evidence["artifacts"]:
                    item = available.get("blobs/" + reference["sha256"])
                    if (reference["sha256"] not in registered or item is None or item["sha256"] != reference["sha256"]
                            or item["size_bytes"] != reference["bytes"]):
                        raise _failure("backup_blob_integrity", "A core evidence reference has no matching registered blob.")
            if sum(item["size_bytes"] for item in records) > _MAX_BYTES:
                raise _failure("backup_limits", "The complete database and control payload exceed the byte budget.")
        if snapshot != database_state(store.db):
            raise _failure("backup_changed", "The database snapshot does not match the exclusive source.")
        manifest = {"kind":"taskalong_complete_backup", "format_version":1, "store_uuid":store.store_uuid, "created_at":now(),
                    "database":snapshot, "directories":directories, "files":sorted(records, key=lambda item:item["path"]),
                    "omitted_coordination":sorted([*omitted, *_SQLITE_AUX])}
        manifest["digest"] = digest(manifest)
        for directory in reversed(directories):
            os.chmod(target / directory["path"], directory["mode"])
            _sync(target / directory["path"])
        _write(target / _BACKUP, canonical_bytes(manifest))
        _sync(target)
        _sync(target.parent)
        verify_backup(target, expected_digest=manifest["digest"])
        return manifest
    except (OSError, sqlite3.Error) as exc:
        raise _failure("backup_io", "Complete backup failed; preserve its partial destination and original store.") from exc


def verify_backup(directory, *, expected_digest):
    root = _path(directory)
    _private(root, directory=True)
    _private(root / _BACKUP, directory=False)
    try:
        manifest = loads((root / _BACKUP).read_bytes())
        keys = {"kind","format_version","store_uuid","created_at","database","directories","files","omitted_coordination","digest"}
        if (set(manifest) != keys or manifest["kind"] != "taskalong_complete_backup" or type(manifest["format_version"]) is not int
                or manifest["format_version"] != 1 or digest(manifest) != expected_digest or manifest["digest"] != expected_digest
                or any(type(manifest[key]) is not list for key in ("directories","files","omitted_coordination"))):
            raise _failure("backup_integrity", "The complete backup manifest does not match its trusted identity.")
        for name in manifest["omitted_coordination"]:
            _relative(name)
        for item in manifest["directories"]:
            if set(item) != {"path","mode"}:
                raise _failure("backup_integrity", "The backup directory inventory is invalid.")
            _relative(item["path"])
        for item in manifest["files"]:
            if set(item) != {"path","size_bytes","sha256","mode"}:
                raise _failure("backup_integrity", "The backup inventory is invalid.")
            _relative(item["path"])
        directories, records, omitted = _inventory(root, exclude=(_BACKUP,))
        if omitted or directories != manifest["directories"] or records != manifest["files"]:
            raise _failure("backup_integrity", "Backup files, types, permissions or content differ from the manifest.")
        with _read_db(root / "state.sqlite3") as db:
            observed = database_state(db)
        if observed != manifest["database"] or observed["application"] != "taskalong" or observed["store_uuid"] != manifest["store_uuid"]:
            raise _failure("backup_integrity", "The backup database does not match its complete row/schema manifest.")
        return manifest
    except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
        raise _failure("backup_integrity", "The complete private backup cannot be verified.") from exc


def _publish_restore(stage, target):
    # Plain rename can replace an existing empty directory. Refuse if the local
    # platform/filesystem cannot provide an atomic no-replace directory rename.
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        rename = libc.renamex_np
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        arguments = (os.fsencode(stage), os.fsencode(target), 0x00000004)  # RENAME_EXCL
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        rename = libc.renameat2
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        arguments = (-100, os.fsencode(stage), -100, os.fsencode(target), 1)  # AT_FDCWD, RENAME_NOREPLACE
    else:
        raise _failure("restore_publication_unsupported", "Atomic no-replace directory publication is unavailable.")
    rename.restype = ctypes.c_int
    if rename(*arguments) != 0:
        number = ctypes.get_errno()
        if number in (errno.EEXIST, errno.ENOTEMPTY):
            raise _failure("restore_exists", "Restore cannot replace an existing directory.")
        if number in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
            raise _failure("restore_publication_unsupported", "This filesystem cannot prove atomic no-replace publication.")
        raise OSError(number, os.strerror(number))


def _quarantine_stage(stage, store_uuid):
    # Before the first payload copy, give even an unpublished partial stage a
    # canonical foreign application tag that predecessor clients understand.
    path = stage / "state.sqlite3"
    _write(path, b"")
    with closing(sqlite3.connect(path, isolation_level=None)) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        db.executemany("INSERT INTO metadata VALUES(?,?)", (("store_uuid",store_uuid), ("format_version","1"), ("application",_QUARANTINE)))
        db.execute("PRAGMA user_version=1")
        db.commit()
    with path.open("rb") as output:
        os.fsync(output.fileno())
    _sync(stage)


def restore_backup(directory, destination, *, expected_digest):
    manifest = verify_backup(directory, expected_digest=expected_digest)
    source, target = _path(directory), _path(destination)
    if target.exists():
        raise _failure("restore_exists", "Restore requires a fresh directory; never overwrite a store or later effects.")
    if _overlap(source, target):
        raise _failure("restore_target", "A restore must be separate from its complete backup.")
    try:
        stage = Path(tempfile.mkdtemp(prefix="." + target.name + "-restore-", dir=target.parent))
        with initialization_guard(stage):
            _quarantine_stage(stage, manifest["store_uuid"])
            for item in sorted(manifest["directories"], key=lambda value:(value["path"].count("/"),value["path"])):
                (stage / item["path"]).mkdir(mode=0o700)
            for item in manifest["files"]:
                name = item["path"]
                dest = stage / (".restore-snapshot.sqlite3" if name == "state.sqlite3" else name)
                if _file(source / name, dest) != {key:item[key] for key in ("size_bytes","sha256","mode")}:
                    raise _failure("restore_integrity", "A backup payload changed during restore.")
            snapshot = stage / ".restore-snapshot.sqlite3"
            with closing(sqlite3.connect(snapshot, isolation_level=None)) as db:
                if database_state(db) != manifest["database"]:
                    raise _failure("restore_integrity", "Restored rows differ from the complete snapshot.")
                db.execute("BEGIN IMMEDIATE")
                db.execute("UPDATE metadata SET value=? WHERE key='application'", (_QUARANTINE,))
                db.execute("INSERT INTO metadata VALUES('restore_manifest_digest',?)", (expected_digest,))
                db.commit()
            # Replace only our own foreign bootstrap inside the unpublished
            # stage. The full database has committed its quarantine tag already.
            os.replace(snapshot, stage / "state.sqlite3")
            for item in reversed(manifest["directories"]):
                os.chmod(stage / item["path"], item["mode"])
                _sync(stage / item["path"])
            directories, records, _ = _inventory(stage)
            with _read_db(stage / "state.sqlite3") as db:
                observed = database_state(db)
            receipt = {"kind":"taskalong_quarantined_restore", "format_version":1, "backup_digest":expected_digest,
                       "quarantined":True, "database":observed, "directories":directories, "files":records}
            receipt["digest"] = digest(receipt)
            _write(stage / _RESTORE, canonical_bytes(receipt))
            _sync(stage)
            verify_restored(source, stage, expected_digest=expected_digest)
            _publish_restore(stage, target)
            _sync(target.parent)
        return receipt
    except (OSError, sqlite3.Error) as exc:
        raise _failure("restore_io", "Restore failed; preserve the private staging directory, any completed destination and original backup.") from exc


def verify_restored(directory, destination, *, expected_digest):
    manifest = verify_backup(directory, expected_digest=expected_digest)
    root = _path(destination)
    _private(root, directory=True)
    _private(root / _RESTORE, directory=False)
    try:
        receipt = loads((root / _RESTORE).read_bytes())
        if (receipt.get("kind") != "taskalong_quarantined_restore" or receipt.get("quarantined") is not True
                or receipt.get("backup_digest") != expected_digest or digest(receipt) != receipt.get("digest")):
            raise _failure("restore_integrity", "The restored copy has no matching completed quarantine receipt.")
        directories, records, _ = _inventory(root, exclude=(_RESTORE,))
        if directories != manifest["directories"] or directories != receipt["directories"] or records != receipt["files"]:
            raise _failure("restore_integrity", "The restored inventory changed.")
        original = [item for item in manifest["files"] if item["path"] != "state.sqlite3"]
        if [item for item in records if item["path"] != "state.sqlite3"] != original:
            raise _failure("restore_integrity", "Restored control metadata or blobs differ from the backup.")
        with _read_db(root / "state.sqlite3") as db:
            observed = database_state(db)
        expected = dict(manifest["database"])
        expected["application"] = _QUARANTINE
        expected["tables"] = dict(expected["tables"])
        with _read_db(_path(directory) / "state.sqlite3") as db:
            metadata = dict(db.execute("SELECT key,value FROM metadata"))
        metadata.update(application=_QUARANTINE, restore_manifest_digest=expected_digest)
        expected["tables"]["metadata"] = {"columns":["key","value"], **_rows(sorted(metadata.items()))}
        if observed != expected or observed != receipt["database"]:
            raise _failure("restore_integrity", "Restored rows or quarantine markers differ from the independent backup.")
        return receipt
    except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
        raise _failure("restore_integrity", "The quarantined restoration cannot be verified.") from exc


@functools.lru_cache(maxsize=None)
def _migration_sql(number=2):
    name = {2: "002-document-history.sql", 3: "003-execution-projections.sql",
            4: "004-driver-compatibility.sql", 5: "005-ollama-compatibility.sql",
            6: "006-cursor-compatibility.sql", 7: "007-antigravity-compatibility.sql",
            8: "008-e1-trial-compatibility.sql", 9: "009-muse-handoff-compatibility.sql", 10: "010-ordered-tasks.sql", 11: "011-artifact-handoff.sql"}[number]
    return files("taskalong.resources").joinpath("sql", name).read_text()


@functools.lru_cache(maxsize=None)
def _expected_history_definitions(version: int):
    with closing(sqlite3.connect(":memory:")) as expected:
        for number in range(2, version + 1):
            expected.executescript(_migration_sql(number))
        return {row[0]:tuple(row[1:]) for row in expected.execute("SELECT name,type,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}


@functools.lru_cache(maxsize=None)
def _migration_sql_sha256(number: int) -> str:
    return hashlib.sha256(_migration_sql(number).encode()).hexdigest()


def validate_history_schema(store):
    try:
        version = store.db.execute("PRAGMA user_version").fetchone()[0]
        definitions = _expected_history_definitions(version)
        actual = {row[0]:tuple(row[1:]) for row in store.db.execute("SELECT name,type,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
        if any(actual.get(name) != value for name,value in definitions.items()):
            raise ValueError("missing or altered immutable history")
        for number in range(2, version + 1):
            row = store.db.execute("SELECT operation_key,request_digest,document FROM store_migrations WHERE number=?", (number,)).fetchone()
            receipt = loads(row["document"])
            if (receipt["store_uuid"] != store.store_uuid or receipt["to_version"] != number or digest(receipt) != receipt["digest"]
                    or receipt["from_version"] != number - 1 or receipt["number"] != number or receipt["operation_key"] != row["operation_key"]
                    or receipt["request_digest"] != row["request_digest"]
                    or receipt["migration_sql_sha256"] != _migration_sql_sha256(number)):
                raise ValueError("invalid migration identity")
            operation = store.db.execute("SELECT request_digest,response FROM operations WHERE command='maintenance.upgrade' AND run_id='' AND operation_key=?", (row["operation_key"],)).fetchone()
            if operation is None or operation["request_digest"] != row["request_digest"] or loads(operation["response"]) != {"phase":"observed", "receipt":receipt}:
                raise ValueError("inconsistent migration operation")
    except (sqlite3.Error, KeyError, TypeError, ValueError) as exc:
        raise _failure("store_integrity", "The numbered immutable-history schema/receipt is inconsistent.") from exc


def upgrade(store, *, operation_key, backup_dir, restore_dir, target_version=2):
    require_quiescent(store)
    key_check(operation_key)
    if type(target_version) is not int or target_version not in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11):
        raise _failure("unsupported_store_version", "Select an explicit supported numbered migration.")
    source_version = target_version - 1
    backup, restored = _path(backup_dir), _path(restore_dir)
    targets = (store.root, backup, restored)
    if any(_overlap(a,b) for i,a in enumerate(targets) for b in targets[i+1:]):
        raise _failure("maintenance_target", "Source, backup and restore must be separate non-overlapping directories.")
    request = {"store_uuid":store.store_uuid, "from_version":source_version, "to_version":target_version,
               "backup_target_digest":digest({"path":str(backup)}), "restore_target_digest":digest({"path":str(restored)})}
    request_digest = digest(request)
    with store.transaction() as db:
        prior = store._prior(db, "maintenance.upgrade", "", operation_key, request_digest)
        if prior is not None and prior.get("phase") == "observed":
            if store.format_version < target_version:
                raise _failure("store_integrity", "The completed migration receipt disagrees with its format.")
            recorded = loads(db.execute("SELECT document FROM store_migrations WHERE number=?", (target_version,)).fetchone()[0])
            if recorded != prior["receipt"]:
                raise _failure("store_integrity", "The migration operation and immutable receipt disagree.")
            return recorded
        if store.format_version < source_version:
            raise TaskAlongError("store_migration_order", "Apply each preceding numbered migration before the selected target.", exit_code=4)
        if store.format_version != source_version:
            raise TaskAlongError("store_already_upgraded", "This store already has numbered history; use its original operation receipt.", exit_code=4)
        if prior is None:
            db.execute("INSERT INTO operations VALUES(?,?,?,?,?)", ("maintenance.upgrade", "", operation_key, request_digest, encode({"phase":"prepared"})))
        elif prior != {"phase":"prepared"}:
            raise _failure("store_integrity", "The maintenance operation has an unknown recovery state.")
    if backup.exists() or backup.is_symlink():
        _private(backup / _BACKUP, directory=False)
        retained = loads((backup / _BACKUP).read_bytes())
        manifest = verify_backup(backup, expected_digest=retained["digest"])
    else:
        manifest = create_backup(store, backup)
    # A retained backup is accepted only when it still matches the exclusively
    # owned source in full. Its self-hash alone supplies no trust.
    directories, records, _ = _inventory(store.root, exclude=("state.sqlite3", *_SQLITE_AUX))
    if (manifest["database"] != database_state(store.db) or directories != manifest["directories"]
            or records != [item for item in manifest["files"] if item["path"] != "state.sqlite3"]):
        raise _failure("backup_stale", "The complete backup no longer matches the source; preserve it and reconcile forward.")
    if restored.exists() or restored.is_symlink():
        restoration = verify_restored(backup, restored, expected_digest=manifest["digest"])
    else:
        restoration = restore_backup(backup, restored, expected_digest=manifest["digest"])
    sql = _migration_sql(target_version)
    receipt = {"kind":"store_migration_receipt", "format_version":1, "number":target_version, "from_version":source_version, "to_version":target_version,
               "store_uuid":store.store_uuid, "operation_key":operation_key, "request_digest":request_digest,
               "backup_manifest_digest":manifest["digest"], "restore_receipt_digest":restoration["digest"],
               "migration_sql_sha256":hashlib.sha256(sql.encode()).hexdigest(), "applied_at":now()}
    receipt["digest"] = digest(receipt)
    with store.transaction() as db:
        require_quiescent(store)
        if db.execute("PRAGMA user_version").fetchone()[0] != source_version:
            raise _failure("store_integrity", "Store format changed during exclusive maintenance.")
        statement = ""
        for line in sql.splitlines(keepends=True):
            statement += line
            if sqlite3.complete_statement(statement):
                db.execute(statement)
                statement = ""
        if statement.strip():
            raise _failure("store_integrity", "The numbered migration is incomplete.")
        if target_version == 2:
            for row in db.execute("SELECT profile_id,digest,document FROM profiles").fetchall():
                document = validate("runtime-profile", loads(row["document"]))
                if document["profile_id"] != row["profile_id"] or document["digest"] != row["digest"]:
                    raise _failure("store_integrity", "A legacy profile disagrees with its immutable identity.")
                db.execute("INSERT INTO document_history VALUES(?,?,?,?,?,?)", ("runtime_profile", row["profile_id"], row["digest"], "1.0", row["document"], receipt["applied_at"]))
        db.execute("INSERT INTO store_migrations VALUES(?,?,?,?)", (target_version, operation_key, request_digest, encode(receipt)))
        db.execute("UPDATE metadata SET value=? WHERE key='format_version'", (str(target_version),))
        db.execute("PRAGMA user_version=" + str(target_version))
        db.execute("UPDATE operations SET response=? WHERE command='maintenance.upgrade' AND run_id='' AND operation_key=?",
                   (encode({"phase":"observed", "receipt":receipt}), operation_key))
    store.format_version = target_version
    validate_history_schema(store)
    return receipt


def require_quiescent(store):
    if not store._maintenance_mode:
        raise TaskAlongError("maintenance_required", "Complete maintenance requires exclusive trusted ownership.", exit_code=3)
    blocked = False
    for row in store.db.execute("SELECT run_id,revision,state,document FROM runs"):
        run = loads(row["document"])
        run = validate_versioned("task-run", run, expected_version=run.get("schema_version"))
        blocked |= any(run[key] != row[key] for key in ("run_id","revision","state"))
        blocked |= bool(run["active_attempt_id"] or run["pending_effect_ids"] or run["state"] in {
            "starting", "running", "verifying", "reviewing", "publishing", "cancel_pending"})
    for row in store.db.execute("SELECT attempt_id,run_id,ordinal,active,document FROM attempts"):
        attempt = loads(row["document"])
        blocked |= bool(row["active"] or attempt.get("termination_confirmed") is not True)
        blocked |= any(attempt.get(key) != row[key] for key in ("attempt_id","run_id","ordinal"))
    known_effects = {"workspace.create","workspace.reacquire","candidate.freeze","workspace.retire",
                     "executor.start","verifier.capture","push_branch","create_draft_pr"}
    if store.format_version >= 11:
        known_effects.add("artifact.import")
    for row in store.db.execute("SELECT effect_id,run_id,kind,phase,document FROM effects"):
        effect = loads(row["document"])
        blocked |= row["phase"] != "observed" or effect.get("phase") != "observed"
        blocked |= row["kind"] not in known_effects or any(effect.get(key) != row[key] for key in ("effect_id","run_id","kind"))
        if effect.get("kind") == "artifact.import":
            response = effect.get("response")
            if (not isinstance(response,dict) or response.get("journal_blob_sha256") != effect["request"].get("journal_blob_sha256")
                    or store.operation("effect.observed",effect["run_id"],effect["effect_id"],{"effect_id":effect["effect_id"],"response":response}) is None):
                blocked = True
            else:
                from .artifact_handoff import blob_document, validate_import
                journal=blob_document(store,response["journal_blob_sha256"],"import-journal")
                owner=store.run(effect["run_id"])
                if response.get("cancelled") is True:
                    blocked |= owner.get("cancellation_requested") is not True
                else:
                    attempt=store.detail("attempts",journal["attempt_id"])
                    validate_import(store,owner,attempt)
                    blocked |= response.get("resolved_inputs_blob_sha256") != attempt["resolved_inputs_blob_sha256"]
        if effect.get("kind") in {"executor.start", "verifier.capture"}:
            response = effect.get("response")
            if response is not None and type(response) is not dict:
                raise _failure("store_integrity", "An invocation effect has malformed retained response metadata; preserve it for reconciliation.")
            blocked |= response is None or response.get("termination_confirmed") is not True
    if blocked:
        raise TaskAlongError("maintenance_not_quiescent", "Active or uncertain invocations/effects require reconciliation before maintenance.", exit_code=5, effect_outcome="uncertain")
