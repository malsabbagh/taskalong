"""Private local transactional state. No provider call occurs in a transaction."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import tempfile
import uuid
from datetime import datetime, timezone
from importlib.resources import files
from typing import Callable

from .errors import TaskAlongError
from .validation import canonical_bytes, digest, loads, validate


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def identifier() -> str:
    return str(uuid.uuid4())


def key_check(key: str) -> None:
    if not isinstance(key, str) or not 1 <= len(key) <= 128 or not all(c.isprintable() for c in key):
        raise TaskAlongError("invalid_operation_key", "Operation key must contain 1–128 printable characters.")


def encode(value: dict) -> str:
    return canonical_bytes(value).decode("utf-8")


def _private(path: Path, *, directory: bool, optional_ephemeral: bool = False) -> None:
    # Observe type, owner, mode and link count together. SQLite may unlink an
    # optional WAL/SHM during getattr; its last private inode can have nlink=0.
    try:
        st = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise TaskAlongError("unsafe_state_path", "Control paths cannot be symbolic links.", exit_code=3)
    if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise TaskAlongError("unsafe_state_permissions", "Control storage requires private operator ownership.", exit_code=3)
    if optional_ephemeral and not directory and stat.S_ISREG(st.st_mode) and st.st_nlink == 0:
        return
    if (directory and not stat.S_ISDIR(st.st_mode)) or (not directory and (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1)):
        raise TaskAlongError("unsafe_state_path", "Control storage has an unexpected file type.", exit_code=3)


@contextlib.contextmanager
def initialization_guard(root: Path):
    import fcntl
    path = root / "initialize.lock"
    if path.exists() or path.is_symlink():
        _private(path, directory=False)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


class Store:
    """One store UUID, immutable records, expected-revision mutations and receipts."""

    def __init__(self, root: str | Path):
        self.root = Path(root).absolute()
        # Validate every existing selected path component; never resolve an attacker link.
        for part in [self.root, *self.root.parents]:
            if part.is_symlink():
                # macOS aliases /var and /tmp are OS-controlled aliases, never selected leaves.
                if part not in (Path("/var"), Path("/tmp")):
                    raise TaskAlongError("unsafe_state_path", "A control path traverses a symbolic link.", exit_code=3)
        if not self.root.exists():
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        _private(self.root, directory=True)
        self.blob_root = self.root / "blobs"
        self.blob_root.mkdir(mode=0o700, exist_ok=True)
        _private(self.blob_root, directory=True)
        with initialization_guard(self.root):
            self._open_database()

    def _open_database(self):
        self.db_path = self.root / "state.sqlite3"
        if not self.db_path.exists():
            fd = os.open(self.db_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        _private(self.db_path, directory=False)
        for suffix in ("-wal", "-shm"):
            _private(Path(str(self.db_path) + suffix), directory=False, optional_ephemeral=True)
        self.db = sqlite3.connect(self.db_path, timeout=5, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA busy_timeout=5000")
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        tables = self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        if version not in (0, 1) or (version == 0 and tables):
            self.db.close()
            raise TaskAlongError("unsupported_store_version", "Store format is unknown; preserve it and use a compatible runtime.", exit_code=70)
        if version == 1:
            try:
                current_metadata = dict(self.db.execute("SELECT key,value FROM metadata"))
                if current_metadata.get("format_version") != "1":
                    raise ValueError("unknown metadata format")
                uuid.UUID(current_metadata["store_uuid"])
            except (KeyError, ValueError, TypeError, sqlite3.Error) as exc:
                self.db.close()
                raise TaskAlongError("store_integrity", "Store metadata is missing, corrupt or unsupported; preserve the database.", exit_code=70) from exc
            if current_metadata.get("application") != "taskalong":
                self.db.close()
                raise TaskAlongError("unsupported_store_application", "This is not a tagged TaskAlong store; preserve it and use its owning application.", exit_code=70)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        if version == 0:
            # Executescript otherwise commits a prior BEGIN; place BEGIN in the script itself.
            sql = files("taskalong.resources").joinpath("sql/001-initial.sql").read_text()
            try:
                self.db.executescript("BEGIN IMMEDIATE;\n" + sql)
                self.db.executemany("INSERT INTO metadata VALUES (?,?)", [("store_uuid", identifier()), ("format_version", "1"), ("created_at", now()), ("runtime_version", "0.1.0a1"), ("application", "taskalong")])
                self.db.execute("PRAGMA user_version=1")
                self.db.commit()
            except BaseException:
                self.db.rollback()
                # Another first client may have initialized while we waited.
                if self.db.execute("PRAGMA user_version").fetchone()[0] != 1:
                    raise
        try:
            metadata = dict(self.db.execute("SELECT key,value FROM metadata"))
            if metadata.get("format_version") != "1":
                raise ValueError("unknown metadata format")
            self.store_uuid = str(uuid.UUID(metadata["store_uuid"]))
        except (KeyError, ValueError, TypeError, sqlite3.Error) as exc:
            self.db.close()
            raise TaskAlongError("store_integrity", "Store metadata is missing, corrupt or unsupported; preserve the database.", exit_code=70) from exc
        if metadata.get("application") != "taskalong":
            self.db.close()
            raise TaskAlongError("unsupported_store_application", "This is not a tagged TaskAlong store; preserve it and use its owning application.", exit_code=70)

    @contextlib.contextmanager
    def guard(self, run_id: str, purpose: str):
        import fcntl
        try:
            uuid.UUID(run_id)
        except (ValueError, AttributeError, TypeError) as exc:
            raise TaskAlongError("invalid_run_id", "A canonical run UUID is required.") from exc
        if purpose not in {"verify", "publish", "dispatch"}:
            raise ValueError("Unknown guard purpose")
        directory = self.root / "guards"
        directory.mkdir(mode=0o700, exist_ok=True)
        _private(directory, directory=True)
        path = directory / (run_id + "." + purpose + ".lock")
        if path.exists() or path.is_symlink():
            _private(path, directory=False)
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise TaskAlongError("operation_in_progress", "Another owned operation holds this run boundary.", exit_code=4) from exc
            yield
        finally:
            os.close(descriptor)

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    @contextlib.contextmanager
    def transaction(self):
        try:
            self.db.execute("BEGIN IMMEDIATE")
            yield self.db
            self.db.commit()
        except sqlite3.IntegrityError as exc:
            self.db.rollback()
            raise TaskAlongError("store_conflict", "The requested identity or immutable record conflicts.", exit_code=4) from exc
        except BaseException:
            self.db.rollback()
            raise

    def setting(self, name: str, default=None):
        row = self.db.execute("SELECT document FROM settings WHERE name=?", (name,)).fetchone()
        return loads(row[0]) if row else default

    def set_setting(self, name: str, document: dict):
        with self.transaction() as db:
            db.execute("INSERT INTO settings VALUES (?,?) ON CONFLICT(name) DO UPDATE SET document=excluded.document", (name, encode(document)))

    def repository(self, registration_id: str) -> dict:
        row = self.db.execute("SELECT document FROM repositories WHERE registration_id=?", (registration_id,)).fetchone()
        if not row:
            raise TaskAlongError("repository_not_registered", "Register the local repository with this store first.", exit_code=3)
        return loads(row[0])

    def register_repository(self, document: dict) -> dict:
        with self.transaction() as db:
            row = db.execute("SELECT document FROM repositories WHERE identity=?", (document["identity"],)).fetchone()
            if row:
                previous = loads(row[0])
                if previous["workspace_root"] != document["workspace_root"]:
                    raise TaskAlongError("repository_registration_conflict", "Workspace root differs from the existing registration.", exit_code=4)
                return previous
            db.execute("INSERT INTO repositories VALUES (?,?,?)", (document["registration_id"], document["identity"], encode(document)))
        return document

    def profile(self, profile_id: str) -> dict:
        row = self.db.execute("SELECT document FROM profiles WHERE profile_id=?", (profile_id,)).fetchone()
        if not row:
            raise TaskAlongError("profile_missing", "Register the exact runtime profile first.", exit_code=3)
        return loads(row[0])

    def register_profile(self, document: dict) -> dict:
        with self.transaction() as db:
            row = db.execute("SELECT digest FROM profiles WHERE profile_id=?", (document["profile_id"],)).fetchone()
            if row and row[0] != document["digest"]:
                raise TaskAlongError("profile_immutable", "A changed runtime profile needs a new profile identity.", exit_code=4)
            db.execute("INSERT OR IGNORE INTO profiles VALUES (?,?,?)", (document["profile_id"], document["digest"], encode(document)))
        return document

    def run(self, run_id: str) -> dict:
        row = self.db.execute("SELECT document FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if not row:
            raise TaskAlongError("run_not_found", "Run identity does not exist in this store.")
        return loads(row[0])

    def spec(self, run: dict) -> dict:
        row = self.db.execute("SELECT document FROM task_specs WHERE task_id=? AND revision=?", (run["task_id"], run["task_revision"])).fetchone()
        document = loads(row[0])
        if digest(document) != document["digest"] or document["digest"] != run["spec_digest"]:
            raise TaskAlongError("store_integrity", "The immutable specification digest does not match.", exit_code=70)
        return document

    def events(self, run_id: str, after_seq: int = 0, limit: int = 1000):
        self.run(run_id)
        if type(after_seq) is not int or after_seq < 0 or type(limit) is not int or not 1 <= limit <= 1000:
            raise TaskAlongError("invalid_cursor", "Event cursor and page size are out of bounds.")
        return [loads(r[0]) for r in self.db.execute("SELECT document FROM events WHERE run_id=? AND seq>? ORDER BY seq LIMIT ?", (run_id, after_seq, limit))]

    def _event(self, db, run: dict, event_type: str, payload=None, *, actor="core", operation_key=None):
        seq = db.execute("SELECT coalesce(max(seq),0)+1 FROM events WHERE run_id=?", (run["run_id"],)).fetchone()[0]
        document = {"kind": "run_event", "schema_version": "1.0", "event_id": identifier(), "run_id": run["run_id"], "seq": seq, "run_revision": run["revision"], "attempt_id": run["active_attempt_id"], "type": event_type, "payload_version": "1.0", "at": now(), "actor_role": actor, "operation_key": operation_key, "payload": payload or {}, "qualification": run["qualification"], "extensions": {}}
        validate("run-event", document)
        db.execute("INSERT INTO events(event_id,run_id,seq,run_revision,document) VALUES (?,?,?,?,?)", (document["event_id"], run["run_id"], seq, run["revision"], encode(document)))

    def _prior(self, db, command, run_id, operation_key, request_digest):
        row = db.execute("SELECT request_digest,response FROM operations WHERE command=? AND run_id=? AND operation_key=?", (command, run_id, operation_key)).fetchone()
        if row:
            if row[0] != request_digest:
                raise TaskAlongError("operation_key_conflict", "Operation key was already used for different inputs.", exit_code=4)
            return loads(row[1])
        return None

    def operation(self, command, run_id, operation_key, request):
        key_check(operation_key)
        return self._prior(self.db, command, run_id, operation_key, digest(request))

    def create_run(self, spec: dict, operation_key: str):
        key_check(operation_key)
        request_digest = digest(spec)
        with self.transaction() as db:
            prior = self._prior(db, "submit", "", operation_key, request_digest)
            if prior:
                return prior
            row = db.execute("SELECT digest FROM task_specs WHERE task_id=? AND revision=?", (spec["task_id"], spec["revision"])).fetchone()
            if row and row[0] != spec["digest"]:
                raise TaskAlongError("task_revision_conflict", "Task revision is immutable; submit a new revision.", exit_code=4)
            db.execute("INSERT OR IGNORE INTO task_specs VALUES (?,?,?,?)", (spec["task_id"], spec["revision"], spec["digest"], encode(spec)))
            run = {"kind": "task_run", "schema_version": "1.0", "run_id": identifier(), "task_id": spec["task_id"], "task_revision": spec["revision"], "spec_digest": spec["digest"], "revision": 1, "state": "created", "blocked_from": None, "created_at": now(), "updated_at": now(), "repository_registration_id": spec["repository"]["registration_id"], "workspace_id": None, "lease_generation": 0, "active_attempt_id": None, "attempts": [], "candidate": None, "evidence_ids": [], "acceptance_id": None, "pending_effect_ids": [], "budget_consumed": {"attempts": 0, "active_seconds": 0, "output_bytes": 0, "input_tokens": None, "output_tokens": None, "cost_usd": None}, "blockers": [], "publication": None, "qualification": spec["qualification"], "extensions": {}}
            validate("task-run", run)
            db.execute("INSERT INTO runs VALUES (?,?,?,?,?,?)", (run["run_id"], run["task_id"], run["task_revision"], 1, run["state"], encode(run)))
            self._event(db, run, "run.created", {"spec_digest": spec["digest"]}, operation_key=operation_key)
            db.execute("INSERT INTO operations VALUES (?,?,?,?,?)", ("submit", "", operation_key, request_digest, encode(run)))
        return run

    def mutate(self, run_id: str, command: str, operation_key: str, expected_revision: int | None, request: dict, change: Callable, *, events=None, actor="core", fence: int | None = None):
        key_check(operation_key)
        request_digest = digest(request)
        with self.transaction() as db:
            prior = self._prior(db, command, run_id, operation_key, request_digest)
            if prior:
                return prior
            run = self.run(run_id)
            if expected_revision is not None and (type(expected_revision) is not int or run["revision"] != expected_revision):
                raise TaskAlongError("revision_conflict", "Run revision changed; inspect the run before issuing another operation.", exit_code=4)
            if fence is not None:
                self.require_fence(run, fence, db=db)
            change(run, db)
            run["revision"] += 1
            run["updated_at"] = now()
            validate("task-run", run)
            db.execute("UPDATE runs SET revision=?,state=?,document=? WHERE run_id=? AND revision=?", (run["revision"], run["state"], encode(run), run_id, run["revision"] - 1))
            for event_type, payload in events or [(command, {})]:
                self._event(db, run, event_type, payload, actor=actor, operation_key=operation_key)
            db.execute("INSERT INTO operations VALUES (?,?,?,?,?)", (command, run_id, operation_key, request_digest, encode(run)))
        return run

    def detail(self, table: str, identity: str):
        keys = {"attempts": "attempt_id", "effects": "effect_id", "evidence": "evidence_id", "acceptances": "acceptance_id", "authorities": "authority_id"}
        if table not in keys:
            raise ValueError("Unsupported detail table")
        row = self.db.execute(f"SELECT document FROM {table} WHERE {keys[table]}=?", (identity,)).fetchone()
        if not row:
            raise TaskAlongError("record_missing", "The required immutable or operational record is missing.", exit_code=70)
        return loads(row[0])

    def add_authority(self, run_id: str, document: dict):
        self.run(run_id)
        with self.transaction() as db:
            db.execute("INSERT INTO authorities VALUES (?,?,?)", (document["authority_id"], run_id, encode(document)))
        return document

    def authority(self, run: dict, scope: set[str], decision_digest: str, authority_id=None):
        documents = [self.detail("authorities", authority_id)] if authority_id else [loads(r[0]) for r in self.db.execute("SELECT document FROM authorities WHERE run_id=?", (run["run_id"],))]
        for document in documents:
            try:
                validate("authority", document)
            except TaskAlongError:
                continue
            if document["decision"] != "authorized" or document["issued_at"] > now():
                continue
            if document["run_id"] == run["run_id"] and document["qualification"] == run["qualification"] and document["intent_digest"] == decision_digest and document["expires_at"] > now() and scope <= set(document["scope"]):
                if document["source"] == "local_operator" and document["principal"] == str(os.getuid()):
                    return document
        raise TaskAlongError("authority_missing", "The operating-system operator must authorize this exact intent and effect scope.", exit_code=3)

    def next_lease_generation(self, run: dict) -> int:
        """Observe the next repository-wide fence, including retired owners."""
        row = self.db.execute("SELECT generation FROM leases WHERE repository_id=?", (run["repository_registration_id"],)).fetchone()
        return (row["generation"] if row else 0) + 1

    def acquire_lease(self, db, run: dict, workspace: dict):
        registration = run["repository_registration_id"]
        row = db.execute("SELECT * FROM leases WHERE repository_id=?", (registration,)).fetchone()
        if row and row["run_id"] != run["run_id"]:
            if row["state"] != "retired":
                raise TaskAlongError("workspace_occupied", "The repository has an active or retained owner; retire an eligible terminal workspace explicitly.", exit_code=4)
            previous = self.run(row["run_id"])
            archived = self.retired_lease(previous)
            retired_row = loads(row["document"])
            if (previous["state"] not in {"cancelled", "failed", "draft_published", "accepted"}
                    or archived["generation"] != row["generation"] or archived["token"] != row["token"]
                    or retired_row.get("state") != "retired" or retired_row.get("run_id") != previous["run_id"]
                    or retired_row.get("generation") != row["generation"] or retired_row.get("store_uuid") != self.store_uuid):
                raise TaskAlongError("store_integrity", "The retired repository owner has no matching terminal retirement receipt.", exit_code=70)
        elif row and row["state"] not in ("held", "retained"):
            raise TaskAlongError("lease_retired", "A retired run cannot reacquire or reuse its preserved workspace.", exit_code=3)
        generation = (row["generation"] if row else 0) + 1
        expected_workspace_generation = row["generation"] if row and row["run_id"] == run["run_id"] else generation
        if (workspace.get("run_id") != run["run_id"] or workspace.get("store_uuid") != self.store_uuid
                or workspace.get("generation") != expected_workspace_generation
                or workspace.get("lease_generation") != expected_workspace_generation):
            raise TaskAlongError("lease_conflict", "The workspace intent does not match the current repository fence and owner.", exit_code=4)
        lease = {"repository_id": registration, "run_id": run["run_id"], "workspace": workspace, "generation": generation, "token": secrets.token_hex(32), "store_uuid": self.store_uuid, "state": "held", "heartbeat": now()}
        db.execute("INSERT INTO leases VALUES (?,?,?,?,?,?) ON CONFLICT(repository_id) DO UPDATE SET run_id=excluded.run_id,generation=excluded.generation,token=excluded.token,state=excluded.state,document=excluded.document", (registration, run["run_id"], generation, lease["token"], "held", encode(lease)))
        run["workspace_id"] = workspace["workspace_id"]
        run["lease_generation"] = generation
        return lease

    def lease(self, run: dict):
        row = self.db.execute("SELECT * FROM leases WHERE repository_id=?", (run["repository_registration_id"],)).fetchone()
        if not row:
            raise TaskAlongError("lease_missing", "No owned workspace lease exists.", exit_code=3)
        lease = loads(row["document"])
        if any(lease.get(key) != row[key] for key in ("run_id", "generation", "state", "token")):
            raise TaskAlongError("store_integrity", "Repository lease columns disagree with the private receipt.", exit_code=70)
        if row["run_id"] != run["run_id"] or row["state"] == "retired":
            code = "lease_retired" if "taskalong:workspace_retirement" in run["extensions"] else "lease_conflict"
            raise TaskAlongError(code, "This run no longer owns an active repository lease; its workspace and history are preserved.", exit_code=3 if code == "lease_retired" else 4)
        return lease

    def retired_lease(self, run: dict) -> dict:
        """Read a private historical lease without granting its old fence."""
        row = self.db.execute("SELECT document FROM effects WHERE run_id=? AND kind='workspace.retire' AND phase='observed'", (run["run_id"],)).fetchone()
        if not row:
            raise TaskAlongError("retirement_missing", "No completed workspace retirement receipt exists for this run.", exit_code=3)
        effect = loads(row[0])
        lease = effect.get("response", {}).get("lease", {})
        retirement = run["extensions"].get("taskalong:workspace_retirement", {})
        if (effect.get("run_id") != run["run_id"] or effect.get("kind") != "workspace.retire" or effect.get("phase") != "observed"
                or lease.get("run_id") != run["run_id"] or lease.get("repository_id") != run["repository_registration_id"]
                or lease.get("store_uuid") != self.store_uuid
                or lease.get("generation") != run["lease_generation"] or lease.get("workspace", {}).get("workspace_id") != run["workspace_id"]
                or retirement.get("generation") != lease.get("generation") or retirement.get("workspace_id") != run["workspace_id"]):
            raise TaskAlongError("store_integrity", "The retained workspace retirement receipt does not match its original owner.", exit_code=70)
        return lease

    def retire_lease(self, run_id: str, *, operation_key: str, expected_revision: int, workspace_subject: dict):
        """Atomically retire a proven terminal lease; never remove its data.

        The application caller holds all run guards and the supervisor guard,
        and independently observed the exact owned workspace. This transaction
        repeats the safety predicates before revoking the current fence.
        """
        def retire(run, db):
            if run["state"] not in {"cancelled", "failed", "draft_published", "accepted"}:
                raise TaskAlongError("retirement_not_terminal", "Only a completed or accepted quiescent run can retire its workspace.", exit_code=3)
            self.require_fence(run, run["lease_generation"], db=db)
            if run["active_attempt_id"] is not None or db.execute("SELECT 1 FROM attempts WHERE run_id=? AND active=1", (run_id,)).fetchone():
                raise TaskAlongError("retirement_execution_active", "The run still has an active or uncertain execution; preserve its ownership.", exit_code=5, effect_outcome="uncertain")
            effect_rows = db.execute("SELECT phase,document FROM effects WHERE run_id=?", (run_id,)).fetchall()
            effects = [loads(row["document"]) for row in effect_rows]
            if run["pending_effect_ids"] or any(row["phase"] != "observed" or effect.get("phase") != "observed" or effect.get("run_id") != run_id for row, effect in zip(effect_rows, effects)):
                raise TaskAlongError("retirement_effects_pending", "Pending or unknown effects must be reconciled before retirement.", exit_code=5, effect_outcome="uncertain")
            attempts = [loads(row[0]) for row in db.execute("SELECT document FROM attempts WHERE run_id=?", (run_id,))]
            if not attempts or any(attempt.get("termination_confirmed") is not True for attempt in attempts):
                raise TaskAlongError("retirement_cessation_unconfirmed", "Every recorded execution requires confirmed cessation before retirement.", exit_code=5, effect_outcome="uncertain")
            for effect in effects:
                if effect.get("kind") not in {"executor.start", "verifier.capture"}:
                    continue
                if effect.get("response", {}).get("termination_confirmed") is not True:
                    raise TaskAlongError("retirement_cessation_unconfirmed", "An owned process effect has no confirmed cessation receipt.", exit_code=5, effect_outcome="uncertain")
            lease = self.lease(run)
            if (workspace_subject.get("workspace_id") != run["workspace_id"]
                    or workspace_subject.get("generation") != run["lease_generation"]):
                raise TaskAlongError("lease_conflict", "The observed workspace no longer matches the terminal run fence.", exit_code=4)
            retired_at = now()
            effect = {"effect_id": identifier(), "run_id": run_id, "kind": "workspace.retire", "operation_key": operation_key,
                      "request": {}, "request_digest": digest({}), "phase": "observed",
                      "response": {"lease": lease, "workspace_subject": workspace_subject, "retired_at": retired_at}}
            db.execute("INSERT INTO effects VALUES (?,?,?,?,?,?,?)", (effect["effect_id"], run_id, operation_key, effect["kind"], effect["request_digest"], "observed", encode(effect)))
            retired = {**lease, "state": "retired", "retired_at": retired_at}
            db.execute("UPDATE leases SET state='retired',document=? WHERE repository_id=?", (encode(retired), run["repository_registration_id"]))
            run["extensions"]["taskalong:workspace_retirement"] = {"workspace_id": run["workspace_id"], "generation": run["lease_generation"], "retired_at": retired_at, "preserved": True}
        return self.mutate(run_id, "retire-workspace", operation_key, expected_revision, {}, retire,
                           events=[("workspace.retired", {"preserved": True})], actor="operator")

    def require_fence(self, run: dict, generation: int, *, db=None):
        row = (db or self.db).execute("SELECT run_id,generation,state FROM leases WHERE repository_id=?", (run["repository_registration_id"],)).fetchone()
        if not row or row["run_id"] != run["run_id"] or row["generation"] != generation or row["state"] != "held":
            raise TaskAlongError("lease_conflict", "The workspace generation no longer authorizes this operation.", exit_code=4)

    def heartbeat(self, run_id: str, attempt_id: str):
        with self.transaction() as db:
            run = self.run(run_id)
            self.require_fence(run, run["lease_generation"], db=db)
            if run["active_attempt_id"] != attempt_id:
                raise TaskAlongError("stale_attempt", "The invocation no longer owns this run.", exit_code=4)
            lease = self.lease(run)
            lease["heartbeat"] = now()
            db.execute("UPDATE leases SET document=? WHERE repository_id=?", (encode(lease), run["repository_registration_id"]))

    def put_blob(self, data: bytes, *, media_type="application/json", redaction_version="1"):
        sha = hashlib.sha256(data).hexdigest()
        target = self.blob_root / sha
        if target.exists() or target.is_symlink():
            self.get_blob(sha, registered=False)
        else:
            fd, temporary = tempfile.mkstemp(prefix=".blob-", dir=self.blob_root)
            try:
                with os.fdopen(fd, "wb") as output:
                    output.write(data)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, target)
                dfd = os.open(self.blob_root, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        with self.transaction() as db:
            db.execute("INSERT OR IGNORE INTO blobs VALUES (?,?,?,?)", (sha, len(data), media_type, redaction_version))
        return {"sha256": sha, "bytes": len(data), "media_type": media_type, "redaction_version": redaction_version}

    def get_blob(self, sha: str, *, registered=True):
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise TaskAlongError("blob_integrity", "Invalid content address.", exit_code=70)
        target = self.blob_root / sha
        _private(target, directory=False)
        try:
            data = target.read_bytes()
        except OSError as exc:
            raise TaskAlongError("blob_missing", "A referenced artifact is missing; preserve the store.", exit_code=70) from exc
        row = self.db.execute("SELECT bytes FROM blobs WHERE sha256=?", (sha,)).fetchone() if registered else None
        if hashlib.sha256(data).hexdigest() != sha or (registered and (not row or row[0] != len(data))):
            raise TaskAlongError("blob_integrity", "A referenced artifact has changed; preserve the store.", exit_code=70)
        return data

    def backup(self, destination: str | Path):
        target = Path(destination)
        if target.exists() or target.is_symlink():
            raise TaskAlongError("backup_exists", "Backup destination must be new.")
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        other = sqlite3.connect(target)
        try:
            self.db.backup(other)
        finally:
            other.close()
        return target
