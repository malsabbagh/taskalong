"""Bounded private byte evidence, without process or provider lifecycle claims.

A finalized receipt proves only closure of this sink. It does not prove process
cessation, provider completion, acceptance, or remote settlement. Files are
private local evidence; permissions do not isolate mutually hostile same-uid code.
"""
from __future__ import annotations

import hashlib
from functools import wraps
import os
from pathlib import Path
import stat
from threading import RLock
from collections.abc import Mapping

from .errors import TaskAlongError
from .validation import canonical_bytes, loads

_STREAMS = ("stdout", "stderr", "result")
_MAX_OUTPUT = 4_194_304
_OUTPUT_CEILINGS = {"1.0": _MAX_OUTPUT, "2.0": 64 * 1024 * 1024}
_MAX_ITER_RECORD_BYTES = 16 * 1024 * 1024
_MAX_RECORDS = 8192
_RECORD_BYTES = 16_384
_EVENT_BYTES = 4096
_CADENCE = 65_536
_INTEGER = 2**53 - 1
_FLAGS = os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)


def _invalid():
    return TaskAlongError("private_capture_invalid", "Private capture evidence is invalid or unavailable.")


def _output_ceiling(schema_version):
    if type(schema_version) is not str or schema_version not in _OUTPUT_CEILINGS:
        raise _invalid()
    return _OUTPUT_CEILINGS[schema_version]


def _integer(value, maximum=_INTEGER):
    return type(value) is int and 0 <= value <= maximum


def _sha(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _state(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _regular(info, maximum, mode):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != mode
            or not 0 <= info.st_size <= maximum):
        raise _invalid()


def _write_all(fd, data, advance=lambda chunk: None):
    view = memoryview(data)
    while view:
        try:
            written = os.write(fd, view[:_CADENCE])
        except InterruptedError:
            continue
        if written <= 0:
            raise _invalid()
        advance(view[:written])
        view = view[written:]


class _Directory:
    """Hold and recheck every directory entry; never resolve arbitrary links."""
    def __init__(self, root, *, create=False):
        self.fds = []
        self.links = []
        try:
            path = Path(root).absolute()
            for alias, destination in ((Path("/tmp"), Path("/private/tmp")),
                                       (Path("/var"), Path("/private/var"))):
                if (path == alias or alias in path.parents) and alias.is_symlink():
                    if alias.lstat().st_uid != 0 or os.readlink(alias) not in {str(destination), str(destination).lstrip("/")}:
                        raise _invalid()
                    path = destination / path.relative_to(alias)
            if (len(path.parts) < 2 or len(path.parts) > 128
                    or any(p in {"..", "."} or not p.isprintable() for p in path.parts)):
                raise _invalid()
            fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | _FLAGS)
            self.fds.append(fd)
            for index, name in enumerate(path.parts[1:], 1):
                last = index == len(path.parts) - 1
                if last and create:
                    os.mkdir(name, 0o700, dir_fd=fd)  # Fresh directory only.
                    os.fsync(fd)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | _FLAGS, dir_fd=fd)
                self.fds.append(child)
                info = os.fstat(child)
                self.links.append((fd, name, child, (info.st_dev, info.st_ino)))
                fd = child
            self.fd = fd
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        for parent, name, fd, identity in self.links:
            entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(fd)
            if (not stat.S_ISDIR(entry.st_mode) or (entry.st_dev, entry.st_ino) != identity
                    or (held.st_dev, held.st_ino) != identity):
                raise _invalid()
        info = os.fstat(self.fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise _invalid()

    def names(self):
        result = set()
        with os.scandir(self.fd) as entries:
            for entry in entries:
                result.add(entry.name)
                if len(result) > _MAX_RECORDS + 4:
                    raise _invalid()
        return result

    def close(self):
        owned, self.fds = self.fds, []
        first_error = None
        for fd in reversed(owned):
            try:
                os.close(fd)
            except OSError as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error


def _entry(directory, name, fd, maximum, mode):
    directory.check()
    held = os.fstat(fd)
    entry = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    _regular(held, maximum, mode)
    _regular(entry, maximum, mode)
    if _state(held) != _state(entry):
        raise _invalid()
    return _state(held)


def _immutable(directory, name, data):
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | _FLAGS, 0o600, dir_fd=directory.fd)
    try:
        _entry(directory, name, fd, 0, 0o600)
        _write_all(fd, data)
        os.fchmod(fd, 0o400)
        os.fsync(fd)
        _entry(directory, name, fd, len(data), 0o400)
        os.fsync(directory.fd)
    finally:
        os.close(fd)


def _read_record(directory, name):
    fd = os.open(name, os.O_RDONLY | _FLAGS, dir_fd=directory.fd)
    try:
        before = _entry(directory, name, fd, _RECORD_BYTES, 0o400)
        data = bytearray()
        while len(data) <= _RECORD_BYTES:
            chunk = os.read(fd, _RECORD_BYTES + 1 - len(data))
            if not chunk:
                break
            data.extend(chunk)
        if _entry(directory, name, fd, _RECORD_BYTES, 0o400) != before or len(data) != before[2]:
            raise _invalid()
        value = loads(bytes(data), max_bytes=_RECORD_BYTES)
        if canonical_bytes(value) != data:
            raise _invalid()
        return value, hashlib.sha256(data).hexdigest(), before
    finally:
        os.close(fd)


def _serialized(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return call


class PrivateCapture:
    """Fresh private sink. Overflow retains the allowed prefix and marks limited.

    ``max_records`` includes the initial and final checkpoint. One record slot is
    reserved for finalize; exhausted checkpoint/event capacity is explicit in the
    receipt. ``observe`` stores bounded strict JSON, without usage interpretation.
    Caller must stop a producer when limits are reached; this class has no process
    effects. A failed write/checkpoint poisons the sink and preserves its files.
    Public operations serialize on one reentrant lock, including aggregate byte
    reservations and closure, so independent stream reader threads may share it.
    ``schema_version="2.0"`` explicitly opts into a maximum 64 MiB raw budget;
    legacy 1.0 remains capped at 4 MiB. Checkpoint metadata stays independently
    capped at 8,192 records, regardless of native protocol record limits.
    """
    def __init__(self, root, *, max_output_bytes=_MAX_OUTPUT, max_records=_MAX_RECORDS,
                 schema_version="1.0"):
        ceiling = _output_ceiling(schema_version)
        if (not _integer(max_output_bytes, ceiling) or not _integer(max_records, _MAX_RECORDS)
                or max_records < 2):
            raise _invalid()
        self._lock = RLock()
        self._directory = None
        self._fds = {}
        self._closed = self._finalized = self._failed = False
        self._closure_bytes = None
        self._closure_metadata = {}
        self._limit = max_output_bytes
        self._max_records = max_records
        self._sequence = 0
        self._previous = None
        self._observed = dict.fromkeys(_STREAMS, 0)
        self._retained = dict.fromkeys(_STREAMS, 0)
        self._hashes = {s: hashlib.sha256() for s in _STREAMS}
        self._states = {}
        self._events = []
        self._events_observed = self._events_retained = 0
        self._metadata_limited = False
        self._since_checkpoint = 0
        try:
            self._directory = _Directory(root, create=True)
            config = {"kind": "private_local_provider_capture", "schema_version": schema_version,
                      "max_output_bytes": max_output_bytes, "max_records": max_records}
            data = canonical_bytes(config)
            _immutable(self._directory, "capture.json", data)
            self._config_hash = hashlib.sha256(data).hexdigest()
            for stream in _STREAMS:
                name = stream + ".bin"
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | _FLAGS, 0o600, dir_fd=self._directory.fd)
                self._fds[stream] = fd
                self._states[stream] = _entry(self._directory, name, fd, 0, 0o600)
            self._checkpoint(finalized=False)
        except (OSError, ValueError, TypeError, TaskAlongError):
            self.close()
            raise _invalid() from None

    @property
    @_serialized
    def limited(self) -> bool:
        """Signal the owner to stop its producer; no cancellation occurs here."""
        return self._metadata_limited or sum(self._observed.values()) > sum(self._retained.values())

    def _active(self):
        if self._closed or self._finalized or self._failed:
            raise _invalid()

    @_serialized
    def write(self, stream, chunk: bytes) -> None:
        self._active()
        if type(stream) is not str or stream not in _STREAMS or type(chunk) is not bytes:
            raise _invalid()
        if self._observed[stream] + len(chunk) > _INTEGER:
            raise _invalid()
        allowed = min(len(chunk), self._limit - sum(self._retained.values()))
        try:
            fd = self._fds[stream]
            before = _entry(self._directory, stream + ".bin", fd, self._limit, 0o600)
            if before != self._states[stream] or before[2] != self._retained[stream]:
                raise _invalid()
            def advance(part):
                self._hashes[stream].update(part)
                self._retained[stream] += len(part)
                self._since_checkpoint += len(part)
            offset = 0
            while offset < allowed:
                end = min(allowed, offset + _CADENCE - self._since_checkpoint)
                self._observed[stream] += end - offset
                _write_all(fd, memoryview(chunk)[offset:end], advance)
                offset = end
                self._states[stream] = _entry(self._directory, stream + ".bin", fd, self._limit, 0o600)
                if self._since_checkpoint >= _CADENCE:
                    self.checkpoint()
                    # Once index capacity is exhausted, raw retention still has
                    # its separate finite bound; don't spin at a zero cadence.
                    self._since_checkpoint = 0
            self._observed[stream] += len(chunk) - allowed
        except (OSError, ValueError, TypeError, TaskAlongError):
            self._failed = True
            raise _invalid() from None

    @_serialized
    def observe(self, event: Mapping) -> None:
        self._active()
        if not isinstance(event, Mapping):
            raise _invalid()
        data = canonical_bytes(dict(event))
        if self._events_observed == _INTEGER:
            raise _invalid()
        if len(data) > _EVENT_BYTES:
            self._events_observed += 1
            self._metadata_limited = True
            return
        if len(self._events) == 2:
            self.checkpoint()
        self._events_observed += 1
        if len(self._events) == 2:
            self._metadata_limited = True
            return
        self._events.append(loads(data))
        self._events_retained += 1

    def _snapshot(self, finalized):
        return {"schema_version": "1.0", "kind": "private_capture_checkpoint",
                "sequence": self._sequence, "config_sha256": self._config_hash,
                "previous_sha256": self._previous, "finalized": finalized,
                "output_limited": sum(self._observed.values()) > sum(self._retained.values()),
                "metadata_limited": self._metadata_limited,
                "observations": {"observed": self._events_observed, "retained": self._events_retained},
                "events": self._events,
                "streams": {s: {"path": s + ".bin", "observed_bytes": self._observed[s],
                                "retained_bytes": self._retained[s], "sha256": self._hashes[s].hexdigest()}
                            for s in _STREAMS}}

    def _checkpoint(self, *, finalized):
        try:
            self._directory.check()
            expected = {"capture.json", *(s + ".bin" for s in _STREAMS),
                        *(f"record-{i:06d}.json" for i in range(self._sequence))}
            if self._directory.names() != expected:
                raise _invalid()
            for stream, fd in self._fds.items():
                if _entry(self._directory, stream + ".bin", fd, self._limit, 0o600) != self._states[stream]:
                    raise _invalid()
                os.fsync(fd)  # Raw bytes precede the immutable index record.
            data = canonical_bytes(self._snapshot(finalized))
            if len(data) > _RECORD_BYTES:
                raise _invalid()
            _immutable(self._directory, f"record-{self._sequence:06d}.json", data)
            self._previous = hashlib.sha256(data).hexdigest()
            self._sequence += 1
            self._events = []
            self._since_checkpoint = 0
        except (OSError, ValueError, TypeError, TaskAlongError):
            self._failed = True
            raise _invalid() from None

    @_serialized
    def checkpoint(self) -> None:
        self._active()
        if self._sequence >= self._max_records - 1:
            self._metadata_limited = True
            return
        self._checkpoint(finalized=False)

    @_serialized
    def finalize(self) -> dict:
        self._active()
        self._checkpoint(finalized=True)
        self._finalized = True
        # Independent readback is mandatory before exposing a closure receipt.
        try:
            metadata = {}
            receipt = _read_capture_fd(self._directory, _metadata_states=metadata)
            # The caller receives a mutable dict, never the internal expectation.
            self._closure_bytes = canonical_bytes(receipt)
            self._closure_metadata = metadata
            return receipt
        except (OSError, ValueError, TypeError, KeyError, TaskAlongError):
            self._failed = True
            raise _invalid() from None

    def _readable(self):
        if self._closed or not self._finalized or self._failed:
            raise _invalid()

    @_serialized
    def iter_records(self, stream, *, max_record_bytes=_MAX_ITER_RECORD_BYTES):
        """Yield finalized physical lines without LF, including empty lines.

        This is a lazy evidence reader, not a proposal-acceptance receipt. The
        consumer MUST exhaust it before staging any result: full byte/hash and
        immutable metadata/closure fences run at exhaustion. Nonempty trailing
        bytes without LF reject.
        Only one bounded frame and 64 KiB read window are assembled; raw files
        stay on disk. The per-record limit excludes the terminating LF.
        """
        self._readable()
        if (type(stream) is not str or stream not in _STREAMS
                or not _integer(max_record_bytes, _MAX_ITER_RECORD_BYTES)
                or max_record_bytes == 0):
            raise _invalid()
        return self._iter_records(stream, max_record_bytes)

    def _iter_records(self, stream, maximum):
        pending = bytearray()
        hashed = hashlib.sha256()
        position = 0
        try:
            with self._lock:
                self._readable()
                expected = self._states[stream]
                size = self._retained[stream]
                expected_hash = self._hashes[stream].hexdigest()
            while position < size:
                with self._lock:
                    self._readable()
                    fd = self._fds[stream]
                    if _entry(self._directory, stream + ".bin", fd, self._limit, 0o600) != expected:
                        raise _invalid()
                    chunk = os.pread(fd, min(_CADENCE, size - position), position)
                    if not chunk:
                        raise _invalid()
                    if _entry(self._directory, stream + ".bin", fd, self._limit, 0o600) != expected:
                        raise _invalid()
                position += len(chunk)
                hashed.update(chunk)
                offset = 0
                while offset < len(chunk):
                    newline = chunk.find(b"\n", offset)
                    end = len(chunk) if newline < 0 else newline
                    if len(pending) + end - offset > maximum:
                        raise _invalid()
                    pending.extend(chunk[offset:end])
                    if newline < 0:
                        break
                    record = bytes(pending)
                    pending.clear()
                    # Release the lock across yields; a concurrent close is
                    # allowed, and must fail the resumed reader before proof.
                    with self._lock:
                        self._readable()
                        if _entry(self._directory, stream + ".bin", self._fds[stream], self._limit, 0o600) != expected:
                            raise _invalid()
                    yield record
                    del record
                    offset = end + 1
            with self._lock:
                self._readable()
                if pending or position != size or hashed.hexdigest() != expected_hash:
                    raise _invalid()
                # A later stream can never invalidate an earlier raw proof
                # silently while the consumer processes yielded records.
                for name, fd in self._fds.items():
                    if _entry(self._directory, name + ".bin", fd, self._limit, 0o600) != self._states[name]:
                        raise _invalid()
                # Revalidate all immutable config/index records and every raw
                # stream, then compare against the private finalize snapshot.
                # This rereads disk sequentially; it never assembles the whole
                # capture. Identity checks also reject same-content replacement.
                metadata = {}
                receipt = _read_capture_fd(self._directory, _metadata_states=metadata)
                if (canonical_bytes(receipt) != self._closure_bytes
                        or metadata != self._closure_metadata):
                    raise _invalid()
        except (OSError, ValueError, TypeError, KeyError, TaskAlongError):
            raise _invalid() from None

    @_serialized
    def close(self) -> None:
        for fd in self._fds.values():
            os.close(fd)
        self._fds = {}
        if self._directory is not None:
            self._directory.close()
            self._directory = None
        self._closed = True


def _validate_record(record, sequence, previous, config_hash, old, event_count, config):
    required = {"schema_version", "kind", "sequence", "config_sha256", "previous_sha256",
                "finalized", "output_limited", "metadata_limited", "observations", "events", "streams"}
    if (set(record) != required or record["schema_version"] != "1.0"
            or record["kind"] != "private_capture_checkpoint"
            or not _integer(record["sequence"]) or record["sequence"] != sequence
            or record["config_sha256"] != config_hash or record["previous_sha256"] != previous
            or any(type(record[key]) is not bool for key in ("finalized", "output_limited", "metadata_limited"))
            or type(record["streams"]) is not dict or set(record["streams"]) != set(_STREAMS)
            or type(record["events"]) is not list or len(record["events"]) > 2
            or any(type(e) is not dict or len(canonical_bytes(e)) > _EVENT_BYTES for e in record["events"])):
        raise _invalid()
    obs = record["observations"]
    if (type(obs) is not dict or set(obs) != {"observed", "retained"}
            or not _integer(obs["observed"]) or not _integer(obs["retained"])
            or not event_count + len(record["events"]) == obs["retained"] <= obs["observed"]):
        raise _invalid()
    for stream in _STREAMS:
        value = record["streams"][stream]
        if (type(value) is not dict or set(value) != {"path", "observed_bytes", "retained_bytes", "sha256"}
                or value["path"] != stream + ".bin" or not _sha(value["sha256"])
                or not _integer(value["observed_bytes"]) or not _integer(value["retained_bytes"], config["max_output_bytes"])
                or not value["retained_bytes"] <= value["observed_bytes"]
                or old is not None and (value["retained_bytes"] < old["streams"][stream]["retained_bytes"]
                    or value["observed_bytes"] < old["streams"][stream]["observed_bytes"])):
            raise _invalid()
    retained = sum(v["retained_bytes"] for v in record["streams"].values())
    observed = sum(v["observed_bytes"] for v in record["streams"].values())
    if (retained > config["max_output_bytes"] or record["output_limited"] != (observed > retained)
            or record["output_limited"] and retained != config["max_output_bytes"]
            or obs["observed"] > obs["retained"] and not record["metadata_limited"]
            or old is not None and (old["finalized"] or obs["observed"] < old["observations"]["observed"]
                or old["metadata_limited"] and not record["metadata_limited"])):
        raise _invalid()


def _read_capture_fd(directory, *, _metadata_states=None):
    if _metadata_states is not None and (type(_metadata_states) is not dict or _metadata_states):
        raise _invalid()
    config, config_hash, config_state = _read_record(directory, "capture.json")
    immutable_states = {"capture.json": config_state}
    ceiling = _output_ceiling(config.get("schema_version"))
    if (set(config) != {"kind", "schema_version", "max_output_bytes", "max_records"}
            or config["kind"] != "private_local_provider_capture"
            or not _integer(config["max_output_bytes"], ceiling)
            or not _integer(config["max_records"], _MAX_RECORDS) or config["max_records"] < 2):
        raise _invalid()
    names = directory.names()
    base = {"capture.json", *(s + ".bin" for s in _STREAMS)}
    count = len(names - base)
    if count > config["max_records"] or names != base | {f"record-{i:06d}.json" for i in range(count)}:
        raise _invalid()
    fds, states = {}, {}
    hashes = {s: hashlib.sha256() for s in _STREAMS}
    offsets = dict.fromkeys(_STREAMS, 0)
    old = previous = None
    event_count = 0
    try:
        for stream in _STREAMS:
            fd = os.open(stream + ".bin", os.O_RDONLY | _FLAGS, dir_fd=directory.fd)
            fds[stream] = fd
            states[stream] = _entry(directory, stream + ".bin", fd, config["max_output_bytes"], 0o600)
        if sum(info[2] for info in states.values()) > config["max_output_bytes"]:
            raise _invalid()
        for sequence in range(count):
            name = f"record-{sequence:06d}.json"
            record, digest, record_state = _read_record(directory, name)
            immutable_states[name] = record_state
            _validate_record(record, sequence, previous, config_hash, old, event_count, config)
            for stream in _STREAMS:
                size = record["streams"][stream]["retained_bytes"]
                while offsets[stream] < size:
                    chunk = os.read(fds[stream], min(_CADENCE, size - offsets[stream]))
                    if not chunk:
                        raise _invalid()
                    hashes[stream].update(chunk)
                    offsets[stream] += len(chunk)
                if hashes[stream].hexdigest() != record["streams"][stream]["sha256"]:
                    raise _invalid()
            event_count = record["observations"]["retained"]
            old, previous = record, digest
        streams = {}
        for stream in _STREAMS:
            tail = states[stream][2] - offsets[stream]
            if old is not None and old["finalized"] and tail:
                raise _invalid()
            remaining = tail
            while remaining:
                chunk = os.read(fds[stream], min(_CADENCE, remaining))
                if not chunk:
                    raise _invalid()
                hashes[stream].update(chunk)
                remaining -= len(chunk)
            if _entry(directory, stream + ".bin", fds[stream], config["max_output_bytes"], 0o600) != states[stream]:
                raise _invalid()
            streams[stream] = {"path": stream + ".bin", "actual_bytes": states[stream][2],
                "retained_bytes": states[stream][2], "sha256": hashes[stream].hexdigest(), "checkpointed_bytes": offsets[stream],
                "uncheckpointed_bytes": tail,
                "observed_bytes": old["streams"][stream]["observed_bytes"] if old else 0}
        if directory.names() != names:
            raise _invalid()
        for name, before in immutable_states.items():
            info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
            _regular(info, _RECORD_BYTES, 0o400)
            if _state(info) != before:
                raise _invalid()
        # A later stream or metadata check must not invalidate an earlier raw
        # hash unnoticed. Fence every held raw inode and its named entry again
        # after all bytes and immutable metadata have been validated.
        for stream, fd in fds.items():
            if _entry(directory, stream + ".bin", fd, config["max_output_bytes"], 0o600) != states[stream]:
                raise _invalid()
        directory.check()
        if _metadata_states is not None:
            _metadata_states.update(immutable_states)
        finalized = old is not None and old["finalized"]
        limited = old is not None and (old["output_limited"] or old["metadata_limited"])
        return {"kind": "private_local_provider_capture", "schema_version": config["schema_version"],
                "byte_closure": finalized, "status": "limited" if finalized and limited else "closed" if finalized else "incomplete",
                "output_limited": old["output_limited"] if old else False,
                "metadata_limited": old["metadata_limited"] if old else False,
                "observations": old["observations"] if old else {"observed": 0, "retained": 0},
                "records": count, "last_record_sha256": previous, "config_sha256": config_hash,
                "observed_counts_complete": finalized, "streams": streams}
    finally:
        for fd in fds.values():
            os.close(fd)


def read_capture(root) -> dict:
    """Validate every record and byte prefix; incomplete tails never imply closure.

    Observed counts are checkpoint lower bounds until finalized. Raw bytes can be
    read separately from the referenced private files; no output is decoded here.
    A torn/malformed record is an error, never an ignored last line.
    """
    directory = None
    try:
        directory = _Directory(root)
        return _read_capture_fd(directory)
    except (OSError, ValueError, TypeError, KeyError, TaskAlongError):
        raise _invalid() from None
    finally:
        if directory is not None:
            directory.close()
