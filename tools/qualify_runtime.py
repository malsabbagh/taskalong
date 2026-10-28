#!/usr/bin/env python3
"""Explicit no-inference host experiments; measurement never enables dispatch."""
from __future__ import annotations

import argparse
import json
import sys


STAGES = ("inventory", "model-free", "installed-replay", "controlled-responder",
          "actual-provider", "native-resume")
UNSUPPORTED_STAGES = {"controlled-responder", "actual-provider", "native-resume"}


class _Blocked(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class _Failed(_Blocked):
    pass


class _PrivateEvidence:
    """New private destination, fixed names and hash-derived blobs only."""
    def __init__(self, destination):
        import os
        from pathlib import Path

        self.parent_fd = self.root_fd = self.blobs_fd = None
        self.cases_fd = None
        self.case_fds = []
        self.checked_paths = []
        self.blobs = {}
        self.first_error = None
        self.verifier_watch = None
        self.verifier_privilege = None
        self.cleanup_uncertain = False
        try:
            selected = Path(destination)
            if selected.name in {"", ".", ".."}:
                raise ValueError("unsafe leaf")
            parent = selected.parent.resolve(strict=True)
            self.path = parent / selected.name
            self.parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            os.mkdir(selected.name, 0o700, dir_fd=self.parent_fd)
            self.root_fd = os.open(selected.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                   dir_fd=self.parent_fd)
            os.fchmod(self.root_fd, 0o700)
            os.mkdir("blobs", 0o700, dir_fd=self.root_fd)
            self.blobs_fd = os.open("blobs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=self.root_fd)
            os.fchmod(self.blobs_fd, 0o700)
            self.checked_paths.extend([(parent, self.parent_fd), (self.path, self.root_fd),
                                       (self.path / "blobs", self.blobs_fd)])
            os.fsync(self.parent_fd)
        except (OSError, ValueError):
            self.close()
            raise _Blocked("runtime_evidence_destination_unsafe") from None

    def _write(self, directory, name, raw):
        import os

        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(directory)

    def verify_paths(self):
        """Detect substitution of the private paths used by the owned child.

        This cooperative identity check is not hostile same-user isolation.
        """
        import os
        import stat

        for path, fd in self.checked_paths:
            expected, actual = os.fstat(fd), path.lstat()
            if (not stat.S_ISDIR(actual.st_mode) or (expected.st_dev, expected.st_ino) !=
                    (actual.st_dev, actual.st_ino)):
                raise _Failed("runtime_evidence_destination_changed")

    def blob(self, raw, media="application/json"):
        import hashlib

        if type(raw) is not bytes or len(raw) > 65536 or media not in {"application/json", "application/octet-stream"}:
            raise _Failed("runtime_evidence_limit")
        key = hashlib.sha256(raw).hexdigest()
        if key not in self.blobs:
            if len(self.blobs) >= 64 or sum(map(len, self.blobs.values())) + len(raw) > 4 * 1024 * 1024:
                raise _Failed("runtime_evidence_limit")
            self._write(self.blobs_fd, key + ".bin", raw)
            self.blobs[key] = raw
        elif self.blobs[key] != raw:
            raise _Failed("runtime_evidence_changed")
        return {"sha256": key, "size_bytes": len(raw), "media_type": media, "classification": "private"}

    def manifest(self, raw):
        if len(raw) > 1048576:
            raise _Failed("runtime_evidence_limit")
        self._write(self.root_fd, "manifest.json", raw)

    def replay_report(self, raw):
        if type(raw) is not bytes or len(raw) > 1048576:
            raise _Failed("runtime_evidence_limit")
        self._write(self.root_fd, "replay-report.json", raw)

    def note_failure(self, code):
        if self.root_fd is not None:
            try:
                self._write(self.root_fd, "failure.json", json.dumps({"code": code,
                    "primary_error": self.first_error, "cleanup_uncertain": self.cleanup_uncertain,
                    "durable_evidence": False, "production_dispatch_allowed": False}).encode() + b"\n")
            except OSError:
                pass  # Preserve the original error, not a secondary write error.

    def case_directory(self, name, payload, control):
        import os

        if name not in {"permitted-read", "permitted-write", "bounded-capture", "predispatch-tool-denial",
                        "owned-completion", "closed-gate-cancel", "running-cancel"}:
            raise _Failed("runtime_case_invalid")
        if self.cases_fd is None:
            os.mkdir("cases", 0o700, dir_fd=self.root_fd)
            self.cases_fd = os.open("cases", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.root_fd)
            self.case_fds.append(self.cases_fd)
            self.checked_paths.append((self.path / "cases", self.cases_fd))
        os.mkdir(name, 0o700, dir_fd=self.cases_fd)
        case_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.cases_fd)
        self.case_fds.append(case_fd)
        self.checked_paths.append((self.path / "cases" / name, case_fd))
        directories = {}
        for child in ("workspace", "home", "config", "cache", "data", "tmp", "control"):
            os.mkdir(child, 0o700, dir_fd=case_fd)
            fd = os.open(child, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=case_fd)
            os.fchmod(fd, 0o700)
            self.case_fds.append(fd)
            self.checked_paths.append((self.path / "cases" / name / child, fd))
            directories[child] = fd
        self._write(directories["workspace"], "permitted.txt", payload)
        self._write(directories["control"], "forbidden.txt", control)
        return {"path": self.path / "cases" / name, "fd": case_fd, **directories}

    def read_owned(self, directory, name, *, missing=False, maximum=65536):
        import os
        import stat

        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            if missing:
                return None
            raise
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                raise _Failed("runtime_evidence_limit")
            raw = source.read(maximum + 1)
            after = os.fstat(source.fileno())
            if len(raw) > maximum or (before.st_ino, before.st_size, before.st_mtime_ns) != (
                    after.st_ino, after.st_size, after.st_mtime_ns):
                raise _Failed("runtime_evidence_changed")
        return raw

    def close(self):
        import os

        ok = True
        while self.case_fds:
            try:
                os.close(self.case_fds.pop())
            except OSError:
                ok = False
        self.cases_fd = None
        for key in ("blobs_fd", "root_fd", "parent_fd"):
            fd = getattr(self, key, None)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    ok = False
                setattr(self, key, None)
        return ok


def _measure(path, deadline, *, maximum=8388608, selected_interpreter=False):
    import hashlib
    import os
    import stat
    import time
    from pathlib import Path

    original = Path(path)
    target = original.resolve(strict=True) if selected_interpreter else original
    if time.monotonic() >= deadline:
        raise _Blocked("runtime_inventory_deadline")
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise _Blocked("runtime_inventory_limit")
        digest = hashlib.sha256()
        total = 0
        while True:
            if time.monotonic() >= deadline:
                raise _Blocked("runtime_inventory_deadline")
            raw = source.read(65536)
            if not raw:
                break
            total += len(raw)
            if total > maximum:
                raise _Blocked("runtime_inventory_limit")
            digest.update(raw)
        after = os.fstat(source.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise _Failed("runtime_inputs_changed")
    return {"sha256": digest.hexdigest(), "size_bytes": total}


def _bounded_input(path, deadline, maximum=65536):
    import os
    import stat
    import time

    if time.monotonic() >= deadline:
        raise _Blocked("runtime_inventory_deadline")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise _Blocked("runtime_inventory_limit")
        raw = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        if (len(raw) > maximum or time.monotonic() >= deadline
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                   (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise _Failed("runtime_inputs_changed")
    return raw


def _helper_path(origin):
    from pathlib import Path

    root = Path(__file__).absolute().parent.parent
    return root / ("tests" if origin == "source" else "installed-tests") / "fixtures" / "runtime_canary.py"


def _metadata_path(distribution):
    files = distribution.files
    if files is None or len(files) > 8192:
        raise _Blocked("runtime_dependency_unavailable")
    matches = [p for p in files if len(p.parts) == 2 and p.parts[0].endswith(".dist-info") and p.parts[1] == "METADATA"]
    if len(matches) != 1:
        raise _Blocked("runtime_dependency_unavailable")
    return distribution.locate_file(matches[0])


def _controller_privilege():
    """Observe only the current effective UID; never request identity changes."""
    import os

    getter = getattr(os, "geteuid", None)
    try:
        uid = getter() if callable(getter) else None
    except (OSError, NotImplementedError):
        raise _Blocked("runtime_privilege_unavailable") from None
    if type(uid) is not int or not 0 <= uid <= 2**32 - 1:
        raise _Blocked("runtime_privilege_unavailable")
    return {"scope": "controller", "effective_uid": uid,
            "class": "effective_uid_zero" if uid == 0 else "effective_uid_nonzero"}


def _recheck_privilege(expected):
    try:
        current = _controller_privilege()
    except _Blocked as error:
        raise _Failed(error.code) from None
    if current != expected:
        raise _Failed("runtime_inputs_changed")


def _distribution(name):
    from importlib.metadata import distribution, PackageNotFoundError

    try:
        return distribution(name)
    except PackageNotFoundError:
        raise _Blocked("runtime_dependency_unavailable") from None


def _locked_requirements(raw):
    """Select exact locked pins using the current interpreter's PEP 508 markers."""
    import re

    try:
        from packaging.requirements import InvalidRequirement, Requirement
        from packaging.utils import canonicalize_name
    except ImportError:
        raise _Blocked("runtime_dependency_unavailable") from None
    try:
        lines = re.sub(r"\\\r?\n", " ", raw.decode()).splitlines()
        requirements = []
        seen = set()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            requirement = Requirement(line.split(" --hash=", 1)[0])
            pins = list(requirement.specifier)
            name = canonicalize_name(requirement.name)
            if (requirement.url or requirement.extras or len(pins) != 1
                    or pins[0].operator != "==" or "*" in pins[0].version or name in seen):
                raise _Blocked("runtime_inventory_invalid")
            seen.add(name)
            if requirement.marker is None or requirement.marker.evaluate():
                requirements.append((requirement.name, pins[0].version))
        if not 1 <= len(seen) <= 32:
            raise _Blocked("runtime_inventory_invalid")
        return requirements
    except (UnicodeError, InvalidRequirement):
        raise _Blocked("runtime_inventory_invalid") from None


def _inventory_measurements(deadline, origin, artifact_inventory=None):
    import hashlib
    import importlib
    import importlib.metadata
    import platform
    import re
    import select
    import time
    import tomllib
    from pathlib import Path

    root = Path(__file__).absolute().parent.parent
    source_root = root / "src"
    if origin == "source" and str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))
    try:
        package = importlib.import_module("taskalong")
    except ImportError:
        raise _Blocked("runtime_package_unavailable") from None
    try:
        rq = importlib.import_module("taskalong.runtime_qualification")
    except ImportError:
        raise _Blocked("runtime_dependency_unavailable") from None
    package_root = Path(package.__file__).absolute().parent
    watch = []
    frozen = None
    if origin == "source":
        if package_root.resolve() != (source_root / "taskalong").resolve():
            raise _Blocked("runtime_package_origin_mismatch")
        inventory_path = root / "distribution-inventory.json"
        raw = _bounded_input(inventory_path, deadline)
        declared = rq.loads(raw, max_bytes=65536)
        paths = declared["wheel_sources"]
        if type(paths) is not list or len(paths) > 512 or len(set(paths)) != len(paths):
            raise _Blocked("runtime_inventory_invalid")
        names = [name.removeprefix("src/") for name in paths if type(name) is str and name.startswith("src/taskalong/")]
        if len(names) != len(paths):
            raise _Blocked("runtime_inventory_invalid")
        watch.append((inventory_path, {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}, False, 65536))
    else:
        if artifact_inventory is None:
            raise _Blocked("runtime_installed_inventory_required")
        if (package_root.is_symlink() or not package_root.resolve().is_relative_to(Path(sys.prefix).resolve())
                or package_root.resolve().is_relative_to(root)):
            raise _Blocked("runtime_package_origin_mismatch")
        distribution = _distribution("taskalong")
        located = Path(distribution.locate_file("taskalong/__init__.py")).absolute()
        if (package_root / "__init__.py" != located or package_root.is_symlink()
                or not package_root.resolve().is_relative_to(Path(sys.prefix).resolve())
                or package_root.resolve().is_relative_to(root)):
            raise _Blocked("runtime_package_origin_mismatch")
        raw = _bounded_input(Path(artifact_inventory), deadline)
        frozen = rq.loads(raw, max_bytes=65536)
        rq._shape(frozen, {"kind", "format_version", "artifact_digest", "source_artifact_digest", "source_artifact_kind",
                           "package_version", "payloads", "metadata_sha256", "lock_sha256", "runner_sha256", "helper_sha256", "digest"})
        if (frozen["kind"] != "runtime_artifact_inventory" or frozen["format_version"] != "1.0"
                or frozen["digest"] != rq.digest(frozen)
                or any(not rq._sha(frozen[k]) for k in ("artifact_digest", "source_artifact_digest", "metadata_sha256",
                                                       "lock_sha256", "runner_sha256", "helper_sha256"))
                or frozen["source_artifact_kind"] not in {"wheel", "sdist"}
                or frozen["package_version"] != distribution.version
                or type(frozen["payloads"]) is not dict or not 1 <= len(frozen["payloads"]) <= 512):
            raise _Blocked("runtime_installed_inventory_invalid")
        names = sorted(frozen["payloads"])
        watch.append((Path(artifact_inventory), {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}, False, 65536))
    if not {"taskalong/runtime_qualification.py", "taskalong/resources/qualification/v1/proof-manifest.schema.json"} <= set(names):
        raise _Blocked("runtime_inventory_invalid")
    payloads = {}
    for name in names:
        if (type(name) is not str or not name.startswith("taskalong/") or len(name) > 512
                or any(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", part) is None for part in name.split("/"))):
            raise _Blocked("runtime_inventory_invalid")
        path = package_root.parent / name
        if any(parent.is_symlink() for parent in (path, *path.parents) if parent.is_relative_to(package_root)):
            raise _Blocked("runtime_package_origin_mismatch")
        info = _measure(path, deadline)
        payloads[name] = info
        watch.append((path, info, False, 8388608))
    if frozen is not None and payloads != frozen["payloads"]:
        raise _Blocked("runtime_installed_payload_changed")
    if sum(info["size_bytes"] for info in payloads.values()) > 16 * 1024 * 1024:
        raise _Blocked("runtime_inventory_limit")
    lock_path = root / "requirements-dev.lock"
    lock_raw = _bounded_input(lock_path, deadline)
    lock = {"sha256": hashlib.sha256(lock_raw).hexdigest(), "size_bytes": len(lock_raw)}
    requirements = _locked_requirements(lock_raw)
    dependencies = []
    for name, expected in requirements:
        if time.monotonic() >= deadline:
            raise _Blocked("runtime_inventory_deadline")
        distribution = _distribution(name)
        metadata_path = _metadata_path(distribution)
        metadata = _measure(metadata_path, deadline, maximum=1048576)
        if distribution.version != expected:
            raise _Blocked("runtime_dependency_unavailable")
        dependencies.append({"name": name, "version": distribution.version, "metadata_sha256": metadata["sha256"]})
        watch.append((metadata_path, metadata, False, 1048576))
    if origin == "source":
        project_path = root / "pyproject.toml"
        project_raw = _bounded_input(project_path, deadline)
        project_info = {"sha256": hashlib.sha256(project_raw).hexdigest(), "size_bytes": len(project_raw)}
        package_version = tomllib.loads(project_raw.decode())["project"]["version"]
    else:
        distribution = _distribution("taskalong")
        project_path = _metadata_path(distribution)
        project_info = _measure(project_path, deadline, maximum=1048576)
        package_version = distribution.version
        if (project_info["sha256"] != frozen["metadata_sha256"] or lock["sha256"] != frozen["lock_sha256"]):
            raise _Blocked("runtime_installed_inventory_changed")
    package_info = {"origin": origin, "artifact_digest": None if frozen is None else frozen["artifact_digest"],
                    "source_artifact_digest": None if frozen is None else frozen["source_artifact_digest"],
                    "source_artifact_kind": None if frozen is None else frozen["source_artifact_kind"],
                    "version": package_version, "payloads": payloads, "dependencies": dependencies,
                    "lock_sha256": lock["sha256"], "project_metadata_sha256": project_info["sha256"]}
    executable = _measure(Path(sys.executable), deadline, selected_interpreter=True, maximum=67108864)
    interpreter = {"invocation_path": sys.executable, "executable_sha256": executable["sha256"],
                   "version": sys.version, "implementation": sys.implementation.name,
                   "prefix": sys.prefix, "base_prefix": sys.base_prefix}
    host = {"system": platform.system(), "release": platform.release(),
            "version": platform.version(), "machine": platform.machine(), "privilege": _controller_privilege()}
    backend = ("linux-child-subreaper" if sys.platform == "linux" else
               "darwin-kqueue-no-fork" if sys.platform == "darwin" and hasattr(select, "kqueue") else "unsupported")
    components = {name: payloads[name] for name in ("taskalong/process.py", "taskalong/_linux_lifetime.py")
                  if name in payloads and (sys.platform == "linux" or name.endswith("/process.py"))}
    backend_digest = rq.digest(components, exclude_digest=False) if backend != "unsupported" else None
    runner = _measure(Path(__file__).absolute(), deadline)
    helper_path = _helper_path(origin)
    helper = _measure(helper_path, deadline)
    test_digest = rq.digest({"profile": "owned-host-canaries-v1", "oracle_version": "1.0",
                             "case_ids": list(rq.HOST_CASES)}, exclude_digest=False)
    watch.extend([(lock_path, lock, False, 65536), (project_path, project_info, False, 1048576),
                  (Path(sys.executable), executable, True, 67108864),
                  (Path(__file__).absolute(), runner, False, 8388608), (helper_path, helper, False, 8388608)])
    if frozen is not None and (runner["sha256"] != frozen["runner_sha256"] or helper["sha256"] != frozen["helper_sha256"]):
        raise _Blocked("runtime_installed_harness_changed")
    import os
    facts = {"host": host, "interpreter": interpreter, "package": package_info,
             "backend": {"id": backend, "implementation_digest": backend_digest, "components": components},
             "runner_digest": runner["sha256"], "helper_digest": helper["sha256"],
             "test_inventory_digest": test_digest, "controller_pid": os.getpid()}
    return rq, facts, watch


def _run_canaries(rq, writer, plan, context, facts, campaign_deadline):
    import hashlib
    import time
    from dataclasses import asdict
    from pathlib import Path
    from taskalong import process

    helper = _helper_path(plan["package_origin"])
    cases = []
    first_error = None
    quarantined = False
    helper_invocations = owned_invocations = 0
    execution_started = time.monotonic()
    if not rq.ExperimentPlan.from_dict(plan).executable:
        first_error = {"case_id": None, "code": "runtime_lifecycle_unsupported"}
    for name in plan["case_ids"]:
        case = {"id": name, "campaign_id": plan["campaign_id"], "verdict": "not_run",
                "capability": "unknown", "reason": "not_run_after_failure", "dispatch": "not_sent",
                "process_ref": None, "capture_refs": None, "observation_ref": None}
        if first_error is not None:
            cases.append(case)
            continue
        remaining = campaign_deadline - time.monotonic()
        if remaining <= 0:
            first_error = {"case_id": None, "code": "runtime_campaign_deadline"}
            cases.append(case)
            continue
        payload = context["payload"].encode()
        control = ("taskalong-control-" + context["nonce"]).encode()
        directory = writer.case_directory(name, payload, control)
        writer.verify_paths()
        request = {"campaign_id": plan["campaign_id"], "case_id": name,
                   "nonce": context["nonce"], "payload": context["payload"]}
        stdin = rq.canonical_bytes(request) + b"\n"
        observed = {"campaign_id": plan["campaign_id"], "case_id": name, "nonce": context["nonce"],
                    "target_invocations": 0, "invocation_ref": None, "effect_ref": None,
                    "control_ref": None, "input_consumed": False, "policy_refused": False,
                    "boundary_error": None, "timeout_ms": 0}
        case.update(verdict="passed", capability="unsupported" if name == "predispatch-tool-denial" else "supported",
                    reason="oracle_passed")
        result = None
        capture = {}
        if name == "predispatch-tool-denial":
            observed["policy_refused"] = True
            observed["control_ref"] = writer.blob(writer.read_owned(directory["control"], "forbidden.txt"),
                                                   "application/octet-stream")
        else:
            ready = {"seen": False}

            def on_line(line):
                frame = rq.loads(line)
                if (frame.get("event") == "ready" and frame.get("case_id") == name
                        and frame.get("campaign_id") == plan["campaign_id"] and frame.get("nonce") == context["nonce"]
                        and frame.get("input_sha256") == hashlib.sha256(stdin).hexdigest()):
                    ready["seen"] = True

            def closed_gate(_receipt):
                raise process.ProcessBoundaryError("Qualification gate cancellation.",
                    code="qualification_gate_cancelled", effect_outcome="not_sent")

            env = process.minimal_environment()
            for key, child in (("HOME", "home"), ("XDG_CONFIG_HOME", "config"),
                               ("XDG_CACHE_HOME", "cache"), ("XDG_DATA_HOME", "data"), ("TMPDIR", "tmp")):
                env[key] = str(directory["path"] / child)
            remaining = campaign_deadline - time.monotonic()
            if remaining <= 0:
                first_error = {"case_id": None, "code": "runtime_campaign_deadline"}
                case.update(verdict="not_run", capability="unknown", reason="not_run_after_failure")
                cases.append(case)
                continue
            timeout = min(plan["bounds"]["case_ms"] / 1000, remaining)
            observed["timeout_ms"] = max(1, int(timeout * 1000))
            try:
                _recheck_privilege(facts["host"]["privilege"])
            except _Blocked as error:
                first_error = {"case_id": None, "code": error.code}
                case.update(verdict="not_run", capability="unknown", reason="not_run_after_failure")
                cases.append(case)
                continue
            try:
                result = process.run_bounded([sys.executable, "-I", "-S", str(helper), name],
                    cwd=directory["path"], stdin=stdin, env=env, timeout_seconds=timeout,
                    max_output_bytes=plan["bounds"]["capture_bytes"], max_line_bytes=plan["bounds"]["capture_bytes"],
                    on_spawn=closed_gate if name == "closed-gate-cancel" else None,
                    on_stdout_line=on_line if name == "running-cancel" else None,
                    cancel_requested=(lambda: ready["seen"]) if name == "running-cancel" else None,
                    _capture_private_output=lambda out, err: capture.update(stdout=out, stderr=err))
                case["dispatch"] = "sent"
            except process.ProcessBoundaryError as error:
                result = error.process_result
                case["dispatch"] = error.effect_outcome
                observed["boundary_error"] = {"code": error.code, "effect_outcome": error.effect_outcome}
            except (Exception, KeyboardInterrupt):
                case["dispatch"] = "uncertain"
                observed["boundary_error"] = {"code": "runtime_invocation_failed", "effect_outcome": "uncertain"}
            if result is not None:
                owned_invocations += 1
                if (not result.termination_confirmed or not result.group_termination_confirmed
                        or result.unaccounted_descendants):
                    quarantined = True
            elif case["dispatch"] != "not_sent":
                quarantined = True
            if case["dispatch"] == "uncertain":
                quarantined = True
            if quarantined:
                writer.cleanup_uncertain = True
                if writer.first_error is None:
                    writer.first_error = {"case_id": name, "code": "runtime_cleanup_unknown"}
            if result is not None:
                process_data = asdict(result)
                del process_data["stdout"], process_data["stderr"]
                case["process_ref"] = writer.blob(rq.canonical_bytes(process_data))
            if set(capture) == {"stdout", "stderr"}:
                case["capture_refs"] = {"stdin": writer.blob(stdin, "application/octet-stream"),
                                        "stdout": writer.blob(capture["stdout"], "application/octet-stream"),
                                        "stderr": writer.blob(capture["stderr"], "application/octet-stream")}
            counter = writer.read_owned(directory["fd"], "target-invocations.jsonl", missing=True, maximum=4096)
            if counter is not None:
                observed["invocation_ref"] = writer.blob(counter)
                observed["target_invocations"] = len(counter.splitlines())
                helper_invocations += observed["target_invocations"]
            if case["dispatch"] == "uncertain" or quarantined:
                observed["target_invocations"] = None
            if name in {"permitted-read", "permitted-write"}:
                effect = writer.read_owned(directory["workspace"],
                    "permitted.txt" if name == "permitted-read" else "created.txt", missing=True)
                if effect is not None:
                    observed["effect_ref"] = writer.blob(effect, "application/octet-stream")
            if capture.get("stdout"):
                try:
                    frame = rq.loads(capture["stdout"])
                    observed["input_consumed"] = (frame.get("input_sha256") == hashlib.sha256(stdin).hexdigest()
                                                   and frame.get("nonce") == context["nonce"])
                except Exception:
                    pass
        case["observation_ref"] = writer.blob(rq.canonical_bytes(observed))
        try:
            rq._validate_executed_case(case, plan, facts, context, rq.ProofEvidence.from_blobs(writer.blobs))
        except Exception:
            case.update(verdict="failed", capability="unknown", reason="cleanup_unknown" if quarantined else "oracle_failed")
            first_error = {"case_id": name, "code": "runtime_cleanup_unknown" if quarantined else "runtime_canary_failed"}
            if writer.first_error is None:
                writer.first_error = first_error
        cases.append(case)
    return (cases, first_error, quarantined, int((time.monotonic() - execution_started) * 1000),
            None if quarantined else helper_invocations, None if quarantined else owned_invocations)


def _recheck_inputs(watch, deadline, *, privilege=None):
    try:
        if privilege is not None:
            _recheck_privilege(privilege)
        for path, expected, selected, maximum in watch:
            if _measure(path, deadline, maximum=maximum, selected_interpreter=selected) != expected:
                raise _Failed("runtime_inputs_changed")
        if privilege is not None:
            _recheck_privilege(privilege)
    except _Blocked as error:
        raise _Failed(error.code) from None


def _inventory(args, writer, deadline, started, campaign_deadline):
    import hashlib
    import secrets
    import time
    import uuid
    from datetime import datetime, timezone

    rq, facts, watch = _inventory_measurements(deadline, args.package_origin, args.artifact_inventory)
    writer.verifier_watch = tuple(watch)
    writer.verifier_privilege = facts["host"]["privilege"]
    campaign = str(uuid.uuid4())
    context = rq.canonical_bytes({"campaign_id": campaign, "nonce": secrets.token_hex(32),
                                   "payload": "taskalong-generated-canary-" + secrets.token_hex(16) + "\n"})
    subject = {"kind": "host-experiment", "interpreter_digest": facts["interpreter"]["executable_sha256"],
               "backend_id": facts["backend"]["id"], "backend_digest": facts["backend"]["implementation_digest"],
               "context_digest": hashlib.sha256(context).hexdigest(),
               "package_digest": rq.digest(facts["package"], exclude_digest=False),
               "host_digest": rq.digest(facts["host"], exclude_digest=False)}
    plan = {"kind": "runtime_experiment_plan", "format_version": "1.0", "campaign_id": campaign,
            "stage": args.stage, "profile": args.profile, "package_origin": args.package_origin, "inference": "never",
            "runner_digest": facts["runner_digest"], "helper_digest": facts["helper_digest"],
            "test_inventory_digest": facts["test_inventory_digest"], "subject": subject,
            "bounds": {"inventory_ms": 10000, "case_ms": 5000, "capture_bytes": 65536, "execution_ms": 60000},
            "case_ids": list(rq.HOST_CASES) if args.stage == "model-free" else []}
    plan["digest"] = rq.digest(plan)
    plan_object = rq.ExperimentPlan.from_dict(plan)
    inventory = {"subject": subject, "closure_complete": False,
                 "unmeasured_components": ["Standard library, bytecode caches and native-library closure are not exhaustive.",
                                           "Mutable host context, services and vendor isolation are not qualified."],
                 "measurements": facts}
    finalize_started = time.monotonic()
    inventory_ref = writer.blob(rq.canonical_bytes(inventory))
    context_ref = writer.blob(context)
    initial_finalize_ms = int((time.monotonic() - finalize_started) * 1000)
    cases, first_error, quarantined, execution_ms, helpers, owned = [], None, False, 0, 0, 0
    if args.stage == "model-free":
        cases, first_error, quarantined, execution_ms, helpers, owned = _run_canaries(
            rq, writer, plan, rq.loads(context), facts, campaign_deadline)
    finalize_started = time.monotonic()
    rechecked = False
    if first_error is None:
        try:
            recheck_deadline = min(time.monotonic() + 10, campaign_deadline)
            _recheck_inputs(watch, recheck_deadline, privilege=facts["host"]["privilege"])
            rechecked = True
        except _Blocked as error:
            first_error = {"case_id": None, "code": error.code}
    if writer.first_error is None and first_error is not None:
        writer.first_error = first_error
    document = {"kind": "runtime_qualification_manifest", "format_version": "1.0", "plan": plan,
                "producer_id": "taskalong-owned-host-experiment", "inventory_ref": inventory_ref,
                "context_ref": context_ref, "started_at": started,
                "finished_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "execution_ms": execution_ms, "finalization_ms": initial_finalize_ms + int((time.monotonic() - finalize_started) * 1000),
                "observed_route": {"model": None, "account": None, "route": None, "reason": "not_requested_model_free"},
                "cases": cases, "complete": first_error is None and not quarantined,
                "first_error": first_error, "quarantined": quarantined, "inputs_rechecked": rechecked}
    document["digest"] = rq.digest(document)
    proof = rq.RuntimeProofManifest.from_dict(document)
    assessment = rq.validate_proof(proof, expected_plan=plan_object, evidence=rq.ProofEvidence.from_blobs(writer.blobs))
    if document["complete"] and (not assessment.complete or not assessment.passed):
        raise _Failed("runtime_proof_invalid")
    writer.manifest(proof.to_bytes() + b"\n")
    writer.verify_paths()
    unsupported = (first_error is not None and first_error["code"] == "runtime_lifecycle_unsupported"
                   and helpers == 0 and owned == 0 and not quarantined)
    return {"code": ("runtime_inventory_complete" if args.stage == "inventory" else
                     "runtime_model_free_complete") if document["complete"] else first_error["code"],
            "requested_stage": args.stage, "actual_stage": args.stage,
            "outcome": ("inventory_complete" if args.stage == "inventory" else "model_free_complete") if document["complete"] else "unsupported" if unsupported else "failed",
            "complete": document["complete"], "durable_evidence": True, "proof_digest": proof.digest,
            "production_dispatch_allowed": False, "producer_authenticated": False,
            "closure_complete": False, "helper_invocations": helpers, "owned_invocations": owned,
            "cleanup_uncertain": quarantined,
            "invocation_count_complete": helpers is not None and owned is not None,
            "vendor_capabilities": {"start": "unknown", "instruction_tool_isolation": "unknown",
                                    "native_resume": "unsupported", "remote_cancel": "unsupported",
                                    "hard_token_cap": "unsupported", "hard_cost_cap": "unsupported"}}


def _read_proof_directory(path, rq, deadline):
    import hashlib
    import os
    import re
    import stat
    from pathlib import Path

    selected = Path(path)
    selected = selected.parent.resolve(strict=True) / selected.name
    root_fd = blobs_fd = None
    try:
        root_fd = os.open(selected, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        root_info = os.fstat(root_fd)
        blobs_fd = os.open("blobs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        blob_info = os.fstat(blobs_fd)
        for info in (root_info, blob_info):
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise _Blocked("runtime_replay_input_unsafe")
        def bounded_names():
            names = []
            with os.scandir(blobs_fd) as entries:
                for entry in entries:
                    if len(names) >= 64 or re.fullmatch(r"[a-f0-9]{64}\.bin", entry.name) is None:
                        raise _Failed("runtime_replay_evidence_invalid")
                    names.append(entry.name)
            return names
        names = bounded_names()
        # Fixed child names and held directory descriptors prevent document-
        # selected filesystem callbacks or path traversal.
        def read(directory, name, maximum):
            import time
            if time.monotonic() >= deadline:
                raise _Failed("runtime_replay_deadline")
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(fd, "rb") as source:
                before = os.fstat(source.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_size > maximum
                        or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) & 0o077):
                    raise _Failed("runtime_replay_input_unsafe")
                raw = source.read(maximum + 1)
                after = os.fstat(source.fileno())
                if (len(raw) > maximum or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
                    raise _Failed("runtime_replay_inputs_changed")
                return raw
        original = read(root_fd, "manifest.json", 1048576)
        blobs = {}
        for name in sorted(names):
            raw = read(blobs_fd, name, 65536)
            if hashlib.sha256(raw).hexdigest() != name[:-4]:
                raise _Failed("runtime_replay_evidence_invalid")
            blobs[name[:-4]] = raw
        evidence = rq.ProofEvidence.from_blobs(blobs)
        proof = rq.RuntimeProofManifest.from_bytes(original)
        result = rq.validate_proof(proof, expected_plan=rq.ExperimentPlan.from_dict(proof.to_dict()["plan"]), evidence=evidence)
        if (read(root_fd, "manifest.json", 1048576) != original or sorted(bounded_names()) != sorted(names)
                or any(read(blobs_fd, name, 65536) != blobs[name[:-4]] for name in names)):
            raise _Failed("runtime_replay_inputs_changed")
        for expected, actual in ((root_info, selected.lstat()), (blob_info, (selected / "blobs").lstat())):
            if (not stat.S_ISDIR(actual.st_mode) or (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino)):
                raise _Failed("runtime_replay_inputs_changed")
        return original, evidence, result
    finally:
        for fd in (blobs_fd, root_fd):
            if fd is not None:
                os.close(fd)


def _replay(args, writer, deadline, started, campaign_deadline):
    import argparse
    import hashlib
    import time
    # Establish actual installed identity before accepting any input proof.
    inventory_args = argparse.Namespace(**vars(args))
    inventory_args.stage = "inventory"
    verifier = _inventory(inventory_args, writer, deadline, started, campaign_deadline)
    from taskalong import runtime_qualification as rq
    original_bytes, original_evidence, result = _read_proof_directory(args.replay_dir, rq, min(time.monotonic() + 10, campaign_deadline))
    verifier_bytes = writer.read_owned(writer.root_fd, "manifest.json", maximum=1048576)
    original = rq.RuntimeProofManifest.from_bytes(original_bytes)
    def reference(raw):
        return {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw),
                "media_type": "application/json", "classification": "private"}
    report = {"kind": "runtime_qualification_replay", "format_version": "1.0", "operation": "installed-replay",
              "original_manifest_ref": reference(original_bytes), "original_proof_digest": original.digest,
              "original_subject": original.to_dict()["plan"]["subject"],
              "original_evidence_set_digest": rq.evidence_set_digest(original_evidence),
              "verifier_manifest_ref": reference(verifier_bytes), "verifier_proof_digest": verifier["proof_digest"],
              "original_complete": result.complete, "original_passed": result.passed, "integrity_valid": True}
    report["digest"] = rq.digest(report)
    parsed = rq.RuntimeReplayReport.from_dict(report)
    rq.validate_replay(parsed, original_bytes=original_bytes, original_evidence=original_evidence,
                       verifier_bytes=verifier_bytes, verifier_evidence=rq.ProofEvidence.from_blobs(writer.blobs))
    # Repeat the bounded snapshot after validation; no input paths are written.
    reread, repeated, _ = _read_proof_directory(args.replay_dir, rq, min(time.monotonic() + 10, campaign_deadline))
    if reread != original_bytes or rq.evidence_set_digest(repeated) != rq.evidence_set_digest(original_evidence):
        raise _Failed("runtime_replay_inputs_changed")
    _recheck_inputs(writer.verifier_watch, min(time.monotonic() + 10, campaign_deadline), privilege=writer.verifier_privilege)
    writer.replay_report(parsed.to_bytes() + b"\n")
    writer.verify_paths()
    return {"code": "runtime_replay_complete", "requested_stage": "installed-replay", "actual_stage": "installed-replay",
            "outcome": "replay_complete", "integrity_valid": True, "complete": result.complete,
            "original_complete": result.complete, "original_passed": result.passed,
            "durable_evidence": True, "replay_digest": parsed.digest,
            "production_dispatch_allowed": False, "producer_authenticated": False,
            "helper_invocations": 0, "owned_invocations": 0, "invocation_count_complete": True}


class SafeParser(argparse.ArgumentParser):
    def error(self, _message):
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid runtime experiment arguments.\n")


def parser():
    result = SafeParser(prog="qualify_runtime.py", description=__doc__)
    result.add_argument("--stage", choices=STAGES, default="model-free")
    result.add_argument("--profile", choices=("owned-host-canaries-v1",), default="owned-host-canaries-v1")
    result.add_argument("--package-origin", choices=("source", "installed"), required=True)
    result.add_argument("--inference", choices=("never",), default="never")
    result.add_argument("--evidence-dir", required=True)
    result.add_argument("--artifact-inventory", help="Independently supplied frozen installed-artifact inventory")
    result.add_argument("--replay-dir", help="Existing private proof; offline installed replay only")
    return result


def summary(code, stage):
    # Constant fields and closed stage names only; never print paths, exception
    # text, environment, credentials, nonce data or original capture content.
    return {"code": code, "requested_stage": stage, "outcome": "unsupported",
            "production_dispatch_allowed": False, "durable_evidence": False,
            "actual_stage": None, "helper_invocations": 0}


def main(argv=None):
    args = parser().parse_args(argv)
    # This guard deliberately precedes package loading, evidence destination
    # reservation, credentials, listeners and any owned helper invocation.
    if args.stage in UNSUPPORTED_STAGES:
        print(json.dumps(summary("runtime_stage_unsupported", args.stage), sort_keys=True))
        return 3
    import time
    from datetime import datetime, timezone
    from pathlib import Path

    original_path = list(sys.path)
    writer = None
    try:
        if args.package_origin == "source" and args.artifact_inventory is not None:
            raise _Blocked("runtime_origin_inputs_invalid")
        if ((args.stage == "installed-replay" and (args.package_origin != "installed" or args.replay_dir is None))
                or (args.stage != "installed-replay" and args.replay_dir is not None)):
            raise _Blocked("runtime_origin_inputs_invalid")
        candidate = Path(args.evidence_dir).parent.resolve(strict=True) / Path(args.evidence_dir).name
        source = Path(__file__).resolve().parent.parent
        if candidate == source or candidate.is_relative_to(source):
            raise _Blocked("runtime_evidence_destination_unsafe")
        if args.replay_dir is not None:
            replay = Path(args.replay_dir).parent.resolve(strict=True) / Path(args.replay_dir).name
            if candidate == replay or candidate.is_relative_to(replay) or replay.is_relative_to(candidate):
                raise _Blocked("runtime_replay_paths_overlap")
        campaign_deadline = time.monotonic() + 60
        deadline = min(campaign_deadline, time.monotonic() + 10)
        started = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        writer = _PrivateEvidence(args.evidence_dir)
        result = (_replay(args, writer, deadline, started, campaign_deadline) if args.stage == "installed-replay"
                  else _inventory(args, writer, deadline, started, campaign_deadline))
        if not writer.close():
            raise _Failed("runtime_evidence_close_failed")
        print(json.dumps(result, sort_keys=True))
        return 0 if result["complete"] else 3 if result["outcome"] == "unsupported" else 1
    except _Blocked as error:
        primary = writer.first_error if writer is not None else None
        code = primary["code"] if primary is not None else error.code
        if writer is not None:
            writer.note_failure(error.code)
        result = summary(code, args.stage)
        result["cleanup_uncertain"] = writer.cleanup_uncertain if writer is not None else False
        if writer is not None and args.stage == "model-free":
            result.update(helper_invocations=None, owned_invocations=None, invocation_count_complete=False)
        if isinstance(error, _Failed):
            result["outcome"] = "failed"
        print(json.dumps(result, sort_keys=True))
        return 1 if isinstance(error, _Failed) else 3
    except (Exception, KeyboardInterrupt):
        primary = writer.first_error if writer is not None else None
        code = primary["code"] if primary is not None else "runtime_experiment_failed"
        if writer is not None:
            writer.note_failure("runtime_experiment_failed")
        result = summary(code, args.stage)
        result["cleanup_uncertain"] = writer.cleanup_uncertain if writer is not None else False
        if writer is not None and args.stage == "model-free":
            result.update(helper_invocations=None, owned_invocations=None, invocation_count_complete=False)
        result["outcome"] = "failed"
        print(json.dumps(result, sort_keys=True))
        return 1
    finally:
        sys.path[:] = original_path
        if writer is not None:
            writer.close()


if __name__ == "__main__":
    raise SystemExit(main())
