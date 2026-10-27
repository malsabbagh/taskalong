"""CLI-only observation helpers. No taskalong imports or private store writes."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sqlite3
import sys
import time


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


class CLIProbe:
    def __init__(self, root, *, python=None, source=None):
        self.root = Path(root).resolve()
        self.state = self.root / "state"
        self.cwd = self.root / "external-cwd"
        self.cwd.mkdir()
        self.python = str(python or sys.executable)
        # Do not leak credentials or user Python startup into child fixtures.
        names = ("PATH", "HOME", "TMPDIR", "SYSTEMROOT", "LANG", "LC_ALL")
        self.env = {name: os.environ[name] for name in names if name in os.environ}
        self.env.update(PYTHONDONTWRITEBYTECODE="1", GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_CONFIG_NOSYSTEM="1", PYTHONNOUSERSITE="1")
        if source:
            self.env["PYTHONPATH"] = str(Path(source).resolve() / "src")
        elif os.environ.get("PYTHONPATH"):
            self.env["PYTHONPATH"] = os.pathsep.join(str(Path(p).resolve()) for p in os.environ["PYTHONPATH"].split(os.pathsep) if p)
        self.commands = []

    def call(self, *args, ok=True, timeout=20):
        argv = [self.python, "-m", "taskalong", "--state-dir", str(self.state), *map(str, args), "--json"]
        result = subprocess.run(argv, cwd=self.cwd, env=self.env,
                                capture_output=True, timeout=timeout)
        record = {"argv": argv, "returncode": result.returncode,
                  "stdout": result.stdout.decode("utf-8", errors="replace")[:65536],
                  "stderr": result.stderr.decode("utf-8", errors="replace")[:16384]}
        self.commands.append(record)
        (self.root / "commands.json").write_bytes(canonical(self.commands))
        if len(result.stdout) > 1_048_576 or len(result.stderr) > 16384:
            raise AssertionError("Unbounded CLI result: " + repr(record))
        if b"Traceback" in result.stderr:
            raise AssertionError("CLI traceback: " + repr(record))
        envelope = json.loads(result.stdout)
        if type(envelope) is not dict or envelope.get("kind") != "command_result":
            raise AssertionError("Expected public command envelope: " + repr(record))
        if ok is True and (result.returncode or not envelope.get("ok")):
            raise AssertionError("CLI operation rejected: " + repr(record))
        # Existing command envelopes distinguish a rejected command from a
        # successfully observed blocked run. Both can carry a nonzero exit.
        # Acceptance requires refusal of the operation, not a new meaning of ok.
        if ok is False and not result.returncode:
            raise AssertionError("CLI unexpectedly accepted: " + repr(record))
        return envelope

    def status(self, run_id):
        return self.call("status", run_id)["data"]

    def wait(self, run_id, predicate, *, timeout=25):
        deadline = time.monotonic() + timeout
        while True:
            observed = self.status(run_id)
            if predicate(observed):
                return observed
            if time.monotonic() >= deadline:
                raise AssertionError("Boundary not observed: " + json.dumps(observed))
            time.sleep(.05)

    def mutation(self, command, run, key, *extra, ok=True):
        return self.call(command, run["run_id"], "--key", key,
                         "--expected-revision", run["revision"], *extra, ok=ok)

    def invocations(self):
        path = self.root / "invocations.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def private_fault_snapshot(self, run_id):
        """Read-only supplemental corruption oracle, never normal CLI evidence."""
        database = self.state / "state.sqlite3"
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
            row = connection.execute("SELECT document FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return json.loads(row[0])

    def write_json(self, name, document):
        path = self.root / name
        path.write_bytes(canonical(document))
        return path

    def identity(self):
        result = subprocess.run([self.python, "-c", "import json,sys,taskalong; print(json.dumps({'python':sys.version,'module':taskalong.__file__}))"],
            cwd=self.cwd, env=self.env, capture_output=True, text=True, timeout=10, check=True)
        return json.loads(result.stdout)

    def prepare_format(self, target):
        """Trusted disposable-store maintenance precondition, not CLI evidence."""
        program = """import sys
from pathlib import Path
from taskalong.store import Store
state, root, target = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
with Store(state):
    pass
with Store.maintenance(state) as store:
    for version in range(store.format_version + 1, target + 1):
        store.upgrade(operation_key='setup-' + str(version), target_version=version,
            backup_dir=root / ('backup-' + str(version)), restore_dir=root / ('restore-' + str(version)))
    assert store.format_version == target
"""
        result = subprocess.run([self.python, "-c", program, str(self.state), str(self.root), str(target)],
            cwd=self.cwd, env=self.env, capture_output=True, text=True, timeout=30)
        (self.root / "maintenance-precondition.json").write_bytes(canonical({"target": target,
            "returncode": result.returncode, "stdout": result.stdout[:65536], "stderr": result.stderr[:16384]}))
        if result.returncode:
            raise AssertionError("Explicit maintenance precondition failed: " + result.stderr)
