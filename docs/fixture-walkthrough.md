# Installed synthetic walkthrough

Production task execution is currently unavailable: every production profile
returns `runtime_policy_unsupported`. This walkthrough exercises the installed
core with generated files, an external test worker, and released ReviewSensei's
fixture backend. It makes no model, sandbox-containment, or real publication
claim. The fake worker is test data from the matching source archive; it is not
an executor shipped inside the wheel.

Use CPython 3.11–3.14, Git, a local filesystem, and matching candidate wheel and
sdist files whose SHA-256 values you have verified. Current measured support and
remaining platform gates are recorded in the qualification guide. No TaskAlong
registry release is implied by these commands.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '/absolute/path/taskalong-0.1.0a1-py3-none-any.whl[review]'
.venv/bin/taskalong --version
.venv/bin/taskalong guide fixture
.venv/bin/taskalong guide operations
.venv/bin/taskalong guide contracts
```

The guides are installed package resources and work from an empty directory.
Reading a guide does not create a state store. The optional extra pins
ReviewSensei 0.8.8; its published wheel has SHA-256
`34337c4da835f794914915aeb2a0b4521f05d4ab13120452ee6ee4e43dbbf1b0`.
For a fully locked replay, install the matching sdist's `requirements-dev.lock`
with `--require-hashes` before installing these two ordinary wheels.

Unpack the matching sdist outside site-packages. Set the absolute directory that
contains its `tests/fixtures/fake_codex.py`:

```sh
export TASKALONG_FIXTURE_SOURCE=/absolute/path/taskalong-0.1.0a1
```

Save the following as `example.py`, then run `.venv/bin/python example.py`.
It creates and preserves a private scratch directory; it does not adopt an
existing repository. Git configuration overrides apply only to this generated
fixture process, so inherited filters/signing settings do not change the example.
Existing repositories must satisfy TaskAlong's policy checks themselves.

```python
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from taskalong.api import RunService
from taskalong.errors import TaskAlongError
from taskalong.validation import digest

source = Path(os.environ["TASKALONG_FIXTURE_SOURCE"]).resolve()
fixture = source / "tests/fixtures/fake_codex.py"
assert fixture.is_file(), "Select the unpacked matching source archive"
root = Path(tempfile.mkdtemp(prefix="taskalong-example-")).resolve()
os.environ.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                  PYTHONDONTWRITEBYTECODE="1")
repo = root / "primary"
repo.mkdir(mode=0o700)
def git(*args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()
git("init", "-b", "main")
git("config", "user.name", "Synthetic Operator")
git("config", "user.email", "synthetic@example.invalid")
git("config", "commit.gpgsign", "false")
(repo / "arithmetic.py").write_text("def add(a, b):\n    return a - b\n")
(repo / "check.py").write_text("from arithmetic import add\nassert add(2, 3) == 5\n")
git("add", "arithmetic.py", "check.py")
git("commit", "-m", "Generated failing fixture")
base = git("rev-parse", "HEAD")

# Copy test data to writable scratch; never edit the source archive or package.
mode_file = root / "fixture-mode.json"
def mode(value):
    mode_file.write_text(json.dumps({"mode": value}))
mode("good")
worker = root / "synthetic-worker"
lines = fixture.read_text().replace("#!/usr/bin/env python3", "#!" + sys.executable, 1).splitlines()
lines = ["    mode = json.loads(Path(" + repr(str(mode_file)) + ").read_text())['mode']"
         if line.startswith("    mode = ") else line for line in lines]
worker.write_text("\n".join(lines) + "\n")
worker.chmod(0o700)

# This launcher is deliberately synthetic and makes no containment claim.
# It runs each declared check, rather than invoking the fake worker as a check.
launcher = root / "synthetic-check-launcher"
launcher.write_text("#!" + sys.executable + "\nimport os,sys\n"
                    "argv=sys.argv[sys.argv.index('--')+1:]\nos.execv(argv[0],argv)\n")
launcher.chmod(0o700)
reviewer = Path(sys.executable).parent / "review-sensei"
assert reviewer.is_file(), "Install the review extra into this interpreter's venv"
config = root / "review.yml"
config.write_text("schema: 1\n")
response = root / "review-response.json"
response.write_text('{"summary":"Generated fixture review.","comments":[]}\n')

service = RunService(root / "state")
registration = service.register_repository(repo, root / "workspaces")
profile = service.register_profile({
    "profile_id": "generated-fixture", "qualification": "synthetic", "adapter": "codex-cli",
    "executable_path": str(worker), "executable_sha256": hashlib.sha256(worker.read_bytes()).hexdigest(),
    "runtime_version": "0.163.0", "model": "gpt-6.1-sol", "reasoning_effort": "high", "service_tier": "default",
    "inference_destination_id": "generated-local-fixture", "permission_policy": {},
    "permission_policy_digest": digest({}), "toolchain_read_roots": [],
    "credential_source_ref": None, "qualification_receipt_ids": []})
service.configure_command_sandbox(launcher)
service.configure_review(config, fixture_response=response, executable=reviewer,
                         python_executable=sys.executable)

def submit(name):
    task = {
        "task_id": name, "revision": 1, "goal": "Correct addition in the generated fixture.",
        "non_goals": ["No network, dependencies, publication, or other source changes."],
        "repository": {"registration_id": registration["registration_id"], "base_commit": base, "base_ref": "main"},
        "scope": {"files": ["arithmetic.py"], "operations": ["modify"]},
        "criteria": [{"id": "sum", "description": "Addition returns 5.", "check_ids": ["sum-check"]}],
        "checks": [{"id": "sum-check", "argv": [sys.executable, "-B", "check.py"], "cwd": ".",
                    "timeout_seconds": 10, "expected_exit_code": 0, "criterion_ids": ["sum"], "required": True}],
        "execution": {"adapter": "codex-cli", "profile_id": profile["profile_id"], "profile_digest": profile["digest"]},
        "permissions": {"local_edit": True, "local_commit": True, "inference_destination_id": profile["inference_destination_id"],
                        "allowed_effects": ["execute", "verify", "commit_candidate"]},
        "budget": {"max_attempts": 2, "attempt_seconds": 5 if name == "recovery-example" else 15, "total_active_seconds": 60,
                   "max_output_bytes": 1048576, "hard_cost_usd": None, "hard_tokens": None},
        "review": {"required": True, "integration": "reviewsensei", "contract": "0.8.8/v1",
                   "config_digest": hashlib.sha256(config.read_bytes()).hexdigest(), "require_full_coverage": True},
        "publication": None, "qualification": "synthetic"}
    run = service.submit(task, operation_key="submit-" + name)
    authority = service.authorize(run["run_id"], decision_digest=run["spec_digest"],
                                  scope=["execute", "verify", "commit_candidate"], qualification="synthetic")
    service.start(run["run_id"], operation_key="start-" + name, expected_revision=run["revision"],
                  authority_id=authority["authority_id"])
    return run["run_id"]

def wait(run_id, states=("accepted", "blocked", "cancelled", "failed")):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        run = service.inspect(run_id)
        if run["state"] in states:
            return run
        time.sleep(.05)
    raise RuntimeError("Inspect the preserved run; do not retry an uncertain effect")

def retire(run):
    deadline = time.monotonic() + 5
    while True:
        try:
            return service.retire_workspace(run["run_id"], operation_key="retire-" + run["run_id"],
                                            expected_revision=run["revision"])
        except TaskAlongError as error:
            if error.code not in {"supervisor_owned", "operation_in_progress"} or time.monotonic() >= deadline:
                raise
            time.sleep(.05)  # Only a proven no-effect guard conflict may retry.

first = wait(submit("accepted-example"))
assert first["state"] == "accepted", first["blockers"]
retire(first)

mode("hang")
recovery = wait(submit("recovery-example"))
assert recovery["state"] == "blocked" and not recovery["active_attempt_id"]
recovery = service.reconcile(recovery["run_id"], operation_key="reconcile-example", expected_revision=recovery["revision"])
mode("good")
service.resume(recovery["run_id"], mode="native", operation_key="native-example", expected_revision=recovery["revision"])
recovery = wait(recovery["run_id"])
assert recovery["state"] == "accepted" and len(recovery["attempts"]) == 2
retire(recovery)

mode("hang")
cancel_id = submit("cancel-example")
running = wait(cancel_id, states=("running",))
service.cancel(cancel_id, operation_key="cancel-example", expected_revision=running["revision"])
cancelled = wait(cancel_id, states=("cancelled", "blocked"))
assert cancelled["state"] == "cancelled", cancelled["blockers"]
retire(cancelled)

mode("good")
interactive = wait(submit("inspect-example"))
assert interactive["state"] == "accepted", interactive["blockers"]
print(json.dumps({"state_dir": str(root / "state"), "run_id": interactive["run_id"],
                  "revision": interactive["revision"], "state": interactive["state"],
                  "qualification": interactive["qualification"]}, indent=2))
service.close()
```

The first candidate reaches acceptance only after its independent command and
released fixture review pass. The recovery task times out, reconciles, and uses
the recorded native thread with a new attempt and fence. The cancellation task
requests cancellation and waits for confirmed local cessation. Retirement admits
the next task while retaining the old workspace and evidence. No publication is
configured or permitted.

Use the printed state directory, run ID and current revision with the CLI:

```sh
taskalong --state-dir STATE_DIR status RUN_ID --json
taskalong --state-dir STATE_DIR events RUN_ID --jsonl
GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 taskalong --state-dir STATE_DIR verify RUN_ID --key fresh-verification --expected-revision REVISION --json
```

For this generated fixture only, the verification command uses the same
process-scoped Git configuration as the example. It does not change host
configuration. Existing user repositories must satisfy their own qualified
Git policy; do not use these overrides to bypass that policy.

Always inspect status before a new mutation, and use a fresh key for new intent.
Repeating the same key returns its original receipt, even if the run later changes.
Do not change a submitted task's budget or profile to make a failed attempt pass.
The 1 MiB output budget covers worker output, result files, checks, reviewer
schema/version probes, and review output; a tiny 64 KiB total may not fund review.

For the standard foreground CLI, Ctrl-C during `verify` returns exit 130. Inspect
the resulting `verification_interrupted` error and run. Confirmed cleanup leaves
a blocked run whose capture is observed; a fresh verification key can continue.
Unknown cessation leaves an unknown pending effect and requires reconciliation;
do not clear it from the database or infer cessation from process absence. An
earlier process crash with no durable receipt remains uncertain after upgrading.
Interrupting a foreground client of a detached worker does not cancel that worker;
use `cancel` and observe `cancel.confirmed`. If verification finished before the
keypress, report the state actually committed rather than claiming interruption.
