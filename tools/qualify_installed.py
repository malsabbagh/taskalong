#!/usr/bin/env python3
"""Qualify built TaskAlong artifacts in fresh venvs outside the checkout.

Only synthetic task data reaches external boundary fixtures. Dependency artifact
downloads are permitted by this explicit qualification command; no model call,
real GitHub mutation, auth lookup, or runtime installation is performed.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
import platform
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import venv
from pathlib import Path

REVIEW_SHA256 = "34337c4da835f794914915aeb2a0b4521f05d4ab13120452ee6ee4e43dbbf1b0"
REVIEW_URL = "https://github.com/malsabbagh/review-sensei/releases/download/v0.8.8/review_sensei-0.8.8-py3-none-any.whl"
FIXTURES = ("tests/fixtures/fake_codex.py", "tests/fixtures/fake_gh.py")
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024


def snapshot_artifact(source: Path, directory: Path) -> tuple[Path, str]:
    """Audit/install a private byte snapshot, never a concurrently rebuilt path."""
    if source.is_symlink() or not source.is_file():
        raise RuntimeError("distribution artifact must be a regular file")
    with source.open("rb") as stream:
        data = stream.read(MAX_ARTIFACT_BYTES + 1)
    if len(data) > MAX_ARTIFACT_BYTES:
        raise RuntimeError("distribution artifact exceeds qualification limit")
    target = directory / source.name
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
    return target, hashlib.sha256(data).hexdigest()


def snapshot_harness(source: Path, work: Path) -> str:
    """Freeze reviewed test/fixture/lock inputs before slow installation begins."""
    inventory = json.loads((source / "distribution-inventory.json").read_text(encoding="utf-8"))
    inputs = {"tools/qualify_installed.py", "requirements-dev.lock"} | {
        path for path in inventory["sdist_sources"] if path.startswith("tests/") and path != "tests/test_distribution.py"}
    values = {relative: (source / relative).read_bytes() for relative in sorted(inputs)}
    (work / "qualify_installed.py").write_bytes(values["tools/qualify_installed.py"])
    (work / "requirements-dev.lock").write_bytes(values["requirements-dev.lock"])
    (work / "fixtures").mkdir()
    for relative in FIXTURES:
        (work / "fixtures" / Path(relative).name).write_bytes(values[relative])
    for relative, data in values.items():
        if relative.startswith("tests/"):
            target = work / "installed-tests" / relative.removeprefix("tests/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    manifest = [{"path": relative, "sha256": hashlib.sha256(data).hexdigest()} for relative, data in sorted(values.items())]
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@contextmanager
def qualification_directory():
    directory = Path(tempfile.mkdtemp(prefix="taskalong-installed-")).resolve()
    try:
        yield directory
    except Exception as error:
        # Preserve synthetic state/worktree/process receipts on failure. Removing
        # an uncertain execution's control records would frustrate reconciliation.
        raise RuntimeError(f"{error}; synthetic qualification retained at {directory}") from error
    else:
        shutil.rmtree(directory)


def clean_environment() -> dict[str, str]:
    env = dict(os.environ)
    for key in list(env):
        if key in {"PYTHONPATH", "PYTHONHOME", "GH_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GIT_SSH_COMMAND"}:
            env.pop(key, None)
    env.update(PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", PIP_DISABLE_PIP_VERSION_CHECK="1",
               GIT_TERMINAL_PROMPT="0", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    return env


def create_environment(path: Path) -> str:
    # Standalone Darwin interpreters locate libpython relative to their executable.
    # Native venv links preserve that layout; copying the executable can abort in
    # dyld before ensurepip starts. Package imports still come from the fresh venv.
    venv.EnvBuilder(with_pip=True, symlinks=sys.platform == "darwin").create(path)
    return str(path / "bin" / "python")


def command(argv: list[str], *, cwd: Path, env: dict, timeout: int = 60) -> str:
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        # Dependency installation errors can mention indexes. Retain diagnostic
        # metadata, never environment values or complete command output.
        detail = ": " + result.stderr[-6000:] if "--child" in argv else ""
        raise RuntimeError(f"qualification subprocess failed: tool={Path(argv[0]).name}, exit={result.returncode}{detail}")
    return result.stdout


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def wrapper(path: Path, python: str, program: str) -> None:
    path.write_text(f"#!{python}\n{program}\n", encoding="utf-8")
    path.chmod(0o700)


def cli(python: str, state: Path, *args: str, ok_codes: tuple[int, ...] = (0,)) -> dict:
    result = subprocess.run([python, "-m", "taskalong", "--state-dir", str(state), *args, "--json"],
                            cwd=Path.cwd(), env=clean_environment(), capture_output=True, text=True, timeout=30)
    if result.returncode not in ok_codes:
        raise AssertionError(f"CLI command {args[0]} returned {result.returncode}")
    value = json.loads(result.stdout)
    assert value["kind"] == "command_result" and value["schema_version"] == "1.0"
    return value


def child_journey(args: argparse.Namespace) -> dict:
    # This code executes only from a copied file with an external CWD. These are
    # the exact same installed APIs used by task-neutral local callers.
    source_root = Path(args.source_root).resolve()
    denied_source_roots = [source_root]
    if args.build_source_root:
        denied_source_roots.append(Path(args.build_source_root).resolve())

    def deny_checkout_reads(event: str, values: tuple) -> None:
        # The copied harness can inspect import identities but cannot read the
        # original checkout. An accidental source/resource fallback fails here.
        if event in {"open", "os.listdir", "os.scandir"} and values and isinstance(values[0], (str, bytes, os.PathLike)):
            target = Path(os.fsdecode(values[0])).absolute()
            if any(target.is_relative_to(root) for root in denied_source_roots):
                raise AssertionError("installed qualification attempted source checkout access")

    sys.addaudithook(deny_checkout_reads)
    import importlib.metadata
    from importlib import resources
    import taskalong
    from taskalong.api import RunService
    from taskalong.validation import canonical_bytes, digest, seal, schema_names

    cwd = Path.cwd()
    package = Path(taskalong.__file__).resolve()
    assert not package.is_relative_to(source_root), "source checkout import leaked into installed qualification"
    assert not any(p and Path(p).resolve().is_relative_to(source_root) for p in sys.path), "source checkout remains importable"
    assert not any(p and Path(p).resolve().is_relative_to(root) for p in sys.path for root in denied_source_roots), "build source remains importable"
    assert os.environ.get("PYTHONPATH") is None
    assert importlib.metadata.version("taskalong") == "0.1.0a1"

    def package_snapshot() -> dict:
        return {str(path.relative_to(package.parent)): {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "mode": path.stat().st_mode}
                for path in package.parent.rglob("*") if path.is_file()}

    before = package_snapshot()
    py = sys.executable
    env = clean_environment()
    for argv in ([py, "-m", "taskalong", "--version"], [str(Path(py).parent / "taskalong"), "--version"], [str(Path(py).parent / "taskalong"), "--help"]):
        assert "taskalong" in command(argv, cwd=cwd, env=env).lower()
    assert len(schema_names()) == 12
    for name in schema_names():
        assert resources.files("taskalong.resources").joinpath(f"schemas/v1/{name}.schema.json").is_file()
    for name in ("templates/worker.txt", "templates/draft-pr.md", "sql/001-initial.sql"):
        assert resources.files("taskalong.resources").joinpath(name).read_bytes()

    repo = cwd / "tiny-project"
    repo.mkdir()
    command(["git", "init", "-b", "main", str(repo)], cwd=cwd, env=env)
    command(["git", "-C", str(repo), "config", "user.name", "Synthetic Operator"], cwd=cwd, env=env)
    command(["git", "-C", str(repo), "config", "user.email", "synthetic@example.invalid"], cwd=cwd, env=env)
    (repo / "arithmetic.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    (repo / "test_arithmetic.py").write_text("import unittest\nfrom arithmetic import add\n\nclass AdditionTests(unittest.TestCase):\n    def test_addition(self):\n        self.assertEqual(add(2, 3), 5)\n", encoding="utf-8")
    baseline = subprocess.run([py, "-m", "unittest", "-q", "test_arithmetic"], cwd=repo, env=env, capture_output=True, timeout=10)
    assert baseline.returncode == 1, "synthetic baseline must demonstrate the actual failing criterion"
    command(["git", "-C", str(repo), "add", "arithmetic.py", "test_arithmetic.py"], cwd=cwd, env=env)
    command(["git", "-C", str(repo), "commit", "-m", "Synthetic baseline"], cwd=cwd, env=env)
    base = command(["git", "-C", str(repo), "rev-parse", "HEAD"], cwd=cwd, env=env).strip()
    bare = cwd / "remote.git"
    command(["git", "init", "--bare", str(bare)], cwd=cwd, env=env)
    command(["git", "-C", str(repo), "push", str(bare), "HEAD:refs/heads/main"], cwd=cwd, env=env)

    fixtures = cwd / "fixtures"
    fake = fixtures / "fake-codex"
    wrapper(fake, py, f"import runpy\nrunpy.run_path({str(fixtures / 'fake_codex.py')!r}, run_name='__main__')")
    sandbox = fixtures / "command-sandbox"
    wrapper(sandbox, py, "import os,sys\na=sys.argv[sys.argv.index('--')+1:]\nos.execv(a[0],a)")
    state = cwd / "private-state"
    service = RunService(state)
    registration = service.register_repository(repo, workspace_root=cwd / "workspaces")
    policy = {}
    profile = seal("runtime-profile", {
        "profile_id": "installed-synthetic-codex", "qualification": "synthetic", "adapter": "codex-cli",
        "executable_path": str(fake), "executable_sha256": hashlib.sha256(fake.read_bytes()).hexdigest(),
        "runtime_version": "0.163.0", "model": "synthetic-fixture", "reasoning_effort": "low", "service_tier": None,
        "inference_destination_id": "synthetic-local-only", "permission_policy": policy,
        "permission_policy_digest": digest(policy), "toolchain_read_roots": [str(Path(py).parent)],
        "credential_source_ref": None, "qualification_receipt_ids": [],
    })
    service.register_profile(profile)
    service.configure_command_sandbox(sandbox)
    fake_gh_state = cwd / "fake-gh-state.json"
    write_json(fake_gh_state, {"repository_full_name": "fixture/repository", "repository_id": 4242,
                               "base_commit": base, "git_remote": str(bare), "prs": [],
                               "lose_create_response": True})
    fake_gh = fixtures / "fake-gh"
    wrapper(fake_gh, py, "import os,runpy\n" + f"os.environ['TASKALONG_FAKE_GH_STATE']={str(fake_gh_state)!r}\n"
            + f"runpy.run_path({str(fixtures / 'fake_gh.py')!r},run_name='__main__')")
    service.configure_publication(fake_gh, bare, qualification="synthetic")
    config = cwd / "review.yml"
    config.write_text("schema: 1\n", encoding="utf-8")
    response = cwd / "review-fixture.json"
    write_json(response, {"summary": "Synthetic clean review.", "comments": []})
    config_sha = hashlib.sha256(config.read_bytes()).hexdigest()
    review_executable = Path(py).parent / "review-sensei"
    if not args.core_only:
        assert importlib.metadata.version("review-sensei") == "0.8.8"
        service.configure_review(config, fixture_response=response, executable=review_executable, python_executable=py)
    spec = seal("task-spec", {
        "task_id": "installed-synthetic-addition", "revision": 1, "goal": "Correct the addition function.",
        "non_goals": ["No dependencies, network, or other files."],
        "repository": {"registration_id": registration["registration_id"], "base_commit": base, "base_ref": "main"},
        "scope": {"files": ["arithmetic.py"], "operations": ["modify"]},
        "criteria": [{"id": "addition", "description": "The function adds two integers.", "check_ids": ["addition-check"]}],
        "checks": [{"id": "addition-check", "argv": [py, "-m", "unittest", "-q", "test_arithmetic"],
                    "cwd": ".", "timeout_seconds": 10, "expected_exit_code": 0, "criterion_ids": ["addition"], "required": True}],
        "execution": {"adapter": "codex-cli", "profile_id": profile["profile_id"], "profile_digest": profile["digest"]},
        "permissions": {"local_edit": True, "local_commit": True, "inference_destination_id": "synthetic-local-only",
                        "allowed_effects": ["execute", "verify", "commit_candidate", "push_branch", "create_draft_pr"]},
        "budget": {"max_attempts": 2, "attempt_seconds": 30, "total_active_seconds": 60, "max_output_bytes": 1048576,
                   "hard_cost_usd": None, "hard_tokens": None},
        "review": {"required": True, "integration": "reviewsensei", "contract": "0.8.8/v1", "config_digest": config_sha, "require_full_coverage": True},
        "publication": {"host": "github.com", "repository_id": 4242, "repository_full_name": "fixture/repository",
                        "base_branch": "main", "title": "Correct synthetic addition",
                        "body_template_digest": hashlib.sha256(b"TaskAlong independently accepted this bounded candidate.").hexdigest()},
        "qualification": "synthetic",
    })
    spec_path = cwd / "task.json"
    write_json(spec_path, spec)
    submitted = cli(py, state, "submit", "--spec", str(spec_path), "--key", "installed-submit")
    run_id = submitted["run_id"]
    first = service.inspect(run_id)
    repeated = cli(py, state, "submit", "--spec", str(spec_path), "--key", "installed-submit")
    assert repeated["run_id"] == run_id
    changed = dict(spec)
    changed["goal"] = "Changed semantic task must conflict."
    changed = seal("task-spec", {k: v for k, v in changed.items() if k != "digest"})
    write_json(cwd / "changed-task.json", changed)
    cli(py, state, "submit", "--spec", str(cwd / "changed-task.json"), "--key", "installed-submit", ok_codes=(4,))
    authority = service.authorize(run_id, decision_digest=spec["digest"], scope=["execute", "verify", "commit_candidate"], qualification="synthetic")
    # Start via the installed console protocol; process ownership and all durable
    # transitions are product code. Poll from new clients rather than sharing a
    # connection with the detached supervisor.
    cli(py, state, "start", run_id, "--expected-revision", str(service.inspect(run_id)["revision"]), "--key", "installed-start")
    deadline = time.monotonic() + 45
    run = first
    while time.monotonic() < deadline:
        run = RunService(state).inspect(run_id)
        if run["state"] in {"accepted", "blocked", "failed", "cancelled"}:
            break
        time.sleep(.1)
    expected = "blocked" if args.core_only else "accepted"
    assert run["state"] == expected, {"expected": expected, "observed": run["state"], "blockers": run.get("blockers")}
    events = service.events(run_id)
    assert events and [event["seq"] for event in events] == list(range(1, len(events) + 1))
    assert len(run["attempts"]) == 1
    invocations = (fixtures / "fake-codex-invocations.jsonl").read_text().splitlines()
    assert len(invocations) == 1 and json.loads(invocations[0])["run_id"] == run_id
    assert command(["git", "-C", str(repo), "rev-parse", "HEAD"], cwd=cwd, env=env).strip() == base
    assert not command(["git", "-C", str(repo), "status", "--porcelain"], cwd=cwd, env=env)
    assert "return a - b" in (repo / "arithmetic.py").read_text()
    cli(py, state, "status", run_id)
    cli(py, state, "export", run_id, "--output", str(cwd / "export"))
    publication = "review-blocked"
    if not args.core_only:
        intent = service.publish_intent(run_id)
        # The fake service creates a PR and loses the response. The product must
        # preserve uncertainty and reconcile it with reads, without another POST.
        cli(py, state, "publish", run_id, "--intent-digest", intent["digest"],
            "--expected-revision", str(service.inspect(run_id)["revision"]), "--key", "installed-publish", ok_codes=(5,))
        unknown = service.inspect(run_id)
        assert unknown["state"] == "blocked"
        cli(py, state, "reconcile", run_id, "--expected-revision", str(unknown["revision"]), "--key", "installed-reconcile")
        run = service.inspect(run_id)
        assert run["state"] == "draft_published"
        assert run["publication"]["kind"] == "fixture" and run["publication"]["draft"] is True
        fake_state = json.loads(fake_gh_state.read_text())
        assert fake_state["create_calls"] == 1 and len(fake_state["prs"]) == 1
        assert command(["git", "--git-dir", str(bare), "rev-parse", f"refs/heads/taskalong/{run_id}"], cwd=cwd, env=env).strip() == run["candidate"]["commit"]
        publication = "fixture-lost-response-reconciled-one-create"
        events = service.events(run_id)
        assert [event["seq"] for event in events] == list(range(1, len(events) + 1))
    after = package_snapshot()
    assert before == after, "application wrote into installed package"
    suite_count = 0
    skipped_platform_cases = []
    if not args.core_only:
        import unittest
        suite = unittest.defaultTestLoader.discover(str(cwd / "installed-tests"))
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=1).run(suite)
        assert result.wasSuccessful(), "installed public-behavior suite failed"
        for test, reason in result.skipped:
            darwin_opposite = (sys.platform == "darwin" and test.id().startswith("test_linux_lifetime.LinuxLifetimeTests.")
                               and reason == "Linux prctl/subreaper kernel qualification")
            linux_opposite = (sys.platform == "linux" and test.id() == "test_linux_lifetime.UnsupportedLifetimeTests.test_non_linux_helper_never_releases_target"
                              and reason == "non-Linux refusal")
            darwin_fault_probe = (sys.platform == "linux" and test.id() == "test_supervisor.ProcessTests.test_unavailable_kernel_lifetime_boundary_never_releases_target"
                                 and reason == "Darwin kernel boundary fault injection")
            assert darwin_opposite or linux_opposite or darwin_fault_probe, "a required behavior case was skipped"
            skipped_platform_cases.append({"test": test.id(), "reason": reason, "required_platform": "Linux" if darwin_opposite else "Darwin"})
        if skipped_platform_cases:
            lifetime_tests = sys.modules["test_linux_lifetime"]
            opposite_class = lifetime_tests.LinuxLifetimeTests if sys.platform == "darwin" else lifetime_tests.UnsupportedLifetimeTests
            expected_skips = {f"test_linux_lifetime.{opposite_class.__name__}.{name}"
                              for name in unittest.defaultTestLoader.getTestCaseNames(opposite_class)}
            if sys.platform == "linux":
                expected_skips.add("test_supervisor.ProcessTests.test_unavailable_kernel_lifetime_boundary_never_releases_target")
            assert {case["test"] for case in skipped_platform_cases} == expected_skips, "the platform-specific skip inventory changed"
        suite_count = result.testsRun - len(skipped_platform_cases)
        assert suite_count > 50, "installed qualification must include the complete reviewed behavior suite"
    assert before == package_snapshot(), "a behavior scenario wrote into the installed package"
    return {"kind": "installed_journey", "format_version": 1, "ok": True, "state": run["state"],
            "qualification": "synthetic", "review": "missing-blocks" if args.core_only else "released-fixture-full-diff",
            "publication": publication, "python": platform.python_version(), "platform": platform.system(),
            "machine": platform.machine(), "package_version": "0.1.0a1", "attempts": len(run["attempts"]),
            "events": len(events), "source_import": False, "real_sandbox_claim": False,
            "installed_behavior_tests": suite_count,
            "skipped_platform_cases": skipped_platform_cases,
            "dependencies": {name: importlib.metadata.version(name) for name in ("jsonschema", "setuptools", "certifi")}}


def acquire_review(path: Path | None, target: Path) -> Path:
    if path:
        data = path.read_bytes()
    else:
        # Read only the public immutable release artifact; no source or task text
        # is transmitted, and there is no provider request.
        try:
            import certifi
            context = ssl.create_default_context(cafile=certifi.where())
        except ImportError:
            context = ssl.create_default_context()
        with urllib.request.urlopen(REVIEW_URL, timeout=30, context=context) as response:
            data = response.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != REVIEW_SHA256:
        raise RuntimeError("released ReviewSensei wheel checksum mismatch")
    target.write_bytes(data)
    return target


def qualify(args: argparse.Namespace) -> dict:
    root = Path(__file__).resolve().parents[1]
    artifact_paths = sorted(args.dist_dir.glob("*.whl" if args.artifact == "wheel" else "*.tar.gz"))
    if len(artifact_paths) != 1:
        raise RuntimeError("expected one selected distribution artifact")
    selected_artifact = artifact_paths[0].absolute()
    from check_dist import audit
    with qualification_directory() as base:
        if base.is_relative_to(root):
            raise RuntimeError("qualification temporary root must be outside checkout")
        artifact, artifact_sha256 = snapshot_artifact(selected_artifact, base)
        audit(artifact, root=root)
        work = base / "work"
        work.mkdir()
        extracted = None
        if args.artifact == "sdist":
            source = base / "sdist"
            source.mkdir()
            # The archive has already been checked for exact paths and links.
            with tarfile.open(artifact, "r:gz") as archive:
                archive.extractall(source, filter="data")
            extracted = source / "taskalong-0.1.0a1"
        harness_inputs_sha256 = snapshot_harness(extracted or root, work)
        env = clean_environment()
        venv_path = base / "venv"
        python = create_environment(venv_path)
        env["PATH"] = str(venv_path / "bin") + os.pathsep + env.get("PATH", os.defpath)
        env["TASKALONG_REVIEW_EXECUTABLE"] = str(venv_path / "bin" / "review-sensei")
        env["TASKALONG_REVIEW_PYTHON"] = python
        install = [python, "-m", "pip", "--isolated", "--disable-pip-version-check", "install"]
        if args.wheelhouse:
            install += ["--no-index", "--find-links", str(args.wheelhouse.resolve())]
        command(install + ["--require-hashes", "-r", str(work / "requirements-dev.lock")], cwd=work, env=env, timeout=60)
        install_artifact = artifact
        if args.artifact == "sdist":
            command([python, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(base / "rebuilt")], cwd=extracted, env=env)
            wheels = list((base / "rebuilt").glob("*.whl"))
            if len(wheels) != 1:
                raise RuntimeError("sdist wheel build did not yield one artifact")
            install_artifact = wheels[0]
            audit(install_artifact, root=extracted)
        command(install + ["--no-deps", str(install_artifact)], cwd=work, env=env)
        if not args.core_only:
            review = acquire_review(args.review_wheel, base / "review_sensei-0.8.8-py3-none-any.whl")
            command(install + ["--no-deps", str(review)], cwd=work, env=env)
        copied = work / "qualify_installed.py"
        child_args = [python, str(copied), "--child", "--source-root", str(root)]
        if extracted:
            child_args.extend(["--build-source-root", str(extracted)])
        if args.core_only:
            child_args.append("--core-only")
        raw = command(child_args, cwd=work, env=env, timeout=600)
        result = json.loads(raw)
        result.update(artifact=args.artifact, artifact_sha256=artifact_sha256,
                      review_wheel_sha256=None if args.core_only else REVIEW_SHA256,
                      dependency_lock_sha256=hashlib.sha256((work / "requirements-dev.lock").read_bytes()).hexdigest(),
                      qualification_inputs_sha256=harness_inputs_sha256,
                      environment="fresh-venv-external-cwd", editable=False)
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--artifact", choices=("wheel", "sdist"), default="wheel")
    parser.add_argument("--mode", choices=("fixture",), default="fixture")
    parser.add_argument("--review-wheel", type=Path)
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--core-only", action="store_true")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--source-root", help=argparse.SUPPRESS)
    parser.add_argument("--build-source-root", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        result = child_journey(args) if args.child else qualify(args)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        if args.child:
            # Synthetic harness failures include assertions for actionable local
            # diagnosis. It never receives live source or credentials.
            import traceback
            traceback.print_exc(file=sys.stderr)
        else:
            print(json.dumps({"kind": "installed_qualification", "format_version": 1, "ok": False,
                              "artifact": args.artifact, "error": str(error)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
