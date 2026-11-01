"""Pinned Codex subprocess boundary, separate from acceptance and publication.

The synthetic seam exercises the real argv/stdin/JSONL/result-file protocol. It
does not qualify a production provider, command sandbox or inference lifecycle.
"""
from __future__ import annotations

from importlib import resources
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import socketserver
import sys
import tempfile
import threading
from typing import Callable, Sequence

from ..errors import TaskAlongError
from ..process import ProcessBoundaryError, fingerprint, minimal_environment, run_bounded
from ..validation import canonical_bytes, digest, loads, validate
from .base import (ExecutionHandle, ExecutionLookup, ExecutionObservation,
                   ExecutionRequest, ExecutorCapabilities, OperationResult, ResumeRequest)
from .codex_protocol import CodexEventDecoder, valid_thread_id


PINNED_RUNTIME_VERSION = "0.163.0"
MAX_RESULT_BYTES = 1024 * 1024


def _reject(code: str, message: str, *, exit_code: int = 3,
            recovery: list[dict] | None = None) -> None:
    raise TaskAlongError(code, message, exit_code=exit_code, recovery=recovery)


def _absolute(path: str | Path) -> str:
    value = Path(path)
    if not value.is_absolute():
        _reject("runtime_policy_invalid", "Runtime paths must be absolute")
    return str(value.resolve())


class CodexCLI:
    """One allowlisted runtime. No executable or arbitrary flags come from tasks."""

    def __init__(self, profile: dict):
        self.profile = profile
        self._observations: dict[str, ExecutionObservation] = {}

    def capabilities(self) -> ExecutorCapabilities:
        return ExecutorCapabilities()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    def start(self, request: ExecutionRequest, *, operation_key: str) -> OperationResult:
        """Direct launch cannot bypass the durable per-run supervisor driver."""
        request_digest = digest({"packet": loads(request.packet), "profile_digest": request.profile_digest,
                                 "lease_generation": request.lease_generation})
        return OperationResult(operation_key, request_digest, "unsupported",
            ExecutionObservation("unknown", self._now(), error_code="supervisor_required"))

    def status(self, lookup: ExecutionLookup) -> ExecutionObservation:
        if lookup.handle and lookup.handle.adapter == "codex-cli" and lookup.handle.version == PINNED_RUNTIME_VERSION:
            prior = self._observations.get(lookup.handle.invocation_id)
            if prior is not None:
                return prior
        # Cross-process operation-key lookup belongs to the durable core. Never
        # reinterpret this as a provider lookup or use the most recent session.
        return ExecutionObservation("unknown", self._now(), error_code="supervisor_receipt_required")

    def cancel(self, handle: ExecutionHandle, *, operation_key: str) -> OperationResult:
        observed = self.status(ExecutionLookup(handle=handle))
        known_terminal = observed.state in ("completed", "failed", "cancelled")
        return OperationResult(operation_key, digest({"handle": {"adapter": handle.adapter,
            "version": handle.version, "invocation_id": handle.invocation_id}}),
            "accepted" if known_terminal else "unknown", observed, handle)

    def resume(self, request: ResumeRequest, *, operation_key: str) -> OperationResult:
        return OperationResult(operation_key, digest({"packet": loads(request.request.packet),
            "thread_id": request.thread_id, "checkpoint_digest": request.checkpoint_digest, "mode": request.mode}),
            "unsupported", ExecutionObservation("unknown", self._now(), error_code="supervisor_required"))

    def preflight(self, *, qualification: str, budget: dict) -> None:
        if sys.platform not in ("darwin", "linux"):
            _reject("runtime_lifecycle_unsupported", "This platform has no qualified local process lifetime boundary",
                    recovery=[{"action": "qualify_existing_linux_adapter", "runtime_version": PINNED_RUNTIME_VERSION,
                               "requirement": "Prove owned start, explicit-thread resume and cancellation through the existing Linux subreaper before dispatch."}])
        if budget.get("hard_cost_usd") is not None or budget.get("hard_tokens") is not None:
            _reject("hard_budget_unsupported", "Codex CLI cannot enforce a hard cost or token budget")
        if self.profile.get("adapter") != "codex-cli":
            _reject("runtime_unsupported", "Only the Codex CLI adapter is supported")
        if self.profile.get("runtime_version") != PINNED_RUNTIME_VERSION:
            _reject("runtime_version_unsupported", "This adapter targets Codex CLI 0.163.0")
        if qualification != self.profile.get("qualification"):
            _reject("qualification_mismatch", "Runtime and task qualification must match")
        executable = self.profile.get("executable_path", "")
        try:
            actual = fingerprint(executable)
        except (OSError, ProcessBoundaryError):
            _reject("runtime_unavailable", "The selected runtime executable is unavailable")
        if actual != self.profile.get("executable_sha256"):
            _reject("runtime_changed", "The selected runtime executable fingerprint changed")
        policy = self.profile.get("permission_policy", {})
        if digest(policy, exclude_digest=False) != self.profile.get("permission_policy_digest"):
            _reject("runtime_policy_changed", "Runtime permission policy digest does not match")
        if qualification == "production":
            # No arbitrary boolean or receipt ID is accepted as proof. Command
            # canaries passed, but effective exec instruction/tool isolation and
            # --no-daemon process lifetime are not yet qualified for this release.
            _reject("runtime_policy_unsupported", "Production dispatch lacks verified start/resume context, tool isolation and complete owned runtime lifetime",
                    recovery=self._qualification_requirements()["next_actions"])
        if qualification != "synthetic":
            _reject("qualification_invalid", "Unknown runtime qualification")

    @staticmethod
    def _qualification_requirements() -> dict:
        """Static unmet contracts, never receipts from this doctor invocation."""
        context_action = {
            "action": "qualify_effective_start_and_resume_context",
            "runtime_version": PINNED_RUNTIME_VERSION,
            "modes": ["start", "native_resume"],
            "required_observations": [
                "effective_configuration_layers",
                "global_and_project_instruction_sources",
                "enabled_user_project_and_bundled_skills",
                "advertised_tools_and_forbidden_tool_dispatch",
            ],
            "requirement": "Prove that only reviewed context and permitted capabilities reach the exact runtime; flags or supplied receipt IDs are insufficient.",
            "preserve_protective_policy": True,
            "policy_requirement": "Preserve applicable managed policy and protective command rules; retain existing permissions and budgets.",
        }
        lifetime_action = {
            "action": "qualify_existing_linux_adapter" if sys.platform == "darwin" else "qualify_owned_no_daemon_lifetime",
            "runtime_version": PINNED_RUNTIME_VERSION,
            "required_backend": "linux-child-subreaper",
            "required_observations": [
                "owned_no_daemon_start_and_exact_thread_resume",
                "worker_and_all_descendant_cessation",
                "cancellation_deadline_and_supervisor_loss_reconciliation",
            ],
            "requirement": "Exercise the existing adapter on Linux with generated synthetic inputs and authorized destinations before adding host capabilities.",
        }
        darwin = sys.platform == "darwin"
        return {
            "blockers": ["exec_discovery_isolation_unqualified", "owned_no_daemon_lifetime_unqualified"],
            "blocker_details": [
                {"code": "exec_discovery_isolation_unqualified", "basis": "static_runtime_contract",
                 "observed_by_this_call": False,
                 "requirement": "Observe effective instructions, skills and tools for actual start and explicit-thread resume while preserving protective policy."},
                {"code": "owned_no_daemon_lifetime_unqualified", "basis": "static_runtime_contract",
                 "observed_by_this_call": False,
                 "backend": "darwin-kqueue-no-fork" if darwin else "linux-child-subreaper" if sys.platform == "linux" else "unsupported",
                 "limitation": "The current Darwin backend leaves every observed fork unaccounted and cannot confirm forked worker descendants stopped." if darwin else
                               "The existing Linux subreaper still requires exact-runtime start/resume and full worker-lifetime qualification."},
            ],
            "next_actions": [context_action, lifetime_action],
            "unperformed_qualification_checks": [
                {"check": "effective_start_and_resume_context", "status": "not_run"},
                {"check": "complete_owned_no_daemon_lifetime", "status": "not_run"},
            ],
        }

    def _config_args(self, *, workspace: str | Path, git_common_dir: str | Path,
                     control_dir: str | Path) -> list[str]:
        policy = self.profile.get("permission_policy", {})
        if not isinstance(policy, dict) or set(policy) - {"credential_deny_roots"}:
            _reject("runtime_policy_invalid", "Unknown runtime permission policy field")
        filesystem: dict[str, str] = {":minimal": "read", ":slash_tmp": "read", ":tmpdir": "read"}
        roots = self.profile.get("toolchain_read_roots", [])
        denies = policy.get("credential_deny_roots", [])
        if not isinstance(roots, list) or not isinstance(denies, list):
            _reject("runtime_policy_invalid", "Runtime roots must be explicit lists")
        for root in roots:
            filesystem[_absolute(root)] = "read"
        # Fixed protected boundaries take precedence over operator toolchain
        # roots even if the exact same path is accidentally listed twice.
        filesystem[_absolute(workspace)] = "write"
        filesystem[_absolute(git_common_dir)] = "read"
        filesystem[_absolute(control_dir)] = "deny"
        for root in denies:
            filesystem[_absolute(root)] = "deny"
        encoded = ",".join(f"{json.dumps(key)}={json.dumps(value)}" for key, value in filesystem.items())
        values = [
            'approval_policy="never"', 'default_permissions="taskalong"',
            'permissions.taskalong={filesystem={' + encoded + '},network={enabled=false}}',
            'web_search="disabled"', 'project_doc_max_bytes=0',
            'developer_instructions=""', 'shell_environment_policy.inherit="none"',
            'features.skip_host_skill_discovery=true',
        ]
        for feature in ("apps", "plugins", "hooks", "memories", "multi_agent", "multi_agent_v2",
                        "skill_search", "browser_use", "computer_use", "image_generation",
                        "remote_plugin", "tool_suggest"):
            values.append(f"features.{feature}=false")
        args = []
        for item in values:
            args.extend(["-c", item])
        args.extend(["-c", "model_reasoning_effort=" + json.dumps(self.profile["reasoning_effort"])])
        if self.profile.get("service_tier") is not None:
            args.extend(["-c", "service_tier=" + json.dumps(self.profile["service_tier"])])
        return args

    def sandbox_argv(self, argv: Sequence[str], *, workspace: str | Path,
                     git_common_dir: str | Path, control_dir: str | Path) -> list[str]:
        if isinstance(argv, (str, bytes)) or not argv:
            _reject("command_invalid", "A check requires an argv list", exit_code=2)
        # sandbox rejects --strict-config in 0.163.0; never silently add a bypass.
        return [self.profile["executable_path"], "--no-daemon", "sandbox", "-P", "taskalong",
                "-C", _absolute(workspace), *self._config_args(workspace=workspace,
                    git_common_dir=git_common_dir, control_dir=control_dir), "--", *argv]

    def build_argv(self, *, workspace: str | Path, git_common_dir: str | Path,
                   control_dir: str | Path, schema_path: str | Path,
                   result_path: str | Path, mode: str = "start", thread_id: str | None = None) -> list[str]:
        config = self._config_args(workspace=workspace, git_common_dir=git_common_dir, control_dir=control_dir)
        if mode == "native_resume":
            if not valid_thread_id(thread_id):
                _reject("native_resume_unavailable", "Native resume requires the exact observed runtime thread ID")
            # Resume has a distinct parser: CWD is the subprocess CWD; no -C flag.
            return [self.profile["executable_path"], "--no-daemon", "exec", "resume", thread_id,
                    "--ignore-user-config", "--strict-config", "--json", *config,
                    "-m", self.profile["model"], "--output-schema", str(schema_path),
                    "--output-last-message", str(result_path), "-"]
        if mode not in ("start", "restart"):
            _reject("execution_mode_invalid", "Unknown execution mode", exit_code=2)
        return [self.profile["executable_path"], "--no-daemon", "exec", "--ignore-user-config",
                "--strict-config", "--json", "--color", "never", *config,
                "-m", self.profile["model"], "-C", _absolute(workspace),
                "--output-schema", str(schema_path), "--output-last-message", str(result_path), "-"]

    def run(self, packet: dict, *, workspace: str | Path, output_dir: str | Path,
            git_common_dir: str | Path | None = None, control_dir: str | Path | None = None,
            cancel_requested: Callable[[], bool] | None = None,
            heartbeat: Callable[[], None] | None = None,
            on_spawn: Callable | None = None, mode: str = "start", thread_id: str | None = None,
            capture_private_output: Callable[[bytes, bytes], None] | None = None,
            _configured_owner: Callable | None = None) -> dict:
        """Run under the existing owner; optionally retain bounded pipe originals.

        The trusted private sink runs after process cleanup, including protocol
        failures. It is not streaming crash persistence or a public result. The
        core owns durable capture references and any subsequent reconciliation.
        """
        if self.profile.get("format") == "configured-provider-profile/1":
            # Separate experimental owner contract. Legacy production preflight
            # and start/resume refusals remain unchanged. A packet cannot select
            # an arbitrary driver: only the in-process durable owner supplies it.
            from ..local_provider_runtime import _execute_codex
            return _execute_codex(self.profile, packet, workspace=workspace,
                output_dir=output_dir, owner=_configured_owner, mode=mode,
                thread_id=thread_id)
        if _configured_owner is not None:
            _reject("runtime_owner_invalid", "Configured ownership requires its versioned profile.")
        if capture_private_output is not None and not callable(capture_private_output):
            _reject("runtime_capture_invalid", "Private output capture requires a trusted callable.")
        budget = packet["remaining_budget"]
        self.preflight(qualification=packet["qualification"], budget=budget)
        validate("worker-packet", packet)
        directory = Path(output_dir)
        if directory.is_symlink():
            _reject("output_path_unsafe", "Attempt output directory must not be a symlink")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.stat().st_mode & 0o077:
            _reject("output_path_unsafe", "Attempt output directory must be private")
        result_path = directory / "worker-result.json"
        if result_path.exists() or result_path.is_symlink():
            _reject("stale_output", "Each executor invocation requires a fresh result path")
        common = git_common_dir or Path(workspace) / ".git"
        control = control_dir or directory.parent
        decoder = CodexEventDecoder(mode=mode, thread_id=thread_id)
        protocol_errors: list[str] = []

        def should_cancel() -> bool:
            return decoder.error_code is not None or bool(cancel_requested and cancel_requested())

        schema = resources.files("taskalong.resources").joinpath("schemas/v1/worker-result.schema.json")
        with resources.as_file(schema) as schema_path:
            argv = self.build_argv(workspace=workspace, git_common_dir=common, control_dir=control,
                                   schema_path=schema_path, result_path=result_path, mode=mode, thread_id=thread_id)
            try:
                process = run_bounded(argv, cwd=workspace, stdin=canonical_bytes(packet),
                    timeout_seconds=budget["attempt_seconds"], max_output_bytes=budget["max_output_bytes"],
                    env=minimal_environment(runtime_parent=True), cancel_requested=should_cancel,
                    heartbeat=heartbeat, on_spawn=(lambda receipt: on_spawn(receipt.to_dict())) if on_spawn else None,
                    on_stdout_line=decoder.consume, _capture_private_output=capture_private_output)
            except ProcessBoundaryError as exc:
                if (exc.code == "cancel_pending" and exc.effect_outcome == "not_sent"
                        and exc.process_result is not None and exc.process_result.termination_confirmed):
                    process = exc.process_result
                    protocol_errors.append("cancel_pending")
                else:
                    raise TaskAlongError(exc.code, "The owned runtime process boundary could not complete safely",
                        exit_code=3 if exc.effect_outcome == "not_sent" else 5,
                        effect_outcome=exc.effect_outcome) from exc
        if decoder.error_code is not None:
            protocol_errors.insert(0, decoder.error_code)
        observed_thread, terminal, usage = decoder.thread_id, decoder.terminal, decoder.usage
        summary = process.to_dict()
        summary.pop("stdout", None)
        # Even stderr is only a private bounded diagnostic, never event payload.
        summary["stderr"] = summary["stderr"][:2048]
        state, error, result = "failed", None, None
        if not process.termination_confirmed:
            state, error = "unknown", "cancellation_unconfirmed"
        elif protocol_errors or process.protocol_error:
            error = protocol_errors[0] if protocol_errors else process.protocol_error
        elif process.output_limited:
            error = "runtime_output_limit"
        elif process.timed_out:
            error = "runtime_timeout"
        elif process.cancelled:
            state, error = "cancelled", "cancellation_confirmed_local"
        elif process.exit_code != 0:
            error = "runtime_failed"
        elif terminal != "turn.completed" or observed_thread is None:
            error = "runtime_terminal_missing"
        else:
            try:
                if result_path.is_symlink() or not result_path.is_file() or result_path.stat().st_size > MAX_RESULT_BYTES:
                    raise ValueError("missing or oversized result")
                # Bounded read remains bounded even if an untrusted producer
                # raced the preceding stat. No raw result is copied to events.
                remaining_output = max(0, budget["max_output_bytes"] - process.output_bytes)
                with result_path.open("rb") as stream:
                    raw_result = stream.read(min(MAX_RESULT_BYTES, remaining_output) + 1)
                summary["output_bytes"] += len(raw_result)
                if len(raw_result) > remaining_output:
                    summary["output_limited"] = True
                    raise TaskAlongError("runtime_output_limit", "The final result exceeds the remaining aggregate output budget.", exit_code=3)
                result = loads(raw_result, max_bytes=MAX_RESULT_BYTES)
                validate("worker-result", result)
                pairs = {"packet_id": packet["packet_id"], "packet_digest": packet["digest"],
                         "run_id": packet["run_id"], "attempt_id": packet["attempt_id"],
                         "spec_digest": packet["spec_digest"], "qualification": packet["qualification"]}
                if any(result.get(key) != value for key, value in pairs.items()):
                    raise ValueError("result binding")
                if result["status"] == "completed":
                    state = "completed"
                else:
                    state, error = "failed", "worker_" + result["status"]
            except (ValueError, OSError, UnicodeError, TaskAlongError) as exc:
                result = None
                error = "runtime_output_limit" if isinstance(exc, TaskAlongError) and exc.code == "runtime_output_limit" else "worker_result_invalid"
        handle = ExecutionHandle("codex-cli", PINNED_RUNTIME_VERSION, process.receipt.invocation_id)
        self._observations[handle.invocation_id] = ExecutionObservation(state, self._now(), handle=handle,
            error_code=error, usage_json=canonical_bytes(usage))
        return {"state": state, "result": result, "thread_id": observed_thread, "usage": usage,
                "process": summary, "error": error, "diagnostics": decoder.diagnostics,
                "checkpoint": {"thread_id": observed_thread, "runtime_profile_digest": self.profile["digest"]} if observed_thread else None}

    def doctor(self, *, workspace: str | Path | None = None,
               git_common_dir: str | Path | None = None, control_dir: str | Path | None = None) -> dict:
        """Runtime checks without inference, login, or configuration edits.

        The separately recorded model-free command canaries are deliberately not
        promoted to complete exec isolation/lifecycle qualification. The selected
        runtime still owns its configuration discovery; doctor does not inspect
        or qualify the complete effective start/resume context.
        """
        requirements = self._qualification_requirements()
        preflight_error = None
        try:
            self.preflight(qualification=self.profile.get("qualification"), budget={"hard_cost_usd": None, "hard_tokens": None})
        except TaskAlongError as exc:
            if exc.code != "runtime_policy_unsupported":
                return {**requirements, "ok": False, "qualified": False,
                        "errors": [exc.to_dict()], "live_inference": False,
                        "observations": [{"check": "profile_preflight", "status": "failed", "code": exc.code},
                                         {"check": "runtime_identity", "status": "not_run"},
                                         {"check": "model_free_command_canaries", "status": "not_run"}]}
            preflight_error = exc
        try:
            result = run_bounded([self.profile["executable_path"], "--version"],
                                 cwd=tempfile.gettempdir(), timeout_seconds=10,
                                 max_output_bytes=4096, env=minimal_environment(runtime_parent=True))
            version_ok = result.exit_code == 0 and re.search(rb"\b0\.163\.0\b", result.stdout) is not None
        except (OSError, ProcessBoundaryError):
            version_ok = False
        if not version_ok:
            canaries = {"passed": False, "status": "runtime_identity_unavailable", "checks": []}
        elif self.profile.get("qualification") == "production":
            canaries = self.probe_sandbox()
        else:
            canaries = {"passed": False, "status": "synthetic_runtime_has_no_containment_claim", "checks": []}
        canary_status = "not_run" if canaries["status"] in ("synthetic_runtime_has_no_containment_claim", "runtime_identity_unavailable") else "passed" if canaries["passed"] else "failed"
        return {**requirements, "ok": version_ok, "qualified": False, "runtime_version": PINNED_RUNTIME_VERSION if version_ok else None,
                "executable_sha256": self.profile.get("executable_sha256"), "live_inference": False,
                "command_canaries": canaries,
                "observations": [{"check": "profile_preflight", "status": "blocked" if preflight_error else "passed",
                                  **({"code": preflight_error.code} if preflight_error else {})},
                                 {"check": "runtime_identity", "status": "passed" if version_ok else "failed"},
                                 {"check": "model_free_command_canaries", "status": canary_status,
                                  "scope": "new_synthetic_command_canaries_only"}],
                "errors": [] if version_ok else [{"code": "runtime_unavailable", "message": "Pinned runtime version was not observed"}],
                "diagnostic_scope": "Runtime identity and optional model-free command canaries; effective start/resume context and complete worker lifetime are not tested."}

    def probe_sandbox(self) -> dict:
        """Command-only probes on fresh synthetic roots; never inspect real secrets.

        Successful command canaries are necessary but insufficient for production
        exec qualification. Each denial requires a successful positive control;
        failure to launch the sandbox cannot masquerade as successful isolation.
        """
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(4096)
                self.request.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 7\r\n\r\ncanary\n")
        class Server(socketserver.TCPServer):
            allow_reuse_address = True
        checks = []
        with tempfile.TemporaryDirectory(prefix="taskalong-doctor-") as raw:
            root = Path(raw).resolve()
            workspace, control, credentials, common = [root / name for name in ("workspace", "control", "credentials", "git-common")]
            for path in (workspace, control, credentials, common):
                path.mkdir(mode=0o700)
            (control/"canary").write_bytes(b"synthetic-control-canary")
            (credentials/"canary").write_bytes(b"synthetic-credential-canary")
            (common/"canary").write_bytes(b"synthetic-git-canary")
            profile = dict(self.profile)
            original = dict(profile.get("permission_policy", {}))
            original["credential_deny_roots"] = sorted(set(original.get("credential_deny_roots", []) + [str(credentials)]))
            profile["permission_policy"] = original
            runner = CodexCLI(profile)
            shell = str(Path(shutil.which("sh") or "/bin/sh").resolve())
            cat = str(Path(shutil.which("cat") or "/bin/cat").resolve())
            def invoke(name, argv, *, allow):
                result = run_bounded(runner.sandbox_argv(argv, workspace=workspace,
                    git_common_dir=common, control_dir=control), cwd=workspace,
                    timeout_seconds=10, max_output_bytes=4096, env=minimal_environment(runtime_parent=True))
                # Exit71 is sandbox_apply failure observed under an outer sandbox;
                # it does not establish a denial for any protected target.
                # These fixed, generated canary argv cannot daemonize. This
                # establishes the observed access check only, never generic
                # repository-command or executor descendant qualification.
                launched = result.exit_code not in (None, 71, 127) and not result.timed_out and result.group_termination_confirmed
                passed = launched and (result.exit_code == 0 if allow else result.exit_code != 0)
                checks.append({"name": name, "passed": passed, "exit_code": result.exit_code,
                               "group_termination_confirmed": result.group_termination_confirmed,
                               "descendant_lifetime_confirmed": result.termination_confirmed})
                return passed
            try:
                permitted = invoke("workspace_write", [shell, "-c", 'printf permitted > "$1"', "probe", str(workspace/"allowed")], allow=True)
                if not permitted or not (workspace/"allowed").is_file():
                    return {"passed": False, "status": "command_sandbox_unavailable", "checks": checks}
                invoke("sibling_write_denied", [shell,"-c",'printf forbidden > "$1"',"probe",str(root/"sibling")], allow=False)
                invoke("control_read_denied", [cat, str(control/"canary")], allow=False)
                invoke("credential_read_denied", [cat, str(credentials/"canary")], allow=False)
                invoke("git_write_denied", [shell,"-c",'printf forbidden > "$1"',"probe",str(common/"forbidden")], allow=False)
                invoke("git_read_permitted", [cat, str(common/"canary")], allow=True)
                # Read actual approved toolchain bytes without exposing them in
                # the receipt. No temporary admission of an unapproved toolchain.
                python = Path(sys.executable).resolve()
                admitted = any(python.is_relative_to(Path(path).resolve()) for path in profile.get("toolchain_read_roots", []))
                if admitted:
                    invoke("toolchain_permitted", [str(python), "-I", "-c", "print('synthetic-toolchain-canary')"], allow=True)
                else:
                    checks.append({"name":"toolchain_permitted", "passed":False, "reason":"selected_toolchain_not_admitted"})
                curl = shutil.which("curl")
                if curl is None:
                    checks.append({"name":"network_denied", "passed":False, "reason":"positive_control_unavailable"})
                else:
                    with Server(("127.0.0.1", 0), Handler) as server:
                        thread = threading.Thread(target=server.serve_forever, daemon=True)
                        thread.start()
                        try:
                            command = [str(Path(curl).resolve()), "--noproxy", "*", "--max-time", "2", "--silent", "http://127.0.0.1:" + str(server.server_address[1]) + "/canary"]
                            positive = run_bounded(command, cwd=workspace, timeout_seconds=5, max_output_bytes=4096)
                            if positive.exit_code == 0 and positive.stdout == b"canary\n":
                                invoke("network_denied", command, allow=False)
                            else:
                                checks.append({"name":"network_denied", "passed":False, "reason":"positive_control_failed"})
                        finally:
                            server.shutdown()
                            thread.join(timeout=2)
                if (root/"sibling").exists() or (common/"forbidden").exists():
                    checks.append({"name":"forbidden_effect_absent", "passed":False})
            except (OSError, ProcessBoundaryError, TaskAlongError):
                return {"passed": False, "status": "command_sandbox_probe_failed", "checks": checks}
        return {"passed": bool(checks) and all(item["passed"] for item in checks),
                "status": "command_canaries_only", "checks": checks}
