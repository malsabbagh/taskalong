"""Explicit Claude fixture projection; no real runtime qualification is implied."""
import hashlib
import platform
import sys
from pathlib import Path

from ..bindings import ProviderProfile
from ..errors import TaskAlongError
from ..execution import CheckBinding, InstructionBundle, SandboxPolicy, ToolPolicy
from ..process import ProcessBoundaryError, fingerprint, minimal_environment, run_bounded
from ..validation import canonical_bytes, loads, schema, seal_versioned, validate_versioned
from .base import ExecutorCapabilities
from .claude_protocol import ClaudeDriverStreamDecoder
from .config import DriverConfig


PROJECTION = "claude-print-fixture/1"


def _refuse(code, message):
    raise TaskAlongError(code, message, exit_code=3)


def _represent_provider(config, provider):
    """Pure declaration check, also usable when revoking an absent runtime."""
    if (provider["digest"] != config["provider_profile_digest"] or provider["harness"] != "claude-code"
            or provider["provider"] not in {"anthropic-account", "anthropic-api"}
            or provider["auth"]["credential_ref"] != config["credential_ref"]
            or provider["service_tier"] is not None or provider["auxiliary_routes"]
            or provider["effort"] not in {"low", "medium", "high", "max"}):
        _refuse("execution_projection_unsupported", "This exact provider declaration cannot be represented by the Claude fixture.")


def represent(binding, installation, provider, policies, configuration, registration):
    """Only the reviewed semantic tool 'claude.edit' maps to wire tool 'Edit'."""
    b, i, p = binding.to_dict(), installation.to_dict(), provider.to_dict()
    config = DriverConfig.from_dict(configuration).to_dict()
    instructions = policies.resolve(b["instruction_bundle_digest"], InstructionBundle).to_dict()
    tools = policies.resolve(b["tool_policy_digest"], ToolPolicy).to_dict()
    worker = policies.resolve(b["worker_sandbox_digest"], SandboxPolicy).to_dict()
    check = policies.resolve(b["check_binding_digest"], CheckBinding).to_dict()
    verifier = policies.resolve(check["sandbox_digest"], SandboxPolicy).to_dict()
    architecture = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x86_64"
    empty_policy = hashlib.sha256(canonical_bytes({})).hexdigest()
    expected_policies = {"instructions":b["instruction_bundle_digest"], "tools":b["tool_policy_digest"],
                         "worker_sandbox":b["worker_sandbox_digest"], "check_binding":b["check_binding_digest"]}
    if (registration["projection"] != PROJECTION or registration["driver_config_digest"] != config["digest"]
            or b["installation_digest"] != installation.digest or config["installation_digest"] != installation.digest
            or b["provider_profile_digest"] != provider.digest or config["provider_profile_digest"] != provider.digest
            or config["policy_digests"] != expected_policies or i["harness"] != "claude-code" or i["adapter_id"] != "claude-code"
            or i["driver_version"] != config["driver_version"] or i["cli_version"] != "synthetic-claude-1"
            or i["executable_digest"] != config["executable"]["sha256"]
            or i["platform"] != {"os":sys.platform,"architecture":architecture,"backend_id":"synthetic-fixture"}
            or p["harness"] != "claude-code" or instructions["texts"] or tools["allowed_tools"] != ["claude.edit"]
            or instructions["protective_policy_digest"] != empty_policy or worker["permission_policy_digest"] != empty_policy
            or worker["role"] != "worker" or verifier["role"] != "independent_check"
            or worker["backend_id"] != "synthetic-fixture" or verifier["backend_id"] != "synthetic-fixture"):
        _refuse("execution_projection_unsupported", "The selected policy or installation is outside the Claude fixture projection.")
    if b["budget"]["max_cost_micro_usd"] is not None or b["budget"]["max_tokens"] is not None:
        _refuse("hard_budget_unsupported", "The Claude fixture cannot enforce a cost or token cap.")
    _represent_provider(config, p)
    return check, verifier


class ClaudeCode:
    """Internal fixture driver; Workflow retains all durable authority/effects.

    No real account, provider, managed-policy or complete vendor lifetime is
    qualified. A valid config is data, not permission to call this driver.
    """
    def __init__(self, config, *, provider):
        self._config = DriverConfig.from_dict(config)
        self._provider = ProviderProfile.from_dict(provider)

    def capabilities(self):
        return ExecutorCapabilities(native_resume=False)

    def preflight(self, *, qualification, budget):
        if qualification == "production":
            _refuse("runtime_policy_unsupported", "Claude production dispatch is not qualified.")
        config, provider = self._config.to_dict(), self._provider.to_dict()
        if qualification != "synthetic" or qualification != config["qualification"]:
            _refuse("qualification_mismatch", "Only the explicitly registered fixture transport is implemented.")
        _represent_provider(config, provider)
        if budget.get("hard_cost_usd") is not None or budget.get("hard_tokens") is not None:
            _refuse("hard_budget_unsupported", "The Claude fixture cannot enforce token or cost limits.")
        executable = Path(config["executable"]["path"])
        try:
            if not executable.is_absolute() or str(executable.resolve()) != str(executable):
                _refuse("runtime_policy_invalid", "The executable requires an exact resolved path.")
            if fingerprint(executable) != config["executable"]["sha256"]:
                _refuse("runtime_changed", "The selected executable bytes changed.")
        except (OSError, ProcessBoundaryError):
            _refuse("runtime_unavailable", "The selected fixture executable is unavailable.")

    def build_argv(self, packet):
        config, provider = self._config.to_dict(), self._provider.to_dict()
        return [config["executable"]["path"], "--print", "--input-format", "text", "--output-format", "stream-json",
                "--verbose", "--json-schema", canonical_bytes(schema("worker-result", version="2.3")).decode(),
                "--model", provider["model"]["requested"], "--effort", provider["effort"],
                "--session-id", packet["session_id"], "--no-session-persistence", "--permission-mode", "default",
                "--safe-mode", "--settings-sources=", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
                "--tools", "Edit", "--allowedTools", "Edit"]

    def run(self, packet, *, workspace, output_dir, git_common_dir=None, control_dir=None,
            cancel_requested=None, heartbeat=None, on_spawn=None, mode="start", thread_id=None):
        packet = validate_versioned("worker-packet", packet, expected_version="2.3")
        self.preflight(qualification=packet["qualification"], budget=packet["remaining_budget"])
        if mode != "start" or thread_id is not None:
            _refuse("native_resume_unsupported", "Claude native continuation is not qualified; restart requires a new attempt.")
        if (packet["bindings"]["driver_config_digest"] != self._config.digest
                or packet["bindings"]["provider_profile_digest"] != self._provider.digest):
            _refuse("execution_identity_mismatch", "The packet names a different immutable driver or provider.")
        directory = Path(output_dir)
        if directory.is_symlink():
            _refuse("output_path_unsafe", "The attempt output path cannot be a symbolic link.")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.stat().st_mode & 0o077:
            _refuse("output_path_unsafe", "Attempt output must be private.")
        home, temporary = directory/"claude-home", directory/"claude-tmp"
        if home.exists() or home.is_symlink() or temporary.exists() or temporary.is_symlink():
            _refuse("stale_output", "Each fixture attempt requires fresh private runtime directories.")
        home.mkdir(mode=0o700)
        temporary.mkdir(mode=0o700)
        env = minimal_environment()
        env.update(HOME=str(home), TMPDIR=str(temporary), CLAUDE_CONFIG_DIR=str(home), XDG_CONFIG_HOME=str(home))
        budget = packet["remaining_budget"]
        decoder = ClaudeDriverStreamDecoder(packet, expected_session_id=packet["session_id"],
            expected_model=self._provider.to_dict()["model"]["requested"],
            max_output_bytes=min(budget["max_output_bytes"], 8 * 1024 * 1024))
        errors = []
        def consume(line):
            if not errors:
                try:
                    decoder.feed(line + b"\n")
                except TaskAlongError as exc:
                    errors.append(exc.code)
        def stop():
            return bool(errors) or bool(cancel_requested and cancel_requested())
        try:
            process = run_bounded(self.build_argv(packet), cwd=workspace, stdin=canonical_bytes(packet),
                timeout_seconds=budget["attempt_seconds"], max_output_bytes=budget["max_output_bytes"], env=env,
                on_stdout_line=consume, cancel_requested=stop, heartbeat=heartbeat,
                on_spawn=(lambda receipt:on_spawn(receipt.to_dict())) if on_spawn else None)
        except ProcessBoundaryError as exc:
            if (exc.code == "cancel_pending" and exc.effect_outcome == "not_sent"
                    and exc.process_result is not None and exc.process_result.termination_confirmed):
                # The closed gate never executed target code, and the owning
                # runner actually proved cleanup. Preserve its receipt so core
                # can atomically acknowledge the pending cancellation.
                process = exc.process_result
                errors.append("cancel_pending")
            else:
                raise TaskAlongError(exc.code, "The owned Claude fixture boundary could not complete safely.",
                    exit_code=3 if exc.effect_outcome == "not_sent" else 5, effect_outcome=exc.effect_outcome) from exc
        summary = process.to_dict()
        summary.pop("stdout", None)
        summary.pop("stderr", None)
        state, error, worker, decoded = "failed", None, None, None
        if not process.termination_confirmed:
            state, error = "unknown", "cancellation_unconfirmed"
        elif errors or process.protocol_error:
            error = errors[0] if errors else process.protocol_error
        elif process.output_limited:
            error = "runtime_output_limit"
        elif process.timed_out:
            error = "runtime_timeout"
        elif process.cancelled:
            state, error = "cancelled", "cancellation_confirmed_local"
        else:
            try:
                decoded = decoder.finish(exit_code=process.exit_code)
                worker = loads(decoded.worker_result_json)
                state = "completed"
            except TaskAlongError as exc:
                error = exc.code
        return {"state":state, "result":worker, "session_id":decoded.session_id if decoded else None,
                "thread_id":None, "process":summary, "error":error, "checkpoint":None,
                "usage":{"input_tokens":None, "output_tokens":None, "cost_usd":None},
                "reported_usage":loads(decoded.reported_usage_json) if decoded else None,
                "diagnostics":{"protocol_version":2, "stdout_sha256":hashlib.sha256(process.stdout).hexdigest(),
                               "reported_model_verified":decoded is not None}}

    def doctor(self, **_):
        return {"qualified":False, "live_inference":False, "production_dispatch_allowed":False,
                "diagnostic_scope":"Synthetic fixture implementation; actual Claude context, routing and complete lifetime remain unqualified."}


def compile_packet(fields, admission):
    """Bind neutral task fields to a frozen, admitted Claude configuration.

    The exact canonical packet is also the stdin wire packet. No legacy runtime
    profile field is manufactured and no opaque session is transferred.
    """
    try:
        config = DriverConfig.from_dict(admission["driver_config"]).to_dict()
        if (admission["schema_version"] != "2.3" or fields["spec_digest"] != admission["spec_digest"]
                or admission["projection"]["projection"] != PROJECTION
                or admission["projection"]["driver_config_digest"] != config["digest"]
                or "runtime_profile_digest" in fields["bindings"]):
            raise TaskAlongError("execution_identity_mismatch", "The packet does not match its exact admitted driver context.", exit_code=3)
        packet = seal_versioned("worker-packet", fields | {
            "bindings":fields["bindings"] | {"driver_config_digest":config["digest"],
                "provider_profile_digest":config["provider_profile_digest"]},
            "binding_digest":admission["binding"]["digest"], "admission_digest":admission["digest"],
            "session_id":fields["attempt_id"], "projection":PROJECTION, "allowed_tools":["Edit"],
            "result_schema_id":"urn:taskalong:schema:v2.3:worker-result"}, version="2.3")
        mapping = seal_versioned("packet-projection", {
            "run_id":packet["run_id"], "attempt_id":packet["attempt_id"], "spec_digest":packet["spec_digest"],
            "canonical_packet_digest":packet["digest"], "wire_packet_digest":packet["digest"],
            "admission_digest":admission["digest"], "projection_digest":admission["projection"]["digest"],
            "driver_config_digest":config["digest"], "provider_profile_digest":config["provider_profile_digest"],
            "session_id":packet["session_id"], "projection":PROJECTION}, version="2.3")
    except (KeyError, TypeError) as exc:
        raise TaskAlongError("execution_identity_mismatch", "A complete admitted driver context is required.", exit_code=3) from exc
    return packet, loads(canonical_bytes(packet)), mapping
