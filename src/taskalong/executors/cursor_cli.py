"""Explicit Cursor fixture projection; installed vendor execution is unqualified."""
import hashlib
import platform
import sys
from pathlib import Path

from ..bindings import ProviderProfile
from ..errors import TaskAlongError
from ..execution import CheckBinding, InstructionBundle, SandboxPolicy, ToolPolicy
from ..process import ProcessBoundaryError, fingerprint, minimal_environment, run_bounded
from ..validation import canonical_bytes, loads, seal_versioned, validate_versioned
from .base import ExecutorCapabilities
from .config import CursorDriverConfig
from .cursor_protocol import CursorStreamDecoder


PROJECTION = "cursor-print-fixture/1"
_MODEL_DIGEST = hashlib.sha256(b"taskalong-cursor-fixture-model-v1").hexdigest()


def _refuse(code, message):
    raise TaskAlongError(code, message, exit_code=3)


def _represent_provider(config, provider):
    if provider["digest"] != config["provider_profile_digest"] or provider["harness"] != "cursor":
        _refuse("execution_identity_mismatch", "The configuration must name this exact Cursor provider.")
    if (provider["provider"] != "cursor-account" or provider["endpoint"] != "https://api2.cursor.sh"
            or provider["auth"] != {"mode": "account", "credential_ref": "fixture-cursor-account"}
            or provider["auth"]["credential_ref"] != config["credential_ref"]
            or provider["model"] != {"requested": "synthetic-cursor-model", "resolved_digest": _MODEL_DIGEST}
            or provider["effort"] is not None or provider["service_tier"] is not None
            or provider["auxiliary_routes"] or provider["unlisted_auxiliary_routes"] != "deny"
            or provider["allowed_disclosure"] != "provider-only" or provider["fallback"] != "forbidden"):
        _refuse("execution_projection_unsupported", "This declaration is outside the original Cursor fixture route.")


def represent(binding, installation, provider, policies, configuration, registration):
    """Pure, exact representability of the original synthetic Edit projection."""
    b, i, p = binding.to_dict(), installation.to_dict(), provider.to_dict()
    config = CursorDriverConfig.from_dict(configuration).to_dict()
    instructions = policies.resolve(b["instruction_bundle_digest"], InstructionBundle).to_dict()
    tools = policies.resolve(b["tool_policy_digest"], ToolPolicy).to_dict()
    worker = policies.resolve(b["worker_sandbox_digest"], SandboxPolicy).to_dict()
    check = policies.resolve(b["check_binding_digest"], CheckBinding).to_dict()
    verifier = policies.resolve(check["sandbox_digest"], SandboxPolicy).to_dict()
    architecture = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x86_64"
    empty_policy = hashlib.sha256(canonical_bytes({})).hexdigest()
    expected_policies = {"instructions": b["instruction_bundle_digest"], "tools": b["tool_policy_digest"],
        "worker_sandbox": b["worker_sandbox_digest"], "check_binding": b["check_binding_digest"]}
    if (registration["projection"] != PROJECTION or registration["driver_config_digest"] != config["digest"]
            or b["installation_digest"] != installation.digest or config["installation_digest"] != installation.digest
            or b["provider_profile_digest"] != provider.digest or config["provider_profile_digest"] != provider.digest
            or config["policy_digests"] != expected_policies or i["harness"] != "cursor" or i["adapter_id"] != "cursor-cli"
            or i["driver_version"] != config["driver_version"] or i["cli_version"] != "synthetic-cursor-1"
            or i["executable_digest"] != config["executable"]["sha256"]
            or i["platform"] != {"os": sys.platform, "architecture": architecture, "backend_id": "synthetic-fixture"}
            or instructions["texts"] or tools["allowed_tools"] != ["cursor.edit"]
            or instructions["protective_policy_digest"] != empty_policy or worker["permission_policy_digest"] != empty_policy
            or worker["role"] != "worker" or verifier["role"] != "independent_check"
            or worker["backend_id"] != "synthetic-fixture" or verifier["backend_id"] != "synthetic-fixture"):
        _refuse("execution_projection_unsupported", "The selected policy or installation is outside the Cursor fixture projection.")
    if b["budget"]["max_cost_micro_usd"] is not None or b["budget"]["max_tokens"] is not None:
        _refuse("hard_budget_unsupported", "The Cursor fixture cannot enforce a cost or token cap.")
    _represent_provider(config, p)
    return check, verifier


class CursorCLI:
    """Internal synthetic driver data; construction grants no execution authority."""
    def __init__(self, configuration, *, provider):
        self._config = CursorDriverConfig.from_dict(configuration)
        self._provider = ProviderProfile.from_dict(provider)
        _represent_provider(self._config.to_dict(), self._provider.to_dict())

    def capabilities(self):
        return ExecutorCapabilities(native_resume=False)

    def preflight(self, *, qualification, budget):
        if qualification == "production":
            _refuse("runtime_policy_unsupported", "Cursor production execution is not qualified.")
        if qualification != "synthetic":
            _refuse("qualification_mismatch", "Only the explicitly registered fixture transport is implemented.")
        config = self._config.to_dict()
        _represent_provider(config, self._provider.to_dict())
        if budget.get("hard_cost_usd") is not None or budget.get("hard_tokens") is not None:
            _refuse("hard_budget_unsupported", "The Cursor fixture cannot enforce a token or cost cap.")
        executable = Path(config["executable"]["path"])
        try:
            if not executable.is_absolute() or str(executable.resolve()) != str(executable):
                _refuse("runtime_policy_invalid", "The fixture executable requires an exact resolved path.")
            if fingerprint(executable) != config["executable"]["sha256"]:
                _refuse("runtime_changed", "The selected executable bytes changed.")
        except (OSError, ProcessBoundaryError):
            _refuse("runtime_unavailable", "The selected fixture executable is unavailable.")

    def build_argv(self, packet):
        packet = validate_versioned("worker-packet", packet, expected_version="2.5")
        if (packet["bindings"]["driver_config_digest"] != self._config.digest
                or packet["bindings"]["provider_profile_digest"] != self._provider.digest):
            _refuse("execution_identity_mismatch", "The packet names a different exact driver or provider.")
        return [self._config.to_dict()["executable"]["path"], "--print", "--output-format", "stream-json",
                "--model", self._provider.to_dict()["model"]["requested"]]

    def run(self, packet, *, workspace, output_dir, git_common_dir=None, control_dir=None,
            cancel_requested=None, heartbeat=None, on_spawn=None, mode="start", thread_id=None):
        if mode != "start" or thread_id is not None:
            _refuse("native_resume_unsupported", "Cursor native continuation is unqualified; choose an explicit fresh restart.")
        packet = validate_versioned("worker-packet", packet, expected_version="2.5")
        argv = self.build_argv(packet)
        self.preflight(qualification=packet["qualification"], budget=packet["remaining_budget"])
        directory = Path(output_dir)
        if directory.is_symlink():
            _refuse("output_path_unsafe", "The attempt output path cannot be a symbolic link.")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.stat().st_mode & 0o077:
            _refuse("output_path_unsafe", "Attempt output must be private.")
        home, temporary = directory / "cursor-home", directory / "cursor-tmp"
        if home.exists() or home.is_symlink() or temporary.exists() or temporary.is_symlink():
            _refuse("stale_output", "Each Cursor fixture attempt requires fresh private runtime directories.")
        home.mkdir(mode=0o700)
        temporary.mkdir(mode=0o700)
        environment = minimal_environment()
        environment.update(HOME=str(home), TMPDIR=str(temporary), XDG_CONFIG_HOME=str(home),
                           XDG_CACHE_HOME=str(home), XDG_DATA_HOME=str(home))
        budget = packet["remaining_budget"]
        forced_cancel = False
        try:
            process = run_bounded(argv, cwd=workspace, stdin=canonical_bytes(packet),
                timeout_seconds=budget["attempt_seconds"], max_output_bytes=budget["max_output_bytes"], env=environment,
                cancel_requested=cancel_requested, heartbeat=heartbeat,
                on_spawn=(lambda receipt: on_spawn(receipt.to_dict())) if on_spawn else None)
        except ProcessBoundaryError as exc:
            if (exc.code == "cancel_pending" and exc.effect_outcome == "not_sent"
                    and exc.process_result is not None and exc.process_result.termination_confirmed):
                process = exc.process_result
                forced_cancel = True
            else:
                raise TaskAlongError(exc.code, "The owned Cursor fixture boundary could not complete safely.",
                    exit_code=3 if exc.effect_outcome == "not_sent" else 5, effect_outcome=exc.effect_outcome) from exc
        summary = process.to_dict()
        summary.pop("stdout", None)
        summary.pop("stderr", None)
        confirmed = (process.termination_confirmed is True and process.group_termination_confirmed is True
                     and process.unaccounted_descendants is False)
        # Decline an overall cessation claim if any owned-process evidence is
        # inconsistent. This never turns missing group proof into confirmation.
        summary["termination_confirmed"] = confirmed
        state, error, worker, turn = "failed", None, None, None
        if not confirmed:
            state, error = "unknown", "cancellation_unconfirmed"
        elif process.protocol_error:
            error = process.protocol_error
        elif process.output_limited:
            error = "runtime_output_limit"
        elif process.timed_out:
            error = "runtime_timeout"
        elif forced_cancel or process.cancelled:
            state, error = "cancelled", "cancel_pending" if forced_cancel else "cancellation_confirmed_local"
        elif process.stderr:
            # This original fixture contract declares no benign stderr text.
            # Unknown diagnostics or a zero-exit denial cannot become success.
            error = "cursor_stderr_unsupported"
        else:
            decoder = CursorStreamDecoder(packet, expected_model=self._config.to_dict()["expected_reported_model"],
                max_output_bytes=min(budget["max_output_bytes"], 8 * 1024 * 1024))
            try:
                # Decode exact retained bytes after EOF; a line callback must
                # not manufacture a newline for a truncated terminal frame.
                decoder.feed(process.stdout)
                turn = decoder.finish(exit_code=process.exit_code)
                worker = loads(turn.worker_result_json)
                state = "completed"
            except TaskAlongError as exc:
                error = exc.code
        return {"state": state, "result": worker, "session_id": turn.session_id if turn else None,
                "thread_id": None, "process": summary, "error": error, "checkpoint": None,
                "usage": {"input_tokens": None, "output_tokens": None, "cost_usd": None}, "reported_usage": None,
                "cursor_observation": turn.observation() if turn else None,
                "_private_capture": {"stdout": process.stdout, "stderr": process.stderr},
                "diagnostics": {"protocol_version": 1, "stdout_sha256": hashlib.sha256(process.stdout).hexdigest(),
                                "reported_model_verified": turn is not None}}

    def doctor(self, **_):
        return {"qualified": False, "live_inference": False, "production_dispatch_allowed": False,
                "diagnostic_scope": "Original Cursor fixture; actual vendor context, model routing and lifetime remain unqualified."}


def compile_packet(fields, admission):
    """Compile exact neutral identities without allocating or transferring a chat."""
    try:
        if type(fields) is not dict or type(admission) is not dict or type(fields["bindings"]) is not dict:
            raise TypeError("admitted objects required")
        reserved = {"kind", "schema_version", "digest", "session_id", "session_policy", "projection",
                    "result_schema_id", "allowed_tools", "binding_digest", "admission_digest"}
        if reserved.intersection(fields) or any(key in fields["bindings"] for key in (
                "runtime_profile_digest", "driver_config_digest", "provider_profile_digest")):
            _refuse("execution_identity_mismatch", "Cursor compilation requires neutral inputs without session or route substitutions.")
        config = CursorDriverConfig.from_dict(admission["driver_config"]).to_dict()
        if (admission["schema_version"] != "2.5" or fields["spec_digest"] != admission["spec_digest"]
                or admission["projection"]["projection"] != PROJECTION
                or admission["projection"]["driver_config_digest"] != config["digest"]
                or admission["binding"]["provider_profile_digest"] != config["provider_profile_digest"]
                or admission["binding"]["installation_digest"] != config["installation_digest"]
                or "runtime_profile_digest" in fields["bindings"]):
            _refuse("execution_identity_mismatch", "The packet does not match its admitted Cursor context.")
        packet = seal_versioned("worker-packet", fields | {
            "bindings": fields["bindings"] | {"driver_config_digest": config["digest"],
                "provider_profile_digest": config["provider_profile_digest"]},
            "binding_digest": admission["binding"]["digest"], "admission_digest": admission["digest"],
            "session_policy": "fresh", "projection": PROJECTION, "allowed_tools": ["Edit"],
            "result_schema_id": "urn:taskalong:schema:v2.5:worker-result"}, version="2.5")
        mapping = seal_versioned("packet-projection", {
            "run_id": packet["run_id"], "attempt_id": packet["attempt_id"], "spec_digest": packet["spec_digest"],
            "canonical_packet_digest": packet["digest"], "wire_packet_digest": packet["digest"],
            "admission_digest": admission["digest"], "projection_digest": admission["projection"]["digest"],
            "driver_config_digest": config["digest"], "provider_profile_digest": config["provider_profile_digest"],
            "session_policy": "fresh", "projection": PROJECTION}, version="2.5")
    except (KeyError, TypeError) as exc:
        raise TaskAlongError("execution_identity_mismatch", "A complete exact Cursor admission is required.", exit_code=3) from exc
    return packet, loads(canonical_bytes(packet)), mapping
