"""Explicit Antigravity fixture projection; installed vendor execution is unqualified."""
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
from .config import AntigravityDriverConfig
from .antigravity_protocol import AntigravityStreamDecoder


PROJECTION = "antigravity-headless-fixture/1"
_MODEL_DIGEST = hashlib.sha256(b"taskalong-agy-fixture-model-v1").hexdigest()


def reported_usage(turn):
    """Untrusted cumulative snapshot, separate from conserved budget accounting."""
    return {"counters": loads(turn.reported_usage_json),
            "scope": "reported_cumulative_snapshot", "installed_scope_qualified": False}


def _refuse(code, message):
    raise TaskAlongError(code, message, exit_code=3)


def _resolve_workspace(workspace):
    """Keep filesystem resolution failures inside the closed capture contract."""
    try:
        return str(Path(workspace).resolve())
    except (OSError, RuntimeError):
        raise TaskAlongError("agy_capture_invalid", "The Antigravity workspace path cannot be validated.", exit_code=70) from None


def _represent_provider(config, provider):
    if provider["digest"] != config["provider_profile_digest"] or provider["harness"] != "antigravity":
        _refuse("execution_identity_mismatch", "The configuration must name this exact Antigravity provider.")
    if (provider["provider"] != "google-account" or provider["endpoint"] != "https://fixture.invalid"
            or provider["auth"] != {"mode": "account", "credential_ref": "fixture-google-account"}
            or provider["auth"]["credential_ref"] != config["credential_ref"]
            or provider["model"] != {"requested": "fixture-agy-model", "resolved_digest": _MODEL_DIGEST}
            or provider["effort"] is not None or provider["service_tier"] is not None
            or provider["auxiliary_routes"] or provider["unlisted_auxiliary_routes"] != "deny"
            or provider["allowed_disclosure"] != "provider-only" or provider["fallback"] != "forbidden"):
        _refuse("execution_projection_unsupported", "This declaration is outside the original Antigravity fixture route.")


def represent(binding, installation, provider, policies, configuration, registration):
    """Pure, exact representability of the original synthetic write projection."""
    b, i, p = binding.to_dict(), installation.to_dict(), provider.to_dict()
    config = AntigravityDriverConfig.from_dict(configuration).to_dict()
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
            or config["policy_digests"] != expected_policies or i["harness"] != "antigravity" or i["adapter_id"] != "antigravity-cli"
            or i["driver_version"] != config["driver_version"] or i["cli_version"] != "synthetic-agy-1"
            or i["executable_digest"] != config["executable"]["sha256"]
            or i["platform"] != {"os": sys.platform, "architecture": architecture, "backend_id": "synthetic-fixture"}
            or instructions["texts"] or tools["allowed_tools"] != ["antigravity.write_file"]
            or instructions["protective_policy_digest"] != empty_policy or worker["permission_policy_digest"] != empty_policy
            or worker["role"] != "worker" or verifier["role"] != "independent_check"
            or worker["backend_id"] != "synthetic-fixture" or verifier["backend_id"] != "synthetic-fixture"):
        _refuse("execution_projection_unsupported", "The selected policy or installation is outside the Antigravity fixture projection.")
    if b["budget"]["max_cost_micro_usd"] is not None or b["budget"]["max_tokens"] is not None:
        _refuse("hard_budget_unsupported", "The Antigravity fixture cannot enforce a cost or token cap.")
    if "remote_cancellation" in b["required_capabilities"]:
        _refuse("remote_cancellation_unsupported", "The Antigravity fixture cannot establish external-server cessation.")
    _represent_provider(config, p)
    return check, verifier


class AntigravityCLI:
    """Internal synthetic driver data; construction grants no execution authority."""
    def __init__(self, configuration, *, provider):
        self._config = AntigravityDriverConfig.from_dict(configuration)
        self._provider = ProviderProfile.from_dict(provider)
        _represent_provider(self._config.to_dict(), self._provider.to_dict())

    def capabilities(self):
        return ExecutorCapabilities(structured_result=True, native_resume=False, local_group_cancel=True,
            provider_start_lookup=False, interactive_approval=False, hard_cost_cap=False, hard_token_cap=False)

    def preflight(self, *, qualification, budget):
        if qualification == "production":
            _refuse("runtime_policy_unsupported", "Antigravity production execution is not qualified.")
        if qualification != "synthetic":
            _refuse("qualification_mismatch", "Only the explicitly registered fixture transport is implemented.")
        config = self._config.to_dict()
        _represent_provider(config, self._provider.to_dict())
        if budget.get("hard_cost_usd") is not None or budget.get("hard_tokens") is not None:
            _refuse("hard_budget_unsupported", "The Antigravity fixture cannot enforce a token or cost cap.")
        executable = Path(config["executable"]["path"])
        try:
            if not executable.is_absolute() or str(executable.resolve()) != str(executable):
                _refuse("runtime_policy_invalid", "The fixture executable requires an exact resolved path.")
            if fingerprint(executable) != config["executable"]["sha256"]:
                _refuse("runtime_changed", "The selected executable bytes changed.")
        except (OSError, RuntimeError):
            raise TaskAlongError("runtime_unavailable", "The selected fixture executable is unavailable.", exit_code=3) from None

    def build_argv(self, packet):
        packet = validate_versioned("worker-packet", packet, expected_version="2.6")
        if (packet["bindings"]["driver_config_digest"] != self._config.digest
                or packet["bindings"]["provider_profile_digest"] != self._provider.digest):
            _refuse("execution_identity_mismatch", "The packet names a different exact driver or provider.")
        timeout = min(self._config.to_dict()["launch"]["print_timeout_seconds"], packet["remaining_budget"]["attempt_seconds"])
        if type(timeout) is not int or timeout < 1:
            _refuse("agy_timeout_unrepresentable", "A positive bounded print timeout must fit the remaining attempt.")
        return [self._config.to_dict()["executable"]["path"], "--input-format", "stream-json",
                "--output-format", "stream-json", "--model", self._provider.to_dict()["model"]["requested"],
                "--json-schema", canonical_bytes(schema("worker-result", version="2.5")).decode(),
                "--print-timeout", str(timeout) + "s", "--disable-slash-commands", "--sandbox"]

    def run(self, packet, *, workspace, output_dir, git_common_dir=None, control_dir=None,
            cancel_requested=None, heartbeat=None, on_spawn=None, mode="start", thread_id=None):
        if mode != "start" or thread_id is not None:
            _refuse("native_resume_unsupported", "Antigravity native continuation is unqualified; choose an explicit fresh restart.")
        packet = validate_versioned("worker-packet", packet, expected_version="2.6")
        argv = self.build_argv(packet)
        self.preflight(qualification=packet["qualification"], budget=packet["remaining_budget"])
        directory = Path(output_dir)
        if directory.is_symlink():
            _refuse("output_path_unsafe", "The attempt output path cannot be a symbolic link.")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.stat().st_mode & 0o077:
            _refuse("output_path_unsafe", "Attempt output must be private.")
        home, temporary = directory / "agy-home", directory / "agy-tmp"
        if home.exists() or home.is_symlink() or temporary.exists() or temporary.is_symlink():
            _refuse("stale_output", "Each Antigravity fixture attempt requires fresh private runtime directories.")
        home.mkdir(mode=0o700)
        temporary.mkdir(mode=0o700)
        environment = minimal_environment()
        environment.update(HOME=str(home), TMPDIR=str(temporary), XDG_CONFIG_HOME=str(home),
                           XDG_CACHE_HOME=str(home), XDG_DATA_HOME=str(home))
        budget = packet["remaining_budget"]
        forced_cancel = False
        capture = None
        stdin = encode_input(packet)
        def capture_original(stdout, stderr):
            nonlocal capture
            capture = {"stdin": stdin, "stdout": stdout, "stderr": stderr}
        try:
            process = run_bounded(argv, cwd=workspace, stdin=stdin,
                timeout_seconds=budget["attempt_seconds"], max_output_bytes=budget["max_output_bytes"], env=environment,
                cancel_requested=cancel_requested, heartbeat=heartbeat,
                on_spawn=(lambda receipt: on_spawn(receipt.to_dict())) if on_spawn else None,
                _capture_private_output=capture_original)
        except ProcessBoundaryError as exc:
            if (exc.code == "cancel_pending" and exc.effect_outcome == "not_sent"
                    and exc.process_result is not None and exc.process_result.termination_confirmed):
                process = exc.process_result
                forced_cancel = True
            else:
                raise TaskAlongError(exc.code, "The owned Antigravity fixture boundary could not complete safely.",
                    exit_code=3 if exc.effect_outcome == "not_sent" else 5, effect_outcome=exc.effect_outcome) from exc
        if capture is None:
            _refuse("agy_capture_missing", "The owned boundary returned no original private output capture.")
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
        elif capture["stderr"]:
            # This original fixture contract declares no benign stderr text.
            # Unknown diagnostics or a zero-exit denial cannot become success.
            error = "agy_diagnostics_unqualified"
        else:
            try:
                decoder = AntigravityStreamDecoder(packet, expected_model=self._config.to_dict()["expected_reported_model"],
                    expected_cwd=_resolve_workspace(workspace),
                    max_output_bytes=min(budget["max_output_bytes"], 8 * 1024 * 1024))
                # Decode exact retained bytes after EOF; a line callback must
                # not manufacture a newline for a truncated terminal frame.
                decoder.feed(capture["stdout"])
                turn = decoder.finish(exit_code=process.exit_code)
                worker = loads(turn.worker_result_json)
                state = "completed"
            except TaskAlongError as exc:
                error = exc.code
        return {"state": state, "result": worker, "session_id": turn.session_id if turn else None,
                "thread_id": None, "process": summary, "error": error, "checkpoint": None,
                "usage": {"input_tokens": None, "output_tokens": None, "cost_usd": None},
                "reported_usage": reported_usage(turn) if turn else None,
                "antigravity_observation": turn.observation() if turn else None,
                "_private_capture": capture,
                "diagnostics": {"protocol_version": 1, "stdout_sha256": hashlib.sha256(capture["stdout"]).hexdigest(),
                                "reported_model_verified": turn is not None}}

    def doctor(self, **_):
        return {"qualified": False, "live_inference": False, "production_dispatch_allowed": False,
                "diagnostic_scope": "Original Antigravity fixture; actual vendor context, model routing and lifetime remain unqualified."}


def compile_packet(fields, admission):
    """Compile exact neutral identities without allocating or transferring a chat."""
    try:
        if type(fields) is not dict or type(admission) is not dict or type(fields["bindings"]) is not dict:
            raise TypeError("admitted objects required")
        reserved = {"kind", "schema_version", "digest", "session_id", "session_policy", "projection",
                    "result_schema_id", "allowed_tools", "binding_digest", "admission_digest"}
        if reserved.intersection(fields) or any(key in fields["bindings"] for key in (
                "runtime_profile_digest", "driver_config_digest", "provider_profile_digest")):
            _refuse("execution_identity_mismatch", "Antigravity compilation requires neutral inputs without session or route substitutions.")
        config = AntigravityDriverConfig.from_dict(admission["driver_config"]).to_dict()
        if (admission["schema_version"] != "2.6" or fields["spec_digest"] != admission["spec_digest"]
                or admission["projection"]["projection"] != PROJECTION
                or admission["projection"]["driver_config_digest"] != config["digest"]
                or admission["binding"]["provider_profile_digest"] != config["provider_profile_digest"]
                or admission["binding"]["installation_digest"] != config["installation_digest"]
                or "runtime_profile_digest" in fields["bindings"]):
            _refuse("execution_identity_mismatch", "The packet does not match its admitted Antigravity context.")
        packet = seal_versioned("worker-packet", fields | {
            "bindings": fields["bindings"] | {"driver_config_digest": config["digest"],
                "provider_profile_digest": config["provider_profile_digest"]},
            "binding_digest": admission["binding"]["digest"], "admission_digest": admission["digest"],
            "session_policy": "fresh", "projection": PROJECTION, "allowed_tools": ["write_file"],
            "result_schema_id": "urn:taskalong:schema:v2.5:worker-result"}, version="2.6")
        mapping = seal_versioned("packet-projection", {
            "run_id": packet["run_id"], "attempt_id": packet["attempt_id"], "spec_digest": packet["spec_digest"],
            "canonical_packet_digest": packet["digest"], "wire_packet_digest": packet["digest"],
            "admission_digest": admission["digest"], "projection_digest": admission["projection"]["digest"],
            "driver_config_digest": config["digest"], "provider_profile_digest": config["provider_profile_digest"],
            "session_policy": "fresh", "projection": PROJECTION, "input_framing": "agy-user-ndjson/1"}, version="2.6")
    except (KeyError, TypeError) as exc:
        raise TaskAlongError("execution_identity_mismatch", "A complete exact Antigravity admission is required.", exit_code=3) from exc
    return packet, loads(canonical_bytes(packet)), mapping


def encode_input(packet):
    """One fixed NDJSON user message; the canonical packet stays unchanged."""
    admitted = validate_versioned("worker-packet", packet, expected_version="2.6")
    raw = canonical_bytes({"type": "user", "message": {"role": "user", "content": canonical_bytes(admitted).decode()}}) + b"\n"
    if len(raw) > 1024 * 1024:
        _refuse("agy_input_limit", "The framed input exceeds the owned runner's stdin limit.")
    return raw
