"""The existing Codex fixture projection; no extra driver or fallback."""
import platform
import sys

from ..errors import TaskAlongError
from ..execution import CheckBinding, InstructionBundle, SandboxPolicy, ToolPolicy

PROJECTION = "codex-v1-fixture/1"

def _refuse(code="execution_projection_unsupported"):
    raise TaskAlongError(code, "The selected execution context is unresolved or outside the implemented fixture projection.", exit_code=3)


def represent(binding, installation, provider, policies, profile, registration):
    b, i, p = binding.to_dict(), installation.to_dict(), provider.to_dict()
    for field, document in (("installation_digest", installation), ("provider_profile_digest", provider)):
        if b[field] != document.digest:
            _refuse("execution_identity_mismatch")
    instructions = policies.resolve(b["instruction_bundle_digest"], InstructionBundle).to_dict()
    tools = policies.resolve(b["tool_policy_digest"], ToolPolicy).to_dict()
    worker = policies.resolve(b["worker_sandbox_digest"], SandboxPolicy).to_dict()
    check = policies.resolve(b["check_binding_digest"], CheckBinding).to_dict()
    verifier = policies.resolve(check["sandbox_digest"], SandboxPolicy).to_dict()
    architecture = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x86_64"
    if (registration["projection"] != PROJECTION or profile["qualification"] != "synthetic"
            or i["harness"] != "codex" or i["adapter_id"] != profile["adapter"] or i["adapter_id"] != "codex-cli"
            or i["driver_version"] != "codex-v1-fixture-1" or i["cli_version"] != profile["runtime_version"]
            or i["executable_digest"] != profile["executable_sha256"]
            or i["platform"] != {"os": sys.platform, "architecture": architecture, "backend_id": "synthetic-fixture"}
            or profile["permission_policy"] != {} or profile["toolchain_read_roots"]
            or instructions["texts"] or tools["allowed_tools"] != ["fixture.edit"]
            or instructions["protective_policy_digest"] != profile["permission_policy_digest"]
            or worker["role"] != "worker" or verifier["role"] != "independent_check"
            or worker["backend_id"] != "synthetic-fixture" or verifier["backend_id"] != "synthetic-fixture"
            or worker["permission_policy_digest"] != profile["permission_policy_digest"]
            or p["harness"] != "codex" or p["provider"] != "openai-account"
            or p["model"]["requested"] != profile["model"] or p["effort"] != profile["reasoning_effort"]
            or p["service_tier"] != profile["service_tier"] or p["auth"]["credential_ref"] != profile["credential_source_ref"]
            or p["auxiliary_routes"]):
        _refuse()
    # Even a non-hard non-null limit cannot be silently discarded by v1.
    if b["budget"]["max_cost_micro_usd"] is not None or b["budget"]["max_tokens"] is not None:
        _refuse("hard_budget_unsupported")
    return check, verifier
