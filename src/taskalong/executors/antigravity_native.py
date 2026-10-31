"""Pure plans for the documented native agy CLI; not an admitted launcher.

The installed help and https://antigravity.google/docs/cli/reference/ describe
these arguments. Neither a plan nor a decoded response qualifies execution,
context isolation, effective effort, process cessation or billing enforcement.
The shared owner must check executable/configuration identity, permissions,
context, scope and its remaining deadline immediately before any dispatch.
The historical antigravity-headless-fixture/1 contract is independent.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import PurePosixPath, PureWindowsPath
import re

from ..errors import TaskAlongError
from .antigravity_native_protocol import checked_native_schema, encode_native_input


@dataclass(frozen=True, slots=True)
class NativeAntigravityConfig:
    """Explicit requested settings, with no auth lookup or qualification claim."""

    executable: str
    executable_sha256: str
    model: str
    effort: str
    print_timeout_seconds: int

    def __post_init__(self):
        executable = self.executable
        if type(executable) is not str or not 1 <= len(executable) <= 4096 or any(
                ord(char) < 32 or ord(char) == 127 for char in executable):
            _refuse()
        path = PureWindowsPath(executable) if "\\" in executable else PurePosixPath(executable)
        if (not path.is_absolute() or len(path.parts) < 2 or ".." in path.parts or str(path) != executable
                or type(self.executable_sha256) is not str
                or not re.fullmatch(r"[a-f0-9]{64}", self.executable_sha256)
                or type(self.model) is not str
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", self.model)
                or type(self.effort) is not str or self.effort not in {"low", "medium", "high", "xhigh", "max"}
                or type(self.print_timeout_seconds) is not int
                or not 1 <= self.print_timeout_seconds <= 86400):
            _refuse()


@dataclass(frozen=True, slots=True)
class NativeAntigravityPlan:
    """Inert argv/input bytes. The process owner supplies cwd and environment."""

    argv: tuple[str, ...]
    stdin: bytes
    executable_sha256: str
    requested_model: str
    requested_effort: str
    print_timeout_seconds: int

    @property
    def stdin_sha256(self):
        return hashlib.sha256(self.stdin).hexdigest()


def _refuse():
    raise TaskAlongError("agy_native_plan_invalid", "The native Antigravity plan requires explicit supported finite settings.",
                         exit_code=3, effect_outcome="not_sent")


def plan_native_turn(config: NativeAntigravityConfig, *, prompt: str,
                     result_schema: dict, remaining_seconds: int) -> NativeAntigravityPlan:
    """Plan one fresh turn without changing settings, credentials or processes.

    Always pin a finite print timeout. The installed CLI defaults to zero, which
    waits indefinitely. This plan cannot extend the core's remaining deadline;
    the core must also reserve its own cleanup time and retain its absolute clock.
    No additional flags, implicit continuation, permission bypass or fallback are
    accepted. Effort is requested, not proven effective by the documented stream.
    """
    if (type(config) is not NativeAntigravityConfig or type(remaining_seconds) is not int
            or remaining_seconds < 1):
        _refuse()
    # Revalidate an inert value without inspecting or executing the binary.
    config.__post_init__()
    schema = checked_native_schema(result_schema)
    timeout = min(config.print_timeout_seconds, remaining_seconds)
    argv = (config.executable, "--input-format", "stream-json", "--output-format", "stream-json",
            "--model", config.model, "--effort", config.effort,
            "--json-schema", json.dumps(schema, ensure_ascii=False, sort_keys=True,
                                        separators=(",", ":"), allow_nan=False),
            "--print-timeout", str(timeout) + "s", "--disable-slash-commands", "--sandbox")
    return NativeAntigravityPlan(argv, encode_native_input(prompt), config.executable_sha256,
                                config.model, config.effort, timeout)


def native_capabilities():
    """Conservative integration scope; documented flags are not runtime proof."""
    return {"scope": "native_cli_offline_helpers/1", "fresh_structured_turn": True,
            "native_resume": False, "provider_start_lookup": False, "interactive_approval": False,
            "remote_cancellation": False, "hard_cost_cap": False, "hard_token_cap": False,
            "effective_effort_verified": False, "context_isolation_verified": False,
            "local_cessation_verified": False, "live_inference_qualified": False,
            "production_dispatch_allowed": False}
