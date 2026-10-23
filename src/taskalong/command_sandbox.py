"""Independent command-check boundary; worker selection grants no check policy.

V1 uses its existing Codex-backed policy. This factory is deliberately separate
from the worker registry so a later worker adapter cannot select the verifier's
sandbox. V2 must bind the check policy explicitly before introducing other modes.
"""
from pathlib import Path
from typing import Protocol, Sequence

from .errors import TaskAlongError
from .executors.codex_cli import CodexCLI


class CommandSandbox(Protocol):
    def prepare_check(self, argv: Sequence[str], *, workspace: str | Path,
                      git_common_dir: str | Path, control_dir: str | Path) -> list[str]: ...


class _CodexCommandSandbox:
    def __init__(self, profile: dict):
        self._builder = CodexCLI(profile)

    def prepare_check(self, argv: Sequence[str], *, workspace: str | Path,
                      git_common_dir: str | Path, control_dir: str | Path) -> list[str]:
        # Preserve the pinned sandbox parser and exact policy construction.
        # Preparation never spawns or supplies a cessation/qualification receipt.
        return self._builder.sandbox_argv(argv, workspace=workspace,
                                         git_common_dir=git_common_dir, control_dir=control_dir)


def command_sandbox_for(profile: dict) -> CommandSandbox:
    if profile.get("adapter") != "codex-cli":
        raise TaskAlongError("command_sandbox_unsupported", "The v1 independent check policy requires the Codex-backed command sandbox.", exit_code=3)
    return _CodexCommandSandbox(profile)
