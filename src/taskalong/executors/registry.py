"""Closed built-in worker selection for the durable supervisor.

Only implemented drivers are admitted. Discovery of a vendor binary does not
register it or qualify dispatch. Task data cannot select an import or fallback.
"""
from types import MappingProxyType

from ..errors import TaskAlongError
from .base import HarnessDriver
from .codex_cli import CodexCLI

_DRIVERS = MappingProxyType({"codex-cli": CodexCLI})


def executor_for(profile: dict) -> HarnessDriver:
    """Select a driver without spawning; its preflight still owns admission.

    New drivers require versioned contracts and independent qualification,
    rather than conditionals or optimistic placeholder implementations here.
    """
    adapter = profile.get("adapter")
    if not isinstance(adapter, str) or adapter not in _DRIVERS:
        raise TaskAlongError("adapter_unavailable", "No implemented driver is registered for the selected adapter.",
                           exit_code=3, recovery=[{"action": "select_implemented_adapter"}])
    return _DRIVERS[adapter](profile)


def default_runtime_requirements() -> dict:
    """Static v1 diagnostic requirements; neither a probe nor qualification."""
    return CodexCLI._qualification_requirements()
