"""Closed built-in worker selection for the durable supervisor.

Only implemented drivers are admitted. Discovery of a vendor binary does not
register it or qualify dispatch. Task data cannot select an import or fallback.
"""
from types import MappingProxyType
from dataclasses import dataclass
from typing import Callable
from functools import partial

from ..errors import TaskAlongError
from .base import HarnessDriver
from .codex_cli import CodexCLI
from .cursor_cli import CursorCLI, compile_packet as compile_cursor_packet, represent as represent_cursor
from .cursor_cli import _represent_provider as cursor_provider
from .cursor_protocol import CursorStreamDecoder
from .antigravity_cli import (AntigravityCLI, compile_packet as compile_agy_packet,
    represent as represent_agy, _represent_provider as agy_provider, encode_input as agy_input,
    reported_usage as agy_usage)
from .antigravity_protocol import AntigravityStreamDecoder
from .config import AntigravityDriverConfig, CursorDriverConfig
from .claude_code import ClaudeCode, OLLAMA_FIXTURE, compile_packet as compile_claude_packet, represent as represent_claude
from .codex_projection import represent as represent_codex
from ..validation import seal


@dataclass(frozen=True, slots=True)
class CaptureContract:
    """Closed built-in observation/capture semantics, never task-selected code."""
    version: str
    name: str
    error_prefix: str
    config_reader: type
    represent_provider: Callable
    decoder: Callable
    input_bytes: Callable | None = None
    reported_usage: Callable | None = None


@dataclass(frozen=True, slots=True)
class DriverContract:
    factory: Callable
    compile_packet: Callable
    represent: Callable
    capture: CaptureContract | None = None


def _codex_packet(fields, admission):
    packet = seal("worker-packet", fields)
    if admission is None:
        return None, packet, None
    from ..execution import project_packet
    return project_packet(packet, admission)


def _claude_driver(configuration, provider):
    if provider is None:
        raise TaskAlongError("execution_document_unresolved", "An exact provider document is required.", exit_code=3)
    return ClaudeCode(configuration, provider=provider)


def _ollama_driver(configuration, provider):
    if provider is None:
        raise TaskAlongError("execution_document_unresolved", "An exact provider document is required.", exit_code=3)
    return ClaudeCode(configuration, provider=provider, contract=OLLAMA_FIXTURE)


def _cursor_driver(configuration, provider):
    if provider is None:
        raise TaskAlongError("execution_document_unresolved", "An exact provider document is required.", exit_code=3)
    return CursorCLI(configuration, provider=provider)


def _agy_driver(configuration, provider):
    if provider is None:
        raise TaskAlongError("execution_document_unresolved", "An exact provider document is required.", exit_code=3)
    return AntigravityCLI(configuration, provider=provider)


def _cursor_decoder(packet, config, attempt, limit):
    return CursorStreamDecoder(packet, expected_model=config["expected_reported_model"], max_output_bytes=limit)


def _agy_decoder(packet, config, attempt, limit):
    from pathlib import Path
    return AntigravityStreamDecoder(packet, expected_model=config["expected_reported_model"],
        expected_cwd=str(Path(attempt["workspace"]["path"]).resolve()), max_output_bytes=limit)


_CODEX = DriverContract(lambda configuration, provider: CodexCLI(configuration), _codex_packet, represent_codex)
_CONTRACTS = MappingProxyType({
    ("1.0", "codex-v1", "runtime_profile", "1.0"): _CODEX,
    ("2.2", "codex-v1-fixture/1", "runtime_profile", "1.0"): _CODEX,
    ("2.3", "claude-print-fixture/1", "driver_config", "2.3"): DriverContract(_claude_driver, compile_claude_packet, represent_claude),
    ("2.4", "claude-ollama-fixture/1", "driver_config", "2.4"): DriverContract(_ollama_driver,
        partial(compile_claude_packet, contract=OLLAMA_FIXTURE), partial(represent_claude, contract=OLLAMA_FIXTURE)),
    ("2.5", "cursor-print-fixture/1", "driver_config", "2.5"): DriverContract(
        _cursor_driver, compile_cursor_packet, represent_cursor,
        CaptureContract("2.5", "cursor", "cursor", CursorDriverConfig, cursor_provider, _cursor_decoder)),
    ("2.6", "antigravity-headless-fixture/1", "driver_config", "2.6"): DriverContract(
        _agy_driver, compile_agy_packet, represent_agy,
        CaptureContract("2.6", "antigravity", "agy", AntigravityDriverConfig, agy_provider, _agy_decoder, agy_input, agy_usage)),
})


def capture_for_version(version):
    """Optional built-in captured-session contract; no runtime discovery."""
    return next((item.capture for key, item in _CONTRACTS.items() if key[0] == version and item.capture), None)


def contract_for(configuration: dict, *, task_version="1.0", projection="codex-v1") -> DriverContract:
    """Select one closed version/projection/config tuple without discovery.

    New drivers require versioned contracts and independent qualification,
    rather than conditionals or optimistic placeholder implementations here.
    """
    kind = configuration.get("kind", "runtime_profile") if isinstance(configuration, dict) else None
    version = configuration.get("schema_version", "1.0") if isinstance(configuration, dict) else None
    key = (task_version, projection, kind, version)
    contract = _CONTRACTS.get(key) if all(type(value) is str for value in key) else None
    if contract is None or kind == "runtime_profile" and configuration.get("adapter") != "codex-cli":
        raise TaskAlongError("adapter_unavailable", "No implemented driver is registered for the selected adapter.",
                           exit_code=3, recovery=[{"action": "select_implemented_adapter"}])
    return contract


def executor_for(profile: dict, *, provider=None, task_version="1.0", projection="codex-v1") -> HarnessDriver:
    """No launch, automatic fallback or authority from portable task data."""
    return contract_for(profile, task_version=task_version, projection=projection).factory(profile, provider)


def default_runtime_requirements() -> dict:
    """Static v1 diagnostic requirements; neither a probe nor qualification."""
    return CodexCLI._qualification_requirements()
