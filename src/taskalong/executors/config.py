"""Immutable local driver descriptions; reading one cannot register a launcher."""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, TYPE_CHECKING

from ..execution import AntigravityDocument, CursorDocument, DriverDocument, OllamaDocument
from ..errors import TaskAlongError
if TYPE_CHECKING:
    from ..trial import TrialDriverConfig


@dataclass(frozen=True, slots=True)
class DriverConfig(DriverDocument):
    schema_name: ClassVar[str] = "driver-config"


@dataclass(frozen=True, slots=True)
class OllamaDriverConfig(OllamaDocument):
    schema_name: ClassVar[str] = "driver-config"


@dataclass(frozen=True, slots=True)
class CursorDriverConfig(CursorDocument):
    schema_name: ClassVar[str] = "driver-config"


@dataclass(frozen=True, slots=True)
class AntigravityDriverConfig(AntigravityDocument):
    schema_name: ClassVar[str] = "driver-config"


def read_driver_config(document: dict) -> DriverConfig | OllamaDriverConfig | CursorDriverConfig | AntigravityDriverConfig | TrialDriverConfig:
    """Select an explicit immutable family, without registering or qualifying it."""
    if type(document) is not dict:
        raise TaskAlongError("schema_validation", "A driver configuration must be a JSON object.")
    if document.get("schema_version") == "2.3":
        return DriverConfig.from_dict(document)
    if document.get("schema_version") == "2.4":
        return OllamaDriverConfig.from_dict(document)
    if document.get("schema_version") == "2.5":
        return CursorDriverConfig.from_dict(document)
    if document.get("schema_version") == "2.6":
        return AntigravityDriverConfig.from_dict(document)
    if document.get("schema_version") == "2.8":
        from ..trial import TrialDriverConfig
        return TrialDriverConfig.from_dict(document)
    raise TaskAlongError("unknown_schema_version", "The driver configuration version is unsupported.")
