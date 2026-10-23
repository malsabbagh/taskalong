"""Immutable local driver descriptions; reading one cannot register a launcher."""
from dataclasses import dataclass
from typing import ClassVar

from ..execution import DriverDocument


@dataclass(frozen=True, slots=True)
class DriverConfig(DriverDocument):
    schema_name: ClassVar[str] = "driver-config"
