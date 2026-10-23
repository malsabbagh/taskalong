"""Immutable v2 semantic records. Reading these records never admits execution.

All identities and digests are declarations. Later trusted resolvers and
qualification must prove their subjects; neither a hash nor a valid document
proves CLI compatibility, credential authority, model routing or containment.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import urlsplit

from .contracts import JsonDocument
from .errors import TaskAlongError
from .validation import canonical_bytes, digest, loads, validate_versioned


def _normalize(document: dict[str, Any]) -> None:
    capabilities = document.get("required_capabilities")
    if isinstance(capabilities, list) and all(isinstance(value, str) for value in capabilities):
        # Preserve duplicate entries so schema admission rejects them.
        document["required_capabilities"] = sorted(capabilities)


def native_resume_compatibility_digest(document: dict[str, Any]) -> str:
    """Identity of exact semantic inputs plus the native session protocol.

    Excludes only the root digest and the compatibility digest itself. This
    names compatibility, not an existing session or permission to resume it.
    """
    subject = {key: value for key, value in document.items() if key != "digest"}
    _normalize(subject)
    resume = subject.get("native_resume")
    if not isinstance(resume, dict):
        raise TaskAlongError("schema_validation", "Native-resume compatibility inputs are required.")
    subject["native_resume"] = {key: value for key, value in resume.items() if key != "compatibility_digest"}
    return digest(subject, exclude_digest=False)


def _semantics(document: dict[str, Any]) -> None:
    if document["kind"] == "provider_profile":
        endpoint = document["endpoint"]
        try:
            parsed = urlsplit(endpoint)
            if (not endpoint.isascii() or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in endpoint)
                    or "\\" in endpoint or "%" in parsed.netloc or parsed.username is not None
                    or parsed.password is not None or not parsed.hostname or parsed.query or parsed.fragment
                    or parsed.port == 0):
                raise ValueError
            if document["provider"] == "ollama-local":
                if parsed.scheme not in {"http", "https"} or not ipaddress.ip_address(parsed.hostname).is_loopback:
                    raise ValueError
            elif parsed.scheme != "https":
                raise ValueError
        except ValueError as exc:
            raise TaskAlongError("schema_validation", "The provider destination is unsupported.") from exc
    if document["kind"] == "execution_binding":
        budget = document["budget"]
        capabilities = document["required_capabilities"]
        for unit in ("cost", "token"):
            required = budget[f"hard_{unit}_cap_required"]
            limit = budget["max_cost_micro_usd" if unit == "cost" else "max_tokens"]
            if required and (limit is None or f"hard_{unit}_cap" not in capabilities):
                raise TaskAlongError("schema_validation", "A required hard cap needs an explicit limit and capability.")
        resume = document["native_resume"]
        if (resume is not None) != ("native_resume" in capabilities):
            raise TaskAlongError("schema_validation", "Native resume requires explicit exact-session compatibility inputs.")
        if resume is not None and resume["compatibility_digest"] != native_resume_compatibility_digest(document):
            raise TaskAlongError("digest_mismatch", "Native-resume compatibility inputs do not match.")


@dataclass(frozen=True, slots=True)
class _SemanticDocument(JsonDocument):
    def __post_init__(self) -> None:
        admitted = validate_versioned(self.schema_name, loads(self._canonical), expected_version="2.0")
        object.__setattr__(self, "_canonical", canonical_bytes(admitted))


@dataclass(frozen=True, slots=True)
class HarnessInstallation(_SemanticDocument):
    schema_name: ClassVar[str] = "harness-installation"


@dataclass(frozen=True, slots=True)
class ProviderProfile(_SemanticDocument):
    schema_name: ClassVar[str] = "provider-profile"


@dataclass(frozen=True, slots=True)
class ExecutionBinding(_SemanticDocument):
    schema_name: ClassVar[str] = "execution-binding"
