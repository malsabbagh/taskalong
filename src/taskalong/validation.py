"""Strict bounded JSON and offline, installed v1 document validation."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from contextlib import contextmanager
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import Any, Iterator

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

from .errors import TaskAlongError
from .paths import safe_relative

_FORMAT_CHECKER = FormatChecker()


@_FORMAT_CHECKER.checks("date-time", raises=(ValueError, TypeError))
def _utc_time(value: object) -> bool:
    if not isinstance(value, str):
        return True
    return value.endswith("Z") and datetime.fromisoformat(value[:-1] + "+00:00").utcoffset().total_seconds() == 0


SCHEMA_NAMES = (
    "task-spec", "task-run", "run-event", "worker-packet", "worker-result",
    "execution-observation", "evidence", "acceptance", "authority",
    "effect-intent", "command-result", "runtime-profile",
)
MAX_DOCUMENT_BYTES = 1_048_576
MAX_DEPTH = 64
_SECRETS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})\b"),
    re.compile(r"(?i)\b(?:authorization\s*:\s*bearer|(?:password|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[=:])\s*[^\s\"']{8,}"),
    re.compile(r"https?://[^\s/@:]+:[^\s/@]+@"),
)


def _invalid(message: str, code: str = "invalid_document") -> TaskAlongError:
    return TaskAlongError(code, message)


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise _invalid("Duplicate JSON object keys are unsupported.", "duplicate_key")
        result[key] = value
    return result


def _no_float(_: str) -> Any:
    raise _invalid("Floating point and non-finite JSON numbers are unsupported.", "invalid_number")


def _bounded(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise _invalid("The document exceeds the nesting limit.", "document_too_deep")
    if value is None or type(value) is bool or type(value) is int:
        if type(value) is int and abs(value) > 2**53 - 1:
            raise _invalid("Integer values must fit the interoperable JSON range.", "invalid_number")
        return
    if type(value) is str:
        try:
            size = len(value.encode("utf-8"))
        except UnicodeError as exc:
            raise _invalid("The document contains invalid Unicode.", "invalid_encoding") from exc
        if size > MAX_DOCUMENT_BYTES:
            raise _invalid("A document string exceeds its size limit.", "document_too_large")
        return
    if type(value) is list:
        if len(value) > 4096:
            raise _invalid("A document list exceeds its item limit.", "document_too_large")
        for item in value:
            _bounded(item, depth + 1)
        return
    if type(value) is dict:
        if len(value) > 4096 or any(type(key) is not str for key in value):
            raise _invalid("Object keys must be bounded JSON strings.")
        for key, item in value.items():
            _bounded(key, depth + 1)
            _bounded(item, depth + 1)
        return
    raise _invalid("Only strict JSON values are supported; floats are forbidden.", "invalid_number" if isinstance(value, float) else "invalid_document")


def canonical_bytes(value: Any) -> bytes:
    """Return canonical UTF-8 bytes; this does not imply schema admission."""
    _bounded(value)
    try:
        result = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise _invalid("The value cannot be represented as strict canonical JSON.") from exc
    if len(result) > MAX_DOCUMENT_BYTES:
        raise _invalid("The document exceeds the byte limit.", "document_too_large")
    return result


def digest(value: Any, *, exclude_digest: bool = True) -> str:
    if exclude_digest and isinstance(value, dict):
        value = {key: item for key, item in value.items() if key != "digest"}
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def loads(data: str | bytes, *, max_bytes: int = MAX_DOCUMENT_BYTES) -> dict[str, Any]:
    if not isinstance(data, (str, bytes)):
        raise _invalid("JSON text or UTF-8 bytes are required.")
    try:
        raw = data if isinstance(data, bytes) else data.encode("utf-8")
        if len(raw) > min(max_bytes, MAX_DOCUMENT_BYTES):
            raise _invalid("The JSON input exceeds its byte limit.", "document_too_large")
        decoded = raw.decode("utf-8", errors="strict")
        value = json.loads(decoded, object_pairs_hook=_pairs, parse_float=_no_float, parse_constant=_no_float)
    except TaskAlongError:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise _invalid("The input is not a bounded UTF-8 JSON document.", "invalid_json") from exc
    if not isinstance(value, dict):
        raise _invalid("A JSON document must have an object root.")
    _bounded(value)
    return value


def load_json(path: str | Path, *, max_bytes: int = MAX_DOCUMENT_BYTES) -> dict[str, Any]:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(min(max_bytes, MAX_DOCUMENT_BYTES) + 1)
    except OSError as exc:
        raise TaskAlongError("document_unreadable", "The requested JSON document cannot be read.") from exc
    return loads(data, max_bytes=max_bytes)


def schema_names(*, version: str = "1.0") -> tuple[str, ...]:
    if version == "1.0":
        return SCHEMA_NAMES
    if version == "2.0":
        return ("harness-installation", "provider-profile", "execution-binding")
    if version == "2.1":
        return ("qualification-receipt", "qualification-decision", "capability-report")
    if version == "2.2":
        return ("task-spec", "instruction-bundle", "tool-policy", "sandbox-policy", "check-binding",
                "worker-packet", "packet-projection", "evidence", "result-view", "capabilities-view")
    if version == "2.3":
        return ("driver-config", "task-spec", "worker-packet", "packet-projection", "worker-result")
    if version == "2.4":
        return ("driver-config", "task-spec", "worker-packet", "packet-projection")
    if version == "2.5":
        return ("driver-config", "task-spec", "worker-packet", "packet-projection", "worker-result")
    if version == "2.6":
        return ("driver-config", "task-spec", "worker-packet", "packet-projection")
    raise _invalid("The schema version is unsupported.", "unknown_schema_version")


def schema(name: str, *, version: str = "1.0") -> dict[str, Any]:
    name = name.removesuffix(".schema.json").replace("_", "-")
    if name not in schema_names(version=version):
        raise _invalid("The schema name is unsupported.", "unknown_schema")
    directory = {"1.0": "v1", "2.0": "v2", "2.1": "v2.1", "2.2": "v2.2", "2.3": "v2.3", "2.4": "v2.4", "2.5": "v2.5", "2.6": "v2.6"}[version]
    return loads(resources.files("taskalong.resources").joinpath("schemas", directory, name + ".schema.json").read_bytes())


def _no_remote(uri: str) -> Resource[Any]:
    raise NoSuchResource(ref=uri)


def schema_registry(*, version: str = "1.0") -> Registry[Any]:
    registry: Registry[Any] = Registry(retrieve=_no_remote)
    for name in schema_names(version=version):
        resource = Resource.from_contents(schema(name, version=version))
        registry = registry.with_resource(resource.id(), resource)
    return registry


@contextmanager
def resource_path(relative: str) -> Iterator[Path]:
    """Give a read-only resource a filesystem path for a bounded subprocess."""
    if relative.startswith("/") or ".." in relative.split("/") or "\\" in relative:
        raise _invalid("Invalid package resource path.")
    resource = resources.files("taskalong.resources").joinpath(*relative.split("/"))
    if not resource.is_file():
        raise _invalid("The package resource is unavailable.")
    with resources.as_file(resource) as path:
        yield path


def screen_sensitive(value: Any) -> None:
    """Reject recognizable credentials before persistence/digests.

    This is a conservative secondary screen, not a claim to detect every secret.
    The error never contains the matched text or a digest of it.
    """
    _bounded(value)
    if isinstance(value, str):
        if any(pattern.search(value) for pattern in _SECRETS):
            raise _invalid("Credential-bearing input must be removed before submission.", "sensitive_input")
    elif isinstance(value, dict):
        credential_keys = {"password", "passwd", "api_key", "apikey", "api-key", "access_token", "refresh_token", "client_secret", "authorization", "private_key"}
        for key, item in value.items():
            if key.lower() in credential_keys and item is not None and item != "":
                raise _invalid("Credential-bearing input must be removed before submission.", "sensitive_input")
            screen_sensitive(key)
            screen_sensitive(item)
    elif isinstance(value, list):
        for item in value:
            screen_sensitive(item)


def _sets(document: dict[str, Any], name: str) -> None:
    # Only these arrays have set semantics. Others retain their meaningful order.
    if name in {"task-spec", "worker-packet"}:
        scope = document.get("scope", {})
        if not isinstance(scope, dict):
            scope = {}
        for key in ("files", "operations"):
            if isinstance(scope.get(key), list) and all(isinstance(x, str) for x in scope[key]):
                scope[key] = sorted(set(scope[key]))
        for check in document.get("checks", []) if isinstance(document.get("checks"), list) else []:
            if isinstance(check, dict) and isinstance(check.get("criterion_ids"), list) and all(isinstance(x, str) for x in check["criterion_ids"]):
                check["criterion_ids"] = sorted(set(check["criterion_ids"]))
    if name == "task-spec":
        for criterion in document.get("criteria", []) if isinstance(document.get("criteria"), list) else []:
            if isinstance(criterion, dict) and isinstance(criterion.get("check_ids"), list) and all(isinstance(x, str) for x in criterion["check_ids"]):
                criterion["check_ids"] = sorted(set(criterion["check_ids"]))
        permissions = document.get("permissions", {})
        if not isinstance(permissions, dict):
            permissions = {}
        if isinstance(permissions.get("allowed_effects"), list) and all(isinstance(x, str) for x in permissions["allowed_effects"]):
            permissions["allowed_effects"] = sorted(set(permissions["allowed_effects"]))
    for key in {"evidence_ids", "criterion_ids", "authority_ids", "toolchain_read_roots", "qualification_receipt_ids", "scope"}:
        items = document.get(key)
        if isinstance(items, list) and all(isinstance(item, str) for item in items):
            document[key] = sorted(set(items))


def _semantics(document: dict[str, Any], name: str) -> None:
    def printable_ids(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if (key == "id" or key.endswith("_id") or key == "operation_key") and isinstance(item, str) and not item.isprintable():
                    raise _invalid("Identifiers must contain printable characters only.")
                printable_ids(item)
        elif isinstance(value, list):
            for item in value:
                printable_ids(item)
    printable_ids(document)
    if name in {"task-spec", "worker-packet"}:
        if sum(len(x.encode("utf-8")) for x in [document["goal"], *document["non_goals"]]) > 16384:
            raise _invalid("The combined goal and non-goals exceed 16 KiB.")
        for path in document["scope"]["files"]:
            safe_relative(path, allow_directory=True)
        for check in document["checks"]:
            safe_relative(check["cwd"], allow_dot=True)
            if check["required"] and check["expected_exit_code"] != 0:
                raise _invalid("Required checks must expect exit code zero.")
            if Path(check["argv"][0]).name.lower() in {"sh", "bash", "zsh", "fish", "dash", "ksh", "cmd", "cmd.exe", "powershell", "pwsh"}:
                raise _invalid("Shell command execution is unsupported.")
        check_ids = [check["id"] for check in document["checks"]]
        if len(set(check_ids)) != len(check_ids):
            raise _invalid("Check identities must be unique.")
    if name == "task-spec":
        criteria = document["criteria"]
        criterion_ids = {criterion["id"] for criterion in criteria}
        if len(criterion_ids) != len(criteria):
            raise _invalid("Criterion identities must be unique.")
        checks = {check["id"]: check for check in document["checks"]}
        for criterion in criteria:
            if not set(criterion["check_ids"]).issubset(checks):
                raise _invalid("A criterion refers to an unknown check.")
            if not any(checks[key]["required"] for key in criterion["check_ids"]):
                raise _invalid("Every criterion needs an independent required check.")
            if any(criterion["id"] not in checks[key]["criterion_ids"] for key in criterion["check_ids"]):
                raise _invalid("Criterion and check bindings must agree.")
        if any(not set(check["criterion_ids"]).issubset(criterion_ids) for check in checks.values()):
            raise _invalid("A check refers to an unknown criterion.")
        if document["budget"]["attempt_seconds"] > document["budget"]["total_active_seconds"]:
            raise _invalid("An attempt budget cannot exceed the total active budget.")
    if name == "worker-result":
        paths = [item["path"] for item in document["changed_files"]]
        if len(paths) != len(set(paths)):
            raise _invalid("Worker changed paths must be unique.")
        for path in paths:
            safe_relative(path)
    if name == "runtime-profile":
        if not Path(document["executable_path"]).is_absolute() or any(not Path(path).is_absolute() for path in document["toolchain_read_roots"]):
            raise _invalid("Trusted runtime paths must be absolute.")
        if digest(document["permission_policy"]) != document["permission_policy_digest"]:
            raise _invalid("The permission-policy digest does not match.", "digest_mismatch")
    if name == "evidence" and document["command"] is not None:
        safe_relative(document["command"]["cwd_relative"], allow_dot=True)
    if name == "authority" and document["expires_at"] <= document["issued_at"]:
        raise _invalid("Authority must expire after it was issued.")


def validate(name: str, document: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize a copy, returning the admitted document.

    The normalized document is the digest subject. Callers must persist this
    returned value rather than the unvalidated input.
    """
    name = name.removesuffix(".schema.json").replace("_", "-")
    canonical_bytes(document)
    if not isinstance(document, dict):
        raise _invalid("A schema document must have an object root.")
    result = copy.deepcopy(document)
    _sets(result, name)
    validator = Draft202012Validator(schema(name), registry=schema_registry(), format_checker=_FORMAT_CHECKER)
    error = next(validator.iter_errors(result), None)
    if error is not None:
        # Error values may contain private task content. Return only a fixed code
        # and the path composed of known schema property names/indexes.
        raise _invalid("The document does not match the supported v1 schema.", "schema_validation")
    _semantics(result, name)
    if "digest" in result and digest(result) != result["digest"]:
        raise _invalid("The document digest does not match normalized content.", "digest_mismatch")
    return result


def seal(name: str, document: dict[str, Any]) -> dict[str, Any]:
    """Normalize an original core document and calculate its content digest."""
    name = name.removesuffix(".schema.json").replace("_", "-")
    if not isinstance(document, dict):
        raise _invalid("A schema document must have an object root.")
    result = copy.deepcopy(document)
    result.setdefault("kind", name.replace("-", "_"))
    result.setdefault("schema_version", "1.0")
    result.setdefault("extensions", {})
    _sets(result, name)
    if "digest" in schema(name)["properties"]:
        result["digest"] = digest(result)
    return validate(name, result)


def validate_versioned(name: str, document: dict[str, Any], *, expected_version: str) -> dict[str, Any]:
    """Read an explicitly selected format without guessing or granting authority.

    V1 retains its original normalization and validation path. V2 records are
    offline semantic descriptions, not resolved or qualified execution routes.
    """
    if expected_version == "1.0":
        return validate(name, document)
    selected = schema(name, version=expected_version)
    canonical_bytes(document)
    if not isinstance(document, dict):
        raise _invalid("A schema document must have an object root.")
    screen_sensitive(document)
    result = copy.deepcopy(document)
    validator = Draft202012Validator(selected, registry=schema_registry(version=expected_version), format_checker=_FORMAT_CHECKER)
    if next(validator.iter_errors(result), None) is not None:
        raise _invalid("The document does not match the selected schema.", "schema_validation")
    if expected_version == "2.0":
        from .bindings import _normalize, _semantics as binding_semantics
        _normalize(result)
        binding_semantics(result)
    elif expected_version == "2.1":
        from .qualification import _semantics as qualification_semantics
        qualification_semantics(result)
    elif expected_version in {"2.2", "2.3", "2.4", "2.5", "2.6"}:
        _sets(result, name)
        if name in {"task-spec", "worker-packet", "worker-result"}:
            _semantics(result, name)
    if "digest" in selected["properties"] and digest(result) != result["digest"]:
        raise _invalid("The document digest does not match normalized content.", "digest_mismatch")
    return result


def seal_versioned(name: str, document: dict[str, Any], *, version: str) -> dict[str, Any]:
    """Seal semantic data for an explicit version; no registration or resolution."""
    if version == "1.0":
        return seal(name, document)
    selected = schema(name, version=version)
    canonical_bytes(document)
    if not isinstance(document, dict):
        raise _invalid("A schema document must have an object root.")
    screen_sensitive(document)
    result = copy.deepcopy(document)
    result.setdefault("kind", name.removesuffix(".schema.json").replace("-", "_"))
    result.setdefault("schema_version", version)
    if version == "2.0":
        from .bindings import _normalize
        _normalize(result)
    elif version in {"2.2", "2.3", "2.4", "2.5", "2.6"}:
        _sets(result, name)
    if "digest" in selected["properties"]:
        result["digest"] = digest(result)
    return validate_versioned(name, result, expected_version=version)
