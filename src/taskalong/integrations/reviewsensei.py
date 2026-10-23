"""Released ReviewSensei 0.8.8 CLI contract; no review-engine imports.

The ordinary full reviewed diff is ``full-reviewed-diff-v1`` assurance. It is
never represented as a confirmed-evidence transaction or live-model evidence.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from ..errors import TaskAlongError
from ..process import ProcessBoundaryError, fingerprint, run_bounded
from ..validation import canonical_bytes, loads

RELEASE = "0.8.8"
WHEEL_SHA256 = "34337c4da835f794914915aeb2a0b4521f05d4ab13120452ee6ee4e43dbbf1b0"
MAX_DOCUMENT_BYTES = 1024 * 1024
PROVIDERS = {"fixture", "local-ollama", "cloud-ollama", "openrouter", "openai-compatible"}


def _blocked(code: str, message: str, *, effect_outcome: str = "not_sent") -> TaskAlongError:
    return TaskAlongError(code, message, exit_code=5 if effect_outcome == "uncertain" else 3,
                         effect_outcome=effect_outcome)


def diff_inventory(diff: bytes) -> tuple[list[str], list[tuple[int, str]]]:
    """Enumerate exact regular-text diff paths and ordered hunk identities.

    The core already restricts candidate changes to UTF-8 additions/modifications.
    This independent parser refuses ambiguous headers, binary, rename and delete
    forms instead of weakening complete-coverage admission.
    """
    if len(diff) > 8 * MAX_DOCUMENT_BYTES:
        raise _blocked("review_diff_too_large", "The review diff exceeds the bounded contract.")
    try:
        text = diff.decode("utf-8", "strict")
    except UnicodeError:
        raise _blocked("review_diff_unsupported", "Review requires a UTF-8 regular-file diff.") from None
    paths: list[str] = []
    hunks: list[tuple[int, str]] = []
    current: str | None = None
    hunk_index = 0
    old_remaining = new_remaining = 0
    for line in text.splitlines():
        if old_remaining or new_remaining:
            if line.startswith("\\ No newline at end of file"):
                continue
            prefix = line[:1]
            if prefix == " ":
                old_remaining -= 1; new_remaining -= 1
            elif prefix == "-":
                old_remaining -= 1
            elif prefix == "+":
                new_remaining -= 1
            else:
                raise _blocked("review_diff_unsupported", "The review diff has a truncated hunk.")
            if old_remaining < 0 or new_remaining < 0:
                raise _blocked("review_diff_unsupported", "The review diff has inconsistent hunk lengths.")
            continue
        if line.startswith(("GIT binary patch", "Binary files ", "deleted file mode ", "rename from ", "rename to ", "old mode ", "new mode ")):
            raise _blocked("review_diff_unsupported", "The review diff contains an unsupported change type.")
        if line.startswith("diff --git "):
            current = None
        elif line.startswith("+++ "):
            path = line[4:]
            if path.startswith('"'):
                try:
                    path = ast.literal_eval(path)
                    # Git C quoting encodes UTF-8 bytes using octal escapes.
                    if "\\" in line:
                        path = path.encode("latin-1").decode("utf-8")
                except (SyntaxError, ValueError, UnicodeError):
                    raise _blocked("review_diff_unsupported", "The review diff has an ambiguous path.") from None
            if not isinstance(path, str) or not path.startswith("b/"):
                raise _blocked("review_diff_unsupported", "Review requires ordinary Git file headers.")
            path = path[2:]
            if not path or path.startswith("/") or any(x in {"", ".", "..", ".git"} for x in path.split("/")) or any(ord(x) < 32 for x in path):
                raise _blocked("review_diff_unsupported", "The review diff has an unsafe path.")
            if path in paths:
                raise _blocked("review_diff_unsupported", "The review diff repeats a file header.")
            paths.append(path)
            current = path
        elif line.startswith("@@ "):
            header = re.match(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@", line)
            if current is None or header is None:
                raise _blocked("review_diff_unsupported", "The review diff has an invalid hunk header.")
            old_remaining = int(header.group(1)) if header.group(1) is not None else 1
            new_remaining = int(header.group(2)) if header.group(2) is not None else 1
            hunk_index += 1
            hunks.append((hunk_index, current))
    if old_remaining or new_remaining or not paths or not hunks or set(paths) != {path for _, path in hunks}:
        raise _blocked("review_diff_unsupported", "Every required review file must have an enumerated text hunk.")
    return paths, hunks


def validate_review_documents(
    result: dict[str, Any], outcome: dict[str, Any], *, schemas: dict[str, dict[str, Any]],
    diff: bytes, subject: dict[str, Any], exit_code: int | None,
    qualification: str, expected_provider: str,
) -> None:
    """Fail closed over schema, exact subject, complete coverage and exit semantics."""
    if exit_code != 0:
        code = "review_cancelled" if exit_code == 130 else "review_not_complete"
        raise _blocked(code, "The independent review did not complete without required fixes.")
    if qualification not in {"synthetic", "production"}:
        raise _blocked("review_qualification_invalid", "The review qualification is unsupported.")
    try:
        registry = Registry().with_resources((doc["$id"], Resource.from_contents(doc)) for doc in schemas.values())
        for name, value in (("review-result", result), ("run-outcome", outcome), ("coverage-manifest", result.get("coverage"))):
            validator = Draft202012Validator(schemas[name], registry=registry)
            if next(validator.iter_errors(value), None) is not None:
                raise ValueError(name)
    except Exception as exc:
        if isinstance(exc, TaskAlongError):
            raise
        raise _blocked("review_schema_invalid", "The released review output failed its installed v1 schema.") from None
    if outcome.get("schema_version") != "1.0" or outcome.get("status") != "reviewed":
        raise _blocked("review_not_complete", "The review outcome is not a reviewed v1 result.")
    if outcome.get("base_sha") != subject["base_commit"] or outcome.get("head_sha") != subject["candidate_commit"]:
        raise _blocked("review_subject_mismatch", "The review subject differs from the candidate.")
    if hashlib.sha256(diff).hexdigest() != subject["diff_sha256"]:
        raise _blocked("review_subject_mismatch", "The immutable diff differs from the candidate binding.")
    if result.get("provider") != expected_provider or expected_provider not in PROVIDERS:
        raise _blocked("review_provider_mismatch", "The review producer differs from the approved provider.")
    if qualification == "production" and expected_provider == "fixture":
        raise _blocked("fixture_in_production", "Fixture review cannot qualify a production run.")
    if result.get("review_status") != "complete" or result.get("coverage_only_partial", False) or "persistence_status" in result:
        raise _blocked("review_not_complete", "Required review coverage is incomplete.")
    if result.get("evidence_policy") not in {"legacy", "confirmed"}:
        raise _blocked("review_assurance_unsupported", "The review evidence policy is unsupported.")
    if any(comment.get("blocking") is True for comment in result.get("comments", [])):
        raise _blocked("review_required_fixes", "The review contains contradictory blocking findings.")
    if not outcome.get("stage_summary") or any(value != "complete" for value in outcome["stage_summary"].values()):
        raise _blocked("review_not_complete", "Every required review stage must be complete.")
    coverage = result["coverage"]
    expected_paths, expected_hunks = diff_inventory(diff)
    actual_paths = coverage["enumerated_paths"]
    actual_files = coverage["files"]
    actual_hunks = coverage["hunks"]
    if (coverage.get("enumeration_complete") is not True or coverage.get("fully_reviewed") is not True
        or len(actual_paths) != len(set(actual_paths)) or set(actual_paths) != set(expected_paths)
        or len(actual_files) != len(expected_paths)
        or {item["path"] for item in actual_files} != set(expected_paths)
        or any(item["outcome"] != "reviewed" or "reason" in item for item in actual_files)
        or len(actual_hunks) != len(expected_hunks)
        or {(item["index"], item["path"]) for item in actual_hunks} != set(expected_hunks)
        or any(item["outcome"] != "reviewed" or "reason" in item for item in actual_hunks)):
        raise _blocked("review_coverage_incomplete", "The review does not cover every exact candidate path and hunk.")


@dataclass(frozen=True)
class ReviewReceipt:
    """Private adapter output; only the invoking core may admit it as evidence."""
    invocation_id: str
    executable_sha256: str
    version: str
    provider: str
    config_digest: str
    subject: dict[str, Any]
    qualification: str
    result: dict[str, Any]
    outcome: dict[str, Any]
    duration_ms: int
    output_bytes: int
    artifacts: tuple[dict[str, Any], ...]
    assurance: str = "full-reviewed-diff-v1"

    def to_dict(self) -> dict[str, Any]:
        # Raw review text is private and is deliberately absent from this receipt.
        return {"invocation_id": self.invocation_id, "executable_sha256": self.executable_sha256,
                "version": self.version, "provider": self.provider, "config_digest": self.config_digest,
                "subject": self.subject, "qualification": self.qualification,
                "duration_ms": self.duration_ms, "output_bytes": self.output_bytes, "artifacts": list(self.artifacts),
                "assurance": self.assurance, "result": "passed", "producer_role": "verifier"}


class ReviewSenseiAdapter:
    """One version-pinned CLI invocation, from a fresh controlled directory."""
    def __init__(self, executable: str | Path, *, python_executable: str | Path | None = None,
                 expected_executable_sha256: str | None = None,
                 expected_provider: str = "fixture", interrupt_requested=None) -> None:
        self.executable = str(Path(executable).absolute())
        self.python_executable = str(Path(python_executable or sys.executable).absolute())
        self.executable_sha256 = fingerprint(self.executable)
        if expected_executable_sha256 is not None and self.executable_sha256 != expected_executable_sha256:
            raise _blocked("review_executable_changed", "The approved review executable changed.")
        if expected_provider not in PROVIDERS:
            raise _blocked("review_provider_unsupported", "The selected review provider is unsupported.")
        self.expected_provider = expected_provider
        self._interrupt_requested = interrupt_requested
        self._observed_process_output_bytes = 0

    def _invoke(self, argv: list[str], *, cwd: Path, timeout_seconds: int,
                max_output_bytes: int, cancel_requested=None, heartbeat=None):
        """Every observed subprocess needs a cessation receipt before its output.

        A failed pre-dispatch gate may prove ``not_sent``. A lost callback or
        descendant receipt never does, including during schema/version probes.
        """
        def callback(function):
            if function is None:
                return None
            def observed():
                try:
                    return function()
                except Exception as exc:
                    # These callbacks run after the process gate is released.
                    # A control-plane error's default not_sent cannot describe
                    # the already dispatched child whose receipt is now lost.
                    raise ProcessBoundaryError("review control callback failed",
                        code="review_callback_failed", effect_outcome="uncertain") from exc
            return observed
        def before_dispatch(receipt):
            if self._interrupt_requested and self._interrupt_requested():
                raise ProcessBoundaryError("Foreground review stopped before dispatch.", code="verification_interrupted", effect_outcome="not_sent")
        try:
            process = run_bounded(argv, cwd=cwd, timeout_seconds=timeout_seconds,
                                  max_output_bytes=max_output_bytes, on_spawn=before_dispatch,
                                  cancel_requested=callback(cancel_requested),
                                  heartbeat=callback(heartbeat))
        except ProcessBoundaryError as exc:
            outcome = exc.effect_outcome if exc.effect_outcome in {"not_sent", "known", "uncertain"} else "uncertain"
            error = _blocked("review_invocation_failed", "The independent review process boundary could not complete safely.", effect_outcome=outcome)
            if exc.code == "verification_interrupted" and outcome == "not_sent":
                error.output_bytes = self._observed_process_output_bytes
            raise error from None
        except OSError:
            # An unexpected boundary error has no returned cessation receipt.
            # Do not infer no-dispatch from the exception's concrete OS subtype.
            raise _blocked("review_process_unreconciled", "The independent review process has no complete cessation receipt.",
                           effect_outcome="uncertain") from None
        if getattr(process, "termination_confirmed", False) is not True:
            raise _blocked("review_process_unreconciled", "The independent review process cessation is unconfirmed.",
                           effect_outcome="uncertain")
        self._observed_process_output_bytes += process.output_bytes
        if process.timed_out or process.cancelled or getattr(process, "protocol_error", None):
            error = _blocked("review_not_complete", "The independent review process did not complete its bounded invocation.",
                             effect_outcome="known")
            if process.cancelled:
                # Every counted stage returned a confirmed kernel receipt.
                # Keep actual capture bytes when an operator interrupts review.
                error.output_bytes = self._observed_process_output_bytes
            raise error
        return process

    def _schemas(self, cwd: Path, *, max_output_bytes: int = 4 * MAX_DOCUMENT_BYTES,
                 cancel_requested=None, heartbeat=None) -> dict[str, dict[str, Any]]:
        # Only importlib public metadata/resources APIs; never ReviewSensei services.
        script = ("import importlib.metadata as m,importlib.resources as r,json;"
                  "assert m.version('review-sensei')=='0.8.8';"
                  "p=r.files('review_sensei').joinpath('schemas');"
                  "print(json.dumps({x.name.removesuffix('.schema.json'):json.loads(x.read_text()) "
                  "for x in p.iterdir() if x.name.endswith('.schema.json')}))")
        result = self._invoke([self.python_executable, "-I", "-c", script], cwd=cwd,
                              timeout_seconds=15, max_output_bytes=max_output_bytes,
                              cancel_requested=cancel_requested, heartbeat=heartbeat)
        self._schema_output_bytes = result.output_bytes
        if result.output_limited:
            raise _blocked("review_output_budget_exhausted", "The review schema observation exceeded the remaining output budget.", effect_outcome="known")
        if result.exit_code != 0:
            raise _blocked("review_release_unsupported", "The selected Python environment lacks the pinned ReviewSensei schemas.", effect_outcome="known")
        try:
            return json.loads(result.stdout, object_pairs_hook=_unique_pairs)
        except (ValueError, UnicodeError):
            raise _blocked("review_release_unsupported", "The installed ReviewSensei schema registry is invalid.", effect_outcome="known") from None

    def review(self, diff: bytes, subject: dict[str, Any], *, config_path: str | Path,
               qualification: str, invocation_dir: str | Path,
               expected_config_digest: str, fixture_response: str | Path | None = None,
               timeout_seconds: int = 60, max_output_bytes: int = 8 * MAX_DOCUMENT_BYTES,
               cancel_requested=None, heartbeat=None) -> ReviewReceipt:
        self._observed_process_output_bytes = 0
        if type(max_output_bytes) is not int or not 1 <= max_output_bytes <= 64 * MAX_DOCUMENT_BYTES:
            raise _blocked("review_output_budget_exhausted", "The review has no valid remaining aggregate output budget.")
        if qualification == "production" and (fixture_response is not None or self.expected_provider == "fixture"):
            raise _blocked("fixture_in_production", "Synthetic review is unavailable for production tasks.")
        if (fixture_response is None) != (self.expected_provider != "fixture"):
            raise _blocked("review_fixture_required", "A fixture review requires one explicit synthetic response.")
        config = Path(config_path)
        if config.is_symlink() or not config.is_file() or config.stat().st_size > MAX_DOCUMENT_BYTES:
            raise _blocked("review_config_invalid", "The approved review configuration is unavailable.")
        config_bytes = config.read_bytes()
        if hashlib.sha256(config_bytes).hexdigest() != expected_config_digest:
            raise _blocked("review_config_changed", "The approved review configuration changed.")
        diff_inventory(diff)
        directory = Path(invocation_dir)
        if directory.exists() or directory.is_symlink():
            raise _blocked("review_stale_output", "Review requires a new private invocation directory.")
        directory.mkdir(mode=0o700, parents=False)
        schemas = self._schemas(directory, max_output_bytes=min(4 * MAX_DOCUMENT_BYTES, max_output_bytes),
                                cancel_requested=cancel_requested, heartbeat=heartbeat)
        consumed = self._schema_output_bytes
        if consumed >= max_output_bytes:
            raise _blocked("review_output_budget_exhausted", "The review has exhausted its aggregate output budget.", effect_outcome="known")
        version = self._invoke([self.executable, "--version"], cwd=directory, timeout_seconds=15,
                               max_output_bytes=min(65536, max_output_bytes - consumed),
                               cancel_requested=cancel_requested, heartbeat=heartbeat)
        consumed += version.output_bytes
        if version.output_limited or consumed >= max_output_bytes:
            raise _blocked("review_output_budget_exhausted", "The review has exhausted its aggregate output budget.", effect_outcome="known")
        if version.exit_code != 0 or not re.search(rb"(?<![\d.])0\.8\.8(?![\d.])", version.stdout):
            raise _blocked("review_release_unsupported", "Only the qualified ReviewSensei 0.8.8 release is supported.", effect_outcome="known")
        diff_path = directory / "input.diff"
        diff_path.write_bytes(diff)
        config_copy = directory / "approved.yml"
        config_copy.write_bytes(config_bytes)
        config_copy.chmod(0o600)
        diff_path.chmod(0o600)
        result_path, outcome_path = directory / "result.json", directory / "outcome.json"
        argv = [self.executable, "--diff", str(diff_path), "--config", str(config_copy),
                "--base-sha", subject["base_commit"], "--head-sha", subject["candidate_commit"],
                "--format", "json", "--exit-semantics", "review", "--no-learning-proposals",
                "--output", str(result_path), "--outcome", str(outcome_path), "--provider", self.expected_provider]
        if fixture_response is not None:
            fixture = Path(fixture_response)
            if fixture.is_symlink() or not fixture.is_file() or fixture.stat().st_size > MAX_DOCUMENT_BYTES:
                raise _blocked("review_fixture_invalid", "The synthetic review fixture is invalid.")
            response_path = directory / "synthetic-response.json"
            response_path.write_bytes(fixture.read_bytes())
            response_path.chmod(0o600)
            argv += ["--fixture-response", str(response_path)]
        process = self._invoke(argv, cwd=directory, timeout_seconds=timeout_seconds,
                               max_output_bytes=min(2 * MAX_DOCUMENT_BYTES, max_output_bytes - consumed),
                               cancel_requested=cancel_requested, heartbeat=heartbeat)
        consumed += process.output_bytes
        if process.receipt.executable_sha256 != self.executable_sha256:
            raise _blocked("review_executable_changed", "The approved review executable changed during invocation.", effect_outcome="known")
        if process.output_limited or consumed >= max_output_bytes:
            raise _blocked("review_output_budget_exhausted", "The review exceeded its aggregate output budget.", effect_outcome="known")
        docs = []
        for path in (result_path, outcome_path):
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_DOCUMENT_BYTES:
                raise _blocked("review_output_missing", "The independent review output is missing or oversized.", effect_outcome="known")
            consumed += path.stat().st_size
            if consumed > max_output_bytes:
                raise _blocked("review_output_budget_exhausted", "The review files exceed its aggregate output budget.", effect_outcome="known")
            path.chmod(0o600)
            try:
                docs.append(loads(path.read_bytes(), max_bytes=MAX_DOCUMENT_BYTES))
            except TaskAlongError as exc:
                raise _blocked(exc.code, exc.message, effect_outcome="known") from None
        result_doc, outcome_doc = docs
        try:
            validate_review_documents(result_doc, outcome_doc, schemas=schemas, diff=diff,
                                      subject=subject, exit_code=process.exit_code,
                                      qualification=qualification, expected_provider=self.expected_provider)
        except TaskAlongError as exc:
            raise _blocked(exc.code, exc.message, effect_outcome="known") from None
        artifacts = tuple({"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                           "bytes": path.stat().st_size, "media_type": "application/json", "redaction_version": "private-v1"}
                          for path in (result_path, outcome_path))
        return ReviewReceipt(process.receipt.invocation_id, process.receipt.executable_sha256, RELEASE,
                             self.expected_provider, expected_config_digest, dict(subject), qualification,
                             result_doc, outcome_doc, process.duration_ms, consumed, artifacts)


def _unique_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate schema key")
        result[key] = value
    return result
