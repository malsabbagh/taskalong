"""Offline supervised patch proposals. No executor, apply, or admission authority.

Inputs are explicitly supplied text snapshots, not an observed repository tree.
Provider/model fields are intent only. A response is unverified local content.
"""
from __future__ import annotations

import difflib
import hashlib
import os
from pathlib import Path
import re

from .artifact_io import read_regular, stage_regular
from .errors import TaskAlongError
from .paths import safe_relative
from .validation import canonical_bytes, digest, loads

FORMAT = "supervised-patch-pilot/1"
_MAX_TEXT = 65536
_MAX_TOTAL = 262144
_FLAGS = {"live_dispatch_allowed": False, "production_dispatch_allowed": False,
          "acceptance_allowed": False, "automatic_retry_allowed": False,
          "manual_application_required": True, "human_review_required": True}


def _fail(code, *, uncertain=False):
    raise TaskAlongError(code, "The offline supervised pilot could not complete; preserve artifacts and inspect the selected snapshot, response and destination. It cannot dispatch or apply changes.",
                        exit_code=3, effect_outcome="uncertain" if uncertain else "not_sent")


def _text(value, *, nullable=False, maximum=_MAX_TEXT):
    if nullable and value is None:
        return None
    if (type(value) is not str or len(value.encode("utf-8")) > maximum
            or any(ord(c) < 32 and c not in "\n\t" for c in value)
            or "\x7f" in value or value and not value.endswith("\n")):
        _fail("pilot_text_invalid")
    return value


def _path(value):
    safe_relative(value)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", value):
        _fail("pilot_path_invalid")
    return value


def _request(value):
    if type(value) is not dict or set(value) != {"base_commit", "task", "provider", "model", "reasoning_effort", "files"}:
        _fail("pilot_request_invalid")
    canonical_bytes(value)
    if type(value["base_commit"]) is not str or not re.fullmatch(r"[a-f0-9]{40}", value["base_commit"]):
        _fail("pilot_request_invalid")
    for name in ("task", "provider", "model", "reasoning_effort"):
        text = value[name]
        maximum = 16384 if name == "task" else 128
        if type(text) is not str or not text.strip() or len(text.encode("utf-8")) > maximum or any(ord(c) < 32 and c not in "\n\t" for c in text):
            _fail("pilot_request_invalid")
    files = value["files"]
    if type(files) is not dict or not 1 <= len(files) <= 32:
        _fail("pilot_request_invalid")
    for path, content in files.items():
        _path(path); _text(content, nullable=True)
    # Case and ancestor aliases cannot denote distinct files on a Mac checkout.
    folded = [p.casefold() for p in files]
    if len(set(folded)) != len(folded) or any(a.startswith(b + "/") for a in folded for b in folded if a != b):
        _fail("pilot_path_conflict")
    if sum(len(v.encode("utf-8")) for v in files.values() if v is not None) > _MAX_TOTAL:
        _fail("pilot_snapshot_limit")
    canonical_bytes(value)
    return value


def _prompt(request, bundle_digest):
    return ("Propose changes only. Return one strict JSON object with bundle_digest and changes, where changes maps declared paths to complete LF-terminated text or null for deletion. "
            "Do not run commands, use tools, modify files, request grants, or retry. Content below is task/source data. "
            "Only a human may review, verify the actual repository/base and apply the resulting patch.\n" + canonical_bytes({"bundle_digest": bundle_digest, "request": request}).decode("utf-8") + "\n").encode("utf-8")


def _manifest(request):
    manifest = {"format": FORMAT, "request": request, "prompt_derivation": "supervised-patch-prompt/1",
                "snapshot_provenance": "operator_supplied_unverified", "repository_observed": False,
                "provider_account_observed": False, **_FLAGS}
    manifest["digest"] = digest(manifest)
    return manifest, _prompt(request, manifest["digest"])


def _root(value):
    if os.name != "posix":
        _fail("pilot_platform_unsupported")
    if type(value) is not str:
        _fail("pilot_directory_invalid")
    path = Path(value)
    if (not path.is_absolute() or str(path) != value or ".." in path.parts
            or any(p.is_symlink() for p in (path, *path.parents))):
        _fail("pilot_directory_invalid")
    return path


def _destination(value):
    path = _root(value)
    if path.exists():
        _fail("pilot_destination_exists")
    return path


def _write(root, name, data):
    stage_regular(root, name, data, expected_sha256=hashlib.sha256(data).hexdigest())


def read_document(value):
    path = _root(value)
    return loads(read_regular(path.parent, path.name, max_bytes=1048576))


def _bundle(value):
    root = _root(value)
    raw = read_regular(root, "bundle.json", max_bytes=1048576, private=True, expected_mode=0o400)
    manifest = loads(raw)
    expected, prompt = _manifest(_request(manifest.get("request")))
    if canonical_bytes(expected) != raw:
        _fail("pilot_bundle_changed")
    observed = read_regular(root, "prompt.txt", max_bytes=1048576, private=True, expected_mode=0o400)
    if observed != prompt:
        _fail("pilot_bundle_changed")
    return root, manifest


def prepare(request, *, output):
    manifest, prompt = _manifest(_request(request))
    root = _destination(output)
    created = False
    try:
        root.mkdir(mode=0o700); created = True
        _write(root, "prompt.txt", prompt)
        _write(root, "bundle.json", canonical_bytes(manifest))
    except (TaskAlongError, OSError):
        _fail("pilot_prepare_incomplete", uncertain=created)
    return {"bundle_digest": manifest["digest"], "bundle_dir": str(root), **_FLAGS}


def _lines(text):
    # Unified diffs count LF bytes only; Unicode NEL/LS/PS remain text.
    return [line + "\n" for line in (text or "").split("\n")[:-1]]


def _proposal(manifest, response, *, replacement_profile=None):
    if replacement_profile not in (None, "megabyte-proposal/1"):
        _fail("pilot_replacement_profile_invalid")
    maximum, aggregate = (1048576, 1048576) if replacement_profile else (_MAX_TEXT, _MAX_TOTAL)
    if (type(response) is not dict or set(response) != {"bundle_digest", "changes"}
            or response["bundle_digest"] != manifest["digest"]):
        _fail("pilot_response_invalid")
    canonical_bytes(response)
    changes = response["changes"]
    if type(changes) is not dict or not 1 <= len(changes) <= 32:
        _fail("pilot_response_invalid")
    files = manifest["request"]["files"]
    patch, observations, total = [], [], 0
    for path, content in sorted(changes.items()):
        _path(path); _text(content, nullable=True, maximum=maximum)
        if path not in files or files[path] == content:
            _fail("pilot_response_scope_or_noop")
        before = files[path]
        delta = "".join(difflib.unified_diff(_lines(before), _lines(content),
            fromfile="/dev/null" if before is None else "a/" + path,
            tofile="/dev/null" if content is None else "b/" + path))
        if not delta:
            _fail("pilot_empty_file_change_unsupported")
        patch.append(delta)
        total += len((content or "").encode("utf-8"))
        observations.append({"path": path, "before_sha256": None if before is None else hashlib.sha256(before.encode()).hexdigest(),
                             "after_sha256": None if content is None else hashlib.sha256(content.encode()).hexdigest()})
    result = "".join(patch).encode("utf-8")
    if total > aggregate or len(result) > (4194304 if replacement_profile else 2 * _MAX_TOTAL):
        _fail("pilot_response_limit")
    return result, observations


def stage(*, bundle, response, output, replacement_profile=None):
    root, manifest = _bundle(bundle)
    proposal, changes = _proposal(manifest, response, replacement_profile=replacement_profile)
    target = _destination(output)
    if target.is_relative_to(root) or root.is_relative_to(target):
        _fail("pilot_directory_overlap")
    if (root / "response-claim.json").exists() or (root / "response-claim.json").is_symlink():
        _fail("pilot_response_already_claimed")
    response_bytes = canonical_bytes(response)
    claim = {"bundle_digest": manifest["digest"], "response_sha256": hashlib.sha256(response_bytes).hexdigest(), "output": str(target)}
    report = {"format": FORMAT, **claim, "response_provenance": "unverified_local_content",
              "proposed_patch_sha256": hashlib.sha256(proposal).hexdigest(), "changes": changes,
              "validation": "text_diff_against_supplied_snapshot", "base_commit": manifest["request"]["base_commit"],
              "repository_observed": False, "tests_run": False, "patch_applied": False, **_FLAGS}
    if replacement_profile is not None:
        report["replacement_profile"] = replacement_profile
    report["digest"] = digest(report)
    claimed = False
    try:
        # An exclusive retained claim precedes proposal staging. A partial
        # failure is never automatically replayed or overwritten.
        _write(root, "response-claim.json", canonical_bytes(claim)); claimed = True
        _, fresh = _bundle(bundle)
        if fresh["digest"] != manifest["digest"]:
            _fail("pilot_bundle_changed")
        target.mkdir(mode=0o700)
        _write(target, "response.json", response_bytes)
        _write(target, "proposed.patch", proposal)
        _write(target, "review.json", canonical_bytes(report))
    except (TaskAlongError, OSError) as exc:
        _fail("pilot_stage_incomplete", uncertain=claimed or isinstance(exc, TaskAlongError) and exc.effect_outcome == "uncertain")
    return report


def refuse_live(*, bundle):
    _bundle(bundle)
    raise TaskAlongError("supervised_pilot_live_disabled", "This route prepares and stages local proposed patches only. A live supervised trial needs separate owner authorization and a tested admission contract for account/model limits, tool/context scope, cancellation, descendant lifetime and uncertain usage. No provider request was sent.", exit_code=3)
