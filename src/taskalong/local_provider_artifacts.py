"""Pure, bounded proposals bound to an integrity-checked task plan.

A plan is not evidence of source truth. The caller must independently verify the
owner-selected repository before dispatch and before manually applying anything.
This module neither reads a checkout nor grants execution/application authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from .errors import TaskAlongError
from .local_provider_tasks import MAX_SNAPSHOT_BYTES, validate_plan
from .validation import MAX_DOCUMENT_BYTES, canonical_bytes, digest

_MAX_PATCH_BYTES = 1048576
_HUNK = re.compile(rb"@@ -([0-9]{1,7})(?:,([0-9]{1,7}))? \+([0-9]{1,7})(?:,([0-9]{1,7}))? @@(?: [^\n]*)?\n")
_INDEX = re.compile(rb"index ([a-f0-9]{7,40})\.\.([a-f0-9]{7,40})(?: (100644|100755))?\n")
_NO_LF = b"\\ No newline at end of file\n"


def _fail(message):
    raise TaskAlongError("provider_artifact_invalid", message, exit_code=3, effect_outcome="not_sent")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


@dataclass(frozen=True, slots=True)
class ProposedArtifact:
    """Immutable bytes only; callers receive fresh metadata on each inspection."""

    patch_bytes: bytes
    manifest_json: bytes

    def to_dict(self):
        return json.loads(self.manifest_json)


def _text(value, *, complete=False):
    if type(value) is not str:
        _fail("Proposal content must be UTF-8 LF text or an explicit deletion.")
    try:
        raw = value.encode("utf-8")
    except UnicodeError:
        _fail("Proposal content contains unsupported Unicode.")
    if any(ord(c) < 32 and c not in "\n\t" or ord(c) == 127 for c in value):
        _fail("Proposal content must use LF text without binary/control characters.")
    if complete and raw and not raw.endswith(b"\n"):
        _fail("Complete replacement content must end with LF.")
    return raw


def _snapshot(snapshot):
    return None if snapshot is None else snapshot["content"].encode("utf-8")


def _side(data, mode):
    return None if data is None else {"sha256": _sha(data), "bytes": len(data), "mode": mode}


def _headers(path, before, after, mode):
    a, b = ("a/" + path).encode("ascii"), ("b/" + path).encode("ascii")
    out = [b"diff --git " + a + b" " + b + b"\n"]
    if before is None:
        out.append(b"new file mode 100644\n")
    elif after is None:
        out.append(b"deleted file mode " + mode.encode("ascii") + b"\n")
    old_oid = "0" * 40 if before is None else _blob(before)
    new_oid = "0" * 40 if after is None else _blob(after)
    suffix = b" " + mode.encode("ascii") if before is not None and after is not None else b""
    out.append(b"index " + old_oid.encode("ascii") + b".." + new_oid.encode("ascii") + suffix + b"\n")
    return out, a, b


def _emit(path, before, after, mode, hunks, budget):
    parts, a, b = _headers(path, before, after, mode)
    if hunks:
        parts += [b"--- " + (b"/dev/null" if before is None else a) + b"\n",
                  b"+++ " + (b"/dev/null" if after is None else b) + b"\n", *hunks]
    size = sum(map(len, parts))
    if size > budget:
        _fail("The generated patch exceeds its explicit byte limit.")
    return b"".join(parts)


def _replacement_hunks(before, after, budget):
    old, new = (before or b"").splitlines(keepends=True), (after or b"").splitlines(keepends=True)
    if not old and not new:
        return []
    result = [f"@@ -{1 if old else 0},{len(old)} +{1 if new else 0},{len(new)} @@\n".encode("ascii")]
    size = len(result[0])
    for prefix, lines in ((b"-", old), (b"+", new)):
        for line in lines:
            item = prefix + line
            if not line.endswith(b"\n"):
                item += b"\n" + _NO_LF
            size += len(item)
            if size > budget:
                _fail("The generated patch exceeds its explicit byte limit.")
            result.append(item)
    return result


def _replacements(plan, response, budget):
    changes = response["changes"]
    if type(changes) is not dict or not 1 <= len(changes) <= 32:
        _fail("A proposal must contain a bounded nonempty change map.")
    results = []
    remaining = budget
    for path in sorted(changes):
        if path not in plan["writable_outputs"]:
            _fail("A changed path is outside the declared writable outputs.")
        snapshot = plan["writable_outputs"][path]
        before = _snapshot(snapshot)
        after = None if changes[path] is None else _text(changes[path], complete=True)
        if before == after:
            _fail("Each declared change must change file presence or content.")
        mode = "100644" if snapshot is None else snapshot["git_mode"]
        piece = _emit(path, before, after, mode, _replacement_hunks(before, after, remaining), remaining)
        remaining -= len(piece)
        results.append((path, before, after, mode, piece))
    return results


def _header_path(line, prefix, side):
    if not line.startswith(prefix) or not line.endswith(b"\n"):
        _fail("Expected an exact unified diff path header.")
    value = line[len(prefix):-1]
    if value == b"/dev/null":
        return None
    if not value.startswith(side + b"/"):
        _fail("Unified diff paths require exact a/ and b/ prefixes.")
    try:
        return value[2:].decode("ascii")
    except UnicodeError:
        _fail("Unified diff paths must use the declared literal path spelling.")


def _canonical_hunks(operations, budget):
    """Add bounded exact context in a linear pass, without fuzzy diff matching."""
    ranges = []
    for i, (kind, _) in enumerate(operations):
        if kind == b" ":
            continue
        start, end = max(0, i - 3), min(len(operations), i + 4)
        if ranges and start <= ranges[-1][1]:
            ranges[-1] = (ranges[-1][0], end)
        else:
            ranges.append((start, end))
    emitted = []
    cursor = old_position = new_position = size = 0
    for start, end in ranges:
        while cursor < start:
            kind = operations[cursor][0]
            old_position += kind != b"+"
            new_position += kind != b"-"
            cursor += 1
        old_count = sum(operations[j][0] != b"+" for j in range(start, end))
        new_count = sum(operations[j][0] != b"-" for j in range(start, end))
        header = (f"@@ -{old_position + bool(old_count)},{old_count} "
                  f"+{new_position + bool(new_count)},{new_count} @@\n").encode("ascii")
        items = [header]
        for j in range(start, end):
            kind, payload = operations[j]
            item = kind + payload
            if not payload.endswith(b"\n"):
                item += b"\n" + _NO_LF
            items.append(item)
        size += sum(map(len, items))
        if size > budget:
            _fail("The generated patch exceeds its explicit byte limit.")
        emitted.extend(items)
        old_position += old_count
        new_position += new_count
        cursor = end
    return emitted


def _hunks(lines, i, before, result_limit, patch_limit):
    source = (before or b"").splitlines(keepends=True)
    result, operations = [], []
    cursor, last_start = 0, -1
    while i < len(lines) and lines[i].startswith(b"@@ "):
        match = _HUNK.fullmatch(lines[i])
        if match is None:
            _fail("A unified hunk header has unsupported counts or syntax.")
        start, count, new_start, new_count = [int(x) if x is not None else 1 for x in match.groups()]
        offset = start if count == 0 else start - 1
        new_offset = new_start if new_count == 0 else new_start - 1
        if (offset < cursor or offset <= last_start or offset > len(source) or count > len(source) - offset
                or count == 0 and start > len(source) or start == 0 and count != 0
                or new_start == 0 and new_count != 0):
            _fail("Unified hunks must have exact monotonic nonoverlapping source positions.")
        result.extend(source[cursor:offset])
        operations.extend((b" ", line) for line in source[cursor:offset])
        if new_offset != len(result):
            _fail("A unified hunk's resulting line position is inconsistent.")
        i += 1
        old_used = new_used = 0
        body = []
        while old_used < count or new_used < new_count:
            if i >= len(lines) or lines[i][:1] not in (b" ", b"+", b"-"):
                _fail("A unified hunk ended before its declared line counts.")
            kind, payload = lines[i][:1], lines[i][1:]
            i += 1
            if i < len(lines) and lines[i] == _NO_LF:
                payload = payload[:-1]
                if not payload:
                    _fail("A no-newline marker cannot represent a phantom empty line.")
                i += 1
            if kind != b"+":
                if old_used >= count or source[offset + old_used] != payload:
                    _fail("Unified diff source context does not exactly match the declared preimage.")
                old_used += 1
            if kind != b"-":
                new_used += 1
                result.append(payload)
            if old_used > count or new_used > new_count:
                _fail("A unified hunk exceeds its declared line counts.")
            body.append((kind, payload))
        if not body or not any(kind in (b"+", b"-") for kind, _ in body):
            _fail("Every unified hunk must contain a content change.")
        operations.extend(body)
        cursor, last_start = offset + count, offset
    result.extend(source[cursor:])
    operations.extend((b" ", line) for line in source[cursor:])
    if any(not line.endswith(b"\n") for line in result[:-1]):
        _fail("A no-newline marker is only valid at the end of a resulting file.")
    after = b"".join(result)
    if len(after) > result_limit:
        _fail("Reconstructed output exceeds its finite byte limit.")
    return i, after, _canonical_hunks(operations, patch_limit)


def _diff(plan, response, budget, result_limit):
    raw = _text(response["patch"])
    if not raw or not raw.endswith(b"\n") or len(raw) > budget:
        _fail("A nonempty LF-terminated patch within the patch limit is required.")
    lines, i, results, seen = raw.splitlines(keepends=True), 0, [], set()
    remaining = budget
    while i < len(lines):
        named = None
        mode_header = index = None
        if lines[i].startswith(b"diff --git "):
            parts = lines[i][:-1].split(b" ")
            if len(parts) != 4 or parts[:2] != [b"diff", b"--git"]:
                _fail("Only conventional unquoted diff --git headers are supported.")
            old = _header_path(b"--- " + parts[2] + b"\n", b"--- ", b"a")
            new = _header_path(b"+++ " + parts[3] + b"\n", b"+++ ", b"b")
            if old != new or old is None:
                _fail("Renames and copies are not supported.")
            named = old
            i += 1
            if i < len(lines) and lines[i].startswith((b"new file mode ", b"deleted file mode ")):
                mode_header = lines[i]
                i += 1
            if i < len(lines) and lines[i].startswith(b"index "):
                index = _INDEX.fullmatch(lines[i])
                if index is None:
                    _fail("Unsupported index metadata.")
                i += 1
        if i < len(lines) and lines[i].startswith(b"--- "):
            old = _header_path(lines[i], b"--- ", b"a")
            if i + 1 >= len(lines):
                _fail("A unified diff requires both path headers.")
            new = _header_path(lines[i + 1], b"+++ ", b"b")
            if old is None and new is None or old is not None and new is not None and old != new:
                _fail("Renames and ambiguous path headers are unsupported.")
            path = old if old is not None else new
            if named is not None and named != path:
                _fail("Git and unified path headers disagree.")
            i += 2
            has_headers = True
        elif named is not None and mode_header is not None and index is not None:
            path = named
            old = None if mode_header.startswith(b"new ") else path
            new = None if mode_header.startswith(b"deleted ") else path
            has_headers = False
        else:
            _fail("Unsupported patch metadata, missing file headers, or trailing payload.")
        if path not in plan["writable_outputs"] or path in seen:
            _fail("Patch paths must name distinct declared writable outputs.")
        seen.add(path)
        snapshot = plan["writable_outputs"][path]
        before = _snapshot(snapshot)
        mode = "100644" if snapshot is None else snapshot["git_mode"]
        if (old is None) != (before is None):
            _fail("New-file metadata disagrees with the declared preimage.")
        expected_mode = (b"new file mode 100644\n" if old is None else
                         b"deleted file mode " + mode.encode("ascii") + b"\n" if new is None else None)
        if mode_header is not None and mode_header != expected_mode:
            _fail("File-mode changes or inconsistent mode metadata are unsupported.")
        if not has_headers and i < len(lines) and lines[i].startswith(b"@@ "):
            _fail("Text hunks require both conventional unified path headers.")
        start_i = i
        i, after, hunks = _hunks(lines, i, before, result_limit, remaining)
        if has_headers and i == start_i:
            _fail("Text path headers require at least one complete unified hunk.")
        if new is None:
            if after != b"":
                _fail("A deletion must remove the exact complete preimage.")
            after = None
        if before == after:
            _fail("Each patch entry must change file presence or content.")
        if index is not None:
            old_id, new_id, index_mode = index.groups()
            actual_old = ("0" * 40 if before is None else _blob(before)).encode("ascii")
            actual_new = ("0" * 40 if after is None else _blob(after)).encode("ascii")
            if (not actual_old.startswith(old_id) or not actual_new.startswith(new_id)
                    or index_mode is not None and (expected_mode is not None or index_mode.decode("ascii") != mode)):
                _fail("Index metadata disagrees with reconstructed content or file mode.")
        piece = _emit(path, before, after, mode, hunks, remaining)
        remaining -= len(piece)
        results.append((path, before, after, mode, piece))
    return results


def validate_response(plan, response, *, max_proposal_bytes=65536, max_patch_bytes=1048576):
    """Validate atomically and return review bytes; perform no IO or application.

    Unified hunks are normalized with exact bounded context for Git review.
    Decoded JSON objects cannot retain duplicate keys: callers decoding wire JSON
    must use the project's strict ``validation.loads`` before calling this API.
    """
    for value, maximum in ((max_proposal_bytes, MAX_DOCUMENT_BYTES), (max_patch_bytes, _MAX_PATCH_BYTES)):
        if type(value) is not int or not 1 <= value <= maximum:
            _fail("Proposal and patch byte limits must be positive bounded integers.")
    validate_plan(plan)
    expected = {"bundle_digest", "changes" if plan["artifact_format"] == "file-replacements/1" else "patch"}
    if type(response) is not dict or set(response) != expected:
        _fail("A response must use the exact versioned proposal object shape.")
    response_bytes = canonical_bytes(response)
    if len(response_bytes) > max_proposal_bytes:
        _fail("The canonical proposal exceeds its explicit byte limit.")
    if type(response["bundle_digest"]) is not str or response["bundle_digest"] != plan["digest"]:
        _fail("The proposal does not bind to the exact task plan.")
    if plan["artifact_format"] == "file-replacements/1":
        results = _replacements(plan, response, max_patch_bytes)
    else:
        results = _diff(plan, response, max_patch_bytes, MAX_SNAPSHOT_BYTES + max_proposal_bytes)
    patch = b"".join(item[4] for item in results)
    manifest = {"format": "configured-provider-artifact/1", "artifact_format": plan["artifact_format"],
                "plan_digest": plan["digest"], "intent_digest": plan["intent_digest"],
                "base_commit": plan["base_commit"], "base_tree": plan["base_tree"],
                "response_sha256": _sha(response_bytes), "response_bytes": len(response_bytes),
                "patch_sha256": _sha(patch), "patch_bytes": len(patch),
                "files": [{"path": p, "before": _side(before, mode), "after": _side(after, mode)}
                          for p, before, after, mode, _ in results],
                "source_truth_verified": False, "manual_application_required": True,
                "human_review_required": True, "execution_allowed": False, "acceptance_allowed": False,
                "production_dispatch_allowed": False, "automatic_retry_allowed": False}
    manifest["digest"] = digest(manifest)
    return ProposedArtifact(patch, canonical_bytes(manifest))
