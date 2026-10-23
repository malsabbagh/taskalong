"""Private 2.5 capture association; consistency evidence, never authority.

The owned driver supplies immutable buffers. Core retains and independently
decodes those bytes against frozen dispatch inputs before recording completion.
Reads repeat the same check without launching, reconciling or granting trust.
"""
import hashlib

from ..bindings import ProviderProfile
from ..errors import TaskAlongError
from ..validation import canonical_bytes, digest, loads, validate_versioned
from .config import CursorDriverConfig
from .cursor_cli import PROJECTION, _represent_provider
from .cursor_protocol import CursorStreamDecoder


_PRIVATE = "private-unredacted-cursor-capture/1"
_ASSOCIATION_KEYS = {"kind", "schema_version", "digest", "run_id", "attempt_id", "spec_digest",
    "packet_digest", "mapping_digest", "admission_digest", "driver_config_digest", "provider_profile_digest",
    "lease_generation", "stdout", "stderr", "observation", "result_artifact"}


def _invalid():
    raise TaskAlongError("cursor_capture_invalid", "The private Cursor handoff evidence is missing or inconsistent.", exit_code=70)


def _context(run, spec, attempt):
    packet = validate_versioned("worker-packet", attempt["canonical_packet"], expected_version="2.5")
    wire = validate_versioned("worker-packet", attempt["packet"], expected_version="2.5")
    mapping = validate_versioned("packet-projection", attempt["packet_projection"], expected_version="2.5")
    admission = attempt["dispatch_admission"]
    config = CursorDriverConfig.from_dict(admission["driver_config"]).to_dict()
    provider = ProviderProfile.from_dict(admission["provider"]).to_dict()
    _represent_provider(config, provider)
    expected = {"driver_config_digest": config["digest"], "provider_profile_digest": provider["digest"]}
    if (spec["schema_version"] != "2.5" or spec["digest"] != run["spec_digest"]
            or admission["schema_version"] != "2.5" or digest(admission) != admission["digest"]
            or admission["spec_digest"] != spec["digest"]
            or admission["binding"]["digest"] != spec["execution"]["binding_digest"]
            or admission["binding"]["provider_profile_digest"] != provider["digest"]
            or admission["binding"]["installation_digest"] != config["installation_digest"]
            or spec["execution"]["driver_config_digest"] != config["digest"]
            or attempt["driver_config_digest"] != config["digest"]
            or canonical_bytes(packet) != canonical_bytes(wire)
            or packet["run_id"] != run["run_id"] or packet["attempt_id"] != attempt["attempt_id"]
            or packet["spec_digest"] != run["spec_digest"] or packet["session_policy"] != "fresh"
            or packet["projection"] != PROJECTION or mapping["projection"] != PROJECTION
            or mapping["session_policy"] != "fresh"
            or packet["binding_digest"] != admission["binding"]["digest"]
            or packet["admission_digest"] != admission["digest"]
            or mapping["projection_digest"] != admission["projection"]["digest"]
            or admission["projection"]["driver_config_digest"] != config["digest"]
            or admission["projection"]["projection"] != PROJECTION
            or mapping["canonical_packet_digest"] != packet["digest"]
            or mapping["wire_packet_digest"] != wire["digest"]
            or any(mapping[key] != packet[key] for key in ("run_id", "attempt_id", "spec_digest", "admission_digest"))
            or any(packet["bindings"][key] != value or mapping[key] != value for key, value in expected.items())
            or packet["bindings"]["workspace_id"] != attempt["workspace"]["workspace_id"]
            or packet["bindings"]["lease_generation"] != attempt["lease_generation"]):
        _invalid()
    return packet, mapping, admission, config


def _read_capture(store, reference):
    if (type(reference) is not dict or set(reference) != {"sha256", "bytes", "media_type", "redaction_version"}
            or reference["media_type"] != "application/octet-stream" or reference["redaction_version"] != _PRIVATE
            or type(reference["bytes"]) is not int or reference["bytes"] < 0):
        _invalid()
    raw = store.get_blob(reference["sha256"])
    if len(raw) != reference["bytes"] or hashlib.sha256(raw).hexdigest() != reference["sha256"]:
        _invalid()
    return raw


def _decode(store, packet, config, stdout, stderr, process):
    limit = min(packet["remaining_budget"]["max_output_bytes"], 8 * 1024 * 1024)
    if (type(stdout) is not dict or type(stderr) is not dict
            or any(type(ref.get("bytes")) is not int or not 0 <= ref["bytes"] <= limit for ref in (stdout, stderr))
            or stdout["bytes"] + stderr["bytes"] > limit):
        _invalid()
    out, err = _read_capture(store, stdout), _read_capture(store, stderr)
    if (not out or err or len(out) + len(err) > limit
            or type(process) is not dict or type(process.get("exit_code")) is not int or process["exit_code"] != 0
            or process.get("termination_confirmed") is not True or process.get("group_termination_confirmed") is not True
            or any(process.get(key) is not False for key in ("timed_out", "cancelled", "output_limited", "unaccounted_descendants"))
            or process.get("protocol_error") is not None or type(process.get("output_bytes")) is not int
            or process["output_bytes"] != len(out) + len(err)):
        _invalid()
    decoder = CursorStreamDecoder(packet, expected_model=config["expected_reported_model"], max_output_bytes=limit)
    decoder.feed(out)
    return decoder.finish(exit_code=process["exit_code"])


def retain_handoff(store, run, spec, attempt, result):
    """Consume reserved fields before any caller can serialize driver output."""
    capture = result.pop("_private_capture", None)
    observation = result.pop("cursor_observation", None)
    session = result.pop("session_id", None)
    # An unknown or failed handoff cannot preserve an unvalidated native ID.
    result["session_id"] = None
    if (type(capture) is not dict or set(capture) != {"stdout", "stderr"}
            or any(type(capture[key]) is not bytes for key in ("stdout", "stderr"))):
        _invalid()
    packet, mapping, admission, config = _context(run, spec, attempt)
    if sum(len(value) for value in capture.values()) > min(packet["remaining_budget"]["max_output_bytes"], 8 * 1024 * 1024):
        _invalid()
    refs = {key: store.put_blob(raw, media_type="application/octet-stream", redaction_version=_PRIVATE)
            for key, raw in capture.items()}
    result["cursor_raw_capture"] = refs
    if result["state"] != "completed":
        return
    turn = _decode(store, packet, config, refs["stdout"], refs["stderr"], result["process"])
    if (canonical_bytes(result.get("result")) != turn.worker_result_json
            or canonical_bytes(observation) != canonical_bytes(turn.observation()) or session != turn.session_id):
        _invalid()
    worker_ref = store.put_blob(turn.worker_result_json)
    association = {"kind": "cursor_private_capture", "schema_version": "1.0",
        "run_id": run["run_id"], "attempt_id": attempt["attempt_id"], "spec_digest": spec["digest"],
        "packet_digest": packet["digest"], "mapping_digest": mapping["digest"], "admission_digest": admission["digest"],
        "driver_config_digest": config["digest"], "provider_profile_digest": config["provider_profile_digest"],
        "lease_generation": attempt["lease_generation"], **refs, "observation": turn.observation(), "result_artifact": worker_ref}
    association["digest"] = digest(association)
    result.update(cursor_capture=association, session_id=turn.session_id)


def validate_handoff(store, run, spec, attempt):
    """Read-only revalidation of a durable completed handoff and finish identity."""
    try:
        association = attempt["cursor_capture"]
        if (type(association) is not dict or set(association) != _ASSOCIATION_KEYS
                or association["kind"] != "cursor_private_capture" or association["schema_version"] != "1.0"
                or association["digest"] != digest(association)):
            _invalid()
        packet, mapping, admission, config = _context(run, spec, attempt)
        expected = {"run_id": run["run_id"], "attempt_id": attempt["attempt_id"], "spec_digest": spec["digest"],
            "packet_digest": packet["digest"], "mapping_digest": mapping["digest"], "admission_digest": admission["digest"],
            "driver_config_digest": config["digest"], "provider_profile_digest": config["provider_profile_digest"],
            "lease_generation": attempt["lease_generation"], "result_artifact": attempt["result_artifact"]}
        if any(canonical_bytes(association[key]) != canonical_bytes(value) for key, value in expected.items()):
            _invalid()
        turn = _decode(store, packet, config, association["stdout"], association["stderr"], attempt["process"])
        checkpoint = attempt["checkpoint"]
        if (canonical_bytes(association["observation"]) != canonical_bytes(turn.observation())
                or store.get_blob(attempt["result_artifact"]["sha256"]) != turn.worker_result_json
                or attempt["termination_confirmed"] is not True or attempt["status"] != "completed"
                or checkpoint["capture_digest"] != association["digest"] or checkpoint["session_policy"] != "fresh"
                or checkpoint["requested_session_id"] is not None or checkpoint["observed_session_id"] != turn.session_id
                or checkpoint["spec_digest"] != spec["digest"] or checkpoint["driver_config_digest"] != config["digest"]
                or attempt["driver_report"]["reported_session_id"] != turn.session_id):
            _invalid()
        row = store.db.execute("SELECT request_digest FROM operations WHERE command='executor.finish' AND run_id=? AND operation_key=?",
            (run["run_id"], attempt["attempt_id"])).fetchone()
        request = {"state": "completed", "artifact": attempt["result_artifact"], "cursor_capture_digest": association["digest"]}
        if row is None or row[0] != digest(request):
            _invalid()
        return association
    except (KeyError, TypeError, ValueError, TaskAlongError) as exc:
        raise TaskAlongError("cursor_capture_invalid", "The private Cursor handoff evidence is missing or inconsistent.", exit_code=70) from exc


def validate_completed_run(store, run):
    """No-op for prior formats or outcomes that do not claim completion."""
    spec = store.spec(run)
    if spec["schema_version"] == "2.5" and run["attempts"]:
        attempt = store.detail("attempts", run["attempts"][-1]["attempt_id"])
        if attempt["status"] == "completed" or run["acceptance_id"]:
            validate_handoff(store, run, spec, attempt)
