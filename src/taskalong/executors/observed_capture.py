"""Shared private capture validation for closed observed-session fixture contracts.

Capture consistency is not execution authority. Old 2.5 field/error meanings are
preserved; 2.6 separately binds its fixed stdin envelope and conversation dialect.
"""
import hashlib

from ..bindings import ProviderProfile
from ..errors import TaskAlongError
from ..validation import canonical_bytes, digest, loads, validate_versioned
from .registry import capture_for_version


_ASSOCIATION_KEYS = {"kind", "schema_version", "digest", "run_id", "attempt_id", "spec_digest",
    "packet_digest", "mapping_digest", "admission_digest", "driver_config_digest", "provider_profile_digest",
    "lease_generation", "stdout", "stderr", "observation", "result_artifact"}


class _Capture:
    def __init__(self, spec):
        self.contract = capture_for_version(spec["schema_version"])
        if self.contract is None:
            raise TaskAlongError("capture_contract_unavailable", "No observed-session capture contract is registered.", exit_code=70)
        self.private_label = "private-unredacted-" + self.contract.name + "-capture/1"
        self.association_keys = _ASSOCIATION_KEYS | ({"stdin"} if self.contract.input_bytes else set())

    def _invalid(self):
        raise TaskAlongError(self.contract.error_prefix + "_capture_invalid", "The private observed-session handoff evidence is missing or inconsistent.", exit_code=70)

    def _context(self, run, spec, attempt):
        packet = validate_versioned("worker-packet", attempt["canonical_packet"], expected_version=self.contract.version)
        wire = validate_versioned("worker-packet", attempt["packet"], expected_version=self.contract.version)
        mapping = validate_versioned("packet-projection", attempt["packet_projection"], expected_version=self.contract.version)
        admission = attempt["dispatch_admission"]
        config = self.contract.config_reader.from_dict(admission["driver_config"]).to_dict()
        provider = ProviderProfile.from_dict(admission["provider"]).to_dict()
        self.contract.represent_provider(config, provider)
        expected = {"driver_config_digest": config["digest"], "provider_profile_digest": provider["digest"]}
        if (spec["schema_version"] != self.contract.version or spec["digest"] != run["spec_digest"]
                or admission["schema_version"] != self.contract.version or digest(admission) != admission["digest"]
                or admission["spec_digest"] != spec["digest"]
                or admission["binding"]["digest"] != spec["execution"]["binding_digest"]
                or admission["binding"]["provider_profile_digest"] != provider["digest"]
                or admission["binding"]["installation_digest"] != config["installation_digest"]
                or spec["execution"]["driver_config_digest"] != config["digest"]
                or attempt["driver_config_digest"] != config["digest"]
                or canonical_bytes(packet) != canonical_bytes(wire)
                or packet["run_id"] != run["run_id"] or packet["attempt_id"] != attempt["attempt_id"]
                or packet["spec_digest"] != run["spec_digest"] or packet["session_policy"] != "fresh"
                or packet["projection"] != config["projection"] or mapping["projection"] != config["projection"]
                or mapping["session_policy"] != "fresh"
                or packet["binding_digest"] != admission["binding"]["digest"]
                or packet["admission_digest"] != admission["digest"]
                or mapping["projection_digest"] != admission["projection"]["digest"]
                or admission["projection"]["driver_config_digest"] != config["digest"]
                or admission["projection"]["projection"] != config["projection"]
                or mapping["canonical_packet_digest"] != packet["digest"]
                or mapping["wire_packet_digest"] != wire["digest"]
                or any(mapping[key] != packet[key] for key in ("run_id", "attempt_id", "spec_digest", "admission_digest"))
                or any(packet["bindings"][key] != value or mapping[key] != value for key, value in expected.items())
                or packet["bindings"]["workspace_id"] != attempt["workspace"]["workspace_id"]
                or packet["bindings"]["lease_generation"] != attempt["lease_generation"]):
            self._invalid()
        return packet, mapping, admission, config

    def _read_capture(self, store, reference):
        if (type(reference) is not dict or set(reference) != {"sha256", "bytes", "media_type", "redaction_version"}
                or reference["media_type"] != "application/octet-stream" or reference["redaction_version"] != self.private_label
                or type(reference["bytes"]) is not int or reference["bytes"] < 0):
            self._invalid()
        raw = store.get_blob(reference["sha256"])
        if len(raw) != reference["bytes"] or hashlib.sha256(raw).hexdigest() != reference["sha256"]:
            self._invalid()
        return raw

    def _decode(self, store, packet, config, stdout, stderr, process, attempt, stdin=None):
        limit = min(packet["remaining_budget"]["max_output_bytes"], 8 * 1024 * 1024)
        if self.contract.input_bytes is not None:
            if (type(stdin) is not dict or type(stdin.get("bytes")) is not int
                    or not 0 <= stdin["bytes"] <= 1024 * 1024):
                self._invalid()
            raw_input = self._read_capture(store, stdin)
            if len(raw_input) > 1024 * 1024 or raw_input != self.contract.input_bytes(packet):
                self._invalid()
        if (type(stdout) is not dict or type(stderr) is not dict
                or any(type(ref.get("bytes")) is not int or not 0 <= ref["bytes"] <= limit for ref in (stdout, stderr))
                or stdout["bytes"] + stderr["bytes"] > limit):
            self._invalid()
        out, err = self._read_capture(store, stdout), self._read_capture(store, stderr)
        if (not out or err or len(out) + len(err) > limit
                or type(process) is not dict or type(process.get("exit_code")) is not int or process["exit_code"] != 0
                or process.get("termination_confirmed") is not True or process.get("group_termination_confirmed") is not True
                or any(process.get(key) is not False for key in ("timed_out", "cancelled", "output_limited", "unaccounted_descendants"))
                or process.get("protocol_error") is not None or type(process.get("output_bytes")) is not int
                or process["output_bytes"] != len(out) + len(err)):
            self._invalid()
        decoder = self.contract.decoder(packet, config, attempt, limit)
        decoder.feed(out)
        return decoder.finish(exit_code=process["exit_code"])

    def retain_handoff(self, store, run, spec, attempt, result):
        """Consume reserved fields before any caller can serialize driver output."""
        capture = result.pop("_private_capture", None)
        observation = result.pop(self.contract.name + "_observation", None)
        session = result.pop("session_id", None)
        # An unknown or failed handoff cannot preserve an unvalidated native ID.
        result["session_id"] = None
        if (type(capture) is not dict or set(capture) != ({"stdout", "stderr", "stdin"} if self.contract.input_bytes else {"stdout", "stderr"})
                or any(type(value) is not bytes for value in capture.values())):
            self._invalid()
        packet, mapping, admission, config = self._context(run, spec, attempt)
        if self.contract.input_bytes is not None and (
                len(capture["stdin"]) > 1024 * 1024 or capture["stdin"] != self.contract.input_bytes(packet)):
            self._invalid()
        if sum(len(capture[key]) for key in ("stdout", "stderr")) > min(packet["remaining_budget"]["max_output_bytes"], 8 * 1024 * 1024):
            self._invalid()
        refs = {key: store.put_blob(raw, media_type="application/octet-stream", redaction_version=self.private_label)
                for key, raw in capture.items()}
        result[self.contract.name + "_raw_capture"] = refs
        if result["state"] != "completed":
            return
        turn = self._decode(store, packet, config, refs["stdout"], refs["stderr"], result["process"], attempt, refs.get("stdin"))
        if (canonical_bytes(result.get("result")) != turn.worker_result_json
                or canonical_bytes(observation) != canonical_bytes(turn.observation()) or session != turn.session_id):
            self._invalid()
        if (self.contract.reported_usage is not None
                and canonical_bytes(result.get("reported_usage")) != canonical_bytes(self.contract.reported_usage(turn))):
            self._invalid()
        worker_ref = store.put_blob(turn.worker_result_json)
        association = {"kind": self.contract.name + "_private_capture", "schema_version": "1.0",
            "run_id": run["run_id"], "attempt_id": attempt["attempt_id"], "spec_digest": spec["digest"],
            "packet_digest": packet["digest"], "mapping_digest": mapping["digest"], "admission_digest": admission["digest"],
            "driver_config_digest": config["digest"], "provider_profile_digest": config["provider_profile_digest"],
            "lease_generation": attempt["lease_generation"], **refs, "observation": turn.observation(), "result_artifact": worker_ref}
        association["digest"] = digest(association)
        result.update({self.contract.name + "_capture": association, "session_id": turn.session_id})

    def validate_handoff(self, store, run, spec, attempt):
        """Read-only revalidation of a durable completed handoff and finish identity."""
        try:
            association = attempt[self.contract.name + "_capture"]
            if (type(association) is not dict or set(association) != self.association_keys
                    or association["kind"] != self.contract.name + "_private_capture" or association["schema_version"] != "1.0"
                    or association["digest"] != digest(association)):
                self._invalid()
            packet, mapping, admission, config = self._context(run, spec, attempt)
            expected = {"run_id": run["run_id"], "attempt_id": attempt["attempt_id"], "spec_digest": spec["digest"],
                "packet_digest": packet["digest"], "mapping_digest": mapping["digest"], "admission_digest": admission["digest"],
                "driver_config_digest": config["digest"], "provider_profile_digest": config["provider_profile_digest"],
                "lease_generation": attempt["lease_generation"], "result_artifact": attempt["result_artifact"]}
            if any(canonical_bytes(association[key]) != canonical_bytes(value) for key, value in expected.items()):
                self._invalid()
            turn = self._decode(store, packet, config, association["stdout"], association["stderr"], attempt["process"], attempt, association.get("stdin"))
            if (self.contract.reported_usage is not None
                    and canonical_bytes(attempt["driver_report"].get("reported_usage")) != canonical_bytes(self.contract.reported_usage(turn))):
                self._invalid()
            checkpoint = attempt["checkpoint"]
            if (canonical_bytes(association["observation"]) != canonical_bytes(turn.observation())
                    or store.get_blob(attempt["result_artifact"]["sha256"]) != turn.worker_result_json
                    or attempt["termination_confirmed"] is not True or attempt["status"] != "completed"
                    or checkpoint["capture_digest"] != association["digest"] or checkpoint["session_policy"] != "fresh"
                    or checkpoint["requested_session_id"] is not None or checkpoint["observed_session_id"] != turn.session_id
                    or checkpoint["spec_digest"] != spec["digest"] or checkpoint["driver_config_digest"] != config["digest"]
                    or attempt["driver_report"]["reported_session_id"] != turn.session_id):
                self._invalid()
            row = store.db.execute("SELECT request_digest FROM operations WHERE command='executor.finish' AND run_id=? AND operation_key=?",
                (run["run_id"], attempt["attempt_id"])).fetchone()
            request = {"state": "completed", "artifact": attempt["result_artifact"], self.contract.name + "_capture_digest": association["digest"]}
            if row is None or row[0] != digest(request):
                self._invalid()
            return association
        except (KeyError, TypeError, ValueError, TaskAlongError) as exc:
            raise TaskAlongError(self.contract.error_prefix + "_capture_invalid", "The private observed-session handoff evidence is missing or inconsistent.", exit_code=70) from exc

def retain_handoff(store, run, spec, attempt, result):
    return _Capture(spec).retain_handoff(store, run, spec, attempt, result)


def validate_handoff(store, run, spec, attempt):
    return _Capture(spec).validate_handoff(store, run, spec, attempt)


def validate_completed_run(store, run):
    """Read-only no-op for earlier families or outcomes without completion."""
    spec = store.spec(run)
    if spec["schema_version"] == "2.12":
        from ..muse_lifecycle import validate_current
        return validate_current(store, run)
    if spec["schema_version"] == "2.9":
        from ..muse_handoff import validate_current
        return validate_current(store, run)
    if capture_for_version(spec["schema_version"]) is not None and run["attempts"]:
        attempt = store.detail("attempts", run["attempts"][-1]["attempt_id"])
        if attempt["status"] == "completed" or run["acceptance_id"]:
            validate_handoff(store, run, spec, attempt)
