"""Closed original Muse plain-output fixture; never a production provider driver."""
from pathlib import Path

from ..errors import TaskAlongError
from ..muse_handoff import MuseConfiguration, compile_packet
from ..process import ProcessBoundaryError, fingerprint
from ..validation import canonical_bytes, validate_versioned
from .base import ExecutionRequest
from .muse_capture import MuseCaptureConfig, capabilities, capture_muse_turn


class MuseFixtureDriver:
    def __init__(self, config):
        self.config = MuseConfiguration.from_dict(config)

    def capabilities(self):
        return capabilities()

    def preflight(self, *, qualification, budget):
        if qualification != "synthetic":
            raise TaskAlongError("runtime_policy_unsupported", "Muse production execution is unqualified.", exit_code=3)
        if (budget.get("hard_cost_usd") is not None or budget.get("hard_tokens") is not None
                or budget.get("attempt_seconds", 1) > 60 or budget.get("max_output_bytes", 1) > 1048576):
            raise TaskAlongError("muse_budget_unsupported", "The synthetic capture requires its finite supported limits.", exit_code=3)
        config = self.config.to_dict()
        try:
            if (str(Path(config["executable"]["path"]).resolve(strict=True)) != config["executable"]["path"]
                    or fingerprint(config["executable"]["path"]) != config["executable"]["sha256"]):
                raise TaskAlongError("runtime_changed", "The registered synthetic executable changed.", exit_code=3)
        except (OSError, ProcessBoundaryError):
            raise TaskAlongError("runtime_unavailable", "The registered synthetic executable is unavailable.", exit_code=3) from None

    def run(self, packet, *, workspace, output_dir, cancel_requested=None, heartbeat=None,
            on_spawn=None, mode="start", thread_id=None, **_):
        packet = validate_versioned("worker-packet", packet, expected_version="2.9")
        config = self.config.to_dict()
        self.preflight(qualification=packet["qualification"], budget=packet["remaining_budget"])
        if packet["bindings"]["driver_config_digest"] != config["digest"]:
            raise TaskAlongError("execution_identity_mismatch", "The packet names another synthetic capture configuration.", exit_code=3)
        request = ExecutionRequest(packet["run_id"], packet["attempt_id"], packet["spec_digest"],
            canonical_bytes(packet), Path(workspace), Path(output_dir), packet["bindings"]["lease_generation"], config["digest"])
        capture = capture_muse_turn(request, config=MuseCaptureConfig(config["executable"]["path"],
            config["executable"]["sha256"], config["build"], config["requested_model"],
            config["permission_profile"], config["max_model_steps"]), qualification="synthetic",
            timeout_seconds=packet["remaining_budget"]["attempt_seconds"],
            max_output_bytes=packet["remaining_budget"]["max_output_bytes"],
            cancel_requested=cancel_requested, heartbeat=heartbeat, on_spawn=on_spawn, mode=mode, thread_id=thread_id)
        process = capture.process.to_dict() if capture.process is not None else {
            "termination_confirmed": False, "group_termination_confirmed": False, "unaccounted_descendants": True,
            "output_bytes": packet["remaining_budget"]["max_output_bytes"], "duration_ms": 0}
        process.pop("stdout", None)
        process.pop("stderr", None)
        process["termination_confirmed"] = (process.get("termination_confirmed") is True
            and process.get("group_termination_confirmed") is True and process.get("unaccounted_descendants") is False)
        state = {"local_turn_completed": "completed", "cancelled_local": "cancelled", "unknown": "unknown"}.get(capture.status, "failed")
        if capture.error == "cancel_pending" and process["termination_confirmed"]:
            state = "cancelled"
        return {"state": state, "result": None, "session_id": None, "thread_id": None, "checkpoint": None,
                "process": process, "error": capture.error, "usage": {"input_tokens": None, "output_tokens": None, "cost_usd": None},
                "_muse_capture": capture}

    def doctor(self, **_):
        return {"qualified": False, "production_dispatch_allowed": False, "live_inference": False,
                "diagnostic_scope": "Original synthetic Muse capture only; no vendor identity or containment proof."}
