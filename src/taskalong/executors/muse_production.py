"""Closed production Muse adapter; missing authentic runtime proof refuses spawn."""
from functools import partial
from pathlib import Path
from .. import muse_runtime
from ..errors import TaskAlongError
from ..muse_lifecycle import MuseProductionConfiguration, compile_packet
from ..validation import canonical_bytes, digest, loads, validate_versioned
from .base import ExecutionRequest
from .muse_capture import MuseCaptureConfig, _capture_owned_turn, capabilities
from .muse_protocol import project_production_exec_argv


class MuseProductionDriver:
    def __init__(self, config, *, runtime_subject=None):
        self.config = MuseProductionConfiguration.from_dict(config).to_dict()
        self.subject = loads(canonical_bytes(runtime_subject)) if runtime_subject is not None else None

    def capabilities(self):
        return capabilities()

    def preflight(self, *, qualification, budget):
        if qualification != "production":
            raise TaskAlongError("qualification_mismatch", "The production Muse adapter cannot execute a fixture route.", exit_code=3, effect_outcome="not_sent")
        if (type(budget.get("max_attempts",1)) is not int or type(budget.get("max_model_steps",1)) is not int
                or budget.get("max_attempts",1) != 1 or budget.get("max_model_steps",1) != 1
                or budget.get("hard_cost_usd") is not None or budget.get("hard_tokens") is not None
                or budget.get("attempt_seconds",1)>60 or budget.get("max_output_bytes",1)>1048576):
            raise TaskAlongError("muse_budget_unsupported", "Production Muse requires the exact finite task bounds.", exit_code=3, effect_outcome="not_sent")
        if self.subject is None or self.subject.get("configuration_digest") != self.config["digest"]:
            raise TaskAlongError("muse_runtime_unqualified", "The production adapter requires the core-owned exact runtime subject.", exit_code=3, effect_outcome="not_sent")
        muse_runtime.require(self.subject)

    def run(self, packet, *, workspace, output_dir, cancel_requested=None, heartbeat=None, on_spawn=None,
            mode="start", thread_id=None, **_):
        packet = validate_versioned("worker-packet", packet, expected_version="2.12")
        config = self.config
        if mode != "start" or thread_id is not None:
            raise TaskAlongError("muse_native_resume_unsupported", "Production Muse supports one fresh owned attempt only.", exit_code=3, effect_outcome="not_sent")
        if packet["bindings"]["driver_config_digest"] != config["digest"]:
            raise TaskAlongError("execution_identity_mismatch", "The production packet names another configuration.", exit_code=3, effect_outcome="not_sent")
        self.preflight(qualification=packet["qualification"], budget=packet["remaining_budget"])
        if packet["runtime_subject_digest"] != digest(self.subject) or packet["spec_digest"] != self.subject["spec_digest"]:
            raise TaskAlongError("execution_identity_mismatch", "The packet names another admitted runtime subject.", exit_code=3, effect_outcome="not_sent")
        request = ExecutionRequest(packet["run_id"],packet["attempt_id"],packet["spec_digest"],canonical_bytes(packet),
            Path(workspace),Path(output_dir),packet["bindings"]["lease_generation"],config["digest"])
        capture = _capture_owned_turn(request,config=MuseCaptureConfig(config["executable"]["path"],config["executable"]["sha256"],
            config["build"],config["requested_model"],config["permission_profile"],1),qualification="production",
            _argv=partial(project_production_exec_argv,reasoning_effort="high"),
            _recheck=lambda: muse_runtime.require(self.subject),
            timeout_seconds=packet["remaining_budget"]["attempt_seconds"],max_output_bytes=packet["remaining_budget"]["max_output_bytes"],
            cancel_requested=cancel_requested,heartbeat=heartbeat,on_spawn=on_spawn,mode=mode,thread_id=thread_id)
        process = capture.process.to_dict() if capture.process is not None else {
            "termination_confirmed":False,"group_termination_confirmed":False,"unaccounted_descendants":True,
            "output_bytes":packet["remaining_budget"]["max_output_bytes"],"duration_ms":0}
        process.pop("stdout",None);process.pop("stderr",None)
        process["termination_confirmed"] = (process.get("termination_confirmed") is True
            and process.get("group_termination_confirmed") is True and process.get("unaccounted_descendants") is False)
        state={"local_turn_completed":"completed","cancelled_local":"cancelled","unknown":"unknown"}.get(capture.status,"failed")
        return {"state":state,"result":None,"session_id":None,"thread_id":None,"checkpoint":None,
            "process":process,"error":capture.error,"usage":{"input_tokens":None,"output_tokens":None,"cost_usd":None},"_muse_capture":capture}

    def doctor(self, **_):
        return muse_runtime.observe({"configuration_digest":self.config["digest"]})
