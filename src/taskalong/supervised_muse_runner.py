"""Pinned supervised Muse runner components; planning/folding only, no transport.

No imported transcript, model catalog, usage snapshot or plan is admission. The
public live command remains closed. This module imports no subprocess/network API.
"""
import copy
import hashlib
import re
import time
import uuid

from . import supervised_pilot as pilot
from .muse_mac_probe import BINARY_SHA256, SCHEMA_FINGERPRINT
from .muse_production import _observe_file
from .validation import canonical_bytes, digest, loads
from .artifact_io import read_regular

FORMAT = "supervised-muse-runner-plan/1"
LIMITS = {"turn_submissions": 1, "provider_retries": 0, "attempt_seconds": 20,
          "interrupt_grace_seconds": 2, "max_output_bytes": 65536,
          "aggregate_inference_cap_enforced": False, "cost_cap_enforced": False}
AXES = {"filesystem": "sandboxed", "network": "restricted", "approval": "onRequest", "reviewer": "human"}


def _fail(code):
    pilot._fail(code)


def _uuid7():
    value = (int(time.time() * 1000) << 80) | (7 << 76) | (uuid.uuid4().int & ((1 << 76) - 1))
    return str(uuid.UUID(int=(value & ~(3 << 62)) | (2 << 62)))


def _uuid(value):
    if type(value) is not str:
        _fail("supervised_muse_identity_invalid")
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError()
    except ValueError:
        _fail("supervised_muse_identity_invalid")
    return value


def _rpc(identifier, method, params=None):
    value = {"jsonrpc": "2.0", "id": identifier, "method": method}
    if params is not None:
        value["params"] = params
    return value


def prepare(*, bundle, executable, output):
    _, manifest = pilot._bundle(bundle)
    request = manifest["request"]
    if (request["provider"], request["model"], request["reasoning_effort"]) != ("muse", "wonder-full", "high"):
        _fail("supervised_muse_route_unsupported")
    binary = _observe_file(executable, executable=True)
    if binary["sha256"] != BINARY_SHA256:
        _fail("supervised_muse_binary_unsupported")
    root = pilot._destination(output)
    plan = {"format": FORMAT, "bundle_digest": manifest["digest"], "prompt": pilot._prompt(request, manifest["digest"]).decode(),
            "binary": binary, "schema_fingerprint": SCHEMA_FINGERPRINT,
            "workspace": str(root / "workspace"), "muse_home": str(root / "data/muse"),
            "session_id": _uuid7(), "session_command_id": _uuid7(), "turn_command_id": _uuid7(), "interrupt_command_id": _uuid7(),
            "provider": "meta", "model": "wonder-full", "reasoning_effort": "high", "permission_profile": ":read-only",
            "argv": [executable, "serve", "--provider", "meta", "--model", "wonder-full", "--disable-write", "--disable-shell",
                     "--disable-request-user-input", "--contributor-mode", "off", "--sandbox-network", "proxy-only"],
            "limits": dict(LIMITS), "account_binding": "unresolved", "existing_account_available_in_fresh_home": False,
            "context_closure_qualified": False, "tool_enforcement_qualified": False, "descendant_cessation": "unknown",
            "remote_usage_settled": False, "requests_are_data_only": True, **pilot._FLAGS}
    plan["digest"] = digest(plan)
    created = False
    try:
        root.mkdir(mode=0o700); created = True
        for name in ("workspace", "home", "config", "cache", "data", "state", "tmp"):
            (root / name).mkdir(mode=0o700)
        pilot._write(root, "runner-plan.json", canonical_bytes(plan))
    except (OSError, pilot.TaskAlongError):
        pilot._fail("supervised_muse_plan_incomplete", uncertain=created)
    return {"plan_digest": plan["digest"], "plan_path": str(root / "runner-plan.json"), "limits": dict(LIMITS), **pilot._FLAGS}


def load_plan(path):
    source = pilot._root(path)
    value = loads(read_regular(source.parent, source.name, max_bytes=1048576, private=True, expected_mode=0o400))
    keys = {"format", "bundle_digest", "prompt", "binary", "schema_fingerprint", "workspace", "muse_home", "session_id", "session_command_id", "turn_command_id", "interrupt_command_id", "provider", "model", "reasoning_effort", "permission_profile", "argv", "limits", "account_binding", "existing_account_available_in_fresh_home", "context_closure_qualified", "tool_enforcement_qualified", "descendant_cessation", "remote_usage_settled", "requests_are_data_only", "digest", *pilot._FLAGS}
    if (set(value) != keys or value.get("format") != FORMAT or value.get("digest") != digest(value)
            or value.get("schema_fingerprint") != SCHEMA_FINGERPRINT
            or canonical_bytes(value.get("limits")) != canonical_bytes(LIMITS)
            or any(value.get(k) is not v for k, v in pilot._FLAGS.items())
            or value.get("requests_are_data_only") is not True
            or any(value.get(k) is not False for k in ("existing_account_available_in_fresh_home", "context_closure_qualified", "tool_enforcement_qualified", "remote_usage_settled"))
            or value.get("account_binding") != "unresolved" or value.get("descendant_cessation") != "unknown"
            or (value.get("provider"), value.get("model"), value.get("reasoning_effort"), value.get("permission_profile")) != ("meta", "wonder-full", "high", ":read-only")
            or value.get("workspace") != str(source.parent / "workspace") or value.get("muse_home") != str(source.parent / "data/muse")
            or type(value.get("binary")) is not dict or value["binary"].get("sha256") != BINARY_SHA256):
        _fail("supervised_muse_plan_invalid")
    expected_argv = [value["binary"].get("path"), "serve", "--provider", "meta", "--model", "wonder-full", "--disable-write", "--disable-shell", "--disable-request-user-input", "--contributor-mode", "off", "--sandbox-network", "proxy-only"]
    if value["argv"] != expected_argv:
        _fail("supervised_muse_plan_invalid")
    ids = [value[k] for k in ("session_id", "session_command_id", "turn_command_id", "interrupt_command_id")]
    if any(uuid.UUID(_uuid(v)).version != 7 for v in ids) or len(set(ids)) != 4:
        _fail("supervised_muse_identity_invalid")
    return value


def initialize_request():
    return _rpc(1, "initialize", {"clientInfo": {"name": "taskalong_supervised_development", "version": "1"},
        "capabilities": {"requestedCapabilities": [], "experimentalApi": True, "userInputDialogs": False}})


def preflight_requests():
    return [{"jsonrpc": "2.0", "method": "initialized"}, _rpc(2, "permissionProfile/list", {}),
            _rpc(3, "model/list", {}), _rpc(4, "usage/read")]


def validate_preflight(plan, *, initialization, profiles, catalog, usage):
    canonical_bytes({"initialization": initialization, "profiles": profiles, "catalog": catalog, "usage": usage})
    if (any(type(v) is not dict for v in (initialization, profiles, catalog, usage))
            or type(profiles.get("profiles")) is not list or any(type(v) is not dict for v in profiles["profiles"])
            or type(catalog.get("models")) is not list or any(type(v) is not dict for v in catalog["models"])):
        _fail("supervised_muse_preflight_invalid")
    expected = {"serverInfo": {"name": "muse", "version": "1.4.10"}, "platformFamily": "unix", "platformOs": "macos",
                "schema": {"version": 1, "fingerprint": SCHEMA_FINGERPRINT}, "grantedCapabilities": [],
                "experimentalApi": True, "sandboxAvailability": "available", "sessionDurability": "durable", "museHome": plan["muse_home"]}
    if any(canonical_bytes({"value": initialization.get(k)}) != canonical_bytes({"value": v}) for k, v in expected.items()):
        _fail("supervised_muse_preflight_changed")
    if not any(p.get("profileId") == ":read-only" and p.get("available") is True and p.get("reviewerAuthority") == "human" for p in profiles.get("profiles", [])):
        _fail("supervised_muse_profile_unavailable")
    models = [m for m in catalog.get("models", []) if m.get("modelId") == "wonder-full" and m.get("providerId") == "meta"]
    if (catalog.get("providerId") != "meta" or type(catalog.get("source")) is not str or catalog.get("source") not in {"providerCatalog", "bundledCatalog", "configCatalog"}
            or len(models) != 1 or type(models[0].get("variants")) is not list or "high" not in models[0]["variants"]):
        _fail("supervised_muse_model_unobserved")
    # Absence remains absence. A last-observed subscription window is neither
    # account authentication, live allowance nor an enforceable inference cap.
    return {"catalog_source": catalog["source"], "reported_subscription_usage": copy.deepcopy(usage.get("usage")),
            "account_binding_qualified": False, "inference_bound_qualified": False, **pilot._FLAGS}


def metadata_requests():
    # Supported experimental read-only surfaces. No login/logout, credential
    # material, settings write or additional tool capability is requested.
    return [_rpc(8, "account/read"), _rpc(9, "settings/readSchema"), _rpc(10, "settings/read")]


def observe_account(value):
    if (type(value) is not dict or not {"state", "credentialRequired"}.issubset(value)
            or not set(value).issubset({"state", "credentialRequired", "label", "avatarUrl"})
            or type(value.get("state")) is not str or not value["state"]
            or type(value.get("credentialRequired")) is not bool):
        _fail("supervised_muse_account_projection_invalid")
    known = {"loggedOut", "envKey", "apiKey", "accountLogin"}
    return {"credential_lane": value["state"] if value["state"] in known else "unknown",
            "credential_required": value["credentialRequired"], "display_identity_present": "label" in value,
            "account_endpoint_bound": False, "allowance_or_cap_qualified": False,
            "provenance": "unverified_projected_metadata", **pilot._FLAGS}


def session_request(plan):
    return _rpc(5, "session/start", {"commandId": plan["session_command_id"], "sessionId": plan["session_id"],
        "workspaceRoot": plan["workspace"], "providerId": "meta", "modelId": "wonder-full", "permissionProfile": ":read-only"})


def validate_session(plan, session):
    canonical_bytes(session)
    expected = {"sessionId": plan["session_id"], "workspaceRoot": plan["workspace"], "providerId": "meta", "modelId": "wonder-full",
                "status": "idle", "activeTurnId": None, "turnCount": 0, "forkedFrom": None}
    if type(session) is not dict or type(session.get("permissionState")) is not dict:
        _fail("supervised_muse_session_changed")
    permission = session["permissionState"]
    if (any(canonical_bytes({"value": session.get(k)}) != canonical_bytes({"value": v}) for k, v in expected.items())
            or permission.get("profileId") != ":read-only" or permission.get("axes") != AXES
            or permission.get("reviewerAuthority") != "human" or permission.get("reviewerAttached") is not True):
        _fail("supervised_muse_session_changed")


def turn_request(plan):
    return _rpc(6, "turn/start", {"commandId": plan["turn_command_id"], "sessionId": plan["session_id"],
        "input": [{"type": "text", "text": plan["prompt"]}], "reasoningEffort": "high"})


def bind_turn(plan, ack):
    if (type(ack) is not dict or ack.get("commandId") != plan["turn_command_id"] or ack.get("status") != "accepted"
            or ack.get("disposition") != "started" or ack.get("startedNewTurn") is not True):
        _fail("supervised_muse_turn_not_fresh")
    return TurnFold(session_id=plan["session_id"], turn_id=_uuid(ack.get("turnId")), interrupt_id=plan["interrupt_command_id"])


def _source_range(value):
    if type(value) is not dict:
        return False
    stream = value.get("stream")
    if type(stream) is not dict or any(type(stream.get(k)) is not str or not stream[k] for k in ("kind", "id")):
        return False
    positions = [value.get(k) for k in ("first", "last")]
    if any(type(p) is not dict or type(p.get("id")) is not str or not p["id"]
           or type(p.get("sequence")) is not int or p["sequence"] < 0 for p in positions):
        return False
    return positions[0]["sequence"] <= positions[1]["sequence"]


class TurnFold:
    """Bounded untrusted event fold and one exact interrupt projection.

    Requests are returned as data, never sent. A matching terminal is an observed
    turn state only: it never settles remote usage or any descendant lifetime.
    """
    def __init__(self, *, session_id, turn_id, interrupt_id):
        self.session_id, self.turn_id, self.interrupt_id = map(_uuid, (session_id, turn_id, interrupt_id))
        self.terminal = None; self.final = None; self.interrupt_sent = False; self.interrupt_acknowledged = False
        self.blockers = []; self.seen = {}; self.items = {}; self.bytes = 0; self.usage = None

    def block(self, reason):
        if reason not in self.blockers:
            self.blockers.append(reason)

    def interrupt(self, reason):
        self.block(reason)
        if self.interrupt_sent or self.terminal is not None:
            return None
        self.interrupt_sent = True
        return _rpc(7, "turn/interrupt", {"commandId": self.interrupt_id, "sessionId": self.session_id, "turnId": self.turn_id, "retract": False})

    def acknowledge_interrupt(self, result):
        if (type(result) is not dict or not self.interrupt_sent or result.get("commandId") != self.interrupt_id or result.get("turnId") != self.turn_id
                or result.get("status") != "accepted"):
            self.block("interrupt_ack_invalid")
            return
        self.interrupt_acknowledged = True

    def feed(self, frame):
        raw = canonical_bytes(frame); self.bytes += len(raw)
        if self.bytes > LIMITS["max_output_bytes"]:
            self.block("output_limit"); return self.interrupt("output_limit")
        if type(frame) is not dict or frame.get("jsonrpc") != "2.0" or "id" in frame or type(frame.get("params")) is not dict:
            self.block("unexpected_frame"); return self.interrupt("unexpected_frame")
        params = frame["params"]; method = frame.get("method")
        if type(method) is not str:
            return self.interrupt("notification_method_invalid")
        if params.get("sessionId") != self.session_id:
            self.block("foreign_session"); return self.interrupt("foreign_session")
        if self.terminal is not None:
            self.block("event_after_terminal"); return None
        cursor = params.get("viewCursor")
        if cursor is not None:
            if type(cursor) is not str or not cursor:
                return self.interrupt("cursor_invalid")
            if cursor in self.seen:
                if self.seen[cursor] != hashlib.sha256(raw).hexdigest():
                    return self.interrupt("cursor_conflict")
                return None
            self.seen[cursor] = hashlib.sha256(raw).hexdigest()
        if method in {"item/completed", "turn/completed", "turn/started", "turn/foregroundCompleted", "session/tokenUsage"} and (not cursor or not _source_range(params.get("sourceRange"))):
            return self.interrupt("durable_source_missing")
        if method in {"item/started", "item/updated", "item/completed"}:
            item = params.get("item", {})
            if type(item) is not dict:
                return self.interrupt("item_invalid")
            if item.get("turnId") != self.turn_id:
                return self.interrupt("foreign_turn")
            kind = item.get("kind")
            if type(kind) is not str or kind not in {"userMessage", "reasoning", "agentMessage"}:
                return self.interrupt("unexpected_activity:" + str(kind))
            if kind == "agentMessage" and (item.get("truncated", False) is not False or item.get("cutOff", False) is not False):
                return self.interrupt("final_message_incomplete")
            if kind == "agentMessage" and method == "item/completed":
                if (item.get("status") != "completed" or item.get("messagePhase") != "finalAnswer"
                        or item.get("truncated", False) is not False or item.get("cutOff", False) is not False
                        or type(item.get("text")) is not str):
                    return self.interrupt("final_message_incomplete")
                identity = item.get("itemId"); revision = item.get("revision")
                if type(identity) is not str or type(revision) is not int or revision < 1:
                    return self.interrupt("final_identity_invalid")
                if identity in self.items or self.final is not None:
                    return self.interrupt("multiple_final_messages")
                self.items[identity] = revision; self.final = item["text"]
        elif method == "turn/completed":
            if params.get("turnId") != self.turn_id or type(params.get("terminal")) is not str or params.get("terminal") not in {"completed", "cancelled", "failed"}:
                return self.interrupt("terminal_invalid")
            self.terminal = params["terminal"]; self.usage = copy.deepcopy(params.get("usage"))
            if self.terminal != "completed": self.block("turn_" + self.terminal)
        elif method == "turn/started":
            if params.get("turnId") != self.turn_id: return self.interrupt("foreign_turn")
        elif method == "turn/foregroundCompleted":
            if params.get("turnId") != self.turn_id:
                return self.interrupt("foreign_turn")
            return self.interrupt("unexpected_background_agents")
        elif method == "session/tokenUsage":
            if params.get("turnId") != self.turn_id:
                return self.interrupt("foreign_turn")
        elif method not in {"item/delta", "session/statusChanged"}:
            return self.interrupt("unexpected_notification:" + str(method))
        return None

    def result(self, *, manifest):
        response = None
        blockers = list(self.blockers)
        if self.terminal is None: blockers.append("turn_terminal_unobserved")
        if self.terminal == "completed" and self.final is None: blockers.append("final_answer_unobserved")
        if self.terminal == "completed" and self.final is not None and not blockers:
            response = loads(self.final, max_bytes=LIMITS["max_output_bytes"])
            pilot._proposal(manifest, response)
        return {"terminal_observed": self.terminal, "interrupt_requested": self.interrupt_sent,
                "interrupt_acknowledged": self.interrupt_acknowledged, "blockers": blockers,
                "response": response, "reported_usage": copy.deepcopy(self.usage), "remote_usage_settled": False,
                "descendant_cessation": "unknown", "transcript_provenance": "unverified_local_content",
                "inference_bound_qualified": False, **pilot._FLAGS}


def _result(frame, identifier):
    if (type(frame) is not dict or set(frame) != {"jsonrpc", "id", "result"} or frame["jsonrpc"] != "2.0"
            or type(frame["id"]) is not int or frame["id"] != identifier or type(frame["result"]) is not dict):
        _fail("supervised_muse_rpc_unexpected")
    return frame["result"]


def replay(*, plan_path, bundle, transcript, output):
    """Drive the protocol against explicit local frames, without any I/O adapter.

    Even a complete transcript cannot authenticate a provider or open admission.
    The saved requests are projections, never requests that this replay sent.
    """
    plan = load_plan(plan_path)
    _, manifest = pilot._bundle(bundle)
    if (plan["bundle_digest"] != manifest["digest"]
            or plan["prompt"] != pilot._prompt(manifest["request"], manifest["digest"]).decode()):
        _fail("supervised_muse_bundle_mismatch")
    if type(transcript) is not dict or set(transcript) != {"responses", "notifications"}:
        _fail("supervised_muse_transcript_invalid")
    canonical_bytes(transcript)
    responses = transcript["responses"]; notifications = transcript["notifications"]
    if type(responses) is not list or len(responses) != 6 or type(notifications) is not list or len(notifications) > 256:
        _fail("supervised_muse_transcript_invalid")
    data = [_result(frame, i + 1) for i, frame in enumerate(responses)]
    observations = validate_preflight(plan, initialization=data[0], profiles=data[1], catalog=data[2], usage=data[3])
    validate_session(plan, data[4].get("session", {}))
    fold = bind_turn(plan, data[5])
    requests = [initialize_request(), *preflight_requests(), session_request(plan), turn_request(plan)]
    for frame in notifications:
        if type(frame) is dict and type(frame.get("id")) is int and frame.get("id") == 7:
            fold.acknowledge_interrupt(_result(frame, 7))
        else:
            interrupt = fold.feed(frame)
            if interrupt is not None: requests.append(interrupt)
    result = fold.result(manifest=manifest)
    result.update(format="supervised-muse-replay/1", plan_digest=plan["digest"], bundle_digest=manifest["digest"],
                  preflight_observations=observations, projected_requests_sent=False,
                  transcript_sha256=hashlib.sha256(canonical_bytes(transcript)).hexdigest())
    result["digest"] = digest(result)
    root = pilot._destination(output); created = False
    try:
        root.mkdir(mode=0o700); created = True
        pilot._write(root, "transcript.json", canonical_bytes(transcript))
        pilot._write(root, "projected-requests.json", canonical_bytes({"sent": False, "requests": requests}))
        if result["response"] is not None:
            pilot._write(root, "response.json", canonical_bytes(result["response"]))
        pilot._write(root, "fold.json", canonical_bytes(result))
    except (OSError, pilot.TaskAlongError):
        pilot._fail("supervised_muse_replay_incomplete", uncertain=created)
    return result


def exec_argv(*, executable, workspace, prompt_file, model_id):
    # The operator selects the observed canonical catalog id explicitly. There
    # is no automatic alias resolution or provider/model fallback.
    if model_id != "muse-wonder-full-1.0":
        _fail("supervised_muse_canonical_model_required")
    for value in (executable, workspace, prompt_file):
        pilot._root(value)
    return [executable, "exec", "--json", "--provider", "meta", "--model", model_id,
            "--reasoning-effort", "high", "--preset", "empty", "--permission-profile", ":read-only",
            "--workspace", workspace, "--prompt-file", prompt_file, "--max-model-steps", "1",
            "--disable-reminders", "--disable-web-tools", "--no-foreign-personal-context",
            "--no-parallel-tool-calls", "--disable-write", "--disable-shell", "--disable-request-user-input",
            "--contributor-mode", "off"]


def prepare_exec(*, bundle, executable, model_id, output):
    _, manifest = pilot._bundle(bundle)
    request = manifest["request"]
    if type(model_id) is not str or request["provider"] != "muse" or request["reasoning_effort"] != "high" or request["model"] not in {"wonder-full", model_id}:
        _fail("supervised_muse_route_unsupported")
    binary = _observe_file(executable, executable=True)
    if binary["sha256"] != BINARY_SHA256:
        _fail("supervised_muse_binary_unsupported")
    target = pilot._destination(output)
    prompt = pilot._prompt(request, manifest["digest"])
    argv = exec_argv(executable=executable, workspace=str(target / "workspace"), prompt_file=str(target / "prompt.txt"), model_id=model_id)
    value = {"format": "supervised-muse-exec-plan/1", "bundle_digest": manifest["digest"], "binary": binary,
             "selected_canonical_model_id": model_id, "model_selection": "explicit_operator_intent_not_alias_resolution",
             "requested_reasoning_effort": "high", "effective_reasoning_effort_observed": False,
             "argv": argv, "prompt_sha256": hashlib.sha256(prompt).hexdigest(), "prompt_bytes": len(prompt),
             "limits_intent": dict(LIMITS), "main_model_step_limit_requested": 1,
             "echo_observations": {"empty_toolset": True, "empty_reminder_roster": True, "native_fork_observed": True,
                                   "personal_skill_catalog_not_excluded": True},
             "account_context_admitted": False, "native_internal_http_retry_policy_qualified": False,
             "whole_process_lifetime_qualified": False, "remote_usage_settled": False,
             "live_transport_admitted": False, "requests_are_data_only": True, **pilot._FLAGS}
    value["digest"] = digest(value)
    created = False
    try:
        target.mkdir(mode=0o700); created = True
        (target / "workspace").mkdir(mode=0o700)
        pilot._write(target, "prompt.txt", prompt)
        pilot._write(target, "exec-plan.json", canonical_bytes(value))
    except (OSError, pilot.TaskAlongError):
        pilot._fail("supervised_muse_exec_plan_incomplete", uncertain=created)
    return value
