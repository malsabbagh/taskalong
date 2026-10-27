#!/usr/bin/env python3
"""Original two-protocol synthetic handoff fixture; no provider or network call."""
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

PAYLOAD = b"Synthetic reviewed handoff bytes.\n"


def main():
    args = sys.argv[1:]
    if args == ["--version"]:
        print("codex-cli 0.163.0")
        return 0
    codex = args[:2] == ["--no-daemon", "exec"]
    # Record target exec before parsing/validating input. A later fixture
    # assertion cannot masquerade as a core launch-gate refusal.
    fd = os.open(Path(__file__).with_name("handoff-starts.jsonl"),
                 os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(json.dumps({"driver":"codex" if codex else "claude"}) + "\n")
    if codex:
        assert "resume" not in args and "--ignore-user-config" in args
        assert "--strict-config" in args and "--json" in args and args[-1] == "-"
    else:
        assert "--print" in args and "--no-session-persistence" in args
        assert "--safe-mode" in args and "--strict-mcp-config" in args
    packet = json.load(sys.stdin)
    mode_path = Path(__file__).with_suffix(".mode.json")
    settings = json.loads(mode_path.read_text()) if mode_path.exists() else {"mode":"good"}
    mode = settings["mode"]
    assert packet["qualification"] == "synthetic"
    assert packet["schema_version"] == ("1.0" if codex else "2.3")
    ordered = packet["extensions"]["taskalong:ordered_step"]
    handoff = packet["extensions"]["taskalong:handoff"]
    selectors = [item for item in ordered["inputs"] if "from_step_id" in item]
    assert len(handoff["staged_inputs"]) == len(selectors)
    staged = []
    for selector,selected in zip(selectors,handoff["staged_inputs"]):
        data = Path(selected["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == selected["sha256"]
        assert len(data) == selected["bytes"]
        if selector["expected_kind"] == "file_set_patch":
            assert json.loads(data)["kind"] == "file_set_patch"
        staged.append({"sha256":selected["sha256"], "bytes":len(data)})
    driver = "codex" if codex else "claude"
    session = "handoff-codex-" + packet["attempt_id"] if codex else packet["session_id"]
    if not codex:
        assert session == packet["attempt_id"] == args[args.index("--session-id") + 1]
    observation = {"driver":driver, "session":session, "attempt_id":packet["attempt_id"],
        "run_id":packet["run_id"], "spec_digest":packet["spec_digest"],
        "step_id":ordered["step_id"], "staged":staged,
        "credential_environment_present":any(k.startswith(("OPENAI_", "ANTHROPIC_", "GH_", "GITHUB_", "AWS_")) for k in os.environ)}
    fd = os.open(Path(__file__).with_name("handoff-invocations.jsonl"),
                 os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(json.dumps(observation) + "\n")
    if codex:
        print(json.dumps({"type":"thread.started", "thread_id":session}), flush=True)
    else:
        print(json.dumps({"type":"system", "subtype":"init", "session_id":session,
            "model":args[args.index("--model") + 1], "tools":["Edit"]}), flush=True)
    if mode == "failed":
        return 1
    changed = []
    for relative in packet["scope"]["files"]:
        target = Path(relative)
        if target.suffix == ".py":
            before = target.read_text()
            after = before.replace("a - b", "a + b")
            if after != before:
                target.write_text(after)
                changed.append({"path":relative,"operation":"modify"})
        elif target.name == "note.txt":
            if mode == "missing-note":
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            payload = settings.get("payload",PAYLOAD.decode()).encode("utf-8")
            after = b"" if mode == "empty" else payload
            before = target.read_bytes() if target.is_file() else None
            if before != after:
                target.write_bytes(after)
                changed.append({"path":relative,"operation":"add" if before is None else "modify"})
        elif target.suffix == ".json" and "patch" in settings:
            patch = settings["patch"]
            assert patch["kind"] == "file_set_patch" and patch["schema_version"] == "2.10"
            target.parent.mkdir(parents=True, exist_ok=True)
            after = json.dumps(patch,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
            before = target.read_bytes() if target.is_file() else None
            if before != after:
                target.write_bytes(after)
                changed.append({"path":relative,"operation":"add" if before is None else "modify"})
    if mode == "failed-after-edits":
        return 1
    worker = {"kind":"worker_result", "schema_version":"1.0" if codex else "2.3",
        "extensions":{}, "result_id":str(uuid.uuid4()), "packet_id":packet["packet_id"],
        "packet_digest":packet["digest"], "run_id":packet["run_id"], "attempt_id":packet["attempt_id"],
        "spec_digest":packet["spec_digest"], "status":"completed", "changed_files":changed,
        "command_claims":[], "summary":"Synthetic handoff; independent acceptance is required.",
        "blockers":[], "deviations":[], "residual_risks":[], "qualification":"synthetic"}
    if codex:
        result = Path(args[args.index("--output-last-message") + 1])
        result.write_text(json.dumps(worker))
        result.chmod(0o600)
        print(json.dumps({"type":"turn.completed", "usage":{"input_tokens":3,"output_tokens":5}}), flush=True)
    else:
        worker.update(driver_config_digest=packet["bindings"]["driver_config_digest"],
            provider_profile_digest=packet["bindings"]["provider_profile_digest"], session_id=session)
        print(json.dumps({"type":"result", "subtype":"success", "is_error":False,
            "permission_denials":[], "session_id":session, "structured_output":worker,
            "usage":{"input_tokens":3,"output_tokens":5}}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
