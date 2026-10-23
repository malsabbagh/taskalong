#!/usr/bin/env python3
"""Original Cursor-shaped responder, with no vendor code or provider request."""
import argparse
import json
import os
from pathlib import Path
import sys
import time
import uuid


parser = argparse.ArgumentParser()
parser.add_argument("--print", action="store_true")
parser.add_argument("--output-format", choices=["stream-json"], required=True)
parser.add_argument("--model", choices=["synthetic-cursor-model"], required=True)
args = parser.parse_args()
assert args.print
packet = json.loads(sys.stdin.buffer.read())
mode_path = Path(__file__).with_suffix(".mode.json")
mode = json.loads(mode_path.read_text()) if mode_path.exists() else {"mode": "good"}
assert packet["schema_version"] == "2.5" and packet["session_policy"] == "fresh"
assert "session_id" not in packet
session = mode.get("session", str(uuid.uuid4()))
assert session not in {packet["packet_id"], packet["run_id"], packet["attempt_id"]}
unexpected = any(key.startswith(("CURSOR_", "ANTHROPIC_", "OPENAI_", "OLLAMA_", "GH_", "GITHUB_", "AWS_"))
    or key.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"} for key in os.environ)
assert not unexpected
observed = {"argv_flags": sys.argv[1:], "session_id": session, "attempt_id": packet["attempt_id"],
    "packet_digest": packet["digest"], "driver_config_digest": packet["bindings"]["driver_config_digest"],
    "provider_profile_digest": packet["bindings"]["provider_profile_digest"],
    "unexpected_environment_present": unexpected, "external_request": "not_sent", "qualification": "synthetic"}
fd = os.open(Path(__file__).with_suffix(".invocations.jsonl"), os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
with os.fdopen(fd, "w") as log:
    log.write(json.dumps(observed) + "\n")
print(json.dumps({"type": "system", "subtype": "init", "session_id": session,
                  "model": "taskalong-fixture-cursor-model"}), flush=True)
if mode["mode"] == "stderr":
    print(mode["diagnostic"], file=sys.stderr, flush=True)
# Only trusted test-owned barriers are consulted; no task field selects a mode.
deadline = time.monotonic() + 15
while Path(__file__).with_suffix(".hold").exists() and not Path(__file__).with_suffix(".release").exists() and time.monotonic() < deadline:
    time.sleep(0.02)
path = packet["scope"]["files"][0]
call = {"type": "tool_call", "subtype": "started", "session_id": session,
        "call_id": "fixture-edit-1", "tool": "Edit", "path": path}
print(json.dumps(call), flush=True)
target = Path(path)
target.write_text(target.read_text().replace("a - b", "a + b"))
print(json.dumps(call | {"subtype": "completed", "is_error": False}), flush=True)
worker = {"kind": "worker_result", "schema_version": "2.5", "extensions": {}, "result_id": str(uuid.uuid4()),
    "packet_id": packet["packet_id"], "packet_digest": packet["digest"], "run_id": packet["run_id"],
    "attempt_id": packet["attempt_id"], "spec_digest": packet["spec_digest"],
    "driver_config_digest": packet["bindings"]["driver_config_digest"],
    "provider_profile_digest": packet["bindings"]["provider_profile_digest"],
    "status": "completed", "changed_files": [{"path": path, "operation": "modify"}], "command_claims": [],
    "summary": "Synthetic Cursor edit; independent checks remain required.", "blockers": [], "deviations": [],
    "residual_risks": [], "qualification": "synthetic"}
if mode["mode"] == "scope_claim_mismatch":
    worker["changed_files"] = []
print(json.dumps({"type": "result", "subtype": "success", "is_error": False,
                  "session_id": session, "result": json.dumps(worker)}), flush=True)
if mode["mode"] == "nonzero":
    raise SystemExit(1)
