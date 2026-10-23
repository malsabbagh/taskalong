#!/usr/bin/env python3
"""Original headless fixture dialect; no Google code, account or service request."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid


parser = argparse.ArgumentParser()
parser.add_argument("--input-format", choices=["stream-json"], required=True)
parser.add_argument("--output-format", choices=["stream-json"], required=True)
parser.add_argument("--model", choices=["fixture-agy-model"], required=True)
parser.add_argument("--json-schema", required=True)
parser.add_argument("--print-timeout", required=True)
parser.add_argument("--disable-slash-commands", action="store_true", required=True)
parser.add_argument("--sandbox", action="store_true", required=True)
args = parser.parse_args()
assert args.print_timeout.endswith("s") and 1 <= int(args.print_timeout[:-1]) <= 300
result_schema = json.loads(args.json_schema)
assert result_schema["$id"] == "urn:taskalong:schema:v2.5:worker-result"
raw = sys.stdin.buffer.read()
assert raw.endswith(b"\n") and len(raw.splitlines()) == 1
envelope = json.loads(raw)
assert set(envelope) == {"type", "message"} and envelope["type"] == "user"
assert set(envelope["message"]) == {"role", "content"} and envelope["message"]["role"] == "user"
packet = json.loads(envelope["message"]["content"])
assert json.dumps(packet, ensure_ascii=False, sort_keys=True, separators=(",", ":")) == envelope["message"]["content"]
assert packet["schema_version"] == "2.6" and packet["session_policy"] == "fresh" and "session_id" not in packet
mode_path = Path(__file__).with_suffix(".mode.json")
mode = json.loads(mode_path.read_text()) if mode_path.exists() else {"mode": "good"}
conversation = mode.get("session", str(uuid.uuid4()))
assert conversation not in {packet["packet_id"], packet["run_id"], packet["attempt_id"]}
unexpected = any(key.startswith(("ANTIGRAVITY_", "GOOGLE_", "GEMINI_", "CURSOR_", "ANTHROPIC_", "OPENAI_", "OLLAMA_", "GH_", "GITHUB_", "AWS_"))
    or key.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"} for key in os.environ)
assert not unexpected
observation = {"argv_flags": sys.argv[1:], "session_id": conversation, "attempt_id": packet["attempt_id"],
    "packet_digest": packet["digest"], "stdin_sha256": hashlib.sha256(raw).hexdigest(),
    "driver_config_digest": packet["bindings"]["driver_config_digest"],
    "provider_profile_digest": packet["bindings"]["provider_profile_digest"],
    "unexpected_environment_present": unexpected, "external_request": "not_sent", "qualification": "synthetic"}
fd = os.open(Path(__file__).with_suffix(".invocations.jsonl"), os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
with os.fdopen(fd, "w") as stream:
    stream.write(json.dumps(observation) + "\n")
print(json.dumps({"type": "init", "conversation_id": conversation, "model": "fixture-agy-model",
    "tools": ["write_file"], "permission_mode": "request-review", "cwd": str(Path.cwd().resolve()),
    "json_schema": result_schema, "agent": "fixture-agent"}), flush=True)
if mode["mode"] == "stderr":
    print(mode["diagnostic"], file=sys.stderr, flush=True)
deadline = time.monotonic() + 15
while Path(__file__).with_suffix(".hold").exists() and not Path(__file__).with_suffix(".release").exists() and time.monotonic() < deadline:
    time.sleep(0.02)
path = packet["scope"]["files"][0]
step = {"index": 7, "kind": "tool", "status": "ACTIVE", "tool": "write_file", "tool_info": {
    "name": "write_file", "parameters": {"path": path}, "error": None, "permission_denied": False}}
print(json.dumps({"type": "step_update", "conversation_id": conversation, "step": step}), flush=True)
target = Path(path)
if mode["mode"] != "no_edit":
    target.write_text(target.read_text().replace("a - b", "a + b"))
step["status"] = "DONE"
if mode["mode"] == "tool_denial":
    step["tool_info"]["permission_denied"] = True
step["usage"] = {"input_tokens": 100, "output_tokens": 20}
print(json.dumps({"type": "step_update", "conversation_id": conversation, "step": step}), flush=True)
worker = {"kind": "worker_result", "schema_version": "2.5", "extensions": {}, "result_id": str(uuid.uuid4()),
    "packet_id": packet["packet_id"], "packet_digest": packet["digest"], "run_id": packet["run_id"],
    "attempt_id": packet["attempt_id"], "spec_digest": packet["spec_digest"],
    "driver_config_digest": packet["bindings"]["driver_config_digest"],
    "provider_profile_digest": packet["bindings"]["provider_profile_digest"],
    "status": "completed", "changed_files": [{"path": path, "operation": "modify"}], "command_claims": [],
    "summary": mode.get("summary", "Synthetic Antigravity edit; independent checks remain required."),
    "blockers": [], "deviations": [], "residual_risks": [], "qualification": "synthetic"}
if mode["mode"] == "scope_claim_mismatch":
    worker["changed_files"] = []
print(json.dumps({"type": "result", "conversation_id": conversation, "status": "SUCCESS", "num_turns": 1,
    "structured_output": worker, "usage": {"input_tokens": 110, "output_tokens": 25, "total_tokens": 135}}), flush=True)
if mode["mode"] == "nonzero":
    raise SystemExit(1)
