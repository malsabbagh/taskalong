#!/usr/bin/env python3
"""Original synthetic Claude-shaped fixture; no captured vendor implementation."""
import argparse
import json
import os
from pathlib import Path
import sys
import time
import subprocess
import uuid


parser = argparse.ArgumentParser()
parser.add_argument("--print", action="store_true")
parser.add_argument("--input-format", choices=["text"], required=True)
parser.add_argument("--output-format", choices=["stream-json"], required=True)
parser.add_argument("--verbose", action="store_true")
parser.add_argument("--json-schema", required=True)
parser.add_argument("--model", required=True)
parser.add_argument("--effort", required=True)
parser.add_argument("--session-id", required=True)
parser.add_argument("--no-session-persistence", action="store_true")
parser.add_argument("--permission-mode", choices=["default"], required=True)
parser.add_argument("--safe-mode", action="store_true")
parser.add_argument("--settings-sources", required=True)
parser.add_argument("--strict-mcp-config", action="store_true")
parser.add_argument("--mcp-config", required=True)
parser.add_argument("--tools", nargs="+", required=True)
parser.add_argument("--allowedTools", nargs="+", required=True)
args = parser.parse_args()
assert args.print and args.verbose and args.no_session_persistence and args.safe_mode and args.strict_mcp_config
assert args.tools == args.allowedTools == ["Edit"] and args.settings_sources == ""
assert json.loads(args.mcp_config) == {"mcpServers":{}}
assert json.loads(args.json_schema)["properties"]["schema_version"]["const"] == "2.3"
packet = json.loads(sys.stdin.buffer.read())
assert packet["session_id"] == packet["attempt_id"] == args.session_id
observed = {"model":args.model, "session_id":args.session_id,
    "credential_environment_present":any(key.startswith(("ANTHROPIC_", "OPENAI_", "OLLAMA_", "GH_", "GITHUB_", "AWS_")) for key in os.environ)}
descriptor = os.open(Path(__file__).with_suffix(".invocations.jsonl"), os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
with os.fdopen(descriptor, "w") as log:
    log.write(json.dumps(observed) + "\n")
mode_path = Path(__file__).with_suffix(".mode.json")
mode = json.loads(mode_path.read_text())["mode"] if mode_path.exists() else "good"
# Test-owned barriers self-expire, including when a test loses its supervisor.
deadline = time.monotonic() + 15
while Path(__file__).with_suffix(".hold").exists() and not Path(__file__).with_suffix(".release").exists() and time.monotonic() < deadline:
    time.sleep(0.02)
if mode == "hang":
    time.sleep(15)
if mode == "persistent-child":
    root = Path(__file__).parent
    child = ("import pathlib,time; root=pathlib.Path(" + repr(str(root)) + "); deadline=time.monotonic()+10\n"
             "while not (root/'child-release').exists() and time.monotonic()<deadline: time.sleep(.01)\n"
             "(root/'child-stopped').write_text('finished')")
    subprocess.Popen([sys.executable, "-c", child], start_new_session=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(json.dumps({"type":"system", "subtype":"init", "session_id":args.session_id,
                  "model":"foreign-model" if mode == "wrong-model" else args.model, "tools":["Edit"]}), flush=True)
target = Path(packet["scope"]["files"][0])
target.write_text(target.read_text().replace("a - b", "a + b"))
worker = {"kind":"worker_result", "schema_version":"2.3", "extensions":{}, "result_id":str(uuid.uuid4()),
    "packet_id":packet["packet_id"], "packet_digest":packet["digest"], "run_id":packet["run_id"],
    "attempt_id":packet["attempt_id"], "spec_digest":packet["spec_digest"],
    "driver_config_digest":packet["bindings"]["driver_config_digest"],
    "provider_profile_digest":packet["bindings"]["provider_profile_digest"], "session_id":args.session_id,
    "status":"completed", "changed_files":[{"path":str(target), "operation":"modify"}], "command_claims":[],
    "summary":"Synthetic edit; independent checks still required.", "blockers":[], "deviations":[],
    "residual_risks":[], "qualification":"synthetic"}
if mode in {"wrong-config", "wrong-provider"}:
    worker["driver_config_digest" if mode == "wrong-config" else "provider_profile_digest"] = "f" * 64
if mode == "wrong-session":
    worker["session_id"] = str(uuid.uuid4())
if mode == "stderr-flood":
    sys.stderr.buffer.write(b"x" * 2_000_000)
    sys.stderr.flush()
if mode == "missing-terminal":
    raise SystemExit(0)
if mode == "malformed-jsonl":
    print('{"type":"result","type":"result"}', flush=True)
    raise SystemExit(0)
terminal = {"type":"result", "subtype":"success", "is_error":False,
    "permission_denials":[{"tool_name":"Edit"}] if mode == "denied" else [],
    "session_id":args.session_id, "structured_output":worker, "usage":{"input_tokens":19,"output_tokens":7},
    "total_cost_usd":0.0000001}
if mode == "missing-denial-metadata":
    del terminal["permission_denials"]
if mode == "terminal-failure":
    terminal.update(subtype="error_during_execution", is_error=True)
if mode == "truncated-terminal":
    print(json.dumps(terminal), end="", flush=True)
    raise SystemExit(0)
print(json.dumps(terminal), flush=True)
if mode == "duplicate-terminal":
    print(json.dumps(terminal), flush=True)
raise SystemExit(1 if mode == "nonzero" else 0)
