#!/usr/bin/env python3
"""Synthetic subprocess fixture. Never distributed as a runtime executor."""
import json
import os
from pathlib import Path
import signal
import sys
import time
import uuid


def main():
    args = sys.argv[1:]
    if args == ["--version"]:
        print("codex-cli 0.163.0")
        return 0
    if args[:2] != ["--no-daemon", "exec"]:
        return 2
    if any(flag not in args for flag in ("--ignore-user-config", "--strict-config", "--json", "--output-schema", "--output-last-message")):
        return 2
    if args[-1] != "-":
        return 2
    packet = json.load(sys.stdin)
    if packet.get("qualification") != "synthetic":
        return 3
    result_path = Path(args[args.index("--output-last-message") + 1])
    mode = packet["goal"].split()[0].removeprefix("fixture:") if packet["goal"].startswith("fixture:") else "good"
    resumed = len(args) > 2 and args[2] == "resume"
    thread = args[3] if resumed else "fixture-" + packet["run_id"]
    if mode == "wrong-resume-thread":
        thread = "fixture-foreign-" + str(uuid.uuid4())
    log = Path(__file__).with_name("fake-codex-invocations.jsonl")
    with log.open("a") as stream:
        stream.write(json.dumps({"run_id": packet["run_id"], "attempt_id": packet["attempt_id"], "mode": "native_resume" if resumed else "start"}) + "\n")
    print(json.dumps({"type": "thread.started", "thread_id": thread}), flush=True)
    if mode in ("hang", "ignore-signals"):
        if mode == "ignore-signals":
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(50)
    if mode == "malformed-jsonl":
        print('{"type":"turn.completed","type":"error"}', flush=True)
    elif mode == "invalid-utf8":
        sys.stdout.buffer.write(b'\xff\n')
        sys.stdout.buffer.flush()
    elif mode == "unknown-event":
        print(json.dumps({"type": "synthetic.future.event", "untrusted": "never public event payload"}), flush=True)
    if mode == "stderr-flood":
        sys.stderr.buffer.write(b"x" * 2_000_000)
        sys.stderr.flush()
    changed = []
    if mode not in ("blocked", "failed", "missing-terminal", "nonzero"):
        for path in packet["scope"]["files"]:
            if path.endswith("/"):
                continue
            target = Path(path)
            if target.is_file():
                before = target.read_text()
                after = before.replace("return a - b", "return a + b").replace("return 1", "return 2")
                if after != before:
                    target.write_text(after)
                    changed.append({"path": path, "operation": "modify"})
                    break
    result = {"kind": "worker_result", "schema_version": "1.0", "extensions": {},
        "result_id": str(uuid.uuid4()), "packet_id": packet["packet_id"],
        "packet_digest": packet["digest"], "run_id": packet["run_id"],
        "attempt_id": packet["attempt_id"], "spec_digest": packet["spec_digest"],
        "status": mode if mode in ("blocked", "failed") else "completed", "changed_files": changed,
        "command_claims": [], "summary": "Synthetic fixture handoff; independent checks are still required.",
        "blockers": [], "deviations": [], "residual_risks": [], "qualification": "synthetic"}
    if mode == "wrong-packet": result["packet_digest"] = "f" * 64
    if mode == "self-acceptance": result["acceptance"] = {"decision": "accepted"}
    if mode == "oversized-result": result["summary"] = "x" * 1_100_000
    result_path.write_text(json.dumps(result))
    result_path.chmod(0o600)
    if mode == "duplicate-result" or mode.endswith("usage-invalid-result"):
        content = result_path.read_text()
        result_path.write_text(content[:-1] + ',"status":"completed"}')
    if mode != "missing-terminal":
        usage = {} if mode.startswith("unknown-usage") else {"input_tokens": 19, "output_tokens": 7}
        if mode.startswith("max-usage"):
            usage = {"input_tokens": 9007199254740991, "output_tokens": 9007199254740991}
        final = json.dumps({"type": "turn.completed", "usage": usage})
        print(final, end="" if mode == "unflushed-terminal" else "\n", flush=True)
    return 1 if mode == "nonzero" else 0


if __name__ == "__main__":
    raise SystemExit(main())
