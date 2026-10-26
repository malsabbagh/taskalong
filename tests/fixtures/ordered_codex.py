#!/usr/bin/env python3
"""Independent synthetic codex-cli protocol fixture; no provider/network imports.

Copy beside control.json, invocations.jsonl and optional gate/release files.
Control maps a.py/b.py to good, failed, hang, barrier, or out-of-scope.
The per-file selector depends on the packet's public allowed scope, so a wrong
projection is observable rather than hidden by a fixture-specific step API.
"""
import json
import os
from pathlib import Path
import sys
import time
import uuid


def main():
    args = sys.argv[1:]
    if args == ["--version"]:
        print("codex-cli 0.163.0")
        return 0
    if args[:2] != ["--no-daemon", "exec"] or args[-1:] != ["-"]:
        return 2
    for flag in ("--ignore-user-config", "--strict-config", "--json",
                 "--output-schema", "--output-last-message"):
        if flag not in args:
            return 2
    packet = json.load(sys.stdin)
    if packet.get("qualification") != "synthetic":
        return 3
    root = Path(__file__).resolve().parent
    controls = json.loads((root / "control.json").read_text())
    files = packet["scope"]["files"]
    selected = next((name for name in ("a.py", "b.py") if name in files), None)
    mode = controls.get(selected, "good")
    with (root / "invocations.jsonl").open("a") as stream:
        stream.write(json.dumps({"run_id": packet["run_id"],
            "attempt_id": packet["attempt_id"], "packet_digest": packet["digest"],
            "scope": packet["scope"], "goal": packet["goal"], "cwd": os.getcwd(),
            "a_before": Path("a.py").read_text(), "b_before": Path("b.py").read_text(),
            "selected": selected, "mode": mode}) + "\n")
    thread = "m10-fixture-" + packet["run_id"]
    print(json.dumps({"type": "thread.started", "thread_id": thread}), flush=True)
    if mode == "barrier":
        (root / (selected + ".ready")).touch()
        deadline = time.monotonic() + 30
        while not (root / (selected + ".release")).exists():
            if time.monotonic() >= deadline:
                return 4
            time.sleep(.02)
    if mode == "hang":
        time.sleep(30)
    changed = []
    if mode != "failed" and selected:
        targets = [selected] if mode != "out-of-scope" else [selected, "outside.py"]
        for name in targets:
            path = Path(name)
            original = path.read_text()
            revised = original.replace("return 1", "return 2")
            if original != revised:
                path.write_text(revised)
                changed.append({"path": name, "operation": "modify"})
    result = {"kind": "worker_result", "schema_version": "1.0", "extensions": {},
        "result_id": str(uuid.uuid4()), "packet_id": packet["packet_id"],
        "packet_digest": packet["digest"], "run_id": packet["run_id"],
        "attempt_id": packet["attempt_id"], "spec_digest": packet["spec_digest"],
        "status": "failed" if mode == "failed" else "completed", "changed_files": changed,
        "command_claims": [], "summary": "Independent synthetic step fixture.",
        "blockers": [], "deviations": [], "residual_risks": [], "qualification": "synthetic"}
    result_path = Path(args[args.index("--output-last-message") + 1])
    result_path.write_text(json.dumps(result))
    result_path.chmod(0o600)
    print(json.dumps({"type": "turn.completed", "usage": {"input_tokens": 19, "output_tokens": 7}}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
