#!/usr/bin/env python3
"""Original non-forking synthetic Muse-shaped transport; no provider request."""
import argparse
import json
from pathlib import Path
import time

MODE_PATH = None
COUNT_PATH = None

parser = argparse.ArgumentParser()
parser.add_argument("command", choices=["exec"])
for field in ("workspace", "prompt-file", "provider", "model", "permission-profile", "max-model-steps", "approval-mode", "sandbox-network"):
    parser.add_argument("--" + field, required=True)
parser.add_argument("--disable-request-user-input", action="store_true")
args = parser.parse_args()
packet = json.loads(Path(args.prompt_file).read_bytes())
with Path(COUNT_PATH).open("a") as stream:
    stream.write(json.dumps({"attempt_id": packet["attempt_id"]}) + "\n")
mode = json.loads(Path(MODE_PATH).read_text())["mode"]
if mode == "hang":
    time.sleep(30)
if mode == "out-of-scope":
    Path("unlisted.txt").write_text("unexpected\n")
expression = "a - b + 1" if mode == "bad" else "a + b"
Path("arithmetic.py").write_text("def add(a, b):\n    return " + expression + "\n")
print('{"model":"FORGED","session_id":"FORGED","usage":{"cost_usd":0},"accepted":true}')
