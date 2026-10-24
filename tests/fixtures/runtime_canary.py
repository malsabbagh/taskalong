#!/usr/bin/env python3
"""Original finite host canary: generated files only, no vendor or network."""
import hashlib
import json
import os
import re
import signal
import stat
import sys
import time
import uuid


ENVIRONMENT_KEYS = {
    "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "SYSTEMROOT",
    "PYTHONDONTWRITEBYTECODE", "GIT_TERMINAL_PROMPT", "GIT_CONFIG_NOSYSTEM",
    "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "TMPDIR", "TMP", "TEMP",
    "__CF_USER_TEXT_ENCODING",
}
CASES = {"permitted-read", "permitted-write", "bounded-capture", "predispatch-tool-denial",
         "owned-completion", "closed-gate-cancel", "running-cancel"}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def object_pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def no_noninteger(_value):
    raise ValueError("unsupported number")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in CASES or not set(os.environ) <= ENVIRONMENT_KEYS:
        raise ValueError("invalid canary invocation")
    mode = sys.argv[1]
    raw = sys.stdin.buffer.read(4097)
    if len(raw) > 4096:
        raise ValueError("input limit")
    request = json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs,
                         parse_float=no_noninteger, parse_constant=no_noninteger)
    if (type(request) is not dict or set(request) != {"campaign_id", "nonce", "case_id", "payload"}
            or request["case_id"] != mode or type(request["campaign_id"]) is not str
            or str(uuid.UUID(request["campaign_id"])) != request["campaign_id"]
            or type(request["nonce"]) is not str or re.fullmatch(r"[a-f0-9]{64}", request["nonce"]) is None
            or type(request["payload"]) is not str or len(request["payload"].encode()) > 1024
            or raw != canonical(request) + b"\n"):
        raise ValueError("invalid canary request")
    invocation = {"campaign_id": request["campaign_id"], "case_id": mode,
                  "input_sha256": hashlib.sha256(raw).hexdigest()}
    fd = os.open("target-invocations.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "ab") as output:
        if not stat.S_ISREG(os.fstat(output.fileno()).st_mode) or os.fstat(output.fileno()).st_size > 4096:
            raise ValueError("invalid counter")
        output.write(canonical(invocation) + b"\n")
        output.flush()
        os.fsync(output.fileno())
    # These two target modes must never be released by a successful campaign.
    if mode in {"predispatch-tool-denial", "closed-gate-cancel"}:
        return 99
    effect = None
    if mode in {"permitted-read", "permitted-write"}:
        directory = os.open("workspace", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if mode == "permitted-read":
                fd = os.open("permitted.txt", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
                with os.fdopen(fd, "rb") as source:
                    if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                        raise ValueError("invalid input file")
                    data = source.read(1025)
                    if len(data) > 1024:
                        raise ValueError("input file limit")
            else:
                data = request["payload"].encode()
                fd = os.open("created.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
                with os.fdopen(fd, "wb") as target:
                    target.write(data)
                    target.flush()
                    os.fsync(target.fileno())
            effect = hashlib.sha256(data).hexdigest()
        finally:
            os.close(directory)
    if mode == "running-cancel":
        signal.signal(signal.SIGINT, lambda *_: sys.exit(130))
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    frame = {**invocation, "nonce": request["nonce"], "effect_sha256": effect,
             "event": "ready" if mode == "running-cancel" else "completed",
             "environment_keys": sorted(os.environ)}
    sys.stdout.buffer.write(canonical(frame) + b"\n")
    sys.stdout.buffer.flush()
    if mode == "bounded-capture":
        sys.stderr.buffer.write(b"Bearer " + request["nonce"].encode() + b"\n")
        sys.stderr.buffer.flush()
    if mode == "running-cancel":
        time.sleep(2)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        sys.stderr.buffer.write(b"canary_input_or_effect_failed\n")
        sys.exit(2)
