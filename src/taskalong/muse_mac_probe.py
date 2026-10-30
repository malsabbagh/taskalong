"""Pinned native model-free MSP initialization. Never a live-admission grant.

The fixed request creates no session/turn and asks for no capabilities. The
native echo provider, restrictive host switches, fresh HOME/XDG and retained
foreground observations are separate from actual tool/isolation qualification.
"""
import json
import os
from pathlib import Path
import sys

from .errors import TaskAlongError
from .experimental_process import FOREGROUND_EXPERIMENT, run_foreground_experiment
from .muse_production import _observe_file
from .process import ProcessBoundaryError, minimal_environment
from .validation import canonical_bytes, digest, loads

BINARY_SHA256="11cc1ae887b4975bbbe1de7358ee9260a612444df9ce4dbfffa1dd785826dbcf"
SCHEMA_FINGERPRINT="sha256:5d3b43e5ccdb7dc4f5a32c380f5f2cde0f10e3059b93610afb2e73f73b1d914c"
ARGV=("serve","--provider","echo","--disable-write","--disable-shell")
REQUEST={"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "clientInfo":{"name":"taskalong_model_free","version":"1"},
    "capabilities":{"requestedCapabilities":[],"userInputDialogs":False,"experimentalApi":False}}}


def _error(code, *, effect_outcome="not_sent"):
    return TaskAlongError(code,"The model-free Muse observation is unavailable or inconsistent; preserve evidence without retrying or granting live admission.",exit_code=3,effect_outcome=effect_outcome)


def decode(raw):
    """Only interpret one exact initialization reply; never accept a grant."""
    if type(raw) is not bytes or len(raw)>131072 or len(raw.splitlines())!=1:
        raise _error("muse_probe_protocol_invalid")
    try:
        value=loads(raw)
        if (set(value)!={"jsonrpc","id","result"} or value["jsonrpc"]!="2.0"
                or type(value["id"]) is not int or value["id"]!=1):raise ValueError()
        result=value["result"]
        if (type(result) is not dict or result.get("grantedCapabilities")!=[]
                or type(result.get("grantedCapabilities")) is not list
                or result.get("experimentalApi") is not False
                or result.get("platformOs")!="macos" or result.get("platformFamily")!="unix"
                or result.get("serverInfo",{}).get("name")!="muse"
                or result.get("serverInfo",{}).get("version")!="1.4.10"
                or result.get("schema",{}).get("version")!=1
                or type(result.get("schema",{}).get("version")) is not int
                or result.get("schema",{}).get("fingerprint")!=SCHEMA_FINGERPRINT
                or result.get("sandboxAvailability") not in {"available","unavailable"}):raise ValueError()
        return {"server_version":"1.4.10","schema_fingerprint":SCHEMA_FINGERPRINT,"muse_home":result.get("museHome"),
            "granted_capabilities":[],"host_reports_sandbox":result["sandboxAvailability"],
            "shell_write_network_enforcement_demonstrated":False,
            "production_dispatch_allowed":False,"acceptance_allowed":False}
    except (KeyError,TypeError,ValueError,AttributeError,TaskAlongError):
        raise _error("muse_probe_protocol_invalid") from None


def _write(root,name,raw):
    fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())


def probe(*,executable,evidence_dir):
    if sys.platform!="darwin":raise _error("muse_probe_platform_unsupported")
    observed=_observe_file(executable,executable=True)
    if observed["sha256"]!=BINARY_SHA256:raise _error("muse_probe_binary_unsupported")
    root=Path(evidence_dir)
    if (not root.is_absolute() or str(root)!=evidence_dir or ".." in root.parts
            or any(p.is_symlink() for p in (root,*root.parents))):raise _error("muse_probe_evidence_invalid")
    if root.exists():raise _error("muse_probe_evidence_exists")
    launched=False
    try:
        root.mkdir(mode=0o700)
        for name in ("home","config","cache","data","state","tmp","workspace"):(root/name).mkdir(mode=0o700)
        env=minimal_environment()
        env.update(HOME=str(root/"home"),XDG_CONFIG_HOME=str(root/"config"),
            XDG_CACHE_HOME=str(root/"cache"),XDG_DATA_HOME=str(root/"data"),
            XDG_STATE_HOME=str(root/"state"),TMPDIR=str(root/"tmp"))
        request=canonical_bytes(REQUEST)+b"\n"
        _write(root,"request.json",request)
        # Recheck immediately before the fixed non-inference argv. No task
        # fields, credentials, profile changes or tool grants enter this call.
        if _observe_file(executable,executable=True)!=observed:raise _error("muse_probe_binary_changed")
        launched=True
        result=run_foreground_experiment([executable,*ARGV],mode=FOREGROUND_EXPERIMENT,
            cwd=root/"workspace",env=env,stdin=request,timeout_seconds=5,max_output_bytes=131072)
        _write(root,"stdout.bin",result.stdout);_write(root,"stderr.bin",result.stderr)
        receipt=result.to_dict();receipt.pop("stdout");receipt.pop("stderr")
        receipt=loads(json.dumps(receipt).encode("utf-8"))
        _write(root,"process.json",canonical_bytes(receipt))
        if _observe_file(executable,executable=True)!=observed:raise _error("muse_probe_binary_changed")
        if (type(result.root_exit_code) is not int or result.root_exit_code!=0
                or receipt.get("root_exit_observed") is not True
                or receipt.get("group_termination_confirmed") is not True
                or receipt.get("tracking_errors")!=[]
                or result.timed_out or result.output_limited or result.failure_code):
            raise _error("muse_probe_incomplete",effect_outcome="uncertain")
        try:
            interpretation=decode(result.stdout)
            if interpretation["muse_home"]!=str(root/"data/muse"):
                raise _error("muse_probe_context_changed")
        except TaskAlongError as exc:
            raise _error(exc.code,effect_outcome="uncertain") from None
        report={"format":"muse-mac-model-free-probe/1","binary":observed,
            "requested_provider":"echo","requested_host_controls":{"disable_shell":True,"disable_write":True},
            "sessions_created":0,"turns_requested":0,"capabilities_requested":[],
            "observation":interpretation,"process":receipt,"evidence_dir":str(root),
            "effective_real_account_context_observed":False,"remote_usage_settled":False,
            "production_dispatch_allowed":False,"acceptance_allowed":False,
            "notes":["Availability is this native host's report, not a tool enforcement canary.",
                "Fork and descendant uncertainty remain distinct from root/group exit.",
                "Each explicit probe needs a fresh directory; there is no automatic retry or escalation."]}
        report["digest"]=digest(report);_write(root,"report.json",canonical_bytes(report))
        return report
    except TaskAlongError as exc:
        if launched and exc.effect_outcome!="uncertain":
            raise _error(exc.code,effect_outcome="uncertain") from None
        raise
    except ProcessBoundaryError as exc:
        raise _error("muse_probe_lifecycle_failed",effect_outcome=exc.effect_outcome) from None
    except OSError:
        raise _error("muse_probe_io",effect_outcome="uncertain" if launched else "not_sent") from None
