"""Offline Muse exec argument projection, with no launcher or registered driver.

The installed 1.4.10 help and official headless documentation establish these
flags, but do not establish the JSONL event schema. No event decoder, worker
result, session/model observation or live qualification is inferred here.
"""
from pathlib import PurePosixPath
import re

from ..errors import TaskAlongError


def project_plain_exec_argv(*, executable, build, workspace, prompt_file, model,
                            permission_profile, max_model_steps):
    """The documented plain exec surface, without assuming JSON event fields."""
    argv = project_exec_argv(executable=executable, build=build, workspace=workspace,
                             prompt_file=prompt_file, model=model,
                             permission_profile=permission_profile, max_model_steps=max_model_steps)
    return argv[:2] + argv[3:]  # Remove the single fixed --json switch.


def _refuse():
    raise TaskAlongError("muse_projection_unsupported", "Only the bounded observed Muse exec arguments are supported.",
                         exit_code=3, effect_outcome="not_sent")


def _path(value):
    if type(value) is not str or not 1 <= len(value) <= 4096 or "\x00" in value:
        _refuse()
    path = PurePosixPath(value)
    if not path.is_absolute() or len(path.parts) < 2 or ".." in path.parts or str(path) != value:
        _refuse()
    return value


def project_exec_argv(*, executable, build, workspace, prompt_file, model,
                      permission_profile, max_model_steps):
    """Return arguments as data; this does not inspect, authorize or launch Muse.

    A future admitted driver must independently verify the executable closure,
    effective policy, auth/model/plan route, lifetime and exact output contract.
    A model-step bound does not bound observer, judge or subagent spending.
    """
    if type(build) is not str or build != "1.4.10-R6427.1":
        _refuse()
    if type(max_model_steps) is not int or not 1 <= max_model_steps <= 8:
        _refuse()
    executable, workspace, prompt_file = map(_path, (executable, workspace, prompt_file))
    if (type(model) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", model)
            or type(permission_profile) is not str
            or not re.fullmatch(r"[A-Za-z0-9:][A-Za-z0-9._:/-]{0,255}", permission_profile)):
        _refuse()
    return (executable, "exec", "--json", "--provider", "meta",
            "--workspace", workspace, "--prompt-file", prompt_file,
            "--model", model, "--permission-profile", permission_profile,
            "--max-model-steps", str(max_model_steps), "--approval-mode", "untrusted",
            "--sandbox-network", "proxy-only", "--disable-request-user-input")
