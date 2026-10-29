"""Closed production qualification boundary; no caller-supplied grants.

Local file identities and imported records cannot establish effective execution.
The installed Darwin/Muse tuple has no supported authenticated observer for the
required isolation, aggregate inference, account/allowance and full lifetime.
This boundary deliberately starts no CLI, credential discovery or provider call.
"""
import sys
from .errors import TaskAlongError
from .validation import canonical_bytes, digest

REASONS = ("muse_effective_closure_unqualified", "muse_filesystem_network_unqualified",
    "muse_account_allowance_unqualified", "muse_aggregate_inference_unqualified",
    "muse_lifetime_unqualified", "muse_independent_checker_unqualified")


def observe(subject):
    canonical_bytes(subject)
    unsupported = [{"boundary": "aggregate_inference", "supported": False,
        "detail": "The pinned 1.4.10 exec contract has model-step bounds but no supported aggregate observer/judge/subagent bound."},
        {"boundary": "effective_containment", "supported": False,
        "detail": "Requested CLI flags and local input hashes are not an OS-enforced filesystem/network profile."},
        {"boundary": "account_allowance", "supported": False,
        "detail": "No authenticated existing-account endpoint/model/included-allowance observation is available."}]
    if sys.platform == "darwin":
        unsupported.append({"boundary": "owned_native_fork_lifetime", "supported": False,
            "detail": "The existing Darwin kqueue owner proves only non-forking lifetimes; native forks remain quarantined."})
    return {"format": "muse-production-runtime-observation/1", "subject_digest": digest(subject),
        "authenticated_runtime_observed": False, "effective_closure_qualified": False,
        "filesystem_network_qualified": False, "account_allowance_qualified": False,
        "aggregate_inference_qualified": False, "process_lifetime_qualified": False,
        "independent_checker_qualified": False, "production_dispatch_allowed": False,
        "acceptance_allowed": False, "reason_codes": list(REASONS), "host_platform": sys.platform,
        "unsupported_boundaries": unsupported}


def require(subject):
    observation = observe(subject)
    raise TaskAlongError("muse_runtime_unqualified",
        "Production Muse needs authenticated runtime, containment, account, aggregate inference, lifetime and independent-checker evidence.",
        exit_code=3, effect_outcome="not_sent", recovery=[{"action": "qualify_exact_runtime_subject",
            "subject_digest": observation["subject_digest"], "reason_codes": observation["reason_codes"],
            "unsupported_boundaries": observation["unsupported_boundaries"]}])
