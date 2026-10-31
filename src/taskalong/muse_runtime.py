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
    "muse_account_allowance_unqualified",
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
    budget=subject.get("budget", {})
    reasons=list(REASONS)
    if budget.get("hard_tokens") is not None or budget.get("hard_cost_usd") is not None:
        reasons.append("muse_hard_inference_budget_unsupported")
    return {"format": "muse-production-runtime-observation/1", "subject_digest": digest(subject),
        "authenticated_runtime_observed": False, "effective_closure_qualified": False,
        "filesystem_network_qualified": False, "account_allowance_qualified": False,
        "aggregate_inference_qualified": False, "process_lifetime_qualified": False,
        "independent_checker_qualified": False, "production_dispatch_allowed": False,
        "acceptance_allowed": False, "reason_codes": reasons, "host_platform": sys.platform,
        "unsupported_boundaries": unsupported,
        "usage_containment": {"local_invocation_limit":1,
            "local_attempt_seconds":budget.get("attempt_seconds"),
            "local_output_bytes":budget.get("max_output_bytes"),
            "main_model_steps":1,"aggregate_token_or_cost_cap_enforced":False,
            "remote_after_local_stop":"unknown; retain exposure and forbid redispatch",
            "absolute_vendor_cessation_guarantee_required":False,
            "whole_process_boundary_qualified":False}}


def require(subject):
    observation = observe(subject)
    raise TaskAlongError("muse_runtime_unqualified",
        "Production Muse needs a qualified whole-process boundary, effective containment, existing-account route and independent checker; remote exposure must remain held when usage is unknown.",
        exit_code=3, effect_outcome="not_sent", recovery=[{"action": "qualify_exact_runtime_subject",
            "subject_digest": observation["subject_digest"], "reason_codes": observation["reason_codes"],
            "unsupported_boundaries": observation["unsupported_boundaries"]}])
