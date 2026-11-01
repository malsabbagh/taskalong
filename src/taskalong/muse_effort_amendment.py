"""Pure Max-to-High derivation; never State, admission or dispatch authority.

The owner must authenticate and check the original configuration before calling
this helper. Digests establish document integrity, not the truth of an original
configuration supplied by an untrusted caller. No global pointer is changed.
"""
from __future__ import annotations

import re

from . import supervised_pilot as pilot
from .errors import TaskAlongError
from .validation import canonical_bytes, digest, loads

FORMAT = "muse-effort-amendment/1"


def _fail():
    raise TaskAlongError("provider_successor_effort_amendment_invalid",
        "The explicit effort amendment requires the unchanged original Muse Max configuration and task, with High as the sole correction.",
        exit_code=3, effect_outcome="not_sent")


def derive(original_config, original_manifest, effort):
    """Return fresh (High configuration, High manifest, closed amendment).

    Only reasoning_effort and its dependent digests change. Account, model,
    context, source snapshots, task and finite budgets retain their original
    values. The existing wonder-full request alias is preserved verbatim.
    """
    try:
        if (type(effort) is not str or effort != "high"
                or type(original_config) is not dict or type(original_manifest) is not dict):
            _fail()
        config = loads(canonical_bytes(original_config))
        manifest = loads(canonical_bytes(original_manifest))
        if (config.get("format") != "local-muse-provider/6" or config.get("provider") != "muse"
                or config.get("reasoning_effort") != "max" or config.get("digest") != digest(config)
                or type(config.get("model")) is not str
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", config["model"]) is None):
            _fail()
        request = pilot._request(manifest.get("request"))
        expected, _ = pilot._manifest(request)
        if canonical_bytes(manifest) != canonical_bytes(expected):
            _fail()
        models = {config["model"]}
        if config["model"] == "muse-wonder-full-1.0":
            models.add("wonder-full")
        if request["provider"] != "muse" or request["model"] not in models or request["reasoning_effort"] != "max":
            _fail()
        old_configuration, old_bundle = config["digest"], manifest["digest"]
        config["reasoning_effort"] = "high"
        config["digest"] = digest(config)
        request["reasoning_effort"] = "high"
        manifest, _ = pilot._manifest(request)
        amendment = {"format": FORMAT, "from_effort": "max", "to_effort": "high",
            "original_configuration_digest": old_configuration, "configuration_digest": config["digest"],
            "original_bundle_digest": old_bundle, "bundle_digest": manifest["digest"]}
        amendment["digest"] = digest(amendment)
        # Return detached JSON trees, including nested configuration and files.
        return tuple(loads(canonical_bytes(value)) for value in (config, manifest, amendment))
    except (TaskAlongError, ValueError, TypeError, KeyError, AttributeError, UnicodeError,
            RecursionError, OverflowError):
        _fail()
