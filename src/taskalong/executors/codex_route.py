"""Pure, explicit per-run Codex routing; never authentication or dispatch proof.

The existing-native-account label describes the requested authentication path.
This module does not inspect credentials, discover servers, modify configuration,
invoke a client, or establish the account/inference identity behind an endpoint.
"""
from __future__ import annotations

import re

from ..errors import TaskAlongError

SUPPORTED_CLIENT_VERSIONS = frozenset({"0.163.0", "codex-cli 0.163.0"})
_FIELDS = frozenset({"format", "backend", "base_url", "auth_mode"})
_NATIVE = "https://chatgpt.com/backend-api/codex"
_PROXY = re.compile(r"http://127\.0\.0\.1:([1-9][0-9]{0,4})/api/codex/v1")


def _invalid():
    raise TaskAlongError("codex_route_invalid",
                        "Select an explicit supported Codex route without credentials or extra options.",
                        exit_code=3, effect_outcome="not_sent")


def normalize_route(raw):
    """Return a fresh closed JSON object; accept only canonical supported URLs."""
    if (type(raw) is not dict or len(raw) != len(_FIELDS) or any(type(key) is not str for key in raw)
            or set(raw) != _FIELDS or any(type(value) is not str for value in raw.values())):
        _invalid()
    if raw["format"] != "codex-route/1" or raw["auth_mode"] != "existing-native-account":
        _invalid()
    backend, url = raw["backend"], raw["base_url"]
    if backend == "native-chatgpt":
        if url != _NATIVE:
            _invalid()
    elif backend == "existing-ollama-proxy":
        match = _PROXY.fullmatch(url)
        if match is None or int(match[1]) > 65535:
            _invalid()
    else:
        _invalid()
    return {"format": "codex-route/1", "backend": backend,
            "base_url": url, "auth_mode": "existing-native-account"}


def route_overrides(route):
    """Return immutable alternating -c/TOML arguments, revalidating every input.

    The provider remains openai. No auth selectors, keys, environment settings,
    --oss transport substitution, or persisted/global configuration are emitted.
    Canonical URL validation excludes all TOML quoting/escape characters.
    """
    route = normalize_route(route)
    values = ("-c", 'model_provider="openai"',
              "-c", 'openai_base_url="' + route["base_url"] + '"')
    if route["backend"] == "native-chatgpt":
        values += ("-c", 'chatgpt_base_url="https://chatgpt.com/backend-api/"')
    return values
