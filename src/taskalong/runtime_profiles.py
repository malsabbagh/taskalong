"""Pure fixture provider routes; no discovery, networking or live authority.

Observations must come from an explicitly trusted fixture capture. These
readers establish bounded data identity only; current qualification and its
evidence linkage remain the core admission resolver's responsibility.
"""
from dataclasses import dataclass
import hashlib
import ipaddress
import re
from urllib.parse import urlsplit

from .bindings import ProviderProfile
from .contracts import JsonDocument
from .errors import TaskAlongError
from .validation import canonical_bytes, digest, loads, screen_sensitive


_SHA256 = re.compile(r"[a-f0-9]{64}")
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}")
_ID = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
FIXTURE_CLOUD_REFERENCE = "fixture-ollama-cloud"
_FIXTURE_CLOUD_TOKEN = "taskalong-fixture-ollama-cloud-1"  # Original non-secret fixture sentinel.
_OBSERVATION_FIELDS = frozenset({
    "kind", "schema_version", "provider_profile_digest", "endpoint",
    "requested_model", "resolved_model_digest", "model_origin",
    "server_available", "model_available", "tool_protocol", "result_schema_id",
    "external_effect", "managed_route_conflict", "qualification", "auth",
})
_PLAN_FIELDS = frozenset({
    "kind", "schema_version", "provider", "provider_profile_digest",
    "observation_digest", "endpoint", "model", "auth", "qualification",
    "external_request", "remote_cancellation", "cost_accounting", "native_resume",
})


def _refuse(code="provider_route_invalid"):
    raise TaskAlongError(code, "The provider route is outside the supported offline fixture projection.", exit_code=3)


def _matches(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def _endpoint(provider, endpoint):
    if type(endpoint) is not str or len(endpoint) > 2048:
        return False
    if provider == "ollama-cloud":
        return endpoint == "https://ollama.com"
    if provider != "ollama-local":
        return False
    try:
        parsed = urlsplit(endpoint)
        address = ipaddress.ip_address(parsed.hostname)
        host = f"[{address.compressed}]" if address.version == 6 else address.compressed
        return (address.is_loopback and parsed.scheme == "http" and parsed.port is not None
                and 0 < parsed.port <= 65535 and endpoint == f"http://{host}:{parsed.port}")
    except (ValueError, TypeError):
        return False


def _route_auth(provider):
    if provider == "ollama-local":
        return {"mode": "local-no-secret", "credential_ref": None}
    if provider == "ollama-cloud":
        return {"mode": "credential-ref", "credential_ref": FIXTURE_CLOUD_REFERENCE}
    return None


@dataclass(frozen=True, slots=True)
class _RouteRecord(JsonDocument):
    def __post_init__(self):
        _refuse()

    @property
    def digest(self):
        return digest(self.to_dict(), exclude_digest=False)


@dataclass(frozen=True, slots=True)
class FixtureRouteObservation(_RouteRecord):
    """Closed fixture measurement data, never a self-authorizing worker claim."""
    def __post_init__(self):
        value = loads(self._canonical, max_bytes=4096)
        screen_sensitive(value)
        auth = value.get("auth")
        if (set(value) != _OBSERVATION_FIELDS
                or value["kind"] != "ollama_fixture_route_observation" or value["schema_version"] != "1.0"
                or not _matches(value["provider_profile_digest"], _SHA256)
                or not _matches(value["resolved_model_digest"], _SHA256)
                or not _matches(value["requested_model"], _MODEL)
                or type(value["endpoint"]) is not str or not 1 <= len(value["endpoint"]) <= 2048
                or value["model_origin"] not in ("local", "cloud", "forwarded", "unknown")
                or any(value[key] is not None and type(value[key]) is not bool
                       for key in ("server_available", "model_available"))
                or type(value["managed_route_conflict"]) is not bool
                or value["qualification"] != "synthetic"
                or type(auth) is not dict or set(auth) != {"mode", "credential_ref", "token_present", "token_matched"}
                or auth["mode"] not in ("local-no-secret", "credential-ref")
                or auth["credential_ref"] is not None and not _matches(auth["credential_ref"], _ID)
                or any(auth[key] is not None and type(auth[key]) is not bool for key in ("token_present", "token_matched"))
                or value["external_effect"] not in ("none", "active", "unknown", "reported-complete")
                or value["tool_protocol"] != "fixture-edit/1"
                or value["result_schema_id"] != "urn:taskalong:schema:v2.3:worker-result"):
            _refuse()
        object.__setattr__(self, "_canonical", canonical_bytes(value))


@dataclass(frozen=True, slots=True)
class OllamaFixtureRoute(_RouteRecord):
    """Immutable launch description; no server request or remote receipt exists."""
    def __post_init__(self):
        value = loads(self._canonical, max_bytes=4096)
        screen_sensitive(value)
        model, auth = value.get("model"), value.get("auth")
        if (set(value) != _PLAN_FIELDS or value["kind"] != "ollama_fixture_route"
                or value["schema_version"] != "1.0" or value["provider"] not in ("ollama-local", "ollama-cloud")
                or not _matches(value["provider_profile_digest"], _SHA256)
                or not _matches(value["observation_digest"], _SHA256)
                or not _endpoint(value["provider"], value["endpoint"])
                or type(model) is not dict or set(model) != {"requested", "resolved_digest"}
                or not _matches(model["requested"], _MODEL) or not _matches(model["resolved_digest"], _SHA256)
                or auth != _route_auth(value["provider"])
                or value["qualification"] != "synthetic" or value["external_request"] != "not_sent"
                or value["remote_cancellation"] != "unsupported" or value["cost_accounting"] != "unknown"
                or value["native_resume"] is not False):
            _refuse()
        object.__setattr__(self, "_canonical", canonical_bytes(value))


def resolve_ollama_route(provider, observation):
    """Validate an explicit fixture snapshot without probing or enabling it."""
    if type(provider) is not ProviderProfile or type(observation) is not FixtureRouteObservation:
        _refuse()
    profile = ProviderProfile(provider.to_bytes()).to_dict()
    observed = FixtureRouteObservation(observation.to_bytes()).to_dict()
    if (profile["provider"] not in ("ollama-local", "ollama-cloud") or not _endpoint(profile["provider"], profile["endpoint"])
            or profile["effort"] is not None or profile["service_tier"] is not None
            or profile["auxiliary_routes"] or profile["auth"] != _route_auth(profile["provider"])
            or profile["provider"] == "ollama-local" and profile["model"]["requested"].lower().endswith(":cloud")):
        _refuse("provider_route_unsupported")
    if (observed["provider_profile_digest"] != provider.digest or observed["endpoint"] != profile["endpoint"]
            or observed["requested_model"] != profile["model"]["requested"]
            or observed["resolved_model_digest"] != profile["model"]["resolved_digest"]
            or observed["model_origin"] != ("local" if profile["provider"] == "ollama-local" else "cloud")
            or observed["server_available"] is not True
            or observed["model_available"] is not True or observed["external_effect"] != "none"
            or observed["managed_route_conflict"]
            or any(observed["auth"][key] != profile["auth"][key] for key in ("mode", "credential_ref"))
            or observed["auth"]["token_present"] is not True or observed["auth"]["token_matched"] is not True):
        _refuse("provider_route_unqualified")
    return OllamaFixtureRoute.from_dict({
        "kind": "ollama_fixture_route", "schema_version": "1.0", "provider": profile["provider"],
        "provider_profile_digest": provider.digest, "observation_digest": observation.digest,
        "endpoint": profile["endpoint"], "model": profile["model"], "auth": profile["auth"],
        "qualification": "synthetic", "external_request": "not_sent",
        "remote_cancellation": "unsupported", "cost_accounting": "unknown", "native_resume": False,
    })


def fixture_environment(route, *, credential_refs=None):
    """Construct fixture-only variables; inherited environment is never read."""
    if type(route) is not OllamaFixtureRoute:
        _refuse()
    plan = OllamaFixtureRoute(route.to_bytes()).to_dict()
    if plan["provider"] == "ollama-local":
        if credential_refs is not None and (type(credential_refs) is not dict or credential_refs):
            _refuse("fixture_credential_unresolved")
        token = "ollama"
    else:
        if type(credential_refs) is not dict or credential_refs != {FIXTURE_CLOUD_REFERENCE: _FIXTURE_CLOUD_TOKEN}:
            _refuse("fixture_credential_unresolved")
        token = _FIXTURE_CLOUD_TOKEN
    return {"ANTHROPIC_BASE_URL": plan["endpoint"], "ANTHROPIC_AUTH_TOKEN": token, "ANTHROPIC_API_KEY": ""}


def require_route_capture(start, lookup, observation, evidence):
    """Bind the leaf to two fresh core evaluations over the same snapshot.

    Invoke only on actual current evaluate() results and their immutable
    EvidenceStore. This performs no independent trust evaluation and supplies
    no votes missing from either mode. Pure route representability remains a
    separate prerequisite; the returned hashes are audit data, not authority.
    """
    from .qualification import Evaluation, EvidenceStore, QualificationDecision
    if (type(start) is not Evaluation or type(lookup) is not Evaluation
            or type(start.decision) is not QualificationDecision or type(lookup.decision) is not QualificationDecision
            or type(observation) is not FixtureRouteObservation or type(evidence) is not EvidenceStore):
        _refuse("provider_route_evidence_unqualified")
    first = QualificationDecision(start.decision.to_bytes()).to_dict()
    second = QualificationDecision(lookup.decision.to_bytes()).to_dict()
    leaf = FixtureRouteObservation(observation.to_bytes())
    facts = leaf.to_dict()
    if (not first["requirements_satisfied"] or not second["requirements_satisfied"]
            or first["mode"] != "start" or second["mode"] != "provider_lookup"
            or any(first[key] != second[key] for key in ("subject", "trust_policy_digest", "evaluated_at"))
            or second["subject"]["provider_profile_digest"] != facts["provider_profile_digest"]
            or second["subject"]["model_digest"] != facts["resolved_model_digest"]):
        _refuse("provider_route_evidence_unqualified")
    results = [item for item in second["capability_results"] if item["capability"] == "provider_lookup"]
    if len(results) != 1 or results[0]["outcome"] != "supported" or not results[0]["evidence_digests"]:
        _refuse("provider_route_evidence_unqualified")
    captured = leaf.to_bytes()
    expected_hash = hashlib.sha256(captured).hexdigest()
    for content_digest in results[0]["evidence_digests"]:
        raw = evidence.get(content_digest)
        if raw is None:
            _refuse("provider_route_evidence_unqualified")
        observed = loads(raw)
        if (observed.get("kind") != "qualification_observation" or observed.get("schema_version") != "2.1"
                or observed.get("mode") != "provider_lookup" or observed.get("capability") != "provider_lookup"
                or observed.get("subject") != second["subject"] or type(observed.get("capture_refs")) is not list):
            _refuse("provider_route_evidence_unqualified")
        matching = [ref for ref in observed["capture_refs"] if type(ref) is dict
                    and ref.get("sha256") == expected_hash and ref.get("size_bytes") == len(captured)
                    and ref.get("media_type") == "application/json"]
        if not matching or evidence.get(expected_hash) != captured:
            _refuse("provider_route_evidence_unqualified")
    return tuple(results[0]["evidence_digests"])
