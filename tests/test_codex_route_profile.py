"""Explicit route projections and bounded synthetic decoding; no native I/O."""
import copy
import json
import unittest

from taskalong.errors import TaskAlongError
from taskalong.local_provider_adapters import normalize_configuration, adapter_invocation, decoder, capabilities
from taskalong.validation import canonical_bytes, digest
from test_local_provider_adapters import configuration, binding, descriptor, wire, PROPOSAL


def route_profile(backend="native-chatgpt"):
    value = configuration() | {"format":"configured-provider-profile/5", "native_roots":{},
        "route":{"format":"codex-route/1", "backend":backend, "auth_mode":"existing-native-account",
            "base_url":"https://chatgpt.com/backend-api/codex" if backend == "native-chatgpt" else "http://127.0.0.1:11434/api/codex/v1"}}
    value["adapter_configuration"]["executable"]["version"] = "0.163.0"
    return value


def route_binding(config):
    return binding() | {"route_digest":digest(config["route"]), "remaining_budget":copy.deepcopy(config["limits"])}


class CodexRouteProfileTests(unittest.TestCase):
    def test_explicit_profile_is_closed_and_legacy_profiles_are_unchanged(self):
        for version in range(1,5):
            old = configuration() | {"format":f"configured-provider-profile/{version}"}
            if version >= 3:old["native_roots"] = {}
            before = copy.deepcopy(old)
            self.assertEqual(normalize_configuration("codex",old),before)
            with self.assertRaises(TaskAlongError):normalize_configuration("codex",old|{"route":route_profile()["route"]})
            self.assertEqual(old,before)
        cfg = route_profile()
        self.assertEqual(normalize_configuration("codex",cfg),cfg)
        for key in ("route","native_roots"):
            with self.assertRaises(TaskAlongError):normalize_configuration("codex",{k:v for k,v in cfg.items() if k != key})
        for provider in ("antigravity","claude-code"):
            raw = configuration(provider)|{k:copy.deepcopy(cfg[k]) for k in ("format","route","native_roots")}
            with self.assertRaises(TaskAlongError):normalize_configuration(provider,raw)

    def test_route_versions_bind_native_and_node_client_descriptors(self):
        cfg = route_profile()
        for version in ("0.162.0","synthetic","0.163.1"):
            value = copy.deepcopy(cfg);value["adapter_configuration"]["executable"]["version"] = version
            with self.assertRaises(TaskAlongError):normalize_configuration("codex",value)
        entry = copy.deepcopy(cfg["adapter_configuration"]["executable"])
        native = descriptor("/synthetic/native-codex","c")|{"version":"codex-cli 0.163.0"}
        cfg["adapter_configuration"]["runtime_closure"] = {"kind":"node",
            "node":descriptor("/synthetic/node","b"),"entrypoint":entry,"native_binary":native}
        self.assertEqual(normalize_configuration("codex",cfg),cfg)
        cfg["adapter_configuration"]["runtime_closure"]["native_binary"]["version"] = "future"
        with self.assertRaises(TaskAlongError):normalize_configuration("codex",cfg)

    def test_native_and_proxy_routes_preserve_context_and_protective_flags(self):
        for backend in ("native-chatgpt","existing-ollama-proxy"):
            cfg = route_profile(backend);bound = route_binding(cfg)
            before = copy.deepcopy((cfg,bound))
            invocation = adapter_invocation(cfg,bound,b"Synthetic public prompt.\n")
            argv = invocation["argv"]
            self.assertIn('openai_base_url='+json.dumps(cfg["route"]["base_url"]),argv)
            self.assertIn('model_provider="openai"',argv)
            self.assertEqual(argv[argv.index("--sandbox")+1],"read-only")
            self.assertIn('approval_policy="never"',argv)
            self.assertNotIn("--ignore-user-config",argv)
            self.assertNotIn("--skip-git-repo-check",argv)
            self.assertFalse(any("forced_login_method" in arg for arg in argv))
            self.assertEqual(invocation["env_overrides"],{})
            self.assertEqual((cfg,bound),before)
            caps = capabilities(cfg)
            self.assertEqual(caps["authenticated_account"],"unknown")
            self.assertEqual(caps["inference_origin"],"unqualified")

    def test_explicit_route_binding_cannot_be_omitted_or_swapped(self):
        cfg = route_profile();bound = route_binding(cfg)
        for bad in (None,"0"*64,digest(route_profile("existing-ollama-proxy")["route"])):
            with self.assertRaises(TaskAlongError):adapter_invocation(cfg,bound|{"route_digest":bad},b"Public.\n")
            with self.assertRaises(TaskAlongError):decoder(cfg,bound|{"route_digest":bad},cfg["limits"])

    def test_profile_five_retains_extended_finite_caps_and_decodes_proposals(self):
        cfg = route_profile()
        cfg["limits"].update(attempt_seconds=1440,max_output_bytes=67108864,
            max_record_bytes=16777216,max_proposal_bytes=1048576,max_protocol_records=131072)
        self.assertEqual(normalize_configuration("codex",cfg),cfg)
        bound = route_binding(cfg);stream = decoder(cfg,bound,cfg["limits"])
        stream.feed("stdout",wire({"type":"thread.started","thread_id":"synthetic-session"},{"type":"turn.completed"}))
        stream.feed("result",canonical_bytes(PROPOSAL))
        observed = stream.finish(0)
        self.assertEqual(observed["terminal_status"],"completed")
        self.assertEqual(observed["structured_result"],PROPOSAL)
        for key,value in (("attempt_seconds",1441),("max_output_bytes",67108865),
                          ("max_record_bytes",16777217),("max_proposal_bytes",1048577),
                          ("max_protocol_records",131073)):
            with self.subTest(key=key),self.assertRaises(TaskAlongError):
                normalize_configuration("codex",cfg|{"limits":cfg["limits"]|{key:value}})
