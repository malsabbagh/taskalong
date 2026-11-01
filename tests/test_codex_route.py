"""Pure synthetic route metadata; no Codex, account, server or filesystem I/O."""
import json
import os
import socket
import subprocess
import tomllib
import unittest
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong.executors.codex_route import (SUPPORTED_CLIENT_VERSIONS,
                                            normalize_route, route_overrides)


def route(backend="native-chatgpt", url="https://chatgpt.com/backend-api/codex"):
    return {"format": "codex-route/1", "backend": backend, "base_url": url,
            "auth_mode": "existing-native-account"}


class CodexRouteTests(unittest.TestCase):
    def invalid(self, value):
        for function in (normalize_route, route_overrides):
            with self.subTest(function=function.__name__, value=value), self.assertRaises(TaskAlongError) as error:
                function(value)
            self.assertEqual(error.exception.code, "codex_route_invalid")
            self.assertEqual(error.exception.exit_code, 3)
            self.assertEqual(error.exception.effect_outcome, "not_sent")

    def test_native_exact_overrides_and_toml_values(self):
        value = route_overrides(route())
        self.assertEqual(value, ("-c", 'model_provider="openai"',
                                "-c", 'openai_base_url="https://chatgpt.com/backend-api/codex"',
                                "-c", 'chatgpt_base_url="https://chatgpt.com/backend-api/"'))
        self.assertEqual(tomllib.loads("\n".join(value[1::2])), {
            "model_provider": "openai", "openai_base_url": "https://chatgpt.com/backend-api/codex",
            "chatgpt_base_url": "https://chatgpt.com/backend-api/"})

    def test_proxy_exact_overrides_and_no_native_ancillary_override(self):
        selected = route("existing-ollama-proxy", "http://127.0.0.1:11434/api/codex/v1")
        value = route_overrides(selected)
        self.assertEqual(value, ("-c", 'model_provider="openai"',
                                "-c", 'openai_base_url="http://127.0.0.1:11434/api/codex/v1"'))
        self.assertEqual(tomllib.loads("\n".join(value[1::2])), {
            "model_provider": "openai", "openai_base_url": selected["base_url"]})

    def test_proxy_port_boundaries(self):
        for port in (1, 9, 80, 11434, 65535):
            selected = route("existing-ollama-proxy", f"http://127.0.0.1:{port}/api/codex/v1")
            self.assertEqual(normalize_route(selected), selected)
        for port in ("0", "00", "01", "011434", "65536", "99999", "100000", "-1", "+1", "1.0", "１", "", "1 "):
            self.invalid(route("existing-ollama-proxy", f"http://127.0.0.1:{port}/api/codex/v1"))

    def test_native_url_is_exact(self):
        for url in ("http://chatgpt.com/backend-api/codex", "https://chatgpt.com:443/backend-api/codex",
                    "https://CHATGPT.COM/backend-api/codex", "https://chatgpt.com/backend-api/codex/",
                    "https://chatgpt.com/backend-api/", "https://api.openai.com/v1",
                    "https://chatgpt.com/backend-api/%63odex", "https://chatgpt.com/backend-api/a/../codex",
                    "https://user@chatgpt.com/backend-api/codex", "https://chatgpt.com/backend-api/codex?",
                    "https://chatgpt.com/backend-api/codex#", "https://chatgpt.com/backend-api/codex\n"):
            self.invalid(route(url=url))

    def test_proxy_rejects_host_aliases_credentials_and_other_transports(self):
        for origin in ("http://localhost:11434", "http://127.1:11434", "http://2130706433:11434",
                       "http://127.0.0.2:11434", "http://127.0.0.1.:11434", "http://[::1]:11434",
                       "http://0x7f000001:11434", "http://127.000.000.001:11434",
                       "https://127.0.0.1:11434", "HTTP://127.0.0.1:11434", "http://external.invalid:11434",
                       "http://user:password@127.0.0.1:11434", "http://127.0.0.1@external.invalid:11434"):
            self.invalid(route("existing-ollama-proxy", origin + "/api/codex/v1"))

    def test_proxy_rejects_paths_queries_fragments_escaping_and_toml_injection(self):
        prefix = "http://127.0.0.1:11434"
        for path in ("", "/", "/v1", "/api/codex/v1/", "/api//codex/v1", "/api/codex/./v1",
                     "/api/codex/x/../v1", "/api/codex/%76%31", "/api/codex/v1?", "/api/codex/v1?a=1",
                     "/api/codex/v1#", "/api/codex/v1#fragment", "/api/codex/v1%00", "/api/codex/v1\\",
                     '/api/codex/v1"\nforced_login_method="api"', "/api/codex/v1\r", "/api/codex/v1\x00"):
            self.invalid(route("existing-ollama-proxy", prefix + path))

    def test_closed_fields_and_authentication_options(self):
        self.invalid(None)
        self.invalid([])
        for field in route():
            value = route()
            del value[field]
            self.invalid(value)
        for field in ("api_key", "token", "headers", "env", "forced_login_method", "auth", "extra_args", "config"):
            self.invalid({**route(), field: "synthetic-extra"})
        self.invalid({**route(), 7: "non-JSON key"})

    def test_all_values_require_exact_strings(self):
        class StringSubclass(str):
            pass
        for field in route():
            for value in (None, True, False, 1, 1.0, {}, [], StringSubclass(route()[field])):
                self.invalid({**route(), field: value})
        class DictSubclass(dict):
            pass
        self.invalid(DictSubclass(route()))

    def test_fixed_format_backend_and_descriptive_auth_label(self):
        for field, values in (("format", ("codex-route/2", "codex-route/01", "")),
                              ("backend", ("openai", "ollama", "native-chatgpt ", "--oss")),
                              ("auth_mode", ("api-key", "chatgpt", "existing-account", "verified-native-account"))):
            for value in values:
                self.invalid({**route(), field: value})
        self.invalid(route("native-chatgpt", "http://127.0.0.1:11434/api/codex/v1"))
        self.invalid(route("existing-ollama-proxy", "https://chatgpt.com/backend-api/codex"))
        # The closed object contains no invented observed/verified account field.
        self.assertEqual(set(normalize_route(route())), {"format", "backend", "base_url", "auth_mode"})

    def test_normalized_route_is_fresh_json_and_does_not_mutate_input(self):
        original = route()
        first, second = normalize_route(original), normalize_route(original)
        self.assertEqual(json.loads(json.dumps(first)), original)
        self.assertIsNot(first, original)
        self.assertIsNot(first, second)
        first["base_url"] = "changed-output"
        self.assertEqual(original, route())
        self.assertEqual(second, original)

    def test_overrides_are_immutable_and_revalidate_mutated_objects(self):
        selected = normalize_route(route())
        flags = route_overrides(selected)
        self.assertIs(type(flags), tuple)
        self.assertTrue(all(type(value) is str for value in flags))
        self.assertEqual(flags[::2], ("-c",) * (len(flags) // 2))
        selected["base_url"] = 'https://injected.invalid/"'
        self.assertEqual(flags[3], 'openai_base_url="https://chatgpt.com/backend-api/codex"')
        self.invalid(selected)
        with self.assertRaises(TypeError):
            flags[0] = "changed"

    def test_supported_versions_are_exact_and_immutable(self):
        self.assertIs(type(SUPPORTED_CLIENT_VERSIONS), frozenset)
        self.assertEqual(SUPPORTED_CLIENT_VERSIONS, {"0.163.0", "codex-cli 0.163.0"})
        self.assertNotIn("0.164.0", SUPPORTED_CLIENT_VERSIONS)
        self.assertNotIn("codex-cli 0.163.0-dev", SUPPORTED_CLIENT_VERSIONS)

    def test_no_io_client_server_auth_or_environment_mutation(self):
        fake_environment = {"SYNTHETIC_ACCOUNT_MARKER": "unchanged"}
        with patch("builtins.open", side_effect=AssertionError("unexpected filesystem read")), \
             patch.object(os, "open", side_effect=AssertionError("unexpected descriptor")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("unexpected client")), \
             patch.object(socket, "socket", side_effect=AssertionError("unexpected connection")), \
             patch.object(os, "environ", fake_environment):
            for selected in (route(), route("existing-ollama-proxy", "http://127.0.0.1:11434/api/codex/v1")):
                flags = route_overrides(normalize_route(selected))
                parsed = tomllib.loads("\n".join(flags[1::2]))
                self.assertLessEqual(set(parsed), {"model_provider", "openai_base_url", "chatgpt_base_url"})
                self.assertEqual(parsed["model_provider"], "openai")
                self.assertNotIn("--oss", flags)
                self.assertNotIn("--local-provider", flags)
                self.assertNotIn("forced_login_method", parsed)
            self.assertEqual(fake_environment, {"SYNTHETIC_ACCOUNT_MARKER": "unchanged"})


if __name__ == "__main__":
    unittest.main()
