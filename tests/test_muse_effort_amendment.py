"""Pure synthetic effort correction; no provider, account, process or State."""
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

from taskalong import muse_effort_amendment as amendment, supervised_pilot as pilot
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, digest


def originals(model="muse-wonder-full-1.0", request_model=None):
    config = {"format": "local-muse-provider/6", "provider": "muse", "experimental": True,
        "binary": {"path": "/synthetic/muse", "sha256": "a" * 64},
        "account_home": "/synthetic/account", "muse_home": "/synthetic/data/muse",
        "native_roots": {"XDG_DATA_HOME": "/synthetic/data"}, "model": model,
        "reasoning_effort": "max", "context": "include", "catalog_digest": None,
        "public_context_hashes": {}, "context_hashes": {"capability_policy": "b" * 64},
        "capture_profile": "megabyte-proposal", "attempt_seconds": 1440,
        "max_output_bytes": 67108864, "max_protocol_records": 131072, "max_proposal_bytes": 1048576}
    config["digest"] = digest(config)
    request = {"base_commit": "c" * 40, "task": "Propose a synthetic source change.", "provider": "muse",
        "model": model if request_model is None else request_model, "reasoning_effort": "max",
        "files": {"source.py": "original source\n", "new.py": None}}
    manifest, _ = pilot._manifest(pilot._request(request))
    return config, manifest


class MuseEffortAmendmentTests(unittest.TestCase):
    def invalid(self, config, manifest, effort="high"):
        with self.assertRaises(TaskAlongError) as caught:
            amendment.derive(config, manifest, effort)
        self.assertEqual(caught.exception.code, "provider_successor_effort_amendment_invalid")
        self.assertEqual(caught.exception.exit_code, 3)
        self.assertEqual(caught.exception.effect_outcome, "not_sent")

    def test_only_effort_and_dependent_digests_change(self):
        config, manifest = originals(); before = copy.deepcopy((config, manifest))
        high, bundle, link = amendment.derive(config, manifest, "high")
        self.assertEqual((config, manifest), before)
        self.assertEqual({k:v for k,v in high.items() if k not in {"reasoning_effort", "digest"}},
                         {k:v for k,v in config.items() if k not in {"reasoning_effort", "digest"}})
        self.assertEqual(high["reasoning_effort"], "high")
        request = copy.deepcopy(manifest["request"]); request["reasoning_effort"] = "high"
        self.assertEqual(bundle, pilot._manifest(request)[0])
        self.assertEqual(bundle["request"]["files"], manifest["request"]["files"])
        self.assertEqual(bundle["request"]["task"], manifest["request"]["task"])
        self.assertEqual(high["digest"], digest(high))
        self.assertNotEqual(high["digest"], config["digest"])
        self.assertNotEqual(bundle["digest"], manifest["digest"])
        self.assertEqual(link, {"format": "muse-effort-amendment/1", "from_effort": "max", "to_effort": "high",
            "original_configuration_digest": config["digest"], "configuration_digest": high["digest"],
            "original_bundle_digest": manifest["digest"], "bundle_digest": bundle["digest"], "digest": digest(link)})

    def test_outputs_are_detached_from_each_other_and_inputs(self):
        config, manifest = originals(); before = copy.deepcopy((config, manifest))
        first = amendment.derive(config, manifest, "high")
        second = amendment.derive(config, manifest, "high")
        self.assertEqual(first, second)
        first[0]["native_roots"]["XDG_DATA_HOME"] = "/changed"
        first[0]["context_hashes"].clear()
        first[1]["request"]["files"]["source.py"] = "changed\n"
        first[2]["to_effort"] = "max"
        self.assertEqual((config, manifest), before)
        self.assertEqual(second, amendment.derive(config, manifest, "high"))

    def test_existing_model_alias_is_preserved_without_substitution(self):
        for model, request_model in (("muse-wonder-full-1.0", "wonder-full"),
                                     ("wonder-full", "wonder-full"), ("synthetic-model", "synthetic-model")):
            config, manifest = originals(model, request_model)
            high, bundle, _ = amendment.derive(config, manifest, "high")
            self.assertEqual(high["model"], model)
            self.assertEqual(bundle["request"]["model"], request_model)
        config, manifest = originals("wonder-full", "muse-wonder-full-1.0")
        self.invalid(config, manifest)

    def test_argument_is_exact_high_and_cannot_request_other_changes(self):
        class Text(str): pass
        for effort in (None, False, True, 1, "max", "low", "High", " high", "high\n", Text("high"),
                       {"effort": "high", "model": "changed"}, ["high"]):
            with self.subTest(effort=repr(effort)): self.invalid(*originals(), effort)

    def test_original_config_profile_provider_model_effort_and_integrity_are_required(self):
        for changes in ({"format": "local-muse-provider/5"}, {"provider": "codex"}, {"reasoning_effort": "high"},
                        {"reasoning_effort": None}, {"model": "other-model"}, {"model": []}, {"model": "bad model"}):
            config, manifest = originals(); config.update(changes); config["digest"] = digest(config)
            with self.subTest(changes=changes): self.invalid(config, manifest)
        for key in ("format", "provider", "model", "reasoning_effort", "digest"):
            config, manifest = originals(); config.pop(key)
            if key != "digest": config["digest"] = digest(config)
            with self.subTest(key=key): self.invalid(config, manifest)
        config, manifest = originals(); config["account_home"] = "/changed"
        self.invalid(config, manifest)

    def test_manifest_digest_and_closed_pilot_derivation_are_required(self):
        for changes in ({"digest": "0" * 64}, {"additional": True}, {"manual_application_required": False},
                        {"format": "supervised-patch-pilot/2"}):
            config, manifest = originals(); manifest.update(changes)
            if "digest" not in changes: manifest["digest"] = digest(manifest)
            with self.subTest(changes=changes): self.invalid(config, manifest)
        for key, value in (("reasoning_effort", "high"), ("provider", "codex"), ("model", "other-model")):
            config, manifest = originals(); manifest["request"][key] = value
            manifest, _ = pilot._manifest(manifest["request"])
            with self.subTest(key=key): self.invalid(config, manifest)
        config, manifest = originals(); manifest["request"]["files"]["source.py"] = "tampered\n"
        self.invalid(config, manifest)

    def test_non_json_and_malformed_inputs_have_one_typed_failure(self):
        for bad in (None, [], {}, True, "document"):
            config, manifest = originals()
            self.invalid(bad, manifest); self.invalid(config, bad)
        for bad in (1.5, float("nan"), object(), "\ud800"):
            config, manifest = originals(); config["unexpected"] = bad
            self.invalid(config, manifest)

    def test_no_filesystem_environment_process_socket_or_muse_owner_effects(self):
        config, manifest = originals(); environment = {"SYNTHETIC": "unchanged"}
        with patch("builtins.open", side_effect=AssertionError("filesystem")), \
                patch.object(Path, "open", side_effect=AssertionError("path")), \
                patch.object(os, "open", side_effect=AssertionError("descriptor")), \
                patch.object(subprocess, "Popen", side_effect=AssertionError("process")), \
                patch.object(socket, "socket", side_effect=AssertionError("network")), \
                patch.object(os, "environ", environment):
            result = amendment.derive(config, manifest, "high")
            self.assertEqual(result[0]["reasoning_effort"], "high")
            self.assertEqual(environment, {"SYNTHETIC": "unchanged"})
        self.assertNotIn("muse_experimental", amendment.__dict__)
        self.assertEqual(json.loads(canonical_bytes(result[2])), result[2])


if __name__ == "__main__":
    unittest.main()
