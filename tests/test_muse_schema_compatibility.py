"""Schema transport compatibility: legacy prompts and configs stay unchanged."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from taskalong import muse_experimental as muse, muse_malformed_successor as malformed
from taskalong import muse_response_schema as schema, muse_successor as successor
from taskalong import supervised_pilot as pilot
from taskalong.errors import TaskAlongError
from taskalong.validation import digest
import test_muse_interrupted_recovery as interrupted_fixtures
import test_muse_malformed_successor as malformed_fixtures


def _request():
    return {"base_commit": "a" * 40, "task": "Compatibility intent.", "provider": "muse",
            "model": "muse-wonder-full-1.0", "reasoning_effort": "high",
            "files": {"source.py": "caf\u00e9 \\n literal\nsecond \u03c0\n"}}


@unittest.skipUnless(os.name == "posix", "Private local evidence requires POSIX")
class SchemaCompatibilityTests(unittest.TestCase):
    def test_legacy_prompt_budget_and_argv_unchanged_except_explicit_schema(self):
        manifest, _ = pilot._manifest(_request())
        old = pilot._prompt(manifest["request"], manifest["digest"])
        common = {"binary": {"path": "/bin/muse"}, "context": "include",
                  "model": "muse-wonder-full-1.0", "reasoning_effort": "high",
                  "attempt_seconds": 720, "max_proposal_bytes": 65536,
                  "max_output_bytes": 4194304, "max_protocol_records": 8192}
        legacy = [{"format": "local-muse-provider/3"},
                  {"format": "local-muse-provider/4", "capture_profile": "implementation"},
                  {"format": "local-muse-provider/5", "capture_profile": "large-task", "attempt_seconds": 1440},
                  {"format": muse._MEGABYTE, "capture_profile": "megabyte-proposal", "attempt_seconds": 1440,
                   "max_output_bytes": 67108864, "max_proposal_bytes": 1048576, "max_protocol_records": 131072}]
        for extra in legacy:
            config = {**common, **extra}
            with self.subTest(format=config["format"]):
                self.assertEqual(muse._prompt(config, manifest), old)
                self.assertEqual(muse._budget(config, old)["prompt_bytes"], len(old))
                argv = muse._argv(config, provider="meta", workspace=Path("/tmp/w"), prompt=Path("/tmp/p.txt"), session="session")
                self.assertNotIn("--output-schema", argv)
        config = {**common, **legacy[-1], "format": schema.FORMAT, "response_contract": schema.CONTRACT}
        amended = muse._prompt(config, manifest)
        self.assertEqual(amended, schema.prompt(old))
        self.assertNotEqual(amended, old)
        self.assertEqual(muse._budget(config, amended)["prompt_bytes"], len(amended))
        meta = muse._argv(config, provider="meta", workspace=Path("/tmp/w"), prompt=Path("/tmp/p.txt"), session="session", output_schema=Path("/tmp/s.json"))
        echo = muse._argv(config, provider="echo", workspace=Path("/tmp/w"), prompt=Path("/tmp/p.txt"), session="session")
        self.assertIn("--output-schema", meta)
        self.assertNotIn("--output-schema", echo)

    def test_malformed_derive_changes_only_format_contract_and_digest(self):
        previous = {"format": muse._MEGABYTE, "provider": "muse", "experimental": True,
                    "binary": {"path": "/bin/muse", "sha256": "a" * 64}, "account_home": "/home/test",
                    "muse_home": "/home/test/muse", "native_roots": {}, "model": "muse-wonder-full-1.0",
                    "reasoning_effort": "high", "context": "include", "catalog_digest": None,
                    "public_context_hashes": {}, "context_hashes": {}, "attempt_seconds": 1440,
                    "max_output_bytes": 67108864, "max_proposal_bytes": 32768,
                    "capture_profile": "megabyte-proposal", "max_protocol_records": 131072, "digest": "0" * 64}
        snapshot = copy.deepcopy(previous)
        candidate = malformed.derive(previous)
        self.assertEqual(previous, snapshot)
        self.assertEqual({k for k in candidate if k not in previous or candidate[k] != previous[k]},
                         {"format", "response_contract", "digest"})
        self.assertEqual(candidate["format"], schema.FORMAT)
        self.assertEqual(candidate["response_contract"], schema.CONTRACT)
        self.assertEqual(candidate["digest"], digest(candidate))

    def test_configure_rejects_mismatched_schema_bounds_and_bools(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            base = {"executable": "/bin/true", "account_home": str(root), "muse_home": str(root / "muse")}
            cases = [{"capture_profile": "implementation", "response_contract": schema.CONTRACT},
                     {"capture_profile": "megabyte-proposal", "response_contract": "json-schema-file-changes/2"},
                     {"capture_profile": "megabyte-proposal", "max_output_bytes": 4194304},
                     {"capture_profile": "megabyte-proposal", "max_protocol_records": 8192},
                     {"capture_profile": "megabyte-proposal", "max_proposal_bytes": 1048577},
                     {"capture_profile": "implementation", "max_protocol_records": 8192},
                     {"capture_profile": "megabyte-proposal", "attempt_seconds": True},
                     {"capture_profile": "megabyte-proposal", "max_protocol_records": True},
                     {"capture_profile": "megabyte-proposal", "max_output_bytes": True}]
            for changes in cases:
                with self.subTest(changes=changes), self.assertRaises(TaskAlongError) as caught:
                    muse.configure(None, {**base, **changes})
                self.assertEqual(caught.exception.code, "provider_config_invalid")

    def test_malformed_plan_read_only_and_execute_persists_image_before_preflight(self):
        fixture = malformed_fixtures.MalformedSuccessorTests()
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        derived = malformed.derive(fixture.config)
        key = "provider-config:" + derived["digest"]
        self.assertIsNone(fixture.store.setting(key))
        proof = fixture.plan()
        self.assertIsNone(fixture.store.setting(key))
        fixture.assert_original()
        def denied(config, root):
            self.assertEqual(fixture.store.setting(key), derived)
            raise TaskAlongError("preflight_denied", "synthetic")
        with patch.object(muse, "_preflight", side_effect=denied), patch.object(muse, "run_foreground_experiment", side_effect=AssertionError("no process")), self.assertRaises(TaskAlongError):
            fixture.execute(proof)
        self.assertEqual(fixture.store.setting(key), derived)
        self.assertEqual(fixture.store.setting("provider:muse"), fixture.config)
        reservation = fixture.store.setting("provider-successor:muse:" + fixture.original["run_id"])
        self.assertIsNotNone(reservation)
        with patch.object(muse, "_preflight", side_effect=AssertionError("no replay")), patch.object(muse, "run_foreground_experiment", side_effect=AssertionError("no replay")):
            self.assertEqual(fixture.execute(proof)["run_id"], reservation["run_id"])
        fixture.assert_original()

    def test_legacy_interrupted_successor_refuses_unrelated_schema_config(self):
        fixture = interrupted_fixtures.InterruptedSuccessorTests()
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        proof = fixture.plan()
        fixture.configure(response_contract=schema.CONTRACT)
        self.assertEqual(muse._configuration(fixture.service._store)["format"], schema.FORMAT)
        with patch.object(muse, "_preflight") as preflight, patch.object(muse, "run_foreground_experiment") as owner, self.assertRaises(TaskAlongError):
            fixture.execute(proof)
        preflight.assert_not_called(); owner.assert_not_called()
        self.assertIsNone(fixture.service._store.setting("provider-successor:muse:" + fixture.original["run_id"]))
        self.assertFalse(successor._anchor(fixture.original).exists())
        fixture.configure()
        fixture.c.assert_original()


if __name__ == "__main__":
    unittest.main()
