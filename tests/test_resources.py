"""Schemas are resolved only through installed package resources."""

from importlib import resources
import unittest

from jsonschema import Draft202012Validator
from referencing.exceptions import Unresolvable

from taskalong.validation import resource_path, schema, schema_names, schema_registry


class ResourceTests(unittest.TestCase):
    def test_exact_schema_enumeration_and_valid_local_registry(self):
        expected = {
            "task-spec", "task-run", "run-event", "worker-packet", "worker-result",
            "execution-observation", "evidence", "acceptance", "authority",
            "effect-intent", "command-result", "runtime-profile",
        }
        self.assertEqual(set(schema_names()), expected)
        root = resources.files("taskalong.resources").joinpath("schemas", "v1")
        self.assertEqual({item.name for item in root.iterdir() if item.is_file()}, {name + ".schema.json" for name in expected})
        for name in expected:
            document = schema(name)
            Draft202012Validator.check_schema(document)
            self.assertFalse(document["additionalProperties"])
            self.assertEqual(schema_registry().contents("urn:taskalong:schema:v1:" + name), document)
        with self.assertRaises(Unresolvable):
            schema_registry().resolver().lookup("https://unapproved.invalid/remote.schema.json")

    def test_templates_resolve_as_files_outside_source_paths(self):
        for name in ("templates/worker.txt", "templates/draft-pr.md"):
            with resource_path(name) as path:
                self.assertTrue(path.is_file())
                self.assertGreater(path.stat().st_size, 20)
        with self.assertRaises(Exception):
            with resource_path("../private"):
                self.fail("Traversal must not resolve")


if __name__ == "__main__":
    unittest.main()
