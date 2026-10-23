"""Public installed entry points remain usable without the checkout on sys.path."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class InstalledEntrypointTests(unittest.TestCase):
    def test_module_and_console_from_empty_cwd(self):
        # The test runner itself must use an ordinary installation. Removing
        # PYTHONPATH here deliberately rejects a source-only import setup.
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        env["PYTHONNOUSERSITE"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        with tempfile.TemporaryDirectory() as directory:
            commands = ([sys.executable, "-m", "taskalong", "--version"],
                        [str(Path(sys.executable).parent / "taskalong"), "--version"],
                        [sys.executable, "-m", "taskalong", "--help"])
            for command in commands:
                with self.subTest(entrypoint=command[-1]):
                    result = subprocess.run(command, cwd=directory, env=env, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("taskalong", result.stdout.lower())
                    self.assertEqual(list(Path(directory).iterdir()), [])

    def test_all_installed_resources_are_readable_without_source(self):
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        env["PYTHONNOUSERSITE"] = "1"
        program = """import json
from importlib.resources import files
from taskalong.validation import schema_names
root=files('taskalong.resources')
names=schema_names()
assert len(names)==12
for name in names:
 assert root.joinpath('schemas/v1/'+name+'.schema.json').read_bytes()
for name in ('templates/worker.txt','templates/draft-pr.md','sql/001-initial.sql'):
 assert root.joinpath(name).read_bytes()
print(json.dumps({'schema_count':len(names)}))
"""
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, "-c", program], cwd=directory, env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["schema_count"], 12)
            self.assertFalse(list(Path(directory).iterdir()))


if __name__ == "__main__":
    unittest.main()
