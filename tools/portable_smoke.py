"""Installed stateless contracts; no state store or live-agent support claim."""
from __future__ import annotations
import importlib.metadata
from importlib import resources
import json
import os
from pathlib import Path
import subprocess
import sys
import sysconfig
import unittest
from unittest.mock import patch

TEST_NAMES = ('canonical_json', 'entrypoints', 'guide_resources', 'invalid_cli',
              'installed_origin', 'literal_paths', 'process_refusal', 'schemas')


class PortableContracts(unittest.TestCase):
    def cli(self, args, *, console=False, expected=0):
        scripts = Path(sys.executable).parent
        executable = scripts / ('taskalong.exe' if os.name == 'nt' else 'taskalong')
        argv = [str(executable)] if console else [sys.executable, '-I', '-m', 'taskalong']
        result = subprocess.run(argv + args, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, expected, result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        return result

    def test_canonical_json(self):
        from taskalong.validation import canonical_bytes, loads
        from taskalong.errors import TaskAlongError
        self.assertEqual(canonical_bytes({'b': 2, 'a': 'λ'}), b'{"a":"\xce\xbb","b":2}')
        with self.assertRaises(TaskAlongError):
            loads('{"a":1,"a":2}')

    def test_entrypoints(self):
        for console in (False, True):
            self.assertIn('taskalong 0.1.0a1', self.cli(['--version'], console=console).stdout)
            self.assertIn('guide', self.cli(['--help'], console=console).stdout)

    def test_guide_resources(self):
        guide = json.loads(self.cli(['--json', 'guide', 'fixture']).stdout)
        self.assertTrue(guide['ok'])
        self.assertTrue(guide['data']['markdown'])
        self.assertTrue(resources.files('taskalong.resources').joinpath('sql/001-initial.sql').read_bytes())

    def test_invalid_cli(self):
        value = json.loads(self.cli(['--json', 'no-such-command'], expected=2).stdout)
        self.assertFalse(value['ok'])
        self.assertEqual(value['errors'][0]['code'], 'invalid_cli')

    def test_installed_origin(self):
        import taskalong
        origin = Path(taskalong.__file__).resolve()
        self.assertTrue(origin.is_relative_to(Path(sys.prefix).resolve()), str(origin))
        self.assertIn('site-packages', origin.parts)
        self.assertNotEqual(sys.prefix, sys.base_prefix)
        self.assertFalse((Path.cwd() / 'src/taskalong').exists())
        self.assertEqual(importlib.metadata.version('taskalong'), '0.1.0a1')
        self.assertNotIn('PYTHONPATH', os.environ)

    def test_literal_paths(self):
        from taskalong.paths import safe_relative
        from taskalong.errors import TaskAlongError
        self.assertEqual(safe_relative('folder with spaces/λ.txt'), 'folder with spaces/λ.txt')
        for path in ('../escape', '/absolute', 'folder\\escape', '.git/config'):
            with self.subTest(path=path), self.assertRaises(TaskAlongError):
                safe_relative(path)

    def test_process_refusal(self):
        from taskalong.process import run_bounded, ProcessBoundaryError
        # Exercise the unsupported-platform contract on every host, without spawning.
        cwd = str(Path.cwd())
        with patch('taskalong.process.os.name', 'nt'), patch('taskalong.process.subprocess.Popen') as spawn:
            with self.assertRaisesRegex(ProcessBoundaryError, 'requires POSIX'):
                run_bounded([sys.executable, '-c', 'raise SystemExit(99)'], cwd=cwd)
            spawn.assert_not_called()

    def test_schemas(self):
        from taskalong.validation import schema, validate
        from taskalong.errors import TaskAlongError
        self.assertEqual(schema('task-spec')['type'], 'object')
        with self.assertRaises(TaskAlongError):
            validate('task-spec', {})


def main():
    if unittest.defaultTestLoader.getTestCaseNames(PortableContracts) != sorted('test_' + name for name in TEST_NAMES):
        raise ValueError('portable test inventory differs from declared contracts')
    suite = unittest.TestSuite(PortableContracts('test_' + name) for name in TEST_NAMES)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    if not result.wasSuccessful() or result.skipped or result.testsRun != len(TEST_NAMES):
        raise SystemExit(1)
    import taskalong
    print(json.dumps({'test_ids': list(TEST_NAMES), 'passed': result.testsRun,
                      'skipped': [], 'python': sys.version.split()[0],
                      'implementation': sys.implementation.name,
                      'gil_disabled': bool(sysconfig.get_config_var('Py_GIL_DISABLED')),
                      'installed_origin': str(Path(taskalong.__file__).resolve()),
                      'prefix': str(Path(sys.prefix).resolve())}))


if __name__ == '__main__':
    main()
