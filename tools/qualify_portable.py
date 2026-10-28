"""Qualify two installed artifacts on Windows; validate a closed same-run receipt."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import time

from qualification_bundle import CI_PYTHON_VERSION
from portable_smoke import TEST_NAMES
from check_dist import audit

BUDGET = 900
SCOPE = 'stateless-installed-contracts-only'
ARTIFACT_PATHS = {'wheel': 'dist/taskalong-0.1.0a1-py3-none-any.whl',
                  'sdist': 'dist/taskalong-0.1.0a1.tar.gz',
                  'rebuilt': 'portable-rebuilt/taskalong-0.1.0a1-py3-none-any.whl'}


def validate_receipt(value, binding):
    expected = {'kind': 'windows_portable', 'format_version': 2, 'ok': True,
                'binding': binding, 'python': CI_PYTHON_VERSION, 'platform': 'Windows',
                'scope': SCOPE, 'implementation': 'cpython', 'gil_disabled': False}
    if (not isinstance(value, dict) or set(value) != set(expected) | {'artifacts', 'installed_artifacts', 'results', 'elapsed_seconds'}
            or type(value['format_version']) is not int or value['ok'] is not True
            or value['gil_disabled'] is not False
            or any(value[k] != v for k, v in expected.items())
            or type(value['elapsed_seconds']) not in (int, float)
            or not 0 <= value['elapsed_seconds'] <= BUDGET):
        raise ValueError('Windows receipt identity or budget mismatch')
    if not isinstance(value['artifacts'], dict) or set(value['artifacts']) != {'wheel', 'sdist'}:
        raise ValueError('Windows artifacts missing')
    if not isinstance(value['installed_artifacts'], dict) or set(value['installed_artifacts']) != {'wheel', 'sdist'}:
        raise ValueError('Windows installed artifacts missing')
    if value['installed_artifacts']['wheel'] != value['artifacts']['wheel']:
        raise ValueError('Windows wheel input differs from installed artifact')
    for digest in [*value['artifacts'].values(), *value['installed_artifacts'].values()]:
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('Windows artifact digest invalid')
    if not isinstance(value['results'], dict) or set(value['results']) != {'wheel', 'sdist'}:
        raise ValueError('Windows artifact results missing')
    for result in value['results'].values():
        if (not isinstance(result, dict) or set(result) != {'test_ids', 'passed', 'skipped', 'python', 'implementation', 'gil_disabled', 'installed_origin', 'prefix'}
                or result['test_ids'] != list(TEST_NAMES) or type(result['passed']) is not int
                or result['passed'] != len(TEST_NAMES) or result['skipped'] != []
                or result['python'] != CI_PYTHON_VERSION or result['implementation'] != 'cpython'
                or result['gil_disabled'] is not False):
            raise ValueError('Windows portable inventory incomplete')
        from pathlib import PureWindowsPath
        if not all(isinstance(result[k], str) for k in ('installed_origin', 'prefix')):
            raise ValueError('Windows installed paths must be strings')
        origin, prefix = PureWindowsPath(result['installed_origin']), PureWindowsPath(result['prefix'])
        if (not prefix.is_absolute() or not origin.is_absolute()
                or '..' in origin.parts or '..' in prefix.parts
                or prefix.name.lower() != 'venv' or origin == prefix or not origin.is_relative_to(prefix)
                or tuple(p.lower() for p in origin.relative_to(prefix).parts) !=
                   ('lib', 'site-packages', 'taskalong', '__init__.py')):
            raise ValueError('Windows installed origin outside isolated environment')
    return {'scope': SCOPE, 'artifacts': value['artifacts'],
            'installed_artifacts': value['installed_artifacts'], 'tests_per_artifact': len(TEST_NAMES)}



def audit_inputs(root):
    for label in ('wheel', 'sdist'):
        audit(root / ARTIFACT_PATHS[label], root=root)


def verify_artifacts(value, directory, source_root):
    """Check the Windows build itself; independent OS archive bytes may differ."""
    for folder, expected in (('dist', {Path(ARTIFACT_PATHS[k]).name for k in ('wheel', 'sdist')}),
                             ('portable-rebuilt', {Path(ARTIFACT_PATHS['rebuilt']).name})):
        path = directory / folder
        if path.is_symlink() or not path.is_dir() or {p.name for p in path.iterdir()} != expected:
            raise ValueError('Windows artifact inventory incomplete or unexpected')
    expected_hashes = {'wheel': value['artifacts']['wheel'], 'sdist': value['artifacts']['sdist'],
                       'rebuilt': value['installed_artifacts']['sdist']}
    for label, relative in ARTIFACT_PATHS.items():
        path = directory / relative
        audit(path, root=source_root)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hashes[label]:
            raise ValueError('Windows retained artifact bytes differ from tested snapshot')
    return {'verified_artifacts': len(ARTIFACT_PATHS)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if (platform.system() != 'Windows' or platform.python_version() != CI_PYTHON_VERSION
            or sys.implementation.name != 'cpython' or sysconfig.get_config_var('Py_GIL_DISABLED')):
        raise ValueError('Windows qualification requires pinned native Windows interpreter')
    from qualification_shards import source_binding
    from qualify_installed import clean_environment
    root = Path(__file__).resolve().parents[1]
    binding = source_binding(root)
    started = time.monotonic()
    diagnostics = root / 'portable-diagnostics'
    diagnostics.mkdir(exist_ok=False)
    env = clean_environment()
    sequence = 0
    def run(argv, cwd=root):
        nonlocal sequence
        sequence += 1
        remaining = BUDGET - (time.monotonic() - started)
        if remaining <= 0:
            raise TimeoutError('portable qualification deadline exceeded')
        result = subprocess.run([str(a) for a in argv], cwd=cwd, env=env,
                                capture_output=True, timeout=min(remaining, 180))
        (diagnostics / f'{sequence}.stdout').write_bytes(result.stdout)
        (diagnostics / f'{sequence}.stderr').write_bytes(result.stderr)
        if result.returncode:
            raise RuntimeError(f'portable phase {sequence} failed with exit {result.returncode}')
        return result.stdout
    if (root / 'dist').exists():
        raise ValueError('portable build requires an empty dist directory')
    run([sys.executable, '-m', 'build', '--no-isolation', '--sdist', '--wheel'])
    wheel, = (root / 'dist').glob('*.whl')
    sdist, = (root / 'dist').glob('*.tar.gz')
    run([sys.executable, root / 'tools/normalize_sdist.py', sdist])
    run([sys.executable, root / 'tools/check_dist.py', '--dist-dir', root / 'dist'])
    audit_inputs(root)
    artifacts = {label: hashlib.sha256(path.read_bytes()).hexdigest() for label, path in [('wheel', wheel), ('sdist', sdist)]}
    results, installed_artifacts = {}, {}
    retained_rebuilt = root / 'portable-rebuilt'
    retained_rebuilt.mkdir(exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='taskalong portable λ ') as scratch:
        base = Path(scratch)
        for label, artifact in [('wheel', wheel), ('sdist', sdist)]:
            work = base / label
            work.mkdir()
            venv = work / 'venv'
            run([sys.executable, '-m', 'venv', venv], work)
            python = venv / 'Scripts/python.exe'
            run([python, '-m', 'pip', '--isolated', 'install', '--require-hashes', '-r', root / 'requirements-dev.lock'], work)
            if label == 'sdist':
                rebuilt = work / 'rebuilt'
                run([python, '-m', 'pip', '--isolated', 'wheel', '--no-build-isolation', '--no-deps', '--wheel-dir', rebuilt, artifact], work)
                artifact, = rebuilt.glob('*.whl')
                audit(artifact, root=root)
                shutil.copyfile(artifact, root / ARTIFACT_PATHS['rebuilt'])
            installed_artifacts[label] = hashlib.sha256(artifact.read_bytes()).hexdigest()
            run([python, '-m', 'pip', '--isolated', 'install', '--no-deps', artifact], work)
            smoke = work / 'portable_smoke.py'
            shutil.copyfile(root / 'tools/portable_smoke.py', smoke)
            results[label] = json.loads(run([python, '-I', smoke], work))
    value = {'kind': 'windows_portable', 'format_version': 2, 'ok': True, 'binding': binding,
             'python': platform.python_version(), 'platform': platform.system(), 'scope': SCOPE,
             'artifacts': artifacts, 'installed_artifacts': installed_artifacts, 'results': results,
             'implementation': sys.implementation.name, 'gil_disabled': bool(sysconfig.get_config_var('Py_GIL_DISABLED')), 'elapsed_seconds': time.monotonic() - started}
    validate_receipt(value, binding)
    verify_artifacts(value, root, root)
    if source_binding(root) != binding:
        raise ValueError('portable checkout changed during qualification')
    value['elapsed_seconds'] = time.monotonic() - started
    validate_receipt(value, binding)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True)


if __name__ == '__main__':
    main()
