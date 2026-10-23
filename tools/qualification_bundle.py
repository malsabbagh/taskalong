#!/usr/bin/env python3
"""Bind same-run producer artifacts to the exact reviewed checkout and profile."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess


def hashes(root: Path, paths: list[str]) -> dict:
    values = {}
    for name in paths:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('bundle input is not a regular file')
        values[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def identity(root: Path, os_profile: str, python_profile: str) -> dict:
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    if commit != os.environ['GITHUB_SHA']:
        raise ValueError('bundle checkout differs from tested event commit')
    if '.'.join(platform.python_version_tuple()[:2]) != python_profile:
        raise ValueError('bundle interpreter profile mismatch')
    if platform.system() != {'macos-15': 'Darwin', 'ubuntu-24.04': 'Linux'}[os_profile]:
        raise ValueError('bundle platform mismatch')
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().strip('\0').split('\0')
    return {'format_version': 1, 'run_id': os.environ['GITHUB_RUN_ID'],
            'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'event': os.environ['GITHUB_EVENT_NAME'],
            'source_commit': commit,
            'source_tree': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=root, text=True).strip(),
            'producer_job_key': f'producer / {os_profile} / Python {python_profile}',
            'os_profile': os_profile, 'python_profile': python_profile,
            'source_files': hashes(root, tracked),
            'artifacts': hashes(root, sorted(str(p.relative_to(root)) for p in (root / 'dist').iterdir()))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('write', 'verify'))
    parser.add_argument('--os-profile', required=True, choices=('macos-15', 'ubuntu-24.04'))
    parser.add_argument('--python-profile', required=True, choices=('3.11', '3.12', '3.13', '3.14'))
    args = parser.parse_args()
    root = Path.cwd()
    value = identity(root, args.os_profile, args.python_profile)
    if set(value['artifacts']) != {'dist/taskalong-0.1.0a1-py3-none-any.whl', 'dist/taskalong-0.1.0a1.tar.gz'}:
        raise ValueError('expected exactly the matching producer wheel and sdist')
    path = root / 'producer-identity.json'
    if args.operation == 'write':
        with path.open('x', encoding='utf-8') as stream:
            json.dump(value, stream, sort_keys=True)
    elif json.loads(path.read_text()) != value:
        raise ValueError('producer artifact, run, profile or checkout identity mismatch')
    print(json.dumps({'kind': 'qualification_bundle', 'ok': True, 'operation': args.operation,
                      'identity_sha256': hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()}))


if __name__ == '__main__':
    main()
