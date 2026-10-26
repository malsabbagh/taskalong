#!/usr/bin/env python3
"""Seal and aggregate artifact lanes without changing format-2 qualification."""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import subprocess
import unittest

from qualification_bundle import hashes
from qualify_installed import (PHASE_SECONDS, QUALIFICATION_SECONDS, REVIEW_SHA256,
                               is_sha, json_digest, make_schedule,
                               validate_journey, validate_test_accounting)

PROFILES = [(system, python) for system in ('ubuntu-24.04', 'macos-15')
            for python in ('3.11', '3.12', '3.13', '3.14')]
LANES = {'wheel-core': ('wheel', 'core-only'), 'sdist': ('sdist',)}
ARTIFACTS = {'wheel': 'dist/taskalong-0.1.0a1-py3-none-any.whl',
             'sdist': 'dist/taskalong-0.1.0a1.tar.gz'}
JOURNEY_FIELDS = {'kind', 'format_version', 'ok', 'state', 'qualification', 'review',
    'publication', 'python', 'platform', 'machine', 'package_version', 'attempts', 'events',
    'source_import', 'real_sandbox_claim', 'installed_behavior_tests', 'skipped_platform_cases',
    'dependencies'}
EXTRA_FIELDS = {'artifact', 'artifact_sha256', 'behavior_test_ids', 'dependency_lock_sha256',
    'editable', 'elapsed_seconds', 'environment', 'package_snapshot_sha256', 'phases',
    'qualification_inputs_sha256', 'review_wheel_sha256', 'schedule', 'total_budget_seconds'}
PARENT_FIELDS = {'identity', 'ok', 'failure', 'budget_seconds', 'elapsed_seconds',
    'direct_child_exit', 'direct_child_reaped', 'descendant_cleanup_confirmed', 'stdout',
    'stderr', 'secondary_errors', 'receipt_persisted'}


def read_json(path: Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('missing, linked or oversized shard input')
    return json.loads(path.read_bytes())


def source_binding(root: Path) -> dict:
    def git(*argv):
        return subprocess.check_output(['git', *argv], cwd=root).decode().strip()
    commit = git('rev-parse', 'HEAD')
    if commit != os.environ['GITHUB_SHA']:
        raise ValueError('aggregate checkout differs from event commit')
    return {'run_id': os.environ['GITHUB_RUN_ID'], 'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'],
        'event': os.environ['GITHUB_EVENT_NAME'], 'source_commit': commit,
        'source_tree': git('rev-parse', 'HEAD^{tree}'),
        'source_files': hashes(root, git('ls-files', '-z').strip('\0').split('\0'))}


def validate_producer(value: dict, binding: dict, system: str, python: str):
    expected = binding | {'format_version': 1, 'os_profile': system, 'python_profile': python,
                         'producer_job_key': f'producer / {system} / Python {python}'}
    if (not isinstance(value, dict) or set(value) != set(expected) | {'artifacts'}
            or any(value[k] != v for k, v in expected.items())
            or not isinstance(value['artifacts'], dict)
            or set(value['artifacts']) != set(ARTIFACTS.values())
            or any(not is_sha(v) for v in value['artifacts'].values())):
        raise ValueError('producer source, run, attempt, profile or artifact identity mismatch')


def harness_digest(producer):
    inputs = {'tools/qualify_installed.py', 'tools/qualify_runtime.py', 'requirements-dev.lock'} | {
        path for path in producer['source_files'] if path.startswith('tests/') and path != 'tests/test_distribution.py'}
    return json_digest([{'path': path, 'sha256': producer['source_files'][path]} for path in sorted(inputs)])


def result_name(binding, system, python, lane):
    return f"qualification-{lane_name(system, python, lane)}-{binding['source_commit']}-{binding['run_attempt']}"


def seconds(value, limit):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= limit


def inventory_receipt(binding, producer, ids):
    schedule = make_schedule(ids)
    return {'kind': 'installed_inventory', 'format_version': 1, 'binding': binding,
        'producer_identity_sha256': json_digest(producer), 'test_ids': sorted(ids),
        'inventory_sha256': schedule['inventory_sha256']}


def discover_inventory(root: Path):
    """Independent producer discovery; distribution-only tests are not installed."""
    def flatten(suite):
        for item in suite:
            if isinstance(item, unittest.TestSuite):
                yield from flatten(item)
            else:
                yield item.id()
    loader = unittest.TestLoader()
    suite = loader.discover(str(root / 'tests'))
    if loader.errors:
        raise ValueError('producer inventory discovery failed')
    ids = [identifier for identifier in flatten(suite) if not identifier.startswith('test_distribution.')]
    make_schedule(ids)
    return sorted(ids)


def validate_receipt(value: dict, producer: dict, mode: str):
    """Recheck closed terminal receipts, phases and the complete skip inventory."""
    if not isinstance(value, dict) or set(value) != JOURNEY_FIELDS | EXTRA_FIELDS:
        raise ValueError('invalid closed installed receipt')
    core = mode == 'core-only'
    artifact = 'wheel' if core else mode
    system = {'ubuntu-24.04': 'Linux', 'macos-15': 'Darwin'}[producer['os_profile']]
    fixed = {'format_version': 2, 'artifact': artifact,
        'artifact_sha256': producer['artifacts'][ARTIFACTS[artifact]],
        'dependency_lock_sha256': producer['source_files']['requirements-dev.lock'],
        'review_wheel_sha256': None if core else REVIEW_SHA256,
        'environment': 'fresh-venv-external-cwd', 'editable': False, 'source_import': False,
        'total_budget_seconds': QUALIFICATION_SECONDS, 'platform': system, 'ok': True}
    if any(type(value[k]) is not type(v) or value[k] != v for k, v in fixed.items()):
        raise ValueError('installed receipt identity or limits mismatch')
    if (not value['python'].startswith(producer['python_profile'] + '.')
            or not seconds(value['elapsed_seconds'], QUALIFICATION_SECONDS)
            or value['qualification_inputs_sha256'] != harness_digest(producer)
            or not is_sha(value['package_snapshot_sha256'])):
        raise ValueError('invalid installed environment or elapsed budget')
    journey = {k: value[k] for k in JOURNEY_FIELDS}
    journey.update(format_version=1, installed_behavior_tests=0, skipped_platform_cases=[])
    validate_journey(journey, core_only=core)
    ids, schedule = value['behavior_test_ids'], value['schedule']
    if core:
        if ids != [] or schedule is not None or value['installed_behavior_tests'] != 0 or value['skipped_platform_cases'] != []:
            raise ValueError('core-only lane cannot substitute behavior coverage')
    else:
        if (not isinstance(ids, list) or ids != sorted(ids) or schedule != make_schedule(ids)):
            raise ValueError('behavior inventory differs from format-2 schedule')
        skips = value['skipped_platform_cases']
        if not isinstance(skips, list) or any(not isinstance(r, dict) or set(r) != {'test', 'reason', 'required_platform'} for r in skips):
            raise ValueError('invalid skip inventory')
        skipped = {r['test'] for r in skips}
        results = [{'test_ids': batch, 'outcomes': {i: 'skipped' if i in skipped else 'passed' for i in batch},
                    'skipped_platform_cases': [r for r in skips if r['test'] in batch]}
                   for batch in schedule['batches']]
        count, _ = validate_test_accounting(schedule, results, system.lower())
        if type(value['installed_behavior_tests']) is not int or value['installed_behavior_tests'] != count:
            raise ValueError('behavior count differs from exact test accounting')
    phases = ['sample'] if core else ['inventory', 'sample', 'tests-0', 'tests-1']
    if not isinstance(value['phases'], list) or len(value['phases']) != len(phases):
        raise ValueError('missing or duplicate terminal phases')
    for phase, receipt in zip(phases, value['phases']):
        identity = {'phase': phase, 'artifact_sha256': fixed['artifact_sha256'],
            'harness_sha256': value['qualification_inputs_sha256'],
            'lock_sha256': fixed['dependency_lock_sha256'],
            'schedule_sha256': None if core or phase == 'inventory' else json_digest(schedule)}
        limit = 60 if phase == 'inventory' else PHASE_SECONDS
        if (not isinstance(receipt, dict) or set(receipt) != PARENT_FIELDS
                or receipt['identity'] != identity or receipt['ok'] is not True
                or receipt['failure'] is not None or type(receipt['direct_child_exit']) is not int
                or receipt['direct_child_exit'] != 0 or receipt['direct_child_reaped'] is not True
                or receipt['descendant_cleanup_confirmed'] is not False
                or receipt['receipt_persisted'] is not True or receipt['secondary_errors'] != []
                or not seconds(receipt['budget_seconds'], limit) or receipt['budget_seconds'] <= 0
                or not seconds(receipt['elapsed_seconds'], receipt['budget_seconds'])):
            raise ValueError('invalid, failed or mismatched terminal phase')
        for stream in ('stdout', 'stderr'):
            observed = receipt[stream]
            if (not isinstance(observed, dict) or set(observed) != {'file', 'bytes', 'truncated', 'sha256'}
                    or observed['file'] != f'diagnostics/{phase}.{stream}'
                    or type(observed['bytes']) is not int or not 0 <= observed['bytes'] <= 4 * 1024 * 1024
                    or observed['truncated'] is not False or not is_sha(observed['sha256'])):
                raise ValueError('invalid or truncated phase stream')


def lane_name(system, python, lane):
    return f'{system}-py{python}-{lane}'


def validate_lane(directory: Path, binding: dict, system: str, python: str, lane: str, *, seal=False):
    producer_path = directory / 'producer-identity.json'
    producer = read_json(producer_path)
    validate_producer(producer, binding, system, python)
    canonical = read_json(directory / 'installed-inventory.json')
    if (not isinstance(canonical, dict) or 'test_ids' not in canonical
            or canonical != inventory_receipt(binding, producer, canonical['test_ids'])):
        raise ValueError('producer inventory identity mismatch')
    files = ['producer-identity.json', 'installed-inventory.json', *(f'installed-{mode}.json' for mode in LANES[lane])]
    receipts = {mode: read_json(directory / f'installed-{mode}.json') for mode in LANES[lane]}
    for mode, value in receipts.items():
        validate_receipt(value, producer, mode)
        if mode != 'core-only' and value['behavior_test_ids'] != canonical['test_ids']:
            raise ValueError('installed behavior differs from independent producer inventory')
    # All modes in this lane use the same immutable source harness and lock.
    if len({r['qualification_inputs_sha256'] for r in receipts.values()}) != 1:
        raise ValueError('lane harness identities differ')
    expected = {'kind': 'qualification_shard', 'format_version': 1, 'lane': lane,
        'os_profile': system, 'python_profile': python, 'binding': binding,
        'files': hashes(directory, files), 'producer_identity_sha256': json_digest(producer)}
    path = directory / 'shard.json'
    if seal:
        with path.open('x', encoding='utf-8') as output:
            json.dump(expected, output, sort_keys=True)
            output.write('\n')
    elif read_json(path) != expected:
        raise ValueError('missing, stale or mismatched shard envelope')
    return producer, receipts


def aggregate(root: Path, binding: dict, profiles=PROFILES):
    expected = {result_name(binding, system, python, lane) for system, python in profiles for lane in LANES}
    if root.is_symlink() or not root.is_dir() or {p.name for p in root.iterdir()} != expected:
        raise ValueError('missing, duplicate or extra shard results')
    summaries = []
    for system, python in profiles:
        lanes = {}
        producers = []
        for lane in LANES:
            directory = root / result_name(binding, system, python, lane)
            if directory.is_symlink() or not directory.is_dir():
                raise ValueError('invalid shard result directory')
            allowed = {'shard.json', 'producer-identity.json', 'installed-inventory.json', *(f'installed-{m}.json' for m in LANES[lane])}
            if {p.name for p in directory.iterdir()} != allowed:
                raise ValueError('extra or missing lane files')
            producer, receipts = validate_lane(directory, binding, system, python, lane)
            producers.append(producer)
            lanes.update(receipts)
        wheel, sdist = lanes['wheel'], lanes['sdist']
        if producers[0] != producers[1]:
            raise ValueError('shards used different producer artifacts')
        for field in ('schedule', 'behavior_test_ids', 'skipped_platform_cases', 'installed_behavior_tests',
                      'qualification_inputs_sha256', 'dependency_lock_sha256'):
            if wheel[field] != sdist[field]:
                raise ValueError('wheel and sdist coverage or harness mismatch')
        summaries.append({'os_profile': system, 'python_profile': python,
            'inventory_sha256': wheel['schedule']['inventory_sha256'],
            'tests_per_artifact': len(wheel['behavior_test_ids']),
            'passed_per_artifact': wheel['installed_behavior_tests'],
            'skips_per_artifact': len(wheel['skipped_platform_cases']),
            'qualification_seconds': {m: r['elapsed_seconds'] for m, r in lanes.items()}})
    return {'kind': 'qualification_aggregate', 'format_version': 1, 'ok': True,
            'binding': binding, 'shards': len(expected), 'profiles': summaries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('inventory', 'seal', 'aggregate'))
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--os-profile', choices=sorted({s for s, _ in PROFILES}))
    parser.add_argument('--python-profile', choices=sorted({p for _, p in PROFILES}))
    parser.add_argument('--lane', choices=LANES)
    args = parser.parse_args()
    binding = source_binding(Path(__file__).resolve().parents[1])
    if args.operation == 'inventory':
        if not all((args.os_profile, args.python_profile)) or args.lane:
            parser.error('inventory requires profile arguments')
        producer = read_json(args.directory / 'producer-identity.json')
        validate_producer(producer, binding, args.os_profile, args.python_profile)
        result = inventory_receipt(binding, producer, discover_inventory(Path(__file__).resolve().parents[1]))
    elif args.operation == 'seal':
        if not all((args.os_profile, args.python_profile, args.lane)):
            parser.error('seal requires profile and lane')
        validate_lane(args.directory, binding, args.os_profile, args.python_profile, args.lane, seal=True)
        result = {'kind': 'qualification_shard_sealed', 'ok': True}
    else:
        if args.lane or bool(args.os_profile) != bool(args.python_profile):
            parser.error('aggregate requires either both profile arguments or neither')
        profiles = [(args.os_profile, args.python_profile)] if args.os_profile else PROFILES
        result = aggregate(args.directory, binding, profiles)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
