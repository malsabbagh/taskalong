"""Distribution audits reject unexpected bytes and unsafe archive members."""
from __future__ import annotations

import importlib.util
import base64
import csv
import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stdout, redirect_stderr
import zipfile
import copy
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location("taskalong_distribution_auditor", Path(__file__).resolve().parents[1] / "tools" / "check_dist.py")
auditor = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(auditor)
_QUALIFIER_SPEC = importlib.util.spec_from_file_location("taskalong_installed_qualifier", Path(__file__).resolve().parents[1] / "tools" / "qualify_installed.py")
qualifier = importlib.util.module_from_spec(_QUALIFIER_SPEC)
_QUALIFIER_SPEC.loader.exec_module(qualifier)


class QualificationShardTests(unittest.TestCase):
    """The final gate must fail closed when a shard result is incomplete."""

    @classmethod
    def setUpClass(cls):
        # Distribution tests stay outside the installed behavior inventory.
        # Import exactly the reviewed tools without changing installed tests.
        with mock.patch.dict(sys.modules, {'qualification_bundle': cls.load_tool('qualification_bundle'),
                                           'qualify_installed': qualifier}):
            cls.shards = cls.load_tool('qualification_shards')

    @staticmethod
    def load_tool(name):
        spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / 'tools' / (name + '.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def fixture(self, system='ubuntu-24.04', python='3.11'):
        q = self.shards
        binding = {'run_id': '1234', 'run_attempt': '2', 'event': 'pull_request',
                   'source_commit': 'c' * 40, 'source_tree': 'd' * 40,
                   'source_files': {name: 'a' * 64 for name in ('requirements-dev.lock',
                       'tools/qualify_installed.py', 'tools/qualify_runtime.py', 'tests/test_a.py')}}
        producer = binding | {'format_version': 1, 'os_profile': system, 'python_profile': python,
            'producer_job_key': f'producer / {system} / Python {python}',
            'artifacts': {name: 'b' * 64 for name in q.ARTIFACTS.values()}}
        ids = ['test_a.Cases.test_one', 'test_a.Cases.test_two', 'test_b.Cases.test_three']
        schedule = qualifier.make_schedule(ids)
        receipts = {}
        for mode in ('wheel', 'sdist', 'core-only'):
            core = mode == 'core-only'
            value = {'kind': 'installed_journey', 'format_version': 2, 'ok': True,
                'state': 'blocked' if core else 'draft_published', 'qualification': 'synthetic',
                'review': 'missing-blocks' if core else 'released-fixture-full-diff',
                'publication': 'review-blocked' if core else 'fixture-lost-response-reconciled-one-create',
                'python': '3.14.10' if python == '3.14' else python + '.9', 'platform': 'Linux' if system.startswith('ubuntu') else 'Darwin',
                'machine': 'synthetic', 'package_version': '0.1.0a1', 'attempts': 1, 'events': 2,
                'source_import': False, 'real_sandbox_claim': False,
                'installed_behavior_tests': 0 if core else len(ids), 'skipped_platform_cases': [],
                'dependencies': {'jsonschema': '4.26.0', 'certifi': '2026.7.22', 'setuptools': '84.0.0'},
                'artifact': 'wheel' if core else mode, 'artifact_sha256': 'b' * 64,
                'behavior_test_ids': [] if core else ids, 'dependency_lock_sha256': 'a' * 64,
                'editable': False, 'elapsed_seconds': 10, 'environment': 'fresh-venv-external-cwd',
                'package_snapshot_sha256': 'e' * 64, 'phases': [],
                'qualification_inputs_sha256': q.harness_digest(producer),
                'review_wheel_sha256': None if core else qualifier.REVIEW_SHA256,
                'schedule': None if core else schedule, 'total_budget_seconds': 1500}
            for phase in (['sample'] if core else ['inventory', 'sample', 'tests-0', 'tests-1']):
                identity = {'phase': phase, 'artifact_sha256': 'b' * 64,
                    'harness_sha256': value['qualification_inputs_sha256'], 'lock_sha256': 'a' * 64,
                    'schedule_sha256': None if core or phase == 'inventory' else qualifier.json_digest(schedule)}
                parent = {'identity': identity, 'ok': True, 'failure': None, 'budget_seconds': 60 if phase == 'inventory' else 600,
                    'elapsed_seconds': 1, 'direct_child_exit': 0, 'direct_child_reaped': True,
                    'descendant_cleanup_confirmed': False, 'secondary_errors': [], 'receipt_persisted': True}
                for stream in ('stdout', 'stderr'):
                    parent[stream] = {'file': f'diagnostics/{phase}.{stream}', 'bytes': 1,
                                      'truncated': False, 'sha256': 'f' * 64}
                value['phases'].append(parent)
            receipts[mode] = value
        return binding, producer, receipts

    def write_lanes(self, root, binding, producer, receipts, *, format_version=2):
        q = self.shards
        system, python = producer['os_profile'], producer['python_profile']
        for lane, modes in q.LANES.items():
            directory = root / q.result_name(binding, system, python, lane)
            directory.mkdir()
            (directory / 'producer-identity.json').write_text(json.dumps(producer))
            canonical = q.inventory_receipt(binding, producer, receipts['wheel']['behavior_test_ids'])
            (directory / 'installed-inventory.json').write_text(json.dumps(canonical))
            for mode in modes:
                (directory / f'installed-{mode}.json').write_text(json.dumps(receipts[mode]))
            q.validate_lane(directory, binding, system, python, lane, seal=True, format_version=format_version)

    def format3_fixture(self, system='ubuntu-24.04', python='3.11'):
        binding, producer, receipts = self.fixture(system, python)
        for mode, value in receipts.items():
            value['format_version'] = 3
            core = mode == 'core-only'
            if not core:
                value['schedule'] = qualifier.make_schedule(value['behavior_test_ids'], format_version=3)
                template = value['phases'][2]
                value['phases'] = value['phases'][:2] + [copy.deepcopy(template) for _ in range(4)]
            for index, phase in enumerate(value['phases']):
                name = 'sample' if core else ['inventory', 'sample', 'tests-0', 'tests-1', 'tests-2', 'tests-3'][index]
                phase['identity'].update(phase=name, schedule_sha256=(None if core or name == 'inventory'
                    else qualifier.json_digest(value['schedule'])))
                for stream in ('stdout', 'stderr'):
                    phase[stream]['file'] = f'diagnostics/{name}.{stream}'
        return binding, producer, receipts

    def test_full_cli_gate_requires_valid_windows_receipt_after_posix_results(self):
        q = self.shards
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch) / 'shards'
            root.mkdir()
            for system, python in q.PROFILES:
                binding, producer, receipts = self.format3_fixture(system, python)
                self.write_lanes(root, binding, producer, receipts, format_version=3)
            argv = ['qualification_shards', 'aggregate', '--format-version', '3', '--directory', str(root)]
            with mock.patch.object(q, 'source_binding', return_value=binding), \
                    mock.patch.object(sys, 'argv', argv), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    q.main()
            PortableReceiptTests.setUpClass()
            portable = PortableReceiptTests.portable
            receipt = PortableReceiptTests().receipt()
            receipt['binding'] = binding
            portable_directory = root.parent / 'portable-result'
            portable_directory.mkdir()
            (portable_directory / 'dist').mkdir()
            (portable_directory / 'portable-rebuilt').mkdir()
            receipt_path = portable_directory / 'windows-portable.json'
            try:
                receipt_path.write_text(json.dumps(receipt))
                output = io.StringIO()
                with mock.patch.object(q, 'source_binding', return_value=binding), \
                        mock.patch.dict(sys.modules, {'qualify_portable': portable}), \
                        mock.patch.object(portable, 'verify_artifacts', return_value={'verified_artifacts': 3}), \
                        mock.patch.object(sys, 'argv', argv + ['--portable-receipt', str(receipt_path)]), redirect_stdout(output):
                    q.main()
                self.assertEqual(json.loads(output.getvalue())['windows_portable']['tests_per_artifact'], 8)
                receipt['binding'] = dict(binding, run_attempt='999')
                receipt_path.write_text(json.dumps(receipt))
                with mock.patch.object(q, 'source_binding', return_value=binding), \
                        mock.patch.dict(sys.modules, {'qualify_portable': portable}), \
                        mock.patch.object(portable, 'verify_artifacts', return_value={'verified_artifacts': 3}), \
                        mock.patch.object(sys, 'argv', argv + ['--portable-receipt', str(receipt_path)]):
                    with self.assertRaises(ValueError):
                        q.main()
            finally:
                receipt_path.unlink(missing_ok=True)

    def test_format3_envelope2_requires_uniform_protocol_and_all_four_phases(self):
        q = self.shards
        binding, producer, receipts = self.format3_fixture()
        profile = [('ubuntu-24.04', '3.11')]
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self.write_lanes(root, binding, producer, receipts, format_version=3)
            result = q.aggregate(root, binding, profile, format_version=3)
            self.assertEqual(result['format_version'], 2)
            self.assertEqual(result['qualification_format_version'], 3)
            for lane in root.iterdir():
                envelope = json.loads((lane / 'shard.json').read_text())
                self.assertEqual(envelope['format_version'], 2)
                self.assertEqual(envelope['qualification_format_version'], 3)
            with self.assertRaises(ValueError):
                q.aggregate(root, binding, profile)  # Legacy mode never accepts format3.
            lane = root / q.result_name(binding, *profile[0], 'sdist')
            envelope = json.loads((lane / 'shard.json').read_text())
            envelope['format_version'] = 1
            envelope.pop('qualification_format_version')
            (lane / 'shard.json').write_text(json.dumps(envelope))
            with self.assertRaises(ValueError):
                q.aggregate(root, binding, profile, format_version=3)
        for fault in ('missing', 'duplicate', 'mixed', 'boolean', 'skip'):
            with self.subTest(fault=fault):
                value = copy.deepcopy(receipts['wheel'])
                if fault == 'missing':
                    value['phases'].pop()
                elif fault == 'duplicate':
                    value['phases'][5] = copy.deepcopy(value['phases'][4])
                elif fault == 'mixed':
                    value['schedule'] = qualifier.make_schedule(value['behavior_test_ids'])
                elif fault == 'boolean':
                    value['format_version'] = True
                else:
                    value['skipped_platform_cases'] = [{'test': value['behavior_test_ids'][0],
                        'reason': 'new skip', 'required_platform': 'Darwin'}]
                with self.assertRaises(ValueError):
                    q.validate_receipt(value, producer, 'wheel', format_version=3)

    def test_format3_full_matrix_requires_four_envelope2_results(self):
        q = self.shards
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            for system, python in q.PROFILES:
                binding, producer, receipts = self.format3_fixture(system, python)
                self.write_lanes(root, binding, producer, receipts, format_version=3)
            result = q.aggregate(root, binding, format_version=3)
            self.assertEqual(result['shards'], 4)
            self.assertEqual(len(result['profiles']), 2)
            self.assertEqual(result['qualification_format_version'], 3)

    def test_format3_rejects_mixed_lane_versions_even_with_valid_individual_envelopes(self):
        q = self.shards
        profile = [('ubuntu-24.04', '3.11')]
        binding, producer, receipts = self.format3_fixture()
        _, _, legacy = self.fixture()
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self.write_lanes(root, binding, producer, receipts, format_version=3)
            lane = root / q.result_name(binding, *profile[0], 'sdist')
            (lane / 'installed-sdist.json').write_text(json.dumps(legacy['sdist']))
            (lane / 'shard.json').unlink()
            q.validate_lane(lane, binding, *profile[0], 'sdist', seal=True)
            with self.assertRaises(ValueError):
                q.aggregate(root, binding, profile, format_version=3)

    def test_complete_matrix_requires_all_four_shards(self):
        q = self.shards
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            for system, python in q.PROFILES:
                binding, producer, receipts = self.fixture(system, python)
                self.write_lanes(root, binding, producer, receipts)
            result = q.aggregate(root, binding)
            self.assertTrue(result['ok'])
            self.assertEqual(result['shards'], 4)
            self.assertEqual(len(result['profiles']), 2)
            for directory in root.iterdir():
                if directory.is_dir():
                    (directory / 'shard.json').unlink()
                    break
            with self.assertRaises(ValueError):
                q.aggregate(root, binding)

    def test_receipts_refuse_omissions_duplicates_skips_and_phase_faults(self):
        q = self.shards
        _, producer, receipts = self.fixture()
        original = receipts['wheel']
        mutations = [
            lambda v: v['phases'].pop(),
            lambda v: v['phases'].append(copy.deepcopy(v['phases'][0])),
            lambda v: v['behavior_test_ids'].pop(),
            lambda v: v['behavior_test_ids'].append(v['behavior_test_ids'][0]),
            lambda v: v.update(installed_behavior_tests=2),
            lambda v: v.update(total_budget_seconds=1501),
            lambda v: v.update(source_import=True),
            lambda v: v.update(artifact_sha256='0' * 64),
            lambda v: v.update(dependency_lock_sha256='0' * 64),
            lambda v: v.update(qualification_inputs_sha256='0' * 64),
            lambda v: v.update(elapsed_seconds=float('inf')),
            lambda v: v['phases'][2]['identity'].update(schedule_sha256='0' * 64),
            lambda v: v['phases'][2].update(ok=False),
            lambda v: v['phases'][2].update(budget_seconds=601),
            lambda v: v['phases'][2]['stderr'].update(truncated=True),
            lambda v: v['skipped_platform_cases'].append({'test': v['behavior_test_ids'][0],
                'reason': 'new skip', 'required_platform': 'Darwin'}),
        ]
        q.validate_receipt(original, producer, 'wheel')
        for index, mutate in enumerate(mutations):
            with self.subTest(fault=index):
                value = copy.deepcopy(original)
                mutate(value)
                with self.assertRaises(ValueError):
                    q.validate_receipt(value, producer, 'wheel')

    def test_aggregate_refuses_missing_extra_duplicate_stale_and_tampered_results(self):
        q = self.shards
        binding, producer, receipts = self.fixture()
        profile = [('ubuntu-24.04', '3.11')]
        for fault in ('missing', 'duplicate', 'extra-file', 'stale-attempt', 'producer', 'receipt', 'envelope',
                      'boolean-envelope-version', 'boolean-inventory-version', 'boolean-producer-version', 'symlink'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                self.write_lanes(root, binding, producer, receipts)
                lane = root / q.result_name(binding, *profile[0], 'sdist')
                if fault == 'missing':
                    import shutil
                    shutil.rmtree(lane)
                elif fault == 'duplicate':
                    import shutil
                    shutil.copytree(lane, root / 'duplicate')
                elif fault == 'extra-file':
                    (lane / 'unexpected.json').write_text('{}')
                elif fault == 'stale-attempt':
                    binding = binding | {'run_attempt': '3'}
                elif fault in ('producer', 'receipt', 'envelope', 'boolean-envelope-version',
                               'boolean-inventory-version', 'boolean-producer-version'):
                    path = lane / {'producer': 'producer-identity.json', 'receipt': 'installed-sdist.json',
                        'envelope': 'shard.json', 'boolean-envelope-version': 'shard.json',
                        'boolean-inventory-version': 'installed-inventory.json',
                        'boolean-producer-version': 'producer-identity.json'}[fault]
                    value = json.loads(path.read_text())
                    if fault == 'producer':
                        value['artifacts'][q.ARTIFACTS['wheel']] = '0' * 64
                    elif fault == 'receipt':
                        value['events'] += 1
                    elif fault == 'envelope':
                        value['lane'] = 'wheel-core'
                    else:
                        value['format_version'] = True
                    path.write_text(json.dumps(value))
                else:
                    path = lane / 'installed-sdist.json'
                    raw = path.read_text()
                    path.unlink()
                    target = root / 'linked.json'
                    target.write_text(raw)
                    path.symlink_to(target)
                with self.assertRaises(ValueError):
                    q.aggregate(root, binding, profile)
                binding, _, _ = self.fixture()

    def test_even_resealed_sdist_cannot_change_inventory_or_producer(self):
        q = self.shards
        profile = [('ubuntu-24.04', '3.11')]
        for fault in ('inventory', 'producer'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                binding, producer, receipts = self.fixture()
                self.write_lanes(root, binding, producer, receipts)
                lane = root / q.result_name(binding, *profile[0], 'sdist')
                (lane / 'shard.json').unlink()
                if fault == 'producer':
                    producer['artifacts'][q.ARTIFACTS['wheel']] = '0' * 64
                    (lane / 'producer-identity.json').write_text(json.dumps(producer))
                    canonical = q.inventory_receipt(binding, producer, receipts['wheel']['behavior_test_ids'])
                    (lane / 'installed-inventory.json').write_text(json.dumps(canonical))
                else:
                    receipt = receipts['sdist']
                    receipt['behavior_test_ids'] = receipt['behavior_test_ids'][:2]
                    receipt['schedule'] = qualifier.make_schedule(receipt['behavior_test_ids'])
                    receipt['installed_behavior_tests'] = 2
                    for phase in receipt['phases'][1:]:
                        phase['identity']['schedule_sha256'] = qualifier.json_digest(receipt['schedule'])
                    (lane / 'installed-sdist.json').write_text(json.dumps(receipt))
                if fault == 'inventory':
                    with self.assertRaises(ValueError):
                        q.validate_lane(lane, binding, *profile[0], 'sdist', seal=True)
                    continue
                q.validate_lane(lane, binding, *profile[0], 'sdist', seal=True)
                with self.assertRaises(ValueError):
                    q.aggregate(root, binding, profile)


class QualificationFormat3Tests(unittest.TestCase):
    def test_four_batch_golden_and_legacy_rule_remain_distinct(self):
        groups = {name: [f'test_{name}.Cases.test_{i:02d}' for i in range(count)]
                  for name, count in zip('abcdefgh', (8, 7, 6, 5, 4, 3, 2, 1))}
        ids = sum(groups.values(), [])
        expected = {'format_version': 3, 'rule': 'whole-modules-count-desc-greedy-four-v3',
            'inventory_sha256': qualifier.json_digest(sorted(ids)),
            'batches': [groups['a'] + groups['h'], groups['b'] + groups['g'],
                        groups['c'] + groups['f'], groups['d'] + groups['e']]}
        self.assertEqual(qualifier.make_schedule(ids, format_version=3), expected)
        self.assertEqual(qualifier.make_schedule(list(reversed(ids)), format_version=3), expected)
        self.assertEqual([len(batch) for batch in expected['batches']], [9] * 4)
        qualifier.check_schedule(expected, format_version=3)
        self.assertEqual(qualifier.make_schedule(ids)['format_version'], 2)
        self.assertEqual(len(qualifier.make_schedule(ids)['batches']), 2)
        with self.assertRaises(ValueError):
            qualifier.check_schedule(expected)

    def test_four_batch_closed_schedule_and_version_faults_fail(self):
        ids = [f'test_{name}.C.test_x' for name in 'abcdefgh']
        schedule = qualifier.make_schedule(ids, format_version=3)
        for version in (True, False, 1, 4, 3.0, '3', None):
            with self.subTest(version=version), self.assertRaises(ValueError):
                qualifier.make_schedule(ids, format_version=version)
        for fault in ('version', 'boolean', 'rule', 'missing', 'duplicate', 'order', 'digest', 'extra'):
            value = copy.deepcopy(schedule)
            if fault == 'version': value['format_version'] = 2
            elif fault == 'boolean': value['format_version'] = True
            elif fault == 'rule': value['rule'] = 'whole-modules-count-desc-greedy-two-v2'
            elif fault == 'missing': value['batches'].pop()
            elif fault == 'duplicate': value['batches'][1] = value['batches'][0]
            elif fault == 'order': value['batches'][0].reverse()
            elif fault == 'digest': value['inventory_sha256'] = '0' * 64
            else: value['unreviewed'] = True
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                qualifier.check_schedule(value, format_version=3)

    def test_four_phase_accounting_requires_every_disjoint_assignment(self):
        ids = [f'test_{name}.C.test_x' for name in 'abcd']
        schedule = qualifier.make_schedule(ids, format_version=3)
        good = [{'test_ids': batch, 'outcomes': {i: 'passed' for i in batch},
                 'skipped_platform_cases': []} for batch in schedule['batches']]
        self.assertEqual(qualifier.validate_test_accounting(schedule, good, 'darwin'), (4, []))
        for bad in (good[:3], good + [good[0]], [good[0], good[1], good[2], good[2]]):
            with self.assertRaises(ValueError):
                qualifier.validate_test_accounting(schedule, bad, 'darwin')

    def test_actual_child_selection_runs_each_four_batch_test_exactly_once(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            (work / 'diagnostics').mkdir()
            tests = work / 'installed-tests'
            tests.mkdir()
            for name in 'abcd':
                (tests / f'test_format3_toy_{name}.py').write_text(
                    'import unittest\nclass Cases(unittest.TestCase):\n def test_x(self): self.assertEqual(2+2,4)\n')
            lock = work / 'requirements-dev.lock'
            lock.write_text('synthetic locked input\n')
            schedule = None
            executed = []
            original_path = sys.path[:]
            try:
                with mock.patch.object(Path, 'cwd', return_value=work), \
                     mock.patch.object(qualifier, 'installed_context', return_value=lambda: {'package': 'frozen'}), \
                     mock.patch.object(qualifier, 'verify_harness'), redirect_stderr(io.StringIO()):
                    for phase in ['inventory', 'tests-0', 'tests-1', 'tests-2', 'tests-3']:
                        identity = {'phase': phase, 'artifact_sha256': 'a' * 64, 'harness_sha256': 'b' * 64,
                            'lock_sha256': hashlib.sha256(lock.read_bytes()).hexdigest(),
                            'schedule_sha256': None if schedule is None else qualifier.json_digest(schedule)}
                        phase_input = work / 'phase-input.json'
                        phase_input.write_text(json.dumps({'identity': identity, 'schedule': schedule}))
                        args = type('Args', (), {'phase_input': str(phase_input), 'format_version': 3})()
                        receipt = qualifier.child_phase(args)
                        payload = qualifier.validate_phase(receipt, identity, format_version=3)
                        if phase == 'inventory': schedule = payload['schedule']
                        else: executed.extend(payload['test_ids'])
                        with self.assertRaises(ValueError): qualifier.validate_phase(receipt, identity)
                self.assertEqual(len(executed), 4)
                self.assertEqual(len(set(executed)), 4)
                self.assertEqual(sorted(executed), sorted(sum(schedule['batches'], [])))
            finally:
                sys.path[:] = original_path
                for name in 'abcd': sys.modules.pop(f'test_format3_toy_{name}', None)

    def test_additional_phase_protocol_and_public_safe_export_are_version_bound(self):
        ids = [f'test_{name}.C.test_x' for name in 'abcd']
        schedule = qualifier.make_schedule(ids, format_version=3)
        identity = {'phase': 'tests-3', 'artifact_sha256': 'a' * 64, 'harness_sha256': 'b' * 64,
                    'lock_sha256': 'c' * 64, 'schedule_sha256': qualifier.json_digest(schedule)}
        payload = {'test_ids': schedule['batches'][3],
            'outcomes': {i: 'passed' for i in schedule['batches'][3]}, 'skipped_platform_cases': [],
            'package_snapshot_sha256': 'd' * 64}
        receipt = qualifier.phase_receipt(identity, payload, format_version=3)
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            (work / 'diagnostics').mkdir()
            progress = qualifier.Progress(work / 'diagnostics/tests-3.progress.jsonl', 'tests-3')
            progress.emit('phase-start')
            for test in payload['test_ids']:
                progress.emit('test-start', test=test)
                progress.emit('test-outcome', test=test, outcome='passed')
                progress.emit('test-stop', test=test)
            progress.emit('phase-stop', outcome='passed')
            command = [sys.executable, '-c', 'print(' + repr(json.dumps(receipt)) + ')']
            with self.assertRaises(ValueError):
                qualifier.run_phase(command, cwd=work, env=qualifier.clean_environment(), identity=identity, timeout=2)
            actual, parent = qualifier.run_phase(command, cwd=work, env=qualifier.clean_environment(),
                identity=identity, timeout=2, format_version=3)
            self.assertEqual(actual, payload)
            self.assertTrue(parent['direct_child_reaped'])
            output = work / 'export'
            qualifier.export_evidence(work, output, schedule, format_version=3)
            self.assertTrue((output / 'tests-3.parent.json').is_file())
            self.assertTrue((output / 'tests-3.expected.json').is_file())
            self.assertEqual(json.loads((output / 'discovered-inventory.json').read_text()), schedule)


class DistributionTests(unittest.TestCase):
    def test_autocrlf_npm_launcher_stays_identical_after_offline_pack_and_install(self):
        """Real local npm bin linking preserves hashes only with an LF shebang.

        The CRLF baseline demonstrates npm's mutation; it does not establish
        the bytes of any previously failed Windows CI archive.
        """
        node, npm = shutil.which('node'), shutil.which('npm')
        if not node or not npm:
            self.skipTest('Node and npm are required for the offline own-package regression')
        node_path, npm_path = Path(node).resolve(), Path(npm).resolve()
        candidates = [npm_path if npm_path.name == 'npm-cli.js' else None,
                      node_path.parent / 'node_modules/npm/bin/npm-cli.js',
                      node_path.parent.parent / 'lib/node_modules/npm/bin/npm-cli.js']
        npm_cli = next((p for p in candidates if p is not None and p.is_file()), None)
        if npm_cli is None:
            self.skipTest('The existing npm CLI JavaScript entrypoint is unavailable')
        source = Path(__file__).resolve().parents[1]
        relative = 'packages/npm/cli/bin/taskalong.js'
        canonical = (source / relative).read_bytes()
        self.assertTrue(canonical.startswith(b'#!/usr/bin/env node\n'))
        self.assertNotIn(b'\r\n', canonical)
        with tempfile.TemporaryDirectory(prefix='taskalong-npm-bin-eol-') as directory:
            root = Path(directory)
            package = root / 'packages/npm/cli'
            (package / 'bin').mkdir(parents=True)
            script = root / relative
            script.write_bytes(canonical)
            (package / 'package.json').write_text(json.dumps({
                'name': 'taskalong-bin-eol-fixture', 'version': '1.0.0',
                'bin': {'taskalong-bin-eol-fixture': 'bin/taskalong.js'},
                'files': ['bin/taskalong.js']}), encoding='utf-8')
            user, global_config = root / 'user.npmrc', root / 'global.npmrc'
            user.write_bytes(b'')
            global_config.write_bytes(b'')
            environment = {k: v for k, v in os.environ.items() if not k.upper().startswith('NPM_CONFIG_')
                           and k not in {'NODE_AUTH_TOKEN', 'NPM_TOKEN'}}
            environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_ATTR_NOSYSTEM='1',
                NPM_CONFIG_USERCONFIG=str(user), NPM_CONFIG_GLOBALCONFIG=str(global_config),
                NPM_CONFIG_CACHE=str(root / 'cache'), NPM_CONFIG_UPDATE_NOTIFIER='false')
            def git(*args):
                return subprocess.run(['git', '-c', 'core.attributesFile=' + os.devnull, *args],
                    cwd=root, env=environment, capture_output=True, check=True, timeout=15)
            def npm_run(*args):
                return subprocess.run([str(node_path), str(npm_cli), *args], cwd=package,
                    env=environment, capture_output=True, check=True, timeout=30)
            def pack_and_install(label):
                packed, prefix = root / ('packed-' + label), root / ('prefix-' + label)
                packed.mkdir()
                npm_run('pack', '.', '--offline', '--ignore-scripts', '--pack-destination', str(packed))
                archives = list(packed.glob('*.tgz'))
                self.assertEqual(len(archives), 1)
                with tarfile.open(archives[0]) as archive:
                    archived = archive.extractfile('package/bin/taskalong.js').read()
                npm_run('install', '--prefix', str(prefix), '--offline', '--ignore-scripts', '--no-audit',
                    '--no-fund', '--no-update-notifier', '--no-package-lock', str(archives[0]))
                installed = (prefix / 'node_modules/taskalong-bin-eol-fixture/bin/taskalong.js').read_bytes()
                return archived, installed

            git('init', '-q')
            git('-c', 'core.autocrlf=false', 'add', relative)
            script.unlink()
            git('-c', 'core.autocrlf=true', 'checkout-index', '-f', '--', relative)
            converted = script.read_bytes()
            self.assertEqual(converted, canonical.replace(b'\n', b'\r\n'))
            archived, installed = pack_and_install('crlf')
            self.assertEqual(archived, converted)
            self.assertEqual(installed, converted.replace(b'\r\n', b'\n', 1))
            self.assertNotEqual(hashlib.sha256(installed).hexdigest(), hashlib.sha256(archived).hexdigest())

            (root / '.gitattributes').write_bytes((source / '.gitattributes').read_bytes())
            git('-c', 'core.autocrlf=true', 'add', '.gitattributes')
            script.unlink()
            git('-c', 'core.autocrlf=true', 'checkout-index', '-f', '--', relative)
            self.assertEqual(script.read_bytes(), canonical)
            archived, installed = pack_and_install('lf')
            self.assertEqual(archived, canonical)
            self.assertEqual(installed, archived)
            self.assertEqual(hashlib.sha256(installed).hexdigest(), hashlib.sha256(archived).hexdigest())

    def test_autocrlf_checkout_keeps_approved_license_bytes_in_built_wheel(self):
        """Fresh Git checkout, actual offline wheel build, unchanged strict audit.

        This reproduces autocrlf conversion, not the Windows runner's unknown
        initial/index state after its separate checkout-index correction.
        """
        source = Path(__file__).resolve().parents[1]
        notice = (source / 'LICENSE').read_bytes()
        self.assertEqual(hashlib.sha256(notice).hexdigest(), auditor.APPROVED_LICENSE_SHA256)
        with tempfile.TemporaryDirectory(prefix='taskalong-license-eol-') as directory:
            root = Path(directory)
            environment = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                               GIT_ATTR_NOSYSTEM='1', PIP_NO_INDEX='1')
            def git(*args):
                return subprocess.run(['git', '-c', 'core.attributesFile=' + os.devnull, *args],
                    cwd=root, env=environment, capture_output=True, check=True, timeout=15)
            git('init', '-q')
            (root / 'LICENSE').write_bytes(notice)
            git('-c', 'core.autocrlf=false', 'add', 'LICENSE')
            package = root / 'src' / 'taskalong'
            package.mkdir(parents=True)
            (package / '__init__.py').write_bytes(b'')
            (root / 'pyproject.toml').write_text('''[build-system]
requires = ["setuptools>=77,<85"]
build-backend = "setuptools.build_meta"
[project]
name = "taskalong"
version = "0.1.0a1"
requires-python = ">=3.11,<3.15"
dependencies = ["jsonschema>=4.26,<5"]
license = "MIT"
license-files = ["LICENSE"]
[project.optional-dependencies]
review = ["review-sensei==0.8.8"]
[project.scripts]
taskalong = "taskalong.cli:main"
[tool.setuptools]
package-dir = {"" = "src"}
packages = ["taskalong"]
''', encoding='utf-8')
            inventory = {'wheel_sources': ['src/taskalong/__init__.py']}
            def build(label):
                output = root / label
                subprocess.run([sys.executable, '-c',
                    'from setuptools.build_meta import build_wheel; import sys; build_wheel(sys.argv[1])', str(output)],
                    cwd=root, env=environment, capture_output=True, check=True, timeout=45)
                return output / 'taskalong-0.1.0a1-py3-none-any.whl'

            (root / 'LICENSE').unlink()
            git('-c', 'core.autocrlf=true', 'checkout-index', '-f', '--', 'LICENSE')
            converted = (root / 'LICENSE').read_bytes()
            self.assertEqual(converted, notice.replace(b'\n', b'\r\n'))
            before = build('before-attributes')
            with self.assertRaisesRegex(auditor.AuditError, 'wheel license differs from the approved MIT notice'):
                auditor.audit(before, root=root, inventory=inventory)

            (root / '.gitattributes').write_bytes((source / '.gitattributes').read_bytes())
            git('-c', 'core.autocrlf=true', 'add', '.gitattributes')
            (root / 'LICENSE').unlink()
            git('-c', 'core.autocrlf=true', 'checkout-index', '-f', '--', 'LICENSE')
            self.assertEqual((root / 'LICENSE').read_bytes(), notice)
            after = build('with-attributes')
            self.assertEqual(auditor.read_wheel(after)[f'{auditor.DIST_INFO}/licenses/LICENSE'], notice)
            self.assertEqual(auditor.audit(after, root=root, inventory=inventory)['artifact'], 'wheel')

            (root / 'LICENSE').write_bytes(notice + b'Unapproved additional notice.\n')
            changed = build('changed-notice')
            with self.assertRaisesRegex(auditor.AuditError, 'wheel license differs from the approved MIT notice'):
                auditor.audit(changed, root=root, inventory=inventory)

    def test_runtime_inventory_binds_installed_wheel_and_original_artifact_separately(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "work"
            (work / "tools").mkdir(parents=True)
            (work / "installed-tests" / "fixtures").mkdir(parents=True)
            (work / "tools" / "qualify_runtime.py").write_bytes(b"reviewed runner")
            (work / "installed-tests" / "fixtures" / "runtime_canary.py").write_bytes(b"original finite helper")
            (work / "requirements-dev.lock").write_bytes(b"original lock")
            wheel = root / "taskalong.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("taskalong/runtime_qualification.py", b"original reader")
                archive.writestr("taskalong-0.1.0a1.dist-info/METADATA", b"Name: taskalong\nVersion: 0.1.0a1\n")
            with mock.patch.dict(sys.modules, {"check_dist": auditor}):
                expected = qualifier.freeze_runtime_inventory(wheel, work, source_digest="a" * 64, source_kind="sdist")
            value = json.loads((work / "runtime-artifact-inventory.json").read_bytes())
            self.assertEqual(value["artifact_digest"], hashlib.sha256(wheel.read_bytes()).hexdigest())
            self.assertEqual(value["source_artifact_digest"], "a" * 64)
            self.assertEqual(value["source_artifact_kind"], "sdist")
            self.assertEqual(value["payloads"], {"taskalong/runtime_qualification.py": {
                "sha256": hashlib.sha256(b"original reader").hexdigest(), "size_bytes": len(b"original reader")}})
            self.assertEqual(expected, hashlib.sha256((work / "runtime-artifact-inventory.json").read_bytes()).hexdigest())

    def test_installed_schedule_balances_complete_modules_with_explicit_version(self):
        groups = {name: [f'test_{name}.Cases.test_{index:02d}' for index in range(count)]
                  for name, count in [('a', 8), ('b', 7), ('c', 6), ('d', 5)]}
        ids = sum(groups.values(), [])
        expected = {'format_version': 2, 'rule': 'whole-modules-count-desc-greedy-two-v2',
                    'inventory_sha256': qualifier.json_digest(sorted(ids)),
                    'batches': [groups['a'] + groups['d'], groups['b'] + groups['c']]}
        self.assertEqual(qualifier.make_schedule(ids), expected)
        self.assertEqual(qualifier.make_schedule(list(reversed(ids))), expected)
        self.assertEqual([len(batch) for batch in expected['batches']], [13, 13])

    def test_installed_schedule_ties_and_small_inventories_preserve_lexical_execution(self):
        groups = {name: [f'test_{name}.Cases.test_{index:02d}' for index in range(count)]
                  for name, count in [('d', 1), ('b', 2), ('a', 2), ('c', 1)]}
        ids = sum(groups.values(), [])
        self.assertEqual(qualifier.make_schedule(ids)['batches'],
                         [groups['a'] + groups['c'], groups['b'] + groups['d']])
        self.assertEqual(qualifier.make_schedule(groups['b'])['batches'], [groups['b'], []])
        self.assertEqual(qualifier.make_schedule(groups['c'] + groups['d'])['batches'],
                         [groups['c'], groups['d']])
        unequal = ['test_z.C.test_a', 'test_z.C.test_b', 'test_a.C.test_z']
        self.assertEqual(qualifier.make_schedule(unequal)['batches'], [unequal[:2], unequal[2:]])
        priority = {name: [f'test_{name}.Cases.test_{index:02d}' for index in range(count)]
                    for name, count in [('z', 8), ('a', 7), ('y', 6), ('b', 5)]}
        self.assertEqual(qualifier.make_schedule(sum(priority.values(), []))['batches'],
                         [priority['b'] + priority['z'], priority['a'] + priority['y']])

    def test_new_schedule_rejects_legacy_rule_inventory_and_order_substitution(self):
        ids = ['test_a.C.test_a', 'test_a.C.test_b', 'test_b.C.test_a']
        expected = {'format_version': 2, 'rule': 'whole-modules-count-desc-greedy-two-v2',
                    'inventory_sha256': qualifier.json_digest(ids), 'batches': [ids[:2], ids[2:]]}
        identity = {'phase': 'inventory'}
        payload = {'schedule': expected, 'package_snapshot_sha256': 'a' * 64}
        self.assertEqual(qualifier.validate_phase(qualifier.phase_receipt(identity, payload), identity), payload)
        variants = [dict(expected, format_version=1, rule='sorted-modules-alternating-two-v1'),
                    dict(expected, rule='unreviewed-rule'), dict(expected, inventory_sha256='b' * 64),
                    dict(expected, batches=[list(reversed(ids[:2])), ids[2:]]),
                    dict(expected, batches=[ids[2:], ids[:2]]),
                    dict(expected, batches=[ids[:1], ids[2:]]),
                    dict(expected, batches=[ids[:2] + ids[:1], ids[2:]]),
                    dict(expected, batches=[ids[:2], ['test_other.C.test_a']])]
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                qualifier.validate_phase(qualifier.phase_receipt(identity, dict(payload, schedule=changed)), identity)

    def test_installed_schedule_is_fixed_disjoint_and_module_preserving(self):
        ids = ['test_b.C.test_z', 'test_a.C.test_y', 'test_a.C.test_x', 'test_c.C.test_x']
        schedule = qualifier.make_schedule(ids)
        self.assertEqual(schedule, qualifier.make_schedule(list(reversed(ids))))
        self.assertEqual(sorted(sum(schedule['batches'], [])), sorted(ids))
        self.assertTrue(any({'test_a.C.test_y', 'test_a.C.test_x'} <= set(batch) for batch in schedule['batches']))
        for invalid in (ids + [ids[0]], ['unittest.loader._FailedTest.bad'], []):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                qualifier.make_schedule(invalid)

    def test_phase_terminal_identity_and_closed_shape_are_required(self):
        identity = {'phase': 'probe', 'artifact_sha256': 'a' * 64}
        value = qualifier.phase_receipt(identity, {'ok': True})
        self.assertEqual(qualifier.validate_phase(value, identity), {'ok': True})
        for changed in ({}, dict(value, identity={'phase': 'other'}), dict(value, extra=True), dict(value, ok=False)):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                qualifier.validate_phase(changed, identity)

    def test_phase_timeout_retains_progress_and_bounded_streams_and_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = "import sys,time;print('progress',file=sys.stderr,flush=True);time.sleep(10)"
            with self.assertRaises(qualifier.PhaseFailure) as caught:
                qualifier.run_phase([sys.executable, '-c', code], cwd=root,
                    env=qualifier.clean_environment(), identity={'phase': 'probe'}, timeout=.15)
            receipt = caught.exception.receipt
            self.assertFalse(receipt['ok'])
            self.assertEqual(receipt['failure'], 'timeout')
            self.assertTrue(receipt['direct_child_reaped'])
            self.assertFalse(receipt['descendant_cleanup_confirmed'])
            self.assertIn(b'progress', (root / receipt['stderr']['file']).read_bytes())

    def test_phase_payload_is_closed_and_sample_cannot_claim_false_success(self):
        package_sha = 'd' * 64
        schedule = qualifier.make_schedule(['test_a.C.test_x', 'test_b.C.test_y'])
        good = {'schedule': schedule, 'package_snapshot_sha256': package_sha}
        identity = {'phase': 'inventory'}
        self.assertEqual(qualifier.validate_phase(qualifier.phase_receipt(identity, good), identity), good)
        for payload in (dict(good, extra='unreviewed'), dict(good, package_snapshot_sha256='invalid'),
                        {'journey': {'ok': False}, 'package_snapshot_sha256': package_sha}):
            phase = 'sample' if 'journey' in payload else 'inventory'
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                qualifier.validate_phase(qualifier.phase_receipt({'phase': phase}, payload), {'phase': phase})

    def test_frozen_installed_harness_and_fixture_aliases_cannot_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'source'
            work = Path(directory) / 'work'
            root.mkdir(); work.mkdir()
            files = {'tools/qualify_installed.py': b'original qualifier', 'requirements-dev.lock': b'original lock',
                     'tools/qualify_runtime.py': b'original runtime qualifier',
                     'tests/fixtures/fake_codex.py': b'original worker', 'tests/fixtures/fake_gh.py': b'original boundary',
                     'tests/test_a.py': b'original test'}
            for name, data in files.items():
                target = root / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
            (root / 'distribution-inventory.json').write_text(json.dumps({'sdist_sources': sorted(files)}))
            expected = qualifier.snapshot_harness(root, work)
            qualifier.verify_harness(work, expected)
            for relative in ('qualify_installed.py', 'requirements-dev.lock', 'installed-tests/test_a.py',
                             'tools/qualify_runtime.py',
                             'installed-tests/fixtures/fake_codex.py', 'fixtures/fake_codex.py'):
                path = work / relative; original = path.read_bytes(); path.write_bytes(b'changed')
                with self.subTest(path=relative), self.assertRaises(ValueError):
                    qualifier.verify_harness(work, expected)
                path.write_bytes(original)
            (work / 'installed-tests/test_extra.py').write_bytes(b'new test')
            with self.assertRaises(ValueError):
                qualifier.verify_harness(work, expected)

    def test_evidence_export_excludes_arbitrary_json_and_private_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); work = root / 'work'; work.mkdir()
            diagnostics = work / 'diagnostics'; diagnostics.mkdir()
            (diagnostics / 'private.json').write_text('{"private":"synthetic private state"}')
            qualifier.Progress(diagnostics / 'sample.progress.jsonl', 'sample').emit('phase-start')
            output = root / 'public'
            qualifier.export_evidence(work, output, None)
            self.assertFalse((output / 'private.json').exists())
            self.assertIn('sample.progress.jsonl', {p.name for p in output.iterdir()})
            (diagnostics / 'sample.progress.jsonl').write_text('{"private":"synthetic state"}\n')
            with self.assertRaises(ValueError):
                qualifier.export_evidence(work, root / 'rejected', None)
            row = {'sequence': 1, 'elapsed_seconds': 0.0, 'phase': 'sample', 'event': 'phase-start', 'test': None, 'outcome': None}
            (diagnostics / 'sample.progress.jsonl').write_text(json.dumps(row) + '\n{"partial":')
            qualifier.export_evidence(work, root / 'partial', None)
            self.assertEqual(json.loads((root / 'partial/sample.progress.jsonl').read_text()), row)
            self.assertTrue(json.loads((root / 'partial/sample.progress-summary.json').read_text())['partial_tail_omitted'])

    def test_phase_nonzero_missing_duplicate_and_output_overflow_never_pass(self):
        identity = {'phase': 'probe'}
        value = json.dumps(qualifier.phase_receipt(identity, {'ok': True}))
        codes = ["import sys;print('private diagnostic',file=sys.stderr);sys.exit(3)",
                 "print('{}')", f"print({value!r});print({value!r})",
                 "import sys;sys.stdout.write('x'*1000000);sys.stdout.flush()"]
        for code in codes:
            with self.subTest(code=code[:30]), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(qualifier.PhaseFailure) as caught:
                    qualifier.run_phase([sys.executable, '-c', code], cwd=Path(directory),
                        env=qualifier.clean_environment(), identity=identity, timeout=2, stream_limit=4096)
                self.assertFalse(caught.exception.receipt['ok'])
                self.assertLessEqual(caught.exception.receipt['stdout']['bytes'], 4096)

    def test_phase_cleanup_fault_preserves_timeout_and_no_private_exception_text(self):
        real_popen = subprocess.Popen
        waits = []
        owned = []
        class FaultyWait:
            def __init__(self, child): self.child = child
            def __getattr__(self, name): return getattr(self.child, name)
            def wait(self, *, timeout):
                waits.append(timeout)
                raise OSError(5, 'SYNTHETIC_PRIVATE_EXCEPTION')
        def spawn(*args, **kwargs):
            child = real_popen(*args, **kwargs); owned.append(child); return FaultyWait(child)
        try:
            with tempfile.TemporaryDirectory() as directory, mock.patch.object(qualifier.subprocess, 'Popen', side_effect=spawn):
                with self.assertRaises(qualifier.PhaseFailure) as caught:
                    qualifier.run_phase([sys.executable, '-c', 'import time;time.sleep(10)'], cwd=Path(directory),
                        env=qualifier.clean_environment(), identity={'phase': 'probe'}, timeout=.05)
                receipt = caught.exception.receipt
                self.assertEqual(receipt['failure'], 'timeout')
                self.assertFalse(receipt['direct_child_reaped'])
                self.assertTrue(receipt['secondary_errors'])
                self.assertNotIn('SYNTHETIC_PRIVATE_EXCEPTION', json.dumps(receipt))
                self.assertLessEqual(len(waits), 2)
                self.assertTrue(all(0 < timeout <= 3 for timeout in waits))
        finally:
            for child in owned:
                if child.poll() is None: child.kill()
                child.wait(timeout=3)

    def test_phase_diagnostic_read_error_keeps_other_cleanup_and_unavailable_hash(self):
        read = Path.read_bytes
        seen = []
        def fail_one(path):
            seen.append(path.name)
            if path.name == 'probe.stdout': raise OSError(5, 'SYNTHETIC_PRIVATE_EXCEPTION')
            return read(path)
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(Path, 'read_bytes', fail_one):
            with self.assertRaises(qualifier.PhaseFailure) as caught:
                qualifier.run_phase([sys.executable, '-c', 'print("{}")'], cwd=Path(directory),
                    env=qualifier.clean_environment(), identity={'phase': 'probe'}, timeout=2)
            receipt = caught.exception.receipt
            self.assertFalse(receipt['ok'])
            self.assertIsNone(receipt['stdout']['sha256'])
            self.assertIn('probe.stderr', seen)
            self.assertTrue(receipt['direct_child_reaped'])
            self.assertNotIn('SYNTHETIC_PRIVATE_EXCEPTION', json.dumps(receipt))

    def test_export_failure_preserves_primary_phase_failure(self):
        primary = qualifier.PhaseFailure({'ok': False, 'failure': 'timeout', 'secondary_errors': []})
        with mock.patch.object(qualifier, 'export_evidence', side_effect=OSError(5, 'SYNTHETIC_PRIVATE_EXCEPTION')):
            qualifier.finalize_export(Path('.'), Path('unused'), None, reservation=None, primary=primary, completed=None)
        self.assertEqual(primary.receipt['failure'], 'timeout')
        self.assertEqual(primary.receipt['secondary_errors'], [{'stage': 'evidence_export', 'errno': 5}])
        self.assertNotIn('SYNTHETIC_PRIVATE_EXCEPTION', json.dumps(primary.receipt))

    def test_failed_receipt_persistence_keeps_in_memory_failure_and_no_durable_claim(self):
        identity = {'phase': 'probe'}
        value = json.dumps(qualifier.phase_receipt(identity, {'ok': True}))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(qualifier, 'write_json', side_effect=OSError(28, 'SYNTHETIC_PRIVATE_EXCEPTION')):
            with self.assertRaises(qualifier.PhaseFailure) as caught:
                qualifier.run_phase([sys.executable, '-c', f'print({value!r})'], cwd=Path(directory),
                    env=qualifier.clean_environment(), identity=identity, timeout=2)
            self.assertFalse(caught.exception.receipt['ok'])
            self.assertFalse(caught.exception.receipt['receipt_persisted'])
            self.assertIn({'stage': 'persist_receipt', 'errno': 28}, caught.exception.receipt['secondary_errors'])

    def test_existing_export_destination_refuses_before_setup(self):
        import argparse
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(qualifier, 'create_environment') as create:
            with self.assertRaises(FileExistsError):
                qualifier.qualify(argparse.Namespace(evidence_dir=Path(directory)))
            create.assert_not_called()

    def test_phase_success_is_exactly_one_json_and_has_private_diagnostics(self):
        identity = {'phase': 'probe'}
        value = json.dumps(qualifier.phase_receipt(identity, {'ok': True}))
        with tempfile.TemporaryDirectory() as directory:
            payload, receipt = qualifier.run_phase([sys.executable, '-c', f'print({value!r})'],
                cwd=Path(directory), env=qualifier.clean_environment(), identity=identity, timeout=2)
            self.assertEqual(payload, {'ok': True})
            self.assertTrue(receipt['ok'])
            self.assertTrue(receipt['direct_child_reaped'])

    def test_progress_records_test_cleanup_completion_separately(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'progress.jsonl'
            progress = qualifier.Progress(path, 'tests-0')
            class Sample(unittest.TestCase):
                def test_cleanup(self):
                    self.addCleanup(lambda: progress.emit('cleanup-observed', test=self.id()))
            result = qualifier.ProgressResult(io.StringIO(), True, 0, progress=progress)
            unittest.TestSuite([Sample('test_cleanup')]).run(result)
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([row['event'] for row in rows], ['test-start', 'cleanup-observed', 'test-outcome', 'test-stop'])
            self.assertEqual([row['sequence'] for row in rows], list(range(1, 5)))

    def test_linux_accounting_accepts_only_exact_owned_signal_skip_cases(self):
        required = {
            'test_linux_lifetime.UnsupportedLifetimeTests.test_non_linux_helper_never_releases_target': 'non-Linux refusal',
            'test_supervisor.ProcessTests.test_unavailable_kernel_lifetime_boundary_never_releases_target': 'Darwin kernel boundary fault injection',
            'test_supervisor.ProcessTests.test_denied_owned_signals_return_unknown_before_finite_child_exits': 'Darwin owned signal denial',
            'test_supervisor.ProcessTests.test_signal_denial_after_real_exit_still_requires_kernel_cessation': 'Darwin owned signal exit race',
            'test_supervisor.ProcessTests.test_later_signal_denials_preserve_failure_and_real_lifetime_facts': 'Darwin owned signal fault campaign',
            'test_supervisor.ProcessTests.test_ownership_query_denial_cannot_authorize_a_signal': 'Darwin owned identity query denial',
            'test_supervisor.ProcessTests.test_final_signal_denial_does_not_replace_primary_observation_failure': 'Darwin final cleanup fault campaign',
            'test_claude_driver.ClaudeDriverBoundaryTests.test_malformed_provider_with_denied_signal_is_typed_failure_even_after_cessation': 'Darwin actual driver signal denial',
            'test_foreground_experiment.ForegroundExperimentTests.test_fork_wait_rapid_exit_and_session_escape_keep_descendants_unknown': 'Darwin foreground experiment processes',
            'test_foreground_experiment.ForegroundExperimentTests.test_empty_argument_is_preserved_through_foreground_owner': 'Darwin foreground experiment processes',
            'test_foreground_experiment.ForegroundExperimentTests.test_timeout_cancellation_and_output_limit_use_owned_cleanup': 'Darwin foreground experiment processes',
            'test_foreground_experiment.ForegroundExperimentTests.test_tracking_failure_stays_separate_and_never_releases_a_refused_gate': 'Darwin foreground experiment tracking faults',
            'test_muse_capture_envelope.EnvelopeTests.test_four_mib_combined_bound_and_large_protocol_line': 'Real foreground owner is Darwin-only',
            'test_muse_capture_envelope.EnvelopeTests.test_real_python_callback_cancellation_without_provider': 'Real foreground owner is Darwin-only',
                   'test_muse_native_stop_process.NativeStopProcessTests.test_timeout_then_queued_second_task_stops_and_preserves_receipt': 'Real foreground owner is Darwin-only',
                   'test_muse_native_stop_process.NativeStopProcessTests.test_second_task_without_timeout_requests_owned_stop': 'Real foreground owner is Darwin-only',
                   'test_muse_native_stop_process.NativeStopProcessTests.test_valid_one_task_child_exits_normally': 'Real foreground owner is Darwin-only',
                   'test_muse_native_stop_process.NativeStopProcessTests.test_malformed_row_requests_owned_stop_without_callback_exception': 'Real foreground owner is Darwin-only',
                   'test_muse_native_stop_process.NativeStopProcessTests.test_record_budget_failure_retains_receipt_and_raw_capture': 'Real foreground owner is Darwin-only',
        }
        ordinary = 'test_ordinary.Case.test_required_behavior'
        schedule = qualifier.make_schedule([*required, ordinary])
        results = [{'test_ids': batch,
                    'outcomes': {i: 'skipped' if i in required else 'passed' for i in batch},
                    'skipped_platform_cases': [{'test': i, 'reason': required[i], 'required_platform': 'Darwin'}
                                               for i in batch if i in required]}
                   for batch in schedule['batches']]
        count, skipped = qualifier.validate_test_accounting(schedule, results, 'linux')
        self.assertEqual(count, 1)
        self.assertEqual({row['test']: row['reason'] for row in skipped}, required)
        for fault in ('unknown_skip', 'missing_skip', 'wrong_reason', 'wrong_platform', 'duplicate'):
            bad = json.loads(json.dumps(results))
            selected = next(row for row in bad if row['skipped_platform_cases'])
            skip = selected['skipped_platform_cases'][0]
            if fault == 'unknown_skip':
                selected = next(row for row in bad if ordinary in row['test_ids'])
                selected['outcomes'][ordinary] = 'skipped'
                selected['skipped_platform_cases'].append({'test': ordinary, 'reason': 'Darwin owned signal denial', 'required_platform': 'Darwin'})
            elif fault == 'missing_skip':
                selected['outcomes'][skip['test']] = 'passed'
                selected['skipped_platform_cases'].remove(skip)
            elif fault == 'wrong_reason':
                skip['reason'] = 'optional'
            elif fault == 'wrong_platform':
                skip['required_platform'] = 'Linux'
            else:
                selected['skipped_platform_cases'].append(dict(skip))
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                qualifier.validate_test_accounting(schedule, bad, 'linux')


    def test_batch_accounting_rejects_omitted_duplicate_unknown_and_skip(self):
        schedule = qualifier.make_schedule(['test_a.C.test_x', 'test_b.C.test_y'])
        good = [{'test_ids': batch, 'outcomes': {i: 'passed' for i in batch},
                 'skipped_platform_cases': []} for batch in schedule['batches']]
        self.assertEqual(qualifier.validate_test_accounting(schedule, good, 'darwin')[0], 2)
        for bad in (good[:1], good + [good[0]],
                    [dict(good[0], test_ids=['test_unknown.C.test_z']), good[1]],
                    [dict(good[0], skipped_platform_cases=[{'test': good[0]['test_ids'][0], 'reason': 'optional'}]), good[1]]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                qualifier.validate_test_accounting(schedule, bad, 'darwin')

    def test_linux_streaming_skips_match_exact_darwin_test_decorators(self):
        source = Path(__file__).with_name('test_local_provider_streaming.py')
        spec = importlib.util.spec_from_file_location('streaming_skip_contract_probe', source)
        module = importlib.util.module_from_spec(spec)
        with mock.patch.object(sys, 'platform', 'linux'):
            spec.loader.exec_module(module)
        names = ('test_foreground_passes_live_raw_chunks_without_promoting_cessation',
                 'test_foreground_sink_failure_returns_uncertainty_without_second_dispatch')
        required = {}
        for name in names:
            method = getattr(module.LocalProviderStreamingTests, name)
            self.assertTrue(method.__unittest_skip__)
            required['test_local_provider_streaming.LocalProviderStreamingTests.' + name] = method.__unittest_skip_why__
        ordinary = 'test_ordinary.Case.test_required_behavior'
        for version in (2, 3):
            schedule = qualifier.make_schedule([*required, ordinary], format_version=version)
            results = [{'test_ids': batch,
                'outcomes': {i: 'skipped' if i in required else 'passed' for i in batch},
                'skipped_platform_cases': [{'test': i, 'reason': required[i], 'required_platform': 'Darwin'}
                                           for i in batch if i in required]}
                for batch in schedule['batches']]
            with self.subTest(version=version):
                self.assertEqual(qualifier.validate_test_accounting(schedule, results, 'linux')[0], 1)
                with self.assertRaises(ValueError):
                    qualifier.validate_test_accounting(schedule, results, 'darwin')
                bad = copy.deepcopy(results)
                case = next(r for r in bad if r['skipped_platform_cases'])['skipped_platform_cases'][0]
                case['reason'] = 'optional'
                with self.assertRaises(ValueError):
                    qualifier.validate_test_accounting(schedule, bad, 'linux')

    def test_child_main_keeps_fixture_observations_out_of_terminal_stdout(self):
        value = qualifier.phase_receipt({'phase': 'probe'}, {'ok': True})
        def noisy_child(args):
            print('synthetic observation')
            return value
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(qualifier, 'child_phase', side_effect=noisy_child), redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(qualifier.main(['--child']), 0)
        self.assertEqual(json.loads(stdout.getvalue()), value)
        self.assertIn('synthetic observation', stderr.getvalue())

    def test_every_installed_phase_refuses_checkout_package_reads(self):
        tool = Path(qualifier.__file__).resolve()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'diagnostics').mkdir()
            # The parent can import src/ while this deliberately isolated child
            # imports the wheel. Target the child's actual package in both modes.
            source = Path(subprocess.check_output([sys.executable, '-I', '-c',
                'import taskalong;from pathlib import Path;print(Path(taskalong.__file__).resolve().parent.parent)'],
                cwd=root, env=qualifier.clean_environment(), text=True, timeout=5).strip())
            self.assertIn('site-packages', source.parts)
            for phase in ('inventory', 'sample', 'tests-0', 'tests-1'):
                for boundary in ('source', 'build'):
                    with self.subTest(phase=phase, boundary=boundary):
                        identity = {'phase': phase, 'artifact_sha256': 'a'*64, 'harness_sha256': 'b'*64,
                                    'lock_sha256': 'c'*64, 'schedule_sha256': None}
                        path = root / 'phase-input.json'
                        path.write_text(json.dumps({'identity': identity, 'schedule': None}))
                        argv = [sys.executable, str(tool), '--child', '--source-root', str(source if boundary == 'source' else root / 'checkout')]
                        if boundary == 'build':
                            argv += ['--build-source-root', str(source)]
                        result = subprocess.run(argv + ['--phase-input', str(path)], cwd=root,
                            env=qualifier.clean_environment(), capture_output=True, text=True, timeout=5)
                        self.assertEqual(result.returncode, 1)
                        self.assertEqual(result.stdout, '')
                        self.assertIn('installed qualification attempted source checkout access', result.stderr)

    def test_ci_bundle_refuses_other_run_artifact_or_modified_checkout(self):
        tool = Path(qualifier.__file__).with_name('qualification_bundle.py')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = qualifier.clean_environment()
            def git(*args):
                return subprocess.check_output(['git', *args], cwd=root, env=env, stderr=subprocess.PIPE, text=True).strip()
            git('init', '-b', 'main')
            (root / 'public.txt').write_text('original')
            git('add', 'public.txt')
            git('-c', 'user.name=Synthetic Operator', '-c', 'user.email=synthetic@example.invalid', 'commit', '-m', 'Synthetic bundle')
            env.update(GITHUB_SHA=git('rev-parse', 'HEAD'), GITHUB_RUN_ID='100', GITHUB_RUN_ATTEMPT='1', GITHUB_EVENT_NAME='pull_request')
            dist = root / 'dist'
            dist.mkdir()
            wheel = dist / 'taskalong-0.1.0a1-py3-none-any.whl'
            wheel.write_bytes(b'synthetic wheel bytes')
            (dist / 'taskalong-0.1.0a1.tar.gz').write_bytes(b'synthetic sdist bytes')
            profile = 'macos-15' if sys.platform == 'darwin' else 'ubuntu-24.04'
            def bundle(operation, local=None):
                return subprocess.run([sys.executable, '-c',
                    "import platform,runpy,sys; platform.python_version=lambda: '3.14.10'; "
                    "tool=sys.argv.pop(1); runpy.run_path(tool, run_name='__main__')",
                    str(tool), operation, '--os-profile', profile,
                    '--python-profile', '.'.join(map(str, sys.version_info[:2]))], cwd=root, env=local or env,
                    capture_output=True, text=True, timeout=5)
            self.assertEqual(bundle('write').returncode, 0)
            self.assertEqual(bundle('verify').returncode, 0)
            for field, changed in [('GITHUB_RUN_ID', '101'), ('GITHUB_RUN_ATTEMPT', '2'), ('GITHUB_SHA', '0'*40)]:
                with self.subTest(field=field):
                    self.assertNotEqual(bundle('verify', dict(env, **{field: changed})).returncode, 0)
            wheel.write_bytes(b'changed artifact')
            self.assertNotEqual(bundle('verify').returncode, 0)
            wheel.write_bytes(b'synthetic wheel bytes')
            (root / 'public.txt').write_text('changed source')
            self.assertNotEqual(bundle('verify').returncode, 0)

    def test_fresh_environment_interpreter_and_pip_start(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "venv"
            python = qualifier.create_environment(target)
            result = subprocess.run(
                [python, "-I", "-c", "import sys,pip;print(sys.prefix);print(pip.__file__)"],
                env=qualifier.clean_environment(), capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            prefix, pip_path = result.stdout.strip().splitlines()
            self.assertEqual(Path(prefix).resolve(), target.resolve())
            self.assertTrue(Path(pip_path).resolve().is_relative_to(target.resolve()))

    def test_sdist_normalization_preserves_payload_and_is_reproducible(self):
        tool = Path(__file__).resolve().parents[1] / "tools" / "normalize_sdist.py"
        payload = b"synthetic package content\n"
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ("first.tar.gz", "second.tar.gz")]
            for index, path in enumerate(paths, 1):
                with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
                    folder = tarfile.TarInfo("taskalong-0.1.0a1")
                    folder.type = tarfile.DIRTYPE
                    folder.uid, folder.uname = index, "synthetic-builder"
                    archive.addfile(folder)
                    item = tarfile.TarInfo("taskalong-0.1.0a1/synthetic.py")
                    item.size, item.mode = len(payload), 0o644
                    item.uid = item.gid = item.mtime = index
                    item.uname, item.gname = "synthetic-builder", "synthetic-group"
                    item.pax_headers = {"atime": str(index), "SCHILY.xattr.user.fixture": "synthetic"}
                    archive.addfile(item, io.BytesIO(payload))
                result = subprocess.run([sys.executable, str(tool), str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(auditor.read_sdist(path), {"synthetic.py": payload})
                with tarfile.open(path, "r:gz") as archive:
                    self.assertEqual(archive.getmember("taskalong-0.1.0a1/synthetic.py").mode, 0o644)
            self.assertEqual(paths[0].read_bytes(), paths[1].read_bytes())
            before = paths[0].read_bytes()
            result = subprocess.run([sys.executable, str(tool), str(paths[0])], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(paths[0].read_bytes(), before)

    def test_invalid_sdist_normalization_keeps_input_and_never_extracts(self):
        tool = Path(__file__).resolve().parents[1] / "tools" / "normalize_sdist.py"
        cases = (("taskalong-0.1.0a1/../../outside", tarfile.REGTYPE),
                 ("taskalong-0.1.0a1/link", tarfile.SYMTYPE),
                 ("unexpected-root/synthetic.py", tarfile.REGTYPE))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "untrusted.tar.gz"
            for name, kind in cases:
                with self.subTest(name=name, kind=kind):
                    with tarfile.open(path, "w:gz") as archive:
                        item = tarfile.TarInfo(name)
                        item.type, item.linkname = kind, "../../outside"
                        archive.addfile(item, io.BytesIO() if item.isfile() else None)
                    before = path.read_bytes()
                    result = subprocess.run([sys.executable, str(tool), str(path)], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(path.read_bytes(), before)
                    self.assertEqual({p.name for p in root.iterdir()}, {path.name})

    def test_sdist_rejects_build_machine_metadata(self):
        cases = ({"uid": 123}, {"gid": 123}, {"uname": "synthetic-builder"},
                 {"gname": "synthetic-group"}, {"mtime": 123},
                 {"pax_headers": {"ctime": "123"}})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "untrusted.tar.gz"
            for fields in cases:
                with self.subTest(fields=tuple(fields)):
                    raw = io.BytesIO()
                    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
                        item = tarfile.TarInfo("taskalong-0.1.0a1/synthetic.py")
                        for key, value in fields.items():
                            setattr(item, key, value)
                        archive.addfile(item, io.BytesIO())
                    path.write_bytes(gzip.compress(raw.getvalue(), mtime=0))
                    with self.assertRaises(auditor.AuditError):
                        auditor.read_sdist(path)

    def test_sdist_rejects_gzip_name_comment_and_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "untrusted.tar.gz"
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode="w") as archive:
                archive.addfile(tarfile.TarInfo("taskalong-0.1.0a1/synthetic.py"), io.BytesIO())
            for filename, mtime in (("synthetic-builder.tar", 0), ("", 123)):
                with self.subTest(filename=filename, mtime=mtime):
                    compressed = io.BytesIO()
                    with gzip.GzipFile(filename=filename, fileobj=compressed, mode="wb", mtime=mtime) as stream:
                        stream.write(raw.getvalue())
                    path.write_bytes(compressed.getvalue())
                    with self.assertRaises(auditor.AuditError):
                        auditor.read_sdist(path)
            compressed = bytearray(gzip.compress(raw.getvalue(), mtime=0))
            compressed[3] |= 16  # A valid optional gzip comment, independent of tar contents.
            path.write_bytes(bytes(compressed[:10]) + b"synthetic-builder\0" + bytes(compressed[10:]))
            with self.assertRaises(auditor.AuditError):
                auditor.read_sdist(path)

    def test_wheel_rejects_comment_and_extra_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "untrusted.whl"
            for field in ("archive-comment", "member-comment", "extra"):
                with self.subTest(field=field):
                    with zipfile.ZipFile(path, "w") as archive:
                        item = zipfile.ZipInfo("taskalong/synthetic.py")
                        if field == "archive-comment":
                            archive.comment = b"synthetic-builder"
                        elif field == "member-comment":
                            item.comment = b"synthetic-builder"
                        else:
                            item.extra = b"\xfe\xca\x04\x00test"
                        archive.writestr(item, b"")
                    with self.assertRaises(auditor.AuditError):
                        auditor.read_wheel(path)

    def test_metadata_rejects_unapproved_contact_and_source_urls(self):
        metadata = (b"Name: taskalong\nVersion: 0.1.0a1\nRequires-Python: >=3.11,<3.15\n"
                    b"Requires-Dist: jsonschema<5,>=4.26\n"
                    b'Requires-Dist: review-sensei==0.8.8; extra == "review"\n'
                    b"Provides-Extra: review\nLicense-Expression: MIT\nLicense-File: LICENSE\n")
        auditor._metadata(metadata)
        for field in ("Author", "Author-email", "Maintainer", "Maintainer-email", "Home-page", "Project-URL", "Download-URL"):
            with self.subTest(field=field), self.assertRaises(auditor.AuditError):
                auditor._metadata(metadata + field.encode() + b": synthetic@example.invalid\n")

    def test_metadata_rejects_missing_substituted_and_duplicate_license_fields(self):
        metadata = (b"Name: taskalong\nVersion: 0.1.0a1\nRequires-Python: >=3.11,<3.15\n"
                    b"Requires-Dist: jsonschema<5,>=4.26\n"
                    b'Requires-Dist: review-sensei==0.8.8; extra == "review"\n'
                    b"Provides-Extra: review\nLicense-Expression: MIT\nLicense-File: LICENSE\n")
        auditor._metadata(metadata)
        cases = (metadata.replace(b"License-Expression: MIT\n", b""),
                 metadata.replace(b"License-Expression: MIT", b"License-Expression: Apache-2.0"),
                 metadata + b"License-Expression: MIT\n",
                 metadata.replace(b"License-File: LICENSE", b"License-File: NOTICE"),
                 metadata + b"License-File: LICENSE\n",
                 metadata + b"License: MIT\n")
        for data in cases:
            with self.subTest(data=data), self.assertRaises(auditor.AuditError):
                auditor._metadata(data)

    def test_archive_paths_are_literal_and_contained(self):
        for path in ("../outside", "/outside", "a/../../b", "a//b", "a\\b", "C:/outside", "a/./b", "a\0b"):
            with self.subTest(path=path), self.assertRaises(auditor.AuditError):
                auditor.checked_name(path)
        self.assertEqual(auditor.checked_name("taskalong/resources/templates/worker.txt"), "taskalong/resources/templates/worker.txt")

    def test_wheel_rejects_symlinks_executables_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "untrusted.whl"
            for mode in (stat.S_IFLNK | 0o777, stat.S_IFREG | 0o755):
                with zipfile.ZipFile(path, "w") as archive:
                    item = zipfile.ZipInfo("taskalong/unsafe")
                    item.external_attr = mode << 16
                    archive.writestr(item, "../../outside")
                with self.assertRaises(auditor.AuditError):
                    auditor.read_wheel(path)
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(zipfile.ZipInfo("taskalong/safe.py"), "first")
                # Duplicate ZIP members have platform-dependent extraction behavior.
                with self.assertWarns(UserWarning):
                    archive.writestr(zipfile.ZipInfo("taskalong/safe.py"), "second")
            with self.assertRaises(auditor.AuditError):
                auditor.read_wheel(path)

    def test_sdist_never_follows_link_or_root_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "untrusted.tar.gz"
            for name, kind in (("taskalong-0.1.0a1/linked", tarfile.SYMTYPE), ("taskalong-0.1.0a1/../outside", tarfile.REGTYPE), ("wrong-root/a", tarfile.REGTYPE)):
                with tarfile.open(path, "w:gz") as archive:
                    item = tarfile.TarInfo(name)
                    item.type = kind
                    item.linkname = "../../outside"
                    item.size = 0
                    archive.addfile(item, io.BytesIO())
                with self.assertRaises(auditor.AuditError):
                    auditor.read_sdist(path)

    def test_exact_inventory_does_not_accept_extra_file(self):
        with self.assertRaises(auditor.AuditError):
            auditor._exact({"taskalong/__init__.py", "taskalong/auth.json"}, {"taskalong/__init__.py"}, "wheel")

    def test_record_tampering_and_self_hash_are_rejected(self):
        body = b"synthetic package bytes"
        module_name = "taskalong/__init__.py"
        record_name = f"{auditor.DIST_INFO}/RECORD"
        encoded = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
        stream = io.StringIO()
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerows([(module_name, "sha256=" + encoded, str(len(body))), (record_name, "", "")])
        files = {module_name: body, record_name: stream.getvalue().encode()}
        auditor._record(files)
        files[module_name] = b"changed bytes"
        with self.assertRaises(auditor.AuditError):
            auditor._record(files)
        files[module_name] = body
        files[record_name] = files[record_name].replace((record_name + ",,").encode(), (record_name + ",sha256=forged,1").encode())
        with self.assertRaises(auditor.AuditError):
            auditor._record(files)

    def test_checked_inventory_exists_and_has_no_patterns(self):
        root = Path(__file__).resolve().parents[1]
        inventory = auditor.load_inventory(root)
        self.assertTrue(inventory["wheel_sources"])
        self.assertTrue(all("*" not in p for p in inventory["sdist_sources"]))
        for forbidden in ("tests/", "tools/", ".agents/", ".codex/", "docs/"):
            self.assertFalse(any(p.startswith(forbidden) for p in inventory["wheel_sources"]))

    def test_rebuilding_input_cannot_relabel_qualified_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "taskalong-0.1.0a1-py3-none-any.whl"
            source.write_bytes(b"first artifact bytes")
            snapshots = root / "private-snapshots"
            snapshots.mkdir(mode=0o700)
            copied, observed_hash = qualifier.snapshot_artifact(source, snapshots)
            source.write_bytes(b"replacement artifact bytes")
            self.assertEqual(copied.read_bytes(), b"first artifact bytes")
            self.assertEqual(observed_hash, hashlib.sha256(copied.read_bytes()).hexdigest())
            self.assertNotEqual(observed_hash, hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(copied.stat().st_mode & 0o777, 0o600)

    def test_harness_lock_and_fixtures_cannot_drift_during_install(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            root.mkdir()
            files = {"tools/qualify_installed.py": b"synthetic harness", "requirements-dev.lock": b"first lock",
                     "tools/qualify_runtime.py": b"first runtime qualifier",
                     "tests/test_example.py": b"first test", "tests/fixtures/fake_codex.py": b"first codex",
                     "tests/fixtures/fake_gh.py": b"first gh"}
            for relative, data in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            (root / "distribution-inventory.json").write_text(json.dumps({"sdist_sources": sorted(files)}))
            work = Path(directory) / "first"
            work.mkdir()
            original_digest = qualifier.snapshot_harness(root, work)
            (root / "requirements-dev.lock").write_bytes(b"replacement lock")
            (root / "tests/test_example.py").write_bytes(b"replacement test")
            self.assertEqual((work / "requirements-dev.lock").read_bytes(), b"first lock")
            self.assertEqual((work / "installed-tests/test_example.py").read_bytes(), b"first test")
            replacement = Path(directory) / "second"
            replacement.mkdir()
            self.assertNotEqual(original_digest, qualifier.snapshot_harness(root, replacement))


if __name__ == "__main__":
    unittest.main()


class PortableReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with mock.patch.dict(sys.modules, {
                'qualification_bundle': QualificationShardTests.load_tool('qualification_bundle'),
                'portable_smoke': QualificationShardTests.load_tool('portable_smoke'),
                'check_dist': auditor}):
            cls.portable = QualificationShardTests.load_tool('qualify_portable')

    def receipt(self):
        row = {'test_ids': list(self.portable.TEST_NAMES), 'passed': 8, 'skipped': [],
               'python': '3.14.10', 'implementation': 'cpython', 'gil_disabled': False, 'prefix': 'C:/scratch/venv',
               'installed_origin': 'C:/scratch/venv/Lib/site-packages/taskalong/__init__.py'}
        return {'kind': 'windows_portable', 'format_version': 2, 'ok': True,
                'implementation': 'cpython', 'gil_disabled': False,
                'binding': {'run_id': '1234', 'run_attempt': '2', 'event': 'pull_request',
                            'source_commit': 'a' * 40, 'source_tree': 'd' * 40,
                            'source_files': {'tools/qualify_portable.py': 'e' * 64}},
                'python': '3.14.10', 'platform': 'Windows',
                'scope': 'stateless-installed-contracts-only',
                'artifacts': {'wheel': 'a' * 64, 'sdist': 'b' * 64},
                'installed_artifacts': {'wheel': 'a' * 64, 'sdist': 'c' * 64},
                'results': {'wheel': copy.deepcopy(row), 'sdist': copy.deepcopy(row)},
                'elapsed_seconds': 20}

    def test_portable_closed_receipt_rejects_identity_inventory_and_origin_faults(self):
        good = self.receipt()
        binding = copy.deepcopy(good['binding'])
        self.assertEqual(self.portable.validate_receipt(good, binding)['tests_per_artifact'], 8)
        mutations = [
            lambda v: v.clear(),
            lambda v: v.pop('format_version'),
            lambda v: v.pop('ok'),
            lambda v: v.update(implementation='pypy'),
            lambda v: v.update(gil_disabled=0),
            lambda v: v.update(gil_disabled=True),
            lambda v: v['results']['wheel'].update(implementation='pypy'),
            lambda v: v['results']['wheel'].update(gil_disabled=True),
            lambda v: v['results']['wheel'].update(prefix='C:/'),
            lambda v: v['results']['wheel'].update(installed_origin='C:/scratch/venv/Lib/site-packages/../taskalong/__init__.py'),
            lambda v: v['results']['wheel'].update(prefix=None),
            lambda v: v['installed_artifacts'].update(wheel='f' * 64),
            lambda v: v['installed_artifacts'].pop('sdist'),
            lambda v: v.update(format_version=True),
            lambda v: v.update(ok=False),
            lambda v: v.update(platform='Linux'),
            lambda v: v.update(python='3.14.6'),
            lambda v: v.update(elapsed_seconds=float('nan')),
            lambda v: v.update(elapsed_seconds=901),
            lambda v: v.update(extra=True),
            lambda v: v['binding'].update(run_id='999'),
            lambda v: v['binding'].update(source_tree='f' * 40),
            lambda v: v['binding'].update(event='push'),
            lambda v: v['binding'].update(run_attempt='1'),
            lambda v: v['binding'].update(source_commit='b' * 40),
            lambda v: v['artifacts'].pop('sdist'),
            lambda v: v['artifacts'].update(wheel='bad'),
            lambda v: v['results'].pop('sdist'),
            lambda v: v['results']['wheel']['test_ids'].pop(),
            lambda v: v['results']['wheel'].update(passed=True),
            lambda v: v['results']['wheel'].update(skipped=['schemas']),
            lambda v: v['results']['wheel'].update(installed_origin='C:/checkout/src/taskalong/__init__.py'),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                value = copy.deepcopy(good)
                mutation(value)
                with self.assertRaises(ValueError):
                    self.portable.validate_receipt(value, binding)


    def build_portable_artifacts(self, directory):
        source = Path(__file__).resolve().parents[1]
        directory.mkdir()
        subprocess.run([sys.executable, '-m', 'build', '--no-isolation', '--outdir', str(directory / 'dist')],
                       cwd=source, env=qualifier.clean_environment(), check=True, capture_output=True, timeout=60)
        with mock.patch.dict(sys.modules, {'check_dist': auditor}):
            normalize = QualificationShardTests.load_tool('normalize_sdist')
        normalize.normalize(directory / self.portable.ARTIFACT_PATHS['sdist'])
        rebuilt = directory / 'portable-rebuilt'
        rebuilt.mkdir()
        import shutil
        shutil.copyfile(directory / self.portable.ARTIFACT_PATHS['wheel'],
                        directory / self.portable.ARTIFACT_PATHS['rebuilt'])
        receipt = self.receipt()
        for label in ('wheel', 'sdist'):
            receipt['artifacts'][label] = hashlib.sha256((directory / self.portable.ARTIFACT_PATHS[label]).read_bytes()).hexdigest()
        receipt['installed_artifacts'] = {'wheel': receipt['artifacts']['wheel'],
                                         'sdist': hashlib.sha256((directory / self.portable.ARTIFACT_PATHS['rebuilt']).read_bytes()).hexdigest()}
        return source, receipt

    def test_windows_retained_artifacts_reject_corruption_omission_and_wrong_digests(self):
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch) / 'portable'
            source, receipt = self.build_portable_artifacts(directory)
            self.portable.validate_receipt(receipt, receipt['binding'])
            self.assertEqual(self.portable.verify_artifacts(receipt, directory, source), {'verified_artifacts': 3})
            for label, relative in self.portable.ARTIFACT_PATHS.items():
                path = directory / relative
                original = path.read_bytes()
                with self.subTest(artifact=label):
                    path.write_bytes(b'corrupt archive')
                    with self.assertRaises((auditor.AuditError, ValueError, zipfile.BadZipFile, tarfile.TarError, OSError)):
                        self.portable.verify_artifacts(receipt, directory, source)
                    path.write_bytes(original)
                    path.rename(path.with_suffix('.missing'))
                    with self.assertRaises(ValueError):
                        self.portable.verify_artifacts(receipt, directory, source)
                    path.with_suffix('.missing').rename(path)
            for target in ('wheel', 'sdist'):
                changed = copy.deepcopy(receipt)
                changed['installed_artifacts'][target] = 'f' * 64
                with self.assertRaises(ValueError):
                    if target == 'wheel':
                        self.portable.validate_receipt(changed, changed['binding'])
                    else:
                        self.portable.verify_artifacts(changed, directory, source)

    def test_windows_driver_refuses_corrupt_wheel_and_sdist_before_install_or_receipt(self):
        from types import SimpleNamespace
        import shutil
        with tempfile.TemporaryDirectory() as scratch:
            fixtures = Path(scratch) / 'fixtures'
            source, receipt = self.build_portable_artifacts(fixtures)
            inventory = json.loads((source / 'distribution-inventory.json').read_text())
            for damaged in ('wheel', 'sdist'):
                with self.subTest(damaged=damaged):
                    project = Path(scratch) / damaged
                    project.mkdir()
                    for relative in inventory['sdist_sources']:
                        target = project / relative
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(source / relative, target)
                    calls = []
                    def command(argv, **kwargs):
                        calls.append(argv)
                        if argv[1:3] == ['-m', 'build']:
                            (project / 'dist').mkdir()
                            for label in ('wheel', 'sdist'):
                                target = project / self.portable.ARTIFACT_PATHS[label]
                                if label == damaged:
                                    target.write_bytes(b'corrupt archive')
                                else:
                                    shutil.copyfile(fixtures / self.portable.ARTIFACT_PATHS[label], target)
                        # Deliberately simulate completed normalization, then require the driver's own audit to reject corruption.
                        return subprocess.CompletedProcess(argv, 0, b'', b'')
                    output = project / 'windows-portable.json'
                    with mock.patch.object(self.portable, '__file__', str(project / 'tools/qualify_portable.py')), \
                            mock.patch.object(self.portable.platform, 'system', return_value='Windows'), \
                            mock.patch.object(self.portable.platform, 'python_version', return_value='3.14.10'), \
                            mock.patch.object(self.portable.subprocess, 'run', side_effect=command), \
                            mock.patch.dict(sys.modules, {'qualification_shards': SimpleNamespace(source_binding=lambda _: receipt['binding']), 'qualify_installed': qualifier}), \
                            mock.patch.object(sys, 'argv', ['qualify_portable', '--output', str(output)]):
                        with self.assertRaises((auditor.AuditError, ValueError, zipfile.BadZipFile, tarfile.TarError, OSError)):
                            self.portable.main()
                    self.assertFalse(output.exists())
                    self.assertFalse(any('-m' in argv and 'venv' in argv for argv in calls))
                    self.assertTrue((project / 'portable-diagnostics').is_dir())

    def test_windows_driver_success_is_consumed_with_its_actual_archive_bytes(self):
        from types import SimpleNamespace
        import shutil
        QualificationShardTests.setUpClass()
        shards = QualificationShardTests()
        q = shards.shards
        with tempfile.TemporaryDirectory() as scratch:
            scratch = Path(scratch)
            fixtures = scratch / 'fixtures'
            source, _ = self.build_portable_artifacts(fixtures)
            project = scratch / 'project'
            project.mkdir()
            inventory = json.loads((source / 'distribution-inventory.json').read_text())
            for relative in inventory['sdist_sources']:
                target = project / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source / relative, target)
            results = scratch / 'posix'
            results.mkdir()
            for system, version in q.PROFILES:
                binding, producer, receipts = shards.format3_fixture(system, version)
                shards.write_lanes(results, binding, producer, receipts, format_version=3)
            calls = []
            def command(argv, **kwargs):
                calls.append(argv)
                if argv[1:3] == ['-m', 'build']:
                    (project / 'dist').mkdir()
                    for label in ('wheel', 'sdist'):
                        shutil.copyfile(fixtures / self.portable.ARTIFACT_PATHS[label], project / self.portable.ARTIFACT_PATHS[label])
                if '--wheel-dir' in argv:
                    rebuilt = Path(argv[argv.index('--wheel-dir') + 1])
                    rebuilt.mkdir()
                    self.assertEqual(Path(argv[-1]).resolve(), (project / self.portable.ARTIFACT_PATHS['sdist']).resolve())
                    shutil.copyfile(fixtures / self.portable.ARTIFACT_PATHS['wheel'], rebuilt / Path(self.portable.ARTIFACT_PATHS['rebuilt']).name)
                output = b''
                if '-I' in argv:
                    label = Path(kwargs['cwd']).name
                    row = self.receipt()['results'][label]
                    row['prefix'] = f'C:/synthetic/{label}/venv'
                    row['installed_origin'] = row['prefix'] + '/Lib/site-packages/taskalong/__init__.py'
                    output = json.dumps(row).encode()
                return subprocess.CompletedProcess(argv, 0, output, b'')
            output = project / 'windows-portable.json'
            with mock.patch.object(self.portable, '__file__', str(project / 'tools/qualify_portable.py')), \
                    mock.patch.object(self.portable.platform, 'system', return_value='Windows'), \
                    mock.patch.object(self.portable.platform, 'python_version', return_value='3.14.10'), \
                    mock.patch.object(self.portable.subprocess, 'run', side_effect=command), \
                    mock.patch.dict(sys.modules, {'qualification_shards': SimpleNamespace(source_binding=lambda _: binding), 'qualify_installed': qualifier}), \
                    mock.patch.object(sys, 'argv', ['qualify_portable', '--output', str(output)]):
                self.portable.main()
            portable = scratch / 'portable-result'
            portable.mkdir()
            shutil.copyfile(output, portable / output.name)
            for name in ('dist', 'portable-rebuilt'):
                shutil.copytree(project / name, portable / name)
            stream = io.StringIO()
            with mock.patch.object(q, 'source_binding', return_value=binding), \
                    mock.patch.dict(sys.modules, {'qualify_portable': self.portable}), \
                    mock.patch.object(sys, 'argv', ['qualification_shards', 'aggregate', '--format-version', '3',
                        '--directory', str(results), '--portable-receipt', str(portable / output.name)]), redirect_stdout(stream):
                q.main()
            aggregate = json.loads(stream.getvalue())
            self.assertEqual(aggregate['windows_portable']['verified_artifacts'], 3)
            self.assertEqual(aggregate['shards'], 4)
            self.assertEqual(sum('-I' in argv for argv in calls), 2)

    def test_producer_refuses_wrong_patch_or_free_threaded_interpreter(self):
        bundle = QualificationShardTests.load_tool('qualification_bundle')
        for version, free_threaded in [('3.14.6', 0), ('3.14.10', 1)]:
            with self.subTest(version=version, free_threaded=free_threaded), \
                    mock.patch.dict(bundle.os.environ, {'GITHUB_SHA': 'a' * 40}), \
                    mock.patch.object(bundle.subprocess, 'check_output', return_value='a' * 40), \
                    mock.patch.object(bundle.platform, 'python_version_tuple', return_value=('3', '14', '10')), \
                    mock.patch.object(bundle.platform, 'python_version', return_value=version), \
                    mock.patch.object(bundle.sysconfig, 'get_config_var', return_value=free_threaded):
                with self.assertRaisesRegex(ValueError, 'pinned standard CPython'):
                    bundle.identity(Path('/unused'), 'ubuntu-24.04', '3.14')

    def test_windows_driver_refuses_unqualified_native_interpreter_before_build(self):
        with mock.patch.object(self.portable.platform, 'system', return_value='Linux'), \
                mock.patch.object(sys, 'argv', ['qualify_portable', '--output', 'unused.json']), \
                mock.patch.object(self.portable.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'pinned native Windows'):
                self.portable.main()
            run.assert_not_called()
