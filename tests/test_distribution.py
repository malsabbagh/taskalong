"""Distribution audits reject unexpected bytes and unsafe archive members."""
from __future__ import annotations

import importlib.util
import base64
import csv
import gzip
import hashlib
import io
import json
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stdout, redirect_stderr
import zipfile
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location("taskalong_distribution_auditor", Path(__file__).resolve().parents[1] / "tools" / "check_dist.py")
auditor = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(auditor)
_QUALIFIER_SPEC = importlib.util.spec_from_file_location("taskalong_installed_qualifier", Path(__file__).resolve().parents[1] / "tools" / "qualify_installed.py")
qualifier = importlib.util.module_from_spec(_QUALIFIER_SPEC)
_QUALIFIER_SPEC.loader.exec_module(qualifier)


class DistributionTests(unittest.TestCase):
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
                     'tests/fixtures/fake_codex.py': b'original worker', 'tests/fixtures/fake_gh.py': b'original boundary',
                     'tests/test_a.py': b'original test'}
            for name, data in files.items():
                target = root / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
            (root / 'distribution-inventory.json').write_text(json.dumps({'sdist_sources': sorted(files)}))
            expected = qualifier.snapshot_harness(root, work)
            qualifier.verify_harness(work, expected)
            for relative in ('qualify_installed.py', 'requirements-dev.lock', 'installed-tests/test_a.py',
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
                return subprocess.run([sys.executable, str(tool), operation, '--os-profile', profile,
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
