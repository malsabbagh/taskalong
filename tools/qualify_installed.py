#!/usr/bin/env python3
"""Qualify built TaskAlong artifacts in fresh venvs outside the checkout.

Only synthetic task data reaches external boundary fixtures. Dependency artifact
downloads are permitted by this explicit qualification command; no model call,
real GitHub mutation, auth lookup, or runtime installation is performed.

Format 2 remains the default two-batch protocol. Explicit format 3 uses four
whole-module batches; both protocols retain the same phase and total deadlines.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stdout
import hashlib
import json
import math
import os
import platform
import selectors
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import unittest
from pathlib import Path

REVIEW_SHA256 = "34337c4da835f794914915aeb2a0b4521f05d4ab13120452ee6ee4e43dbbf1b0"
REVIEW_URL = "https://github.com/malsabbagh/review-sensei/releases/download/v0.8.8/review_sensei-0.8.8-py3-none-any.whl"
FIXTURES = ("tests/fixtures/fake_codex.py", "tests/fixtures/fake_gh.py")
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
PHASE_SECONDS = 600
QUALIFICATION_SECONDS = 1500
STREAM_LIMIT = 4 * 1024 * 1024


def json_digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def batch_count(format_version: int) -> int:
    if type(format_version) is not int or format_version not in {2, 3}:
        raise ValueError('unsupported qualification format')
    return 2 if format_version == 2 else 4


def test_phases(format_version: int) -> list[str]:
    return [f'tests-{index}' for index in range(batch_count(format_version))]


def make_schedule(ids: list[str], *, format_version: int = 2) -> dict:
    count = batch_count(format_version)
    if (not isinstance(ids, list) or not ids or any(not isinstance(i, str) for i in ids)
            or len(ids) != len(set(ids)) or any('._FailedTest.' in i or not i.startswith('test_') for i in ids)):
        raise ValueError('invalid installed test inventory')
    modules: dict[str, list[str]] = {}
    for identifier in sorted(ids):
        modules.setdefault(identifier.split('.')[0], []).append(identifier)
    assigned: list[list[str]] = [[] for _ in range(count)]
    loads = [0] * count
    for module in sorted(modules, key=lambda name: (-len(modules[name]), name)):
        index = min(range(count), key=lambda value: (loads[value], value))
        assigned[index].append(module)
        loads[index] += len(modules[module])
    batches = [[identifier for module in sorted(group) for identifier in modules[module]]
               for group in assigned]
    rule = ('whole-modules-count-desc-greedy-two-v2' if format_version == 2
            else 'whole-modules-count-desc-greedy-four-v3')
    return {'format_version': format_version, 'rule': rule,
            'inventory_sha256': json_digest(sorted(ids)), 'batches': batches}


def check_schedule(schedule: dict, *, format_version: int = 2):
    count = batch_count(format_version)
    if (not isinstance(schedule, dict)
            or set(schedule) != {'format_version', 'rule', 'inventory_sha256', 'batches'}
            or type(schedule['format_version']) is not int or schedule['format_version'] != format_version
            or not isinstance(schedule['batches'], list) or len(schedule['batches']) != count
            or any(not isinstance(batch, list) for batch in schedule['batches'])
            or schedule != make_schedule(sum(schedule['batches'], []), format_version=format_version)):
        raise ValueError('invalid qualification schedule')


def phase_receipt(identity: dict, payload: dict, *, format_version: int = 2) -> dict:
    batch_count(format_version)
    return {'kind': 'installed_phase', 'format_version': format_version, 'ok': True, 'identity': identity, 'payload': payload}


def validate_phase(value: dict, identity: dict, *, format_version: int = 2) -> dict:
    phases = test_phases(format_version)
    if (not isinstance(value, dict) or set(value) != {'kind', 'format_version', 'ok', 'identity', 'payload'}
            or value['kind'] != 'installed_phase' or type(value['format_version']) is not int
            or value['format_version'] != format_version or value['ok'] is not True
            or value['identity'] != identity or not isinstance(value['payload'], dict)):
        raise ValueError('missing or mismatched terminal phase receipt')
    payload = value['payload']
    phase = identity['phase']
    if phase == 'probe':  # Small wrapper regressions, never part of a real schedule.
        return payload
    fields = {'inventory': {'schedule', 'package_snapshot_sha256'},
              'sample': {'journey', 'package_snapshot_sha256'}}
    fields.update({phase: {'test_ids', 'outcomes', 'skipped_platform_cases', 'package_snapshot_sha256'}
                   for phase in phases})
    if phase not in fields or set(payload) != fields[phase] or not is_sha(payload['package_snapshot_sha256']):
        raise ValueError('invalid closed phase payload')
    try:
        if phase == 'inventory':
            schedule = payload['schedule']
            check_schedule(schedule, format_version=format_version)
        elif phase == 'sample':
            validate_journey(payload['journey'], core_only=identity.get('schedule_sha256') is None)
        else:
            ids, outcomes, skips = payload['test_ids'], payload['outcomes'], payload['skipped_platform_cases']
            if (not isinstance(ids, list) or any(not isinstance(i, str) for i in ids)
                    or len(ids) != len(set(ids)) or not isinstance(outcomes, dict) or set(outcomes) != set(ids)
                    or any(v not in {'passed', 'skipped'} for v in outcomes.values()) or not isinstance(skips, list)
                    or any(not isinstance(r, dict) or set(r) != {'test', 'reason', 'required_platform'} for r in skips)):
                raise ValueError('invalid behavior phase payload')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('invalid phase payload types') from error
    return payload


def is_sha(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def validate_journey(value: dict, *, core_only: bool):
    fields = {'kind', 'format_version', 'ok', 'state', 'qualification', 'review', 'publication', 'python',
              'platform', 'machine', 'package_version', 'attempts', 'events', 'source_import', 'real_sandbox_claim',
              'installed_behavior_tests', 'skipped_platform_cases', 'dependencies'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('invalid closed sample receipt')
    fixed = {'kind': 'installed_journey', 'format_version': 1, 'ok': True,
             'state': 'blocked' if core_only else 'draft_published', 'qualification': 'synthetic',
             'review': 'missing-blocks' if core_only else 'released-fixture-full-diff',
             'publication': 'review-blocked' if core_only else 'fixture-lost-response-reconciled-one-create',
             'package_version': '0.1.0a1', 'attempts': 1, 'source_import': False, 'real_sandbox_claim': False,
             'installed_behavior_tests': 0, 'skipped_platform_cases': []}
    if any(type(value[k]) is not type(v) or value[k] != v for k, v in fixed.items()):
        raise ValueError('sample receipt does not establish expected journey')
    if (type(value['events']) is not int or value['events'] < 1
            or any(not isinstance(value[k], str) or not 1 <= len(value[k]) <= 100 for k in ('python', 'platform', 'machine'))
            or value['platform'] not in {'Darwin', 'Linux'} or not isinstance(value['dependencies'], dict)
            or set(value['dependencies']) != {'jsonschema', 'setuptools', 'certifi'}
            or any(not isinstance(v, str) or not 1 <= len(v) <= 100 for v in value['dependencies'].values())):
        raise ValueError('invalid sample environment observations')


class Progress:
    def __init__(self, path: Path, phase: str):
        self.path, self.phase, self.started, self.sequence = path, phase, time.monotonic(), 0

    def emit(self, event: str, *, test: str | None = None, outcome: str | None = None):
        self.sequence += 1
        record = {'sequence': self.sequence, 'elapsed_seconds': round(time.monotonic() - self.started, 6),
                  'phase': self.phase, 'event': event, 'test': test, 'outcome': outcome}
        with self.path.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(record, sort_keys=True) + '\n')
            stream.flush()
            os.fsync(stream.fileno())


class ProgressResult(unittest.TextTestResult):
    def __init__(self, *args, progress: Progress, **kwargs):
        super().__init__(*args, **kwargs)
        self.progress, self.outcomes, self.executed = progress, {}, []

    def startTest(self, test):
        self.executed.append(test.id())
        self.progress.emit('test-start', test=test.id())
        super().startTest(test)

    def stopTest(self, test):
        self.progress.emit('test-outcome', test=test.id(), outcome=self.outcomes.get(test.id(), 'failed'))
        super().stopTest(test)
        self.progress.emit('test-stop', test=test.id())

    def addSuccess(self, test):
        self.outcomes[test.id()] = 'passed'
        super().addSuccess(test)

    def addSkip(self, test, reason):
        self.outcomes[test.id()] = 'skipped'
        super().addSkip(test, reason)


class PhaseFailure(RuntimeError):
    def __init__(self, receipt: dict):
        super().__init__('installed phase failed: ' + receipt['failure'])
        self.receipt = receipt


def error_code(stage: str, error: Exception) -> dict:
    number = getattr(error, 'errno', None)
    return {'stage': stage, 'errno': number if type(number) is int else None}


def run_phase(argv: list[str], *, cwd: Path, env: dict, identity: dict, timeout: float,
              stream_limit: int = STREAM_LIMIT, format_version: int = 2) -> tuple[dict, dict]:
    """Own/reap only this child; retain bounded streams without trusting descendants."""
    phase = identity['phase']
    if phase not in {'inventory', 'sample', 'probe', *test_phases(format_version)}:
        raise ValueError('unknown qualification phase')
    folder = cwd / 'diagnostics'
    files, data, secondary = {}, {}, []
    meta = {name: {'file': f'diagnostics/{phase}.{name}', 'bytes': 0, 'truncated': False,
                   'sha256': None} for name in ('stdout', 'stderr')}
    start = time.monotonic()
    failure, child, reaped, exit_code = None, None, False, None
    selector = None
    final_deadline = None

    def attempt(stage, action):
        try:
            return True, action()
        except Exception as error:
            secondary.append(error_code(stage, error))
            return False, None

    try:
        folder.mkdir(exist_ok=True, mode=0o700)
        for name in ('stdout', 'stderr'):
            descriptor = os.open(cwd / meta[name]['file'], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                files[name] = os.fdopen(descriptor, 'wb', buffering=0)
            except Exception:
                attempt(f'close_descriptor_{name}', lambda: os.close(descriptor))
                raise
        selector = selectors.DefaultSelector()
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for name in ('stdout', 'stderr'):
            pipe = getattr(child, name)
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while selector.get_map() or child.poll() is None:
            now = time.monotonic()
            if failure is None and now - start >= timeout:
                failure = 'timeout'
            if failure is not None and final_deadline is None:
                final_deadline = now + 3
                if child.poll() is None:
                    child.kill()
            if final_deadline is not None and now >= final_deadline:
                break
            for key, _ in selector.select(.05):
                name = key.data
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                available = max(0, stream_limit - meta[name]['bytes'])
                retained = chunk[:available]
                if files[name].write(retained) != len(retained):
                    raise OSError('short private diagnostic write')
                meta[name]['bytes'] += len(retained)
                if len(chunk) > available:
                    meta[name]['truncated'] = True
                    failure = failure or 'output_limit'
            if child.poll() is not None and selector.get_map() and final_deadline is None:
                final_deadline = time.monotonic() + 3
        if selector.get_map():
            failure = failure or 'pipe_cleanup_uncertain'
    except Exception as error:
        failure = failure or 'wrapper_failure'
        secondary.append(error_code('execution', error))
    finally:
        # Every resource gets its own bounded cleanup attempt. A failure cannot
        # skip remaining resources or replace the original execution cause.
        if child is not None:
            observed, status = attempt('poll', child.poll)
            if not observed or status is None:
                attempt('kill', child.kill)
            observed, status = attempt('wait', lambda: child.wait(timeout=3))
            if observed:
                reaped, exit_code = True, status
            else:
                failure = failure or 'direct_child_reap_uncertain'
            for name in ('stdout', 'stderr'):
                attempt(f'close_child_{name}', lambda name=name: getattr(child, name).close())
        if selector is not None:
            attempt('close_selector', selector.close)
        for name, stream in files.items():
            attempt(f'close_file_{name}', stream.close)
        for name in ('stdout', 'stderr'):
            observed, raw = attempt(f'read_{name}', lambda name=name: (cwd / meta[name]['file']).read_bytes())
            if observed:
                data[name] = raw
                meta[name]['bytes'] = len(raw)
                meta[name]['sha256'] = hashlib.sha256(raw).hexdigest()
    if exit_code is not None and exit_code != 0:
        failure = failure or 'nonzero_exit'
    if secondary:
        failure = failure or 'cleanup_or_evidence_failure'
    receipt = {'identity': identity, 'ok': False, 'failure': failure, 'secondary_errors': secondary,
               'budget_seconds': timeout, 'elapsed_seconds': round(time.monotonic() - start, 6),
               'direct_child_exit': exit_code, 'direct_child_reaped': reaped,
               'descendant_cleanup_confirmed': False, 'receipt_persisted': False, **meta}
    payload = None
    if failure is None:
        try:
            payload = validate_phase(json.loads(data['stdout']), identity, format_version=format_version)
        except (ValueError, UnicodeError, KeyError):
            receipt['failure'] = 'invalid_terminal_receipt'
    receipt['ok'] = receipt['failure'] is None
    receipt['receipt_persisted'] = True
    persisted, _ = attempt('persist_receipt', lambda: write_json(folder / f'{phase}.parent.json', receipt))
    if not persisted:
        receipt.update(ok=False, receipt_persisted=False, failure=receipt['failure'] or 'cleanup_or_evidence_failure')
    if not receipt['ok']:
        raise PhaseFailure(receipt)
    return payload, receipt


def finalize_export(work: Path, output: Path, schedule: dict | None, *, reservation, primary, completed,
                    format_version: int = 2):
    try:
        export_evidence(work, output, schedule, reservation=reservation, format_version=format_version)
    except Exception as error:
        secondary = error_code('evidence_export', error)
        if isinstance(primary, PhaseFailure):
            primary.receipt['secondary_errors'].append(secondary)
            primary.receipt['receipt_persisted'] = False  # Updated in memory after the original receipt write.
        elif primary is not None:
            primary.qualification_secondary_errors = [secondary]
        else:
            receipt = dict(completed or {}, ok=False, failure='evidence_export_failed', receipt_persisted=False)
            receipt['secondary_errors'] = list(receipt.get('secondary_errors', [])) + [secondary]
            raise PhaseFailure(receipt) from None


def validate_test_accounting(schedule: dict, results: list[dict], system: str) -> tuple[int, list[dict]]:
    check_schedule(schedule, format_version=schedule.get('format_version'))
    expected = sorted(sum(schedule['batches'], []))
    if len(results) != batch_count(schedule['format_version']):
        raise ValueError('incomplete installed schedule')
    executed, skipped = [], []
    for batch, result in zip(schedule['batches'], results):
        ids, outcomes = result['test_ids'], result['outcomes']
        if ids != batch or set(outcomes) != set(batch) or any(v not in {'passed', 'skipped'} for v in outcomes.values()):
            raise ValueError('installed test identity/outcome mismatch')
        cases = result['skipped_platform_cases']
        if {r['test'] for r in cases} != {i for i, v in outcomes.items() if v == 'skipped'}:
            raise ValueError('installed skip accounting mismatch')
        executed.extend(ids)
        skipped.extend(cases)
    if len(executed) != len(set(executed)) or sorted(executed) != expected:
        raise ValueError('installed test union differs from inventory')
    required = {i for i in expected if system == 'darwin' and i.startswith('test_linux_lifetime.LinuxLifetimeTests.')}
    reasons = {i: 'Linux prctl/subreaper kernel qualification' for i in required}
    if system == 'linux':
        reasons = {'test_linux_lifetime.UnsupportedLifetimeTests.test_non_linux_helper_never_releases_target': 'non-Linux refusal',
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
                   'test_local_provider_streaming.LocalProviderStreamingTests.test_foreground_passes_live_raw_chunks_without_promoting_cessation': 'explicit Darwin foreground passthrough',
                   'test_local_provider_streaming.LocalProviderStreamingTests.test_foreground_sink_failure_returns_uncertainty_without_second_dispatch': 'explicit Darwin foreground failure passthrough',
                   'test_muse_capture_envelope.EnvelopeTests.test_four_mib_combined_bound_and_large_protocol_line': 'Real foreground owner is Darwin-only',
                   'test_muse_capture_envelope.EnvelopeTests.test_real_python_callback_cancellation_without_provider': 'Real foreground owner is Darwin-only',
                   'test_muse_native_stop_process.NativeStopProcessTests.test_timeout_then_queued_second_task_stops_and_preserves_receipt': 'Real foreground owner is Darwin-only',
                   'test_muse_native_stop_process.NativeStopProcessTests.test_second_task_without_timeout_requests_owned_stop': 'Real foreground owner is Darwin-only',
                   'test_muse_native_stop_process.NativeStopProcessTests.test_valid_one_task_child_exits_normally': 'Real foreground owner is Darwin-only',
                   'test_muse_native_stop_process.NativeStopProcessTests.test_malformed_row_requests_owned_stop_without_callback_exception': 'Real foreground owner is Darwin-only',
                   'test_muse_native_stop_process.NativeStopProcessTests.test_record_budget_failure_retains_receipt_and_raw_capture': 'Real foreground owner is Darwin-only'}
        required = set(reasons) & set(expected)
        alias = 'test_store_migration.StoreMigrationTests.test_system_alias_and_directory_identity_cannot_hide_overlapping_targets'
        if any(r['test'] == alias for r in skipped):
            reasons[alias] = 'No trusted OS directory alias contains this fixture root'
            required.add(alias)
    if len(skipped) != len({r['test'] for r in skipped}) or {r['test'] for r in skipped} != required:
        raise ValueError('unexpected platform skip inventory')
    if any(set(r) != {'test', 'reason', 'required_platform'} or r['reason'] != reasons.get(r['test'])
           or r['required_platform'] != ('Linux' if system == 'darwin' else 'Darwin') for r in skipped):
        raise ValueError('unexpected platform skip reason')
    return len(executed) - len(skipped), skipped


def export_evidence(work: Path, output: Path, schedule: dict | None, *, reservation=None, format_version: int = 2):
    """Export only validated closed records; arbitrary diagnostics stay private."""
    if (work / 'diagnostics').is_symlink():
        raise ValueError('diagnostic directory cannot be a symlink')
    if reservation is None:
        output.mkdir(parents=True, exist_ok=False, mode=0o700)
    elif output.is_symlink() or not output.is_dir() or (output.stat().st_dev, output.stat().st_ino) != reservation:
        raise ValueError('reserved export directory identity changed')
    ids = set() if schedule is None else set(sum(schedule['batches'], []))
    events = {'phase-start', 'phase-stop', 'inventory-retained', 'test-start', 'test-outcome', 'test-stop',
              'sample-baseline-start', 'sample-submit-start', 'sample-worker-start', 'sample-worker-terminal',
              'sample-publication-start', 'sample-publication-stop'}
    if schedule is not None:
        check_schedule(schedule, format_version=format_version)
    for phase in ['inventory', 'sample', *test_phases(format_version)]:
        path = work / 'diagnostics' / f'{phase}.progress.jsonl'
        parent_path = path.with_name(f'{phase}.parent.json')
        if not path.exists() and not parent_path.exists():
            continue
        if path.is_symlink() or path.exists() and path.stat().st_size > STREAM_LIMIT:
            raise ValueError('invalid progress export file')
        raw = path.read_bytes() if path.exists() else b''
        rows, partial = [], False
        for index, line in enumerate(raw.splitlines(keepends=True)):
            try:
                row = json.loads(line)
            except (ValueError, UnicodeError):
                if not line.endswith(b'\n') and index == len(raw.splitlines()) - 1:
                    partial = True
                    break
                raise ValueError('malformed complete progress record')
            if (not isinstance(row, dict) or set(row) != {'sequence', 'elapsed_seconds', 'phase', 'event', 'test', 'outcome'}
                    or type(row['sequence']) is not int or row['sequence'] != len(rows) + 1
                    or type(row['elapsed_seconds']) not in {int, float} or not math.isfinite(row['elapsed_seconds'])
                    or row['elapsed_seconds'] < (rows[-1]['elapsed_seconds'] if rows else 0)
                    or row['phase'] != phase or row['event'] not in events
                    or row['test'] not in ids | {None} or row['outcome'] not in {None, 'passed', 'skipped', 'failed'}):
                raise ValueError('unreviewed progress record cannot be exported')
            rows.append(row)
        (output / path.name).write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in rows))
        write_json(output / f'{phase}.progress-summary.json', {'source_sha256': hashlib.sha256(raw).hexdigest(),
            'source_bytes': len(raw), 'exported_records': len(rows), 'partial_tail_omitted': partial})
        if parent_path.exists():
            if parent_path.is_symlink() or parent_path.stat().st_size > 16384:
                raise ValueError('invalid parent evidence file')
            value = json.loads(parent_path.read_text())
            fields = {'identity', 'ok', 'failure', 'budget_seconds', 'elapsed_seconds', 'direct_child_exit',
                      'direct_child_reaped', 'descendant_cleanup_confirmed', 'stdout', 'stderr',
                      'secondary_errors', 'receipt_persisted'}
            if not isinstance(value, dict) or set(value) != fields:
                raise ValueError('invalid closed parent evidence')
            identity = value['identity']
            if (not isinstance(identity, dict) or set(identity) != {'phase', 'artifact_sha256', 'harness_sha256', 'lock_sha256', 'schedule_sha256'}
                    or identity['phase'] != phase or any(not is_sha(identity[k]) for k in ('artifact_sha256', 'harness_sha256', 'lock_sha256'))
                    or identity['schedule_sha256'] is not None and not is_sha(identity['schedule_sha256'])):
                raise ValueError('invalid parent identity evidence')
            for name in ('stdout', 'stderr'):
                stream = value[name]
                if (not isinstance(stream, dict) or set(stream) != {'file', 'bytes', 'truncated', 'sha256'}
                        or stream['file'] != f'diagnostics/{phase}.{name}'
                        or stream['sha256'] is not None and not is_sha(stream['sha256'])
                        or type(stream['bytes']) is not int or not 0 <= stream['bytes'] <= STREAM_LIMIT
                        or type(stream['truncated']) is not bool):
                    raise ValueError('invalid parent stream evidence')
            if (type(value['ok']) is not bool or type(value['direct_child_reaped']) is not bool
                    or value['descendant_cleanup_confirmed'] is not False
                    or value['direct_child_exit'] is not None and type(value['direct_child_exit']) is not int
                    or value['failure'] not in {None, 'timeout', 'output_limit', 'pipe_cleanup_uncertain', 'nonzero_exit',
                        'wrapper_failure', 'direct_child_reap_uncertain', 'invalid_terminal_receipt', 'cleanup_or_evidence_failure'}
                    or type(value['receipt_persisted']) is not bool or not isinstance(value['secondary_errors'], list)
                    or any(not isinstance(e, dict) or set(e) != {'stage', 'errno'}
                           or e['stage'] not in {'execution', 'poll', 'kill', 'wait', 'close_child_stdout', 'close_child_stderr',
                               'close_selector', 'close_file_stdout', 'close_file_stderr', 'close_descriptor_stdout',
                               'close_descriptor_stderr', 'read_stdout', 'read_stderr', 'persist_receipt'}
                           or e['errno'] is not None and type(e['errno']) is not int for e in value['secondary_errors'])
                    or any(type(value[k]) not in {float, int} or not math.isfinite(value[k]) or value[k] < 0
                           for k in ('budget_seconds', 'elapsed_seconds'))
                    or value['ok'] and (partial or not rows or rows[-1]['event'] != 'phase-stop')):
                raise ValueError('invalid parent outcome evidence')
            write_json(output / parent_path.name, value)
    if schedule is not None:
        check_schedule(schedule, format_version=format_version)
        write_json(output / 'discovered-inventory.json', schedule)
        for index, batch in enumerate(schedule['batches']):
            write_json(output / f'tests-{index}.expected.json', {'test_ids': batch, 'schedule_sha256': json_digest(schedule)})


def snapshot_artifact(source: Path, directory: Path) -> tuple[Path, str]:
    """Audit/install a private byte snapshot, never a concurrently rebuilt path."""
    if source.is_symlink() or not source.is_file():
        raise RuntimeError("distribution artifact must be a regular file")
    with source.open("rb") as stream:
        data = stream.read(MAX_ARTIFACT_BYTES + 1)
    if len(data) > MAX_ARTIFACT_BYTES:
        raise RuntimeError("distribution artifact exceeds qualification limit")
    target = directory / source.name
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
    return target, hashlib.sha256(data).hexdigest()


def snapshot_harness(source: Path, work: Path) -> str:
    """Freeze reviewed test/fixture/lock inputs before slow installation begins."""
    inventory = json.loads((source / "distribution-inventory.json").read_text(encoding="utf-8"))
    inputs = {"tools/qualify_installed.py", "tools/qualify_runtime.py", "requirements-dev.lock"} | {
        path for path in inventory["sdist_sources"] if path.startswith("tests/") and path != "tests/test_distribution.py"}
    values = {relative: (source / relative).read_bytes() for relative in sorted(inputs)}
    (work / "qualify_installed.py").write_bytes(values["tools/qualify_installed.py"])
    (work / "requirements-dev.lock").write_bytes(values["requirements-dev.lock"])
    (work / "tools").mkdir()
    (work / "tools" / "qualify_runtime.py").write_bytes(values["tools/qualify_runtime.py"])
    (work / "fixtures").mkdir()
    for relative in FIXTURES:
        (work / "fixtures" / Path(relative).name).write_bytes(values[relative])
    for relative, data in values.items():
        if relative.startswith("tests/"):
            target = work / "installed-tests" / relative.removeprefix("tests/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    manifest = [{"path": relative, "sha256": hashlib.sha256(data).hexdigest()} for relative, data in sorted(values.items())]
    write_json(work / 'harness-manifest.json', manifest)
    return json_digest(manifest)


def freeze_runtime_inventory(wheel: Path, work: Path, *, source_digest: str, source_kind: str) -> str:
    """Freeze audited archive expectations separately from installed observations.

    The caller audits the wheel and installs it before this step. The runtime
    tool verifies actual site-package bytes; these hashes do not confer trust.
    """
    from check_dist import read_wheel, DIST_INFO

    files = read_wheel(wheel)
    value = {'kind': 'runtime_artifact_inventory', 'format_version': '1.0',
        'artifact_digest': hashlib.sha256(wheel.read_bytes()).hexdigest(),
        'source_artifact_digest': source_digest, 'source_artifact_kind': source_kind,
        'package_version': '0.1.0a1',
        'payloads': {name: {'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw)}
                     for name, raw in sorted(files.items()) if name.startswith('taskalong/')},
        'metadata_sha256': hashlib.sha256(files[f'{DIST_INFO}/METADATA']).hexdigest(),
        'lock_sha256': hashlib.sha256((work / 'requirements-dev.lock').read_bytes()).hexdigest(),
        'runner_sha256': hashlib.sha256((work / 'tools/qualify_runtime.py').read_bytes()).hexdigest(),
        'helper_sha256': hashlib.sha256((work / 'installed-tests/fixtures/runtime_canary.py').read_bytes()).hexdigest()}
    value['digest'] = json_digest(value)
    path = work / 'runtime-artifact-inventory.json'
    with path.open('xb') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(json.dumps(value, sort_keys=True).encode() + b'\n')
        output.flush()
        os.fsync(output.fileno())
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_harness(work: Path, expected_sha256: str):
    manifest = json.loads((work / 'harness-manifest.json').read_text())
    if not isinstance(manifest, list) or json_digest(manifest) != expected_sha256:
        raise ValueError('frozen harness manifest identity changed')
    installed_paths = set()
    for row in manifest:
        if not isinstance(row, dict) or set(row) != {'path', 'sha256'} or not is_sha(row['sha256']):
            raise ValueError('invalid frozen harness manifest')
        relative = row['path']
        if not isinstance(relative, str) or Path(relative).is_absolute() or '..' in Path(relative).parts:
            raise ValueError('invalid frozen harness path')
        if relative in {'tools/qualify_installed.py', 'requirements-dev.lock'}:
            paths = [work / Path(relative).name]
        elif relative == 'tools/qualify_runtime.py':
            paths = [work / relative]
        elif relative.startswith('tests/') and relative != 'tests/test_distribution.py':
            suffix = relative.removeprefix('tests/')
            installed_paths.add(suffix)
            paths = [work / 'installed-tests' / suffix]
            if relative in FIXTURES:
                paths.append(work / 'fixtures' / Path(relative).name)
        else:
            raise ValueError('unexpected frozen harness path')
        for path in paths:
            if (path.is_symlink() or not path.is_file()
                    or any(p.is_symlink() for p in path.parents if p.is_relative_to(work))
                    or hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']):
                raise ValueError('frozen installed harness bytes changed')
    actual = {str(p.relative_to(work / 'installed-tests')) for p in (work / 'installed-tests').rglob('*') if p.is_file()}
    if installed_paths != actual:
        raise ValueError('frozen installed test inventory changed')


@contextmanager
def qualification_directory():
    directory = Path(tempfile.mkdtemp(prefix="taskalong-installed-")).resolve()
    try:
        yield directory
    except Exception as error:
        # Preserve synthetic state/worktree/process receipts on failure. Removing
        # an uncertain execution's control records would frustrate reconciliation.
        raise RuntimeError(f"{error}; synthetic qualification retained at {directory}") from error
    else:
        shutil.rmtree(directory)


def clean_environment() -> dict[str, str]:
    env = dict(os.environ)
    for key in list(env):
        if key in {"PYTHONPATH", "PYTHONHOME", "GH_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GIT_SSH_COMMAND"}:
            env.pop(key, None)
    env.update(PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", PIP_DISABLE_PIP_VERSION_CHECK="1",
               GIT_TERMINAL_PROMPT="0", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    return env


def create_environment(path: Path, *, timeout: float = 60) -> str:
    # Standalone Darwin interpreters locate libpython relative to their executable.
    # Native venv links preserve that layout; copying the executable can abort in
    # dyld before ensurepip starts. Package imports still come from the fresh venv.
    argv = [sys.executable, '-m', 'venv']
    if sys.platform == 'darwin':
        argv.append('--symlinks')
    subprocess.run(argv + [str(path)], env=clean_environment(), capture_output=True, timeout=timeout, check=True)
    return str(path / "bin" / "python")


def command(argv: list[str], *, cwd: Path, env: dict, timeout: int = 60) -> str:
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        # Dependency installation errors can mention indexes. Retain diagnostic
        # metadata, never environment values or complete command output.
        detail = ": " + result.stderr[-6000:] if "--child" in argv else ""
        raise RuntimeError(f"qualification subprocess failed: tool={Path(argv[0]).name}, exit={result.returncode}{detail}")
    return result.stdout


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def wrapper(path: Path, python: str, program: str) -> None:
    path.write_text(f"#!{python}\n{program}\n", encoding="utf-8")
    path.chmod(0o700)


def cli(python: str, state: Path, *args: str, ok_codes: tuple[int, ...] = (0,)) -> dict:
    result = subprocess.run([python, "-m", "taskalong", "--state-dir", str(state), *args, "--json"],
                            cwd=Path.cwd(), env=clean_environment(), capture_output=True, text=True, timeout=30)
    if result.returncode not in ok_codes:
        raise AssertionError(f"CLI command {args[0]} returned {result.returncode}")
    value = json.loads(result.stdout)
    assert value["kind"] == "command_result" and value["schema_version"] == "1.0"
    return value


def installed_context(args: argparse.Namespace):
    # This code executes only from a copied file with an external CWD. These are
    # the exact same installed APIs used by task-neutral local callers.
    source_root = Path(args.source_root).resolve()
    denied_source_roots = [source_root]
    if args.build_source_root:
        denied_source_roots.append(Path(args.build_source_root).resolve())

    def deny_checkout_reads(event: str, values: tuple) -> None:
        # The copied harness can inspect import identities but cannot read the
        # original checkout. An accidental source/resource fallback fails here.
        if event in {"open", "os.listdir", "os.scandir"} and values and isinstance(values[0], (str, bytes, os.PathLike)):
            target = Path(os.fsdecode(values[0])).absolute()
            if any(target.is_relative_to(root) for root in denied_source_roots):
                raise AssertionError("installed qualification attempted source checkout access")

    sys.addaudithook(deny_checkout_reads)
    import importlib.metadata
    from importlib import resources
    import taskalong
    from taskalong.api import RunService
    from taskalong.validation import canonical_bytes, digest, seal, schema_names

    cwd = Path.cwd()
    package = Path(taskalong.__file__).resolve()
    assert not package.is_relative_to(source_root), "source checkout import leaked into installed qualification"
    assert not any(p and Path(p).resolve().is_relative_to(source_root) for p in sys.path), "source checkout remains importable"
    assert not any(p and Path(p).resolve().is_relative_to(root) for p in sys.path for root in denied_source_roots), "build source remains importable"
    assert os.environ.get("PYTHONPATH") is None
    assert importlib.metadata.version("taskalong") == "0.1.0a1"

    def package_snapshot() -> dict:
        return {str(path.relative_to(package.parent)): {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "mode": path.stat().st_mode}
                for path in package.parent.rglob("*") if path.is_file()}

    return package_snapshot


def child_journey(args: argparse.Namespace, progress: Progress) -> dict:
    package_snapshot = installed_context(args)
    before = package_snapshot()
    from importlib import resources
    import importlib.metadata
    from taskalong.api import RunService
    from taskalong.validation import digest, seal, schema_names
    cwd = Path.cwd()
    py = sys.executable
    env = clean_environment()
    for argv in ([py, "-m", "taskalong", "--version"], [str(Path(py).parent / "taskalong"), "--version"], [str(Path(py).parent / "taskalong"), "--help"]):
        assert "taskalong" in command(argv, cwd=cwd, env=env).lower()
    assert len(schema_names()) == 12
    for name in schema_names():
        assert resources.files("taskalong.resources").joinpath(f"schemas/v1/{name}.schema.json").is_file()
    for name in ("templates/worker.txt", "templates/draft-pr.md", "sql/001-initial.sql"):
        assert resources.files("taskalong.resources").joinpath(name).read_bytes()

    progress.emit('sample-baseline-start')
    repo = cwd / "tiny-project"
    repo.mkdir()
    command(["git", "init", "-b", "main", str(repo)], cwd=cwd, env=env)
    command(["git", "-C", str(repo), "config", "user.name", "Synthetic Operator"], cwd=cwd, env=env)
    command(["git", "-C", str(repo), "config", "user.email", "synthetic@example.invalid"], cwd=cwd, env=env)
    (repo / "arithmetic.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    (repo / "test_arithmetic.py").write_text("import unittest\nfrom arithmetic import add\n\nclass AdditionTests(unittest.TestCase):\n    def test_addition(self):\n        self.assertEqual(add(2, 3), 5)\n", encoding="utf-8")
    baseline = subprocess.run([py, "-m", "unittest", "-q", "test_arithmetic"], cwd=repo, env=env, capture_output=True, timeout=10)
    assert baseline.returncode == 1, "synthetic baseline must demonstrate the actual failing criterion"
    command(["git", "-C", str(repo), "add", "arithmetic.py", "test_arithmetic.py"], cwd=cwd, env=env)
    command(["git", "-C", str(repo), "commit", "-m", "Synthetic baseline"], cwd=cwd, env=env)
    base = command(["git", "-C", str(repo), "rev-parse", "HEAD"], cwd=cwd, env=env).strip()
    bare = cwd / "remote.git"
    command(["git", "init", "--bare", str(bare)], cwd=cwd, env=env)
    command(["git", "-C", str(repo), "push", str(bare), "HEAD:refs/heads/main"], cwd=cwd, env=env)

    fixtures = cwd / "fixtures"
    fake = fixtures / "fake-codex"
    wrapper(fake, py, f"import runpy\nrunpy.run_path({str(fixtures / 'fake_codex.py')!r}, run_name='__main__')")
    sandbox = fixtures / "command-sandbox"
    wrapper(sandbox, py, "import os,sys\na=sys.argv[sys.argv.index('--')+1:]\nos.execv(a[0],a)")
    state = cwd / "private-state"
    service = RunService(state)
    registration = service.register_repository(repo, workspace_root=cwd / "workspaces")
    policy = {}
    profile = seal("runtime-profile", {
        "profile_id": "installed-synthetic-codex", "qualification": "synthetic", "adapter": "codex-cli",
        "executable_path": str(fake), "executable_sha256": hashlib.sha256(fake.read_bytes()).hexdigest(),
        "runtime_version": "0.163.0", "model": "synthetic-fixture", "reasoning_effort": "low", "service_tier": None,
        "inference_destination_id": "synthetic-local-only", "permission_policy": policy,
        "permission_policy_digest": digest(policy), "toolchain_read_roots": [str(Path(py).parent)],
        "credential_source_ref": None, "qualification_receipt_ids": [],
    })
    service.register_profile(profile)
    service.configure_command_sandbox(sandbox)
    fake_gh_state = cwd / "fake-gh-state.json"
    write_json(fake_gh_state, {"repository_full_name": "fixture/repository", "repository_id": 4242,
                               "base_commit": base, "git_remote": str(bare), "prs": [],
                               "lose_create_response": True})
    fake_gh = fixtures / "fake-gh"
    wrapper(fake_gh, py, "import os,runpy\n" + f"os.environ['TASKALONG_FAKE_GH_STATE']={str(fake_gh_state)!r}\n"
            + f"runpy.run_path({str(fixtures / 'fake_gh.py')!r},run_name='__main__')")
    service.configure_publication(fake_gh, bare, qualification="synthetic")
    config = cwd / "review.yml"
    config.write_text("schema: 1\n", encoding="utf-8")
    response = cwd / "review-fixture.json"
    write_json(response, {"summary": "Synthetic clean review.", "comments": []})
    config_sha = hashlib.sha256(config.read_bytes()).hexdigest()
    review_executable = Path(py).parent / "review-sensei"
    if not args.core_only:
        assert importlib.metadata.version("review-sensei") == "0.8.8"
        service.configure_review(config, fixture_response=response, executable=review_executable, python_executable=py)
    spec = seal("task-spec", {
        "task_id": "installed-synthetic-addition", "revision": 1, "goal": "Correct the addition function.",
        "non_goals": ["No dependencies, network, or other files."],
        "repository": {"registration_id": registration["registration_id"], "base_commit": base, "base_ref": "main"},
        "scope": {"files": ["arithmetic.py"], "operations": ["modify"]},
        "criteria": [{"id": "addition", "description": "The function adds two integers.", "check_ids": ["addition-check"]}],
        "checks": [{"id": "addition-check", "argv": [py, "-m", "unittest", "-q", "test_arithmetic"],
                    "cwd": ".", "timeout_seconds": 10, "expected_exit_code": 0, "criterion_ids": ["addition"], "required": True}],
        "execution": {"adapter": "codex-cli", "profile_id": profile["profile_id"], "profile_digest": profile["digest"]},
        "permissions": {"local_edit": True, "local_commit": True, "inference_destination_id": "synthetic-local-only",
                        "allowed_effects": ["execute", "verify", "commit_candidate", "push_branch", "create_draft_pr"]},
        "budget": {"max_attempts": 2, "attempt_seconds": 30, "total_active_seconds": 60, "max_output_bytes": 1048576,
                   "hard_cost_usd": None, "hard_tokens": None},
        "review": {"required": True, "integration": "reviewsensei", "contract": "0.8.8/v1", "config_digest": config_sha, "require_full_coverage": True},
        "publication": {"host": "github.com", "repository_id": 4242, "repository_full_name": "fixture/repository",
                        "base_branch": "main", "title": "Correct synthetic addition",
                        "body_template_digest": hashlib.sha256(b"TaskAlong independently accepted this bounded candidate.").hexdigest()},
        "qualification": "synthetic",
    })
    spec_path = cwd / "task.json"
    write_json(spec_path, spec)
    progress.emit('sample-submit-start')
    submitted = cli(py, state, "submit", "--spec", str(spec_path), "--key", "installed-submit")
    run_id = submitted["run_id"]
    first = service.inspect(run_id)
    repeated = cli(py, state, "submit", "--spec", str(spec_path), "--key", "installed-submit")
    assert repeated["run_id"] == run_id
    changed = dict(spec)
    changed["goal"] = "Changed semantic task must conflict."
    changed = seal("task-spec", {k: v for k, v in changed.items() if k != "digest"})
    write_json(cwd / "changed-task.json", changed)
    cli(py, state, "submit", "--spec", str(cwd / "changed-task.json"), "--key", "installed-submit", ok_codes=(4,))
    authority = service.authorize(run_id, decision_digest=spec["digest"], scope=["execute", "verify", "commit_candidate"], qualification="synthetic")
    # Start via the installed console protocol; process ownership and all durable
    # transitions are product code. Poll from new clients rather than sharing a
    # connection with the detached supervisor.
    progress.emit('sample-worker-start')
    cli(py, state, "start", run_id, "--expected-revision", str(service.inspect(run_id)["revision"]), "--key", "installed-start")
    deadline = time.monotonic() + 45
    run = first
    while time.monotonic() < deadline:
        run = RunService(state).inspect(run_id)
        if run["state"] in {"accepted", "blocked", "failed", "cancelled"}:
            break
        time.sleep(.1)
    expected = "blocked" if args.core_only else "accepted"
    assert run["state"] == expected, {"expected": expected, "observed": run["state"], "blockers": run.get("blockers")}
    progress.emit('sample-worker-terminal')
    events = service.events(run_id)
    assert events and [event["seq"] for event in events] == list(range(1, len(events) + 1))
    assert len(run["attempts"]) == 1
    invocations = (fixtures / "fake-codex-invocations.jsonl").read_text().splitlines()
    assert len(invocations) == 1 and json.loads(invocations[0])["run_id"] == run_id
    assert command(["git", "-C", str(repo), "rev-parse", "HEAD"], cwd=cwd, env=env).strip() == base
    assert not command(["git", "-C", str(repo), "status", "--porcelain"], cwd=cwd, env=env)
    assert "return a - b" in (repo / "arithmetic.py").read_text()
    cli(py, state, "status", run_id)
    cli(py, state, "export", run_id, "--output", str(cwd / "export"))
    publication = "review-blocked"
    if not args.core_only:
        progress.emit('sample-publication-start')
        intent = service.publish_intent(run_id)
        # The fake service creates a PR and loses the response. The product must
        # preserve uncertainty and reconcile it with reads, without another POST.
        cli(py, state, "publish", run_id, "--intent-digest", intent["digest"],
            "--expected-revision", str(service.inspect(run_id)["revision"]), "--key", "installed-publish", ok_codes=(5,))
        unknown = service.inspect(run_id)
        assert unknown["state"] == "blocked"
        cli(py, state, "reconcile", run_id, "--expected-revision", str(unknown["revision"]), "--key", "installed-reconcile")
        run = service.inspect(run_id)
        assert run["state"] == "draft_published"
        assert run["publication"]["kind"] == "fixture" and run["publication"]["draft"] is True
        fake_state = json.loads(fake_gh_state.read_text())
        assert fake_state["create_calls"] == 1 and len(fake_state["prs"]) == 1
        assert command(["git", "--git-dir", str(bare), "rev-parse", f"refs/heads/taskalong/{run_id}"], cwd=cwd, env=env).strip() == run["candidate"]["commit"]
        publication = "fixture-lost-response-reconciled-one-create"
        events = service.events(run_id)
        assert [event["seq"] for event in events] == list(range(1, len(events) + 1))
    progress.emit('sample-publication-stop')
    after = package_snapshot()
    assert before == after, "application wrote into installed package"
    return {"kind": "installed_journey", "format_version": 1, "ok": True, "state": run["state"],
            "qualification": "synthetic", "review": "missing-blocks" if args.core_only else "released-fixture-full-diff",
            "publication": publication, "python": platform.python_version(), "platform": platform.system(),
            "machine": platform.machine(), "package_version": "0.1.0a1", "attempts": len(run["attempts"]),
            "events": len(events), "source_import": False, "real_sandbox_claim": False,
            "installed_behavior_tests": 0,
            "skipped_platform_cases": [],
            "dependencies": {name: importlib.metadata.version(name) for name in ("jsonschema", "setuptools", "certifi")}}


def discovered_tests(cwd: Path) -> list:
    def flatten(suite):
        for item in suite:
            if isinstance(item, unittest.TestSuite):
                yield from flatten(item)
            else:
                yield item
    loader = unittest.TestLoader()
    tests = list(flatten(loader.discover(str(cwd / 'installed-tests'))))
    if loader.errors:
        raise ValueError('installed test discovery failed')
    make_schedule([test.id() for test in tests])
    return tests


def child_phase(args: argparse.Namespace) -> dict:
    format_version = getattr(args, 'format_version', 2)
    phases = test_phases(format_version)
    cwd = Path.cwd()
    value = json.loads(Path(args.phase_input).read_text())
    if set(value) != {'identity', 'schedule'}:
        raise ValueError('invalid phase input')
    identity, schedule = value['identity'], value['schedule']
    if set(identity) != {'phase', 'artifact_sha256', 'harness_sha256', 'lock_sha256', 'schedule_sha256'}:
        raise ValueError('invalid phase identity')
    phase = identity['phase']
    if phase not in {'inventory', 'sample', *phases}:
        raise ValueError('unknown child phase')
    if identity['schedule_sha256'] != (None if schedule is None else json_digest(schedule)):
        raise ValueError('phase schedule identity mismatch')
    progress = Progress(cwd / 'diagnostics' / f'{phase}.progress.jsonl', phase)
    progress.emit('phase-start')
    snapshot = installed_context(args)
    verify_harness(cwd, identity['harness_sha256'])
    if hashlib.sha256((cwd / 'requirements-dev.lock').read_bytes()).hexdigest() != identity['lock_sha256']:
        raise ValueError('phase lock identity mismatch')
    before = snapshot()
    baseline_sha = json_digest(before)
    payload = {}
    if phase == 'sample':
        payload['journey'] = child_journey(args, progress)
    else:
        tests = discovered_tests(cwd)
        actual = make_schedule([test.id() for test in tests], format_version=format_version)
        if phase == 'inventory':
            if schedule is not None:
                raise ValueError('inventory must precede schedule')
            payload['schedule'] = actual
            write_json(cwd / 'diagnostics' / 'discovered-inventory.json', actual)
            progress.emit('inventory-retained')
        else:
            if schedule != actual:
                raise ValueError('installed inventory changed between phases')
            batch = schedule['batches'][int(phase[-1])]
            by_id = {test.id(): test for test in tests}
            write_json(cwd / 'diagnostics' / f'{phase}.expected.json', {'test_ids': batch, 'schedule_sha256': json_digest(schedule)})
            result = unittest.TextTestRunner(stream=sys.stderr, verbosity=1,
                resultclass=lambda *a, **kw: ProgressResult(*a, progress=progress, **kw)).run(
                    unittest.TestSuite([by_id[i] for i in batch]))
            if not result.wasSuccessful() or result.executed != batch:
                raise AssertionError('installed behavior batch failed or omitted tests')
            payload.update(test_ids=result.executed, outcomes=result.outcomes,
                skipped_platform_cases=[{'test': test.id(), 'reason': reason,
                    'required_platform': 'Linux' if sys.platform == 'darwin' else 'Darwin'} for test, reason in result.skipped])
    if before != snapshot():
        raise AssertionError('installed phase mutated package')
    verify_harness(cwd, identity['harness_sha256'])
    payload['package_snapshot_sha256'] = baseline_sha
    progress.emit('phase-stop', outcome='passed')
    return phase_receipt(identity, payload, format_version=format_version)


def acquire_review(path: Path | None, target: Path, *, timeout: float = 30) -> Path:
    if path:
        data = path.read_bytes()
    else:
        # Read only the public immutable release artifact; no source or task text
        # is transmitted, and there is no provider request.
        try:
            import certifi
            context = ssl.create_default_context(cafile=certifi.where())
        except ImportError:
            context = ssl.create_default_context()
        with urllib.request.urlopen(REVIEW_URL, timeout=timeout, context=context) as response:
            data = response.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != REVIEW_SHA256:
        raise RuntimeError("released ReviewSensei wheel checksum mismatch")
    target.write_bytes(data)
    return target


def qualify(args: argparse.Namespace) -> dict:
    format_version = getattr(args, 'format_version', 2)
    behavior_phases = test_phases(format_version)
    started = time.monotonic()
    def budget(limit: float = 60) -> float:
        remaining = QUALIFICATION_SECONDS - (time.monotonic() - started)
        if remaining <= 0:
            raise RuntimeError('total installed qualification budget exhausted')
        return min(limit, remaining)

    reservation = None
    if args.evidence_dir:
        args.evidence_dir = args.evidence_dir.resolve()
        args.evidence_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        reservation = (args.evidence_dir.stat().st_dev, args.evidence_dir.stat().st_ino)

    root = Path(__file__).resolve().parents[1]
    artifact_paths = sorted(args.dist_dir.glob("*.whl" if args.artifact == "wheel" else "*.tar.gz"))
    if len(artifact_paths) != 1:
        raise RuntimeError("expected one selected distribution artifact")
    selected_artifact = artifact_paths[0].absolute()
    from check_dist import audit
    with qualification_directory() as base:
        if base.is_relative_to(root):
            raise RuntimeError("qualification temporary root must be outside checkout")
        artifact, artifact_sha256 = snapshot_artifact(selected_artifact, base)
        audit(artifact, root=root)
        work = base / "work"
        work.mkdir()
        extracted = None
        if args.artifact == "sdist":
            source = base / "sdist"
            source.mkdir()
            # The archive has already been checked for exact paths and links.
            with tarfile.open(artifact, "r:gz") as archive:
                archive.extractall(source, filter="data")
            extracted = source / "taskalong-0.1.0a1"
        harness_inputs_sha256 = snapshot_harness(extracted or root, work)
        env = clean_environment()
        venv_path = base / "venv"
        python = create_environment(venv_path, timeout=budget())
        env["PATH"] = str(venv_path / "bin") + os.pathsep + env.get("PATH", os.defpath)
        env["TASKALONG_REVIEW_EXECUTABLE"] = str(venv_path / "bin" / "review-sensei")
        env["TASKALONG_REVIEW_PYTHON"] = python
        install = [python, "-m", "pip", "--isolated", "--disable-pip-version-check", "install"]
        if args.wheelhouse:
            install += ["--no-index", "--find-links", str(args.wheelhouse.resolve())]
        command(install + ["--require-hashes", "-r", str(work / "requirements-dev.lock")], cwd=work, env=env, timeout=budget())
        install_artifact = artifact
        if args.artifact == "sdist":
            command([python, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(base / "rebuilt")], cwd=extracted, env=env, timeout=budget())
            wheels = list((base / "rebuilt").glob("*.whl"))
            if len(wheels) != 1:
                raise RuntimeError("sdist wheel build did not yield one artifact")
            install_artifact = wheels[0]
            audit(install_artifact, root=extracted)
        command(install + ["--no-deps", str(install_artifact)], cwd=work, env=env, timeout=budget())
        runtime_inventory_sha = freeze_runtime_inventory(install_artifact, work,
            source_digest=artifact_sha256, source_kind=args.artifact)
        if not args.core_only:
            review = acquire_review(args.review_wheel, base / "review_sensei-0.8.8-py3-none-any.whl", timeout=budget(30))
            command(install + ["--no-deps", str(review)], cwd=work, env=env, timeout=budget())
        copied = work / "qualify_installed.py"
        child_args = [python, str(copied), "--child", "--source-root", str(root),
                      '--format-version', str(format_version)]
        if extracted:
            child_args.extend(["--build-source-root", str(extracted)])
        if args.core_only:
            child_args.append("--core-only")
        lock_sha = hashlib.sha256((work / 'requirements-dev.lock').read_bytes()).hexdigest()
        phases, phase_receipts, schedule, package_sha = {}, [], None, None
        order = ['sample'] if args.core_only else ['inventory', 'sample', *behavior_phases]
        primary = None
        try:
            for phase in order:
                identity = {'phase': phase, 'artifact_sha256': artifact_sha256,
                    'harness_sha256': harness_inputs_sha256, 'lock_sha256': lock_sha,
                    'schedule_sha256': None if schedule is None else json_digest(schedule)}
                phase_input = work / 'phase-input.json'
                write_json(phase_input, {'identity': identity, 'schedule': schedule})
                verify_harness(work, harness_inputs_sha256)
                if hashlib.sha256((work / 'runtime-artifact-inventory.json').read_bytes()).hexdigest() != runtime_inventory_sha:
                    raise ValueError('runtime artifact inventory changed')
                payload, receipt = run_phase(child_args + ['--phase-input', str(phase_input)], cwd=work,
                    env=env, identity=identity, timeout=budget(60 if phase == 'inventory' else PHASE_SECONDS),
                    format_version=format_version)
                verify_harness(work, harness_inputs_sha256)
                if hashlib.sha256((work / 'runtime-artifact-inventory.json').read_bytes()).hexdigest() != runtime_inventory_sha:
                    raise ValueError('runtime artifact inventory changed')
                phases[phase] = payload
                phase_receipts.append(receipt)
                current = payload['package_snapshot_sha256']
                if package_sha is not None and current != package_sha:
                    raise ValueError('package changed between installed phases')
                package_sha = current
                if phase == 'inventory':
                    schedule = payload['schedule']
                    check_schedule(schedule, format_version=format_version)
        except BaseException as error:
            primary = error
            raise
        finally:
            # Public-safe evidence contains only closed progress/identity records.
            # Raw streams and synthetic state stay in the retained private root.
            if args.evidence_dir:
                finalize_export(work, args.evidence_dir, schedule, reservation=reservation, primary=primary,
                                completed=phase_receipts[-1] if phase_receipts else None,
                                format_version=format_version)
        result = phases['sample']['journey']
        count, skipped = (0, []) if args.core_only else validate_test_accounting(
            schedule, [phases[phase] for phase in behavior_phases], sys.platform)
        budget()
        result.update(format_version=format_version, installed_behavior_tests=count, skipped_platform_cases=skipped,
                      schedule=schedule, phases=phase_receipts, package_snapshot_sha256=package_sha,
                      elapsed_seconds=round(time.monotonic() - started, 6), total_budget_seconds=QUALIFICATION_SECONDS,
                      behavior_test_ids=[] if args.core_only else sorted(sum(schedule['batches'], [])))
        result.update(artifact=args.artifact, artifact_sha256=artifact_sha256,
                      review_wheel_sha256=None if args.core_only else REVIEW_SHA256,
                      dependency_lock_sha256=lock_sha,
                      qualification_inputs_sha256=harness_inputs_sha256,
                      environment="fresh-venv-external-cwd", editable=False)
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--artifact", choices=("wheel", "sdist"), default="wheel")
    parser.add_argument("--mode", choices=("fixture",), default="fixture")
    parser.add_argument("--review-wheel", type=Path)
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--core-only", action="store_true")
    parser.add_argument('--evidence-dir', type=Path, help='new directory for allowlisted phase/test progress (never raw streams)')
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--source-root", help=argparse.SUPPRESS)
    parser.add_argument("--build-source-root", help=argparse.SUPPRESS)
    parser.add_argument('--phase-input', help=argparse.SUPPRESS)
    parser.add_argument('--format-version', type=int, choices=(2, 3), default=2,
                        help='2: unchanged two-batch protocol; 3: explicit four-batch protocol')
    args = parser.parse_args(argv)
    try:
        if args.child:
            # Some original behavior fixtures emit observations. They are private
            # diagnostics, not additional terminal documents on the stdout wire.
            with redirect_stdout(sys.stderr):
                result = child_phase(args)
        else:
            result = qualify(args)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        if args.child:
            # Synthetic harness failures include assertions for actionable local
            # diagnosis. It never receives live source or credentials.
            import traceback
            traceback.print_exc(file=sys.stderr)
        else:
            cause = error.__cause__ or error
            print(json.dumps({"kind": "installed_qualification", "format_version": args.format_version, "ok": False,
                              "artifact": args.artifact, 'error': type(cause).__name__,
                              'failure': cause.receipt if isinstance(cause, PhaseFailure) else None,
                              'secondary_errors': getattr(cause, 'qualification_secondary_errors', []),
                              'retained_synthetic_state': True}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
