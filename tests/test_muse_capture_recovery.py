"""Expanded capture decisions against disposable State and native fixtures only."""
import concurrent.futures
import contextlib
import errno
import io
import json
import os
from pathlib import Path
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from taskalong.api import RunService
from taskalong import muse_experimental as muse, muse_successor as successor
from taskalong import muse_capture_recovery as recovery
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, digest
import test_muse_successor as fixtures


def torn_record(session, native_run, sequence, *, terminal=False, text='p' * 55000):
    """Ordered observed layout, dummy IDs/content; deliberately no text closer."""
    row = {'schema_version': 1, 'id': 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
           'stream': {'kind': 'session', 'id': session}, 'sequence': sequence, 'recorded_at': 1700000000000,
           'record_type': 'event' if terminal else 'status', 'durability': 'durable' if terminal else 'ephemeral',
           'causation_id': 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
           'payload_type': 'run.terminal.completed' if terminal else 'run.output.delta', 'payload_schema_version': 1,
           'payload': {'kind': 'run_terminal' if terminal else 'run_output_delta', 'command_id': native_run,
                       'run_stream': {'kind': 'run', 'id': native_run}}}
    if terminal:
        row['payload']['terminal'] = 'completed'
    row['payload']['text'] = text
    raw = json.dumps(row, separators=(',', ':')).encode()
    return raw[:-3]  # Remove closing quote and two object closers only.


@unittest.skipUnless(os.name == 'posix', 'Private local State is POSIX')
class ExpandedCaptureTests(unittest.TestCase):
    def setUp(self):
        self.c = fixtures.SuccessorTests('test_two_explicit_timeouts_use_360_then_720_and_preserve_history')
        self.c.setUp()
        self.addCleanup(self.c.doCleanups)
        self.root, self.service = self.c.root, self.c.service
        with patch.object(muse, 'run_foreground_experiment', side_effect=self.overflow):
            self.c.original_at(1440, capture_profile='large-task', max_proposal_bytes=65536, max_protocol_records=2048)
        self.original = self.c.original
        self.configure()

    def configure(self, **changes):
        return self.service.configure_provider('muse', {'executable': str(self.c.binary), 'account_home': str(self.c.home),
            'muse_home': str(self.c.data), 'capture_profile': 'megabyte-proposal', 'attempt_seconds': 1440, **changes})

    def overflow(self, argv, **options):
        result = self.c.owner(argv, **options)
        session = argv[argv.index('--session-id') + 1]
        linked = json.loads(result.stdout.splitlines()[0])
        native_run = linked['payload']['run_stream']['id']
        root = Path(argv[argv.index('--workspace') + 1]).parent
        manifest = json.loads((root / 'bundle/bundle.json').read_bytes())
        response = canonical_bytes({'bundle_digest': manifest['digest'], 'changes': {'source.py': 'x' * 55000 + '\n'}}).decode()
        rows = [linked, linked | {'sequence': 2, 'payload_type': 'fixture.padding', 'payload': {'padding': ''}}]
        for offset in range(0, len(response), 1400):
            rows.append(linked | {'sequence': len(rows) + 1, 'payload_type': 'run.output.delta',
                'payload': {'kind': 'run_output_delta', 'command_id': native_run,
                            'run_stream': {'kind': 'run', 'id': native_run}, 'text': response[offset:offset + 1400]}})
        tail = torn_record(session, native_run, len(rows) + 1, terminal=getattr(self, 'terminal_tail', False))
        initial = b''.join(canonical_bytes(row) + b'\n' for row in rows)
        rows[1]['payload']['padding'] = 'z' * (1048576 - len(initial) - len(tail))
        retained = b''.join(canonical_bytes(row) + b'\n' for row in rows) + tail
        self.assertEqual(len(retained), 1048576)
        full = retained + b' discarded suffix"}}\n'
        options['_on_output_chunk']('stdout', full)
        for line in full.splitlines():
            options['on_stdout_line'](line)
        info = result.to_dict() | {'root_exit_code': 130, 'timed_out': False, 'cancelled': False,
                                   'output_limited': True, 'output_bytes': len(full)}
        return SimpleNamespace(stdout=retained, stderr=b'', root_exit_code=130, timed_out=False,
            cancelled=False, output_limited=True, failure_code=None, to_dict=lambda: info)

    def child(self, argv, **options):
        result = self.c.owner(argv, **options)
        stdout, stderr = result.stdout, result.stderr
        options['_on_output_chunk']('stdout', stdout)
        for line in stdout.splitlines():
            options['on_stdout_line'](line)
        if stderr:
            options['_on_output_chunk']('stderr', stderr)
        if options.get('_retain_output') is False:
            result.stdout = result.stderr = b''
        return result

    def plan(self):
        return self.service.provider_successor_plan(predecessor=self.original['run_id'], reason='capture')

    def execute(self, proof=None, *, key='expanded', service=None):
        return (service or self.service).provider_successor(predecessor=self.original['run_id'], key=key,
            plan_digest=(proof or self.plan())['digest'], output=str(self.root / key), reason='capture')

    def test_unsealed_candidate_is_inspection_only_and_explicit_one_shot_completes(self):
        before = len(self.c.calls)
        proof = self.plan()
        self.assertEqual(proof['format'], 'manual-muse-successor-plan/3')
        self.assertEqual(proof['enrollment']['format'], 'manual-muse-ladder/3')
        self.assertEqual(proof['remaining_controller_slots_including_this'], 1)
        self.assertEqual(proof['attempt_seconds'], 1440)
        self.assertTrue(proof['unsealed_candidate_observed'])
        self.assertFalse(proof['existing_fragment_recovery_supported'])
        self.assertFalse(proof['plan_authorizes_dispatch'])
        self.assertEqual(proof['original_capture_status'], 'limited')
        self.assertEqual(len(self.c.calls), before)
        self.assertLess(len(canonical_bytes(proof)), 8192)
        self.c.mode = 'success'
        with patch.object(muse, 'run_foreground_experiment', side_effect=self.child):
            child = self.execute(proof)
        self.assertEqual(child['state'], 'proposal_ready')
        self.assertEqual(child['manual_successor']['format'], 'manual-muse-successor/3')
        self.assertEqual(child['bundle_digest'], self.original['bundle_digest'])
        self.assertFalse(child['acceptance_allowed'])
        self.assertEqual(self.execute(proof), child)
        with self.assertRaises(TaskAlongError) as caught:
            self.service.provider_successor(predecessor=self.original['run_id'], key='expanded', plan_digest='f' * 64,
                output=str(self.root/'expanded'), reason='capture')
        self.assertEqual(caught.exception.code, 'provider_successor_key_conflict')
        with self.assertRaises(TaskAlongError):
            self.execute(proof, key='duplicate')
        for reason in ('timeout', 'capture'):
            with self.assertRaises(TaskAlongError):
                self.service.provider_successor_plan(predecessor=child['run_id'], reason=reason)
        self.assertEqual(len(self.c.calls), before + 1)
        self.c.assert_original()

    def test_existing_explicit_cli_plan_is_model_free_and_cannot_run_by_itself(self):
        from taskalong.cli import main
        output = io.StringIO()
        before = len(self.c.calls)
        with contextlib.redirect_stdout(output), patch.object(muse, 'run', side_effect=AssertionError('plan attempted dispatch')):
            code = main(['--state-dir', str(self.service._store.root), '--json', 'provider-successor-plan', 'muse',
                         '--predecessor', self.original['run_id'], '--reason', 'capture'])
        self.assertEqual(code, 0)
        value = json.loads(output.getvalue())['data']
        self.assertEqual(value['format'], 'manual-muse-successor-plan/3')
        self.assertFalse(value['plan_authorizes_dispatch'])
        self.assertEqual(len(self.c.calls), before)
        self.assertIsNone(self.service._store.setting('provider-successor:muse:' + self.original['run_id']))

    def test_torn_delta_lexical_binding_and_terminal_prefix_decisions(self):
        root = Path(self.original['output'])
        raw = (root / 'capture/stdout.bin').read_bytes()
        invocation = json.loads((root / 'invocation.json').read_bytes())
        session = invocation['session_id']
        native_run, candidate = recovery.inspect_prefix(raw, session, 2048)
        self.assertTrue(candidate)
        complete, _, tail = raw.rpartition(b'\n')
        last = json.loads(complete.splitlines()[-1])['sequence']
        self.assertTrue(recovery._delta_tail(tail, session, native_run, last))
        invalid = [tail.replace(session.encode(), b'cccccccc-cccc-4ccc-8ccc-cccccccccccc'),
            tail.replace(b'"sequence":' + str(last + 1).encode(), b'"sequence":1'),
            tail.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'),
            tail.replace(b'"durability":"ephemeral"', b'"durability":"durable"'), tail + b'\\', tail + b'\\u00',
            tail + b'\\q', tail + b'\xff', tail + b'"}}', b'{"schem', tail + b'\\ud800']
        for value in invalid:
            with self.subTest(prefix=value[:20]), self.assertRaises(TaskAlongError):
                recovery.inspect_prefix(complete + b'\n' + value, session, 2048)
        terminal = torn_record(session, native_run, last + 1, terminal=True)
        with self.assertRaises(TaskAlongError) as caught:
            recovery.inspect_prefix(complete + b'\n' + terminal, session, 2048)
        self.assertEqual(caught.exception.code, 'provider_successor_terminal_prefix')
        self.assertFalse(caught.exception.recovery[0]['new_dispatch_allowed'])
        self.assertIn('full_sealed_bound_terminal_and_response', str(caught.exception.recovery))

    def prefix_rows(self):
        raw = (Path(self.original['output'])/'capture/stdout.bin').read_bytes()
        linked = json.loads(raw.splitlines()[0])
        return linked, linked['stream']['id'], linked['payload']['run_stream']['id']

    def test_disguised_completed_payload_is_not_nonterminal_prefix(self):
        linked, session, native_run = self.prefix_rows()
        complete = linked | {'sequence': 2, 'payload_type': 'fixture.not_terminal',
            'payload': {'kind': 'run_terminal', 'terminal': 'completed', 'run_stream': {'kind': 'run', 'id': native_run}}}
        variants = [complete]
        for wrong in (True, 1.5, None, {}, 'failed'):
            variants.append(complete | {'payload': complete['payload'] | {'terminal': wrong}})
        variants += [complete | {'payload': {'kind': 'opaque', 'event': {'kind': 'terminal', 'terminal': 'completed'}}},
                     complete | {'payload': {'kind': 'metadata', 'record': {'kind': 'run_terminal', 'terminal': 'completed'}}},
                     complete | {'payload': {'kind': 'opaque', 'nested': {'kind': 'run_terminal', 'terminal': 'completed'}}},
                     complete | {'payload': complete['payload'] | {'run_stream': {'kind': 'run', 'id': 'foreign'}}}]
        for row in variants:
            raw = canonical_bytes(linked) + b'\n' + json.dumps(row, separators=(',', ':')).encode() + b'\n'
            with self.subTest(payload=row['payload']), self.assertRaises(TaskAlongError):
                recovery.inspect_prefix(raw, session, 2048)

    def test_cancelled_prefix_cannot_be_followed_by_output_or_torn_delta(self):
        linked, session, native_run = self.prefix_rows()
        terminal = linked | {'sequence': 2, 'payload_type': 'run.terminal.cancelled',
            'payload': {'kind': 'run_terminal', 'terminal': 'cancelled', 'run_stream': {'kind': 'run', 'id': native_run}}}
        prefix = canonical_bytes(linked) + b'\n' + canonical_bytes(terminal) + b'\n'
        delta = linked | {'sequence': 3, 'payload_type': 'run.output.delta',
            'payload': {'kind': 'run_output_delta', 'command_id': native_run,
                        'run_stream': {'kind': 'run', 'id': native_run}, 'text': 'later output'}}
        for suffix in (canonical_bytes(delta) + b'\n', torn_record(session, native_run, 3),
                       canonical_bytes(delta | {'payload_type': 'fixture.hidden_result', 'payload': {'kind': 'opaque', 'response': {}}}) + b'\n'):
            with self.assertRaises(TaskAlongError):
                recovery.inspect_prefix(prefix + suffix, session, 2048)
        metadata = linked | {'sequence': 3, 'payload_type': 'session.metadata',
            'payload': {'kind': 'metadata', 'run_stream': {'kind': 'run', 'id': native_run}, 'record': {'duration': 1}}}
        self.assertEqual(recovery.inspect_prefix(prefix + canonical_bytes(metadata) + b'\n', session, 2048), (native_run, False))
        metadata['payload']['run_stream']['id'] = 'foreign'
        with self.assertRaises(TaskAlongError):
            recovery.inspect_prefix(prefix + canonical_bytes(metadata) + b'\n', session, 2048)

    def test_journal_terminal_requires_configuration_before_it(self):
        path = self.c.original_journal
        rows = [json.loads(line) for line in path.read_bytes().splitlines()]
        for reordered in ([rows[0], rows[2], rows[1]], [rows[2], rows[0], rows[1]]):
            path.write_bytes(b''.join(canonical_bytes(row) + b'\n' for row in reordered))
            with self.assertRaises(TaskAlongError):
                self.plan()
        path.write_bytes(b''.join(canonical_bytes(row) + b'\n' for row in rows))
        metadata = {'payload': {'kind': 'metadata', 'record': rows[0]['payload']['record'] | {'duration': 1}}}
        with path.open('ab') as stream:
            stream.write(canonical_bytes(metadata) + b'\n')
        self.assertEqual(self.plan()['format'], 'manual-muse-successor-plan/3')
        for later in (rows[1], {'payload': {'kind': 'run', 'event': {'kind': 'output', 'text': 'late'}}},
                      {'payload': {'kind': 'metadata', 'record': rows[0]['payload']['record'] | {'nested': {'kind': 'model_request_configured'}}}}):
            path.write_bytes(b''.join(canonical_bytes(row) + b'\n' for row in [*rows, later]))
            with self.assertRaises(TaskAlongError):
                self.plan()

    def test_journal_cannot_hide_second_terminal_in_session_or_unknown_wrapper(self):
        path = self.c.original_journal
        rows = [json.loads(line) for line in path.read_bytes().splitlines()]
        linked, session, native_run = self.prefix_rows()
        completed = linked | {'sequence': 2, 'payload_type': 'run.terminal.completed',
            'payload': {'kind': 'run_terminal', 'terminal': 'completed', 'run_stream': {'kind': 'run', 'id': native_run}}}
        variants = [completed, completed | {'payload_type': 'fixture.disguised'},
                    {'payload': {'kind': 'metadata', 'record': {'kind': 'run_terminal', 'terminal': 'completed'}}},
                    {'payload': {'kind': 'opaque', 'event': {'kind': 'terminal', 'terminal': 'completed'}}},
                    completed | {'payload': completed['payload'] | {'terminal': True}},
                    completed | {'stream': {'kind': 'session', 'id': 'foreign'}},
                    completed | {'payload': completed['payload'] | {'run_stream': {'kind': 'session', 'id': session}}}]
        for extra in variants:
            path.write_bytes(b''.join(canonical_bytes(row) + b'\n' for row in [*rows, extra]))
            with self.subTest(extra=extra), self.assertRaises(TaskAlongError):
                self.plan()

    def test_event_snapshot_fences_all_files_after_last_read(self):
        root = Path(self.original['output'])
        first = root/'events/0001.json'
        original_bytes = first.read_bytes()
        original = recovery.read_regular
        for change in ('mutate', 'delete', 'replace'):
            changed = []
            def read(directory, name, **kwargs):
                raw = original(directory, name, **kwargs)
                if name == f"events/{self.original['revision']:04d}.json" and not changed:
                    changed.append(True)
                    if change == 'delete':
                        first.unlink()
                    elif change == 'replace':
                        first.rename(root/('old-event-' + change))
                        first.write_bytes(original_bytes)
                        first.chmod(0o400)
                    else:
                        first.chmod(0o600)
                        first.write_bytes(original_bytes + b' ')
                        first.chmod(0o400)
                return raw
            with patch.object(recovery, 'read_regular', side_effect=read), self.assertRaises(TaskAlongError) as caught:
                self.plan()
            self.assertEqual(caught.exception.code, 'provider_successor_history_changed')
            self.assertIsNone(self.service._store.setting('provider-successor:muse:' + self.original['run_id']))
            if first.exists():
                first.chmod(0o600)
            first.write_bytes(original_bytes)
            first.chmod(0o400)

    def test_event_fd_ceiling_and_io_failures_are_typed_without_leaks(self):
        root = Path(self.original['output'])
        with patch.object(recovery.os, 'open', side_effect=AssertionError('event ceiling must precede opening')):
            with self.assertRaises(TaskAlongError) as caught:
                recovery._events(root, self.original | {'revision': 65})
        self.assertEqual(caught.exception.code, 'provider_successor_history_changed')
        original_open, original_stat, original_read, original_seek = os.open, os.stat, os.read, os.lseek
        for failure in ('directory-open', 'open', 'stat', 'read', 'seek'):
            opened = []
            def opening(path, flags, *args, **kwargs):
                if failure == 'open' and path == '0002.json' or failure == 'directory-open' and path == 'events':
                    raise OSError(errno.EMFILE, 'Synthetic event descriptor exhaustion')
                fd = original_open(path, flags, *args, **kwargs)
                opened.append(fd)
                return fd
            def stat(path, *args, **kwargs):
                if failure == 'stat' and path == '0002.json':
                    raise OSError(errno.EIO, 'Synthetic event stat failure')
                return original_stat(path, *args, **kwargs)
            def read(fd, size):
                if failure == 'read':
                    raise OSError(errno.EIO, 'Synthetic event read failure')
                return original_read(fd, size)
            def seek(fd, offset, whence):
                if failure == 'seek':
                    raise OSError(errno.EIO, 'Synthetic event seek failure')
                return original_seek(fd, offset, whence)
            with patch.object(recovery.os, 'open', side_effect=opening) as open_mock, patch.object(recovery.os, 'stat', side_effect=stat) as stat_mock, \
                    patch.object(recovery.os, 'read', side_effect=read), patch.object(recovery.os, 'lseek', side_effect=seek), \
                    patch.object(recovery.os, 'supports_dir_fd', os.supports_dir_fd | {open_mock, stat_mock}), \
                    patch.object(recovery.os, 'supports_follow_symlinks', os.supports_follow_symlinks | {stat_mock}):
                with self.assertRaises(TaskAlongError) as caught:
                    self.plan()
            self.assertEqual(caught.exception.code, 'provider_successor_history_changed')
            for fd in opened:
                with self.assertRaises(OSError) as closed:
                    os.fstat(fd)
                self.assertEqual(closed.exception.errno, errno.EBADF)
            self.assertIsNone(self.service._store.setting('provider-successor:muse:' + self.original['run_id']))

    def test_actual_shaped_completed_terminal_prefix_blocks_even_cancel_journal(self):
        # This is a separate synthetic original, not a mutation or replay.
        self.terminal_tail = True
        with patch.object(muse, 'run_foreground_experiment', side_effect=self.overflow):
            self.c.original_at(720, capture_profile='large-task', max_proposal_bytes=65536, max_protocol_records=2048)
        self.original = self.c.original
        self.configure(attempt_seconds=720)
        before = len(self.c.calls)
        with patch.object(recovery, '_journal', side_effect=AssertionError('terminal prefix must stop before cancellation reuse')), self.assertRaises(TaskAlongError) as caught:
            self.plan()
        self.assertEqual(caught.exception.code, 'provider_successor_terminal_prefix')
        self.assertFalse(caught.exception.recovery[0]['new_dispatch_allowed'])
        self.assertEqual(len(self.c.calls), before)
        self.assertIsNone(self.service._store.setting('provider-successor:muse:' + self.original['run_id']))
        self.c.assert_original()

    def test_terminal_complete_staged_and_unknown_cleanup_refuse(self):
        original = self.original
        for changes in ({'root_exit_observed': False}, {'group_termination_confirmed': False}, {'process_stream_complete': False},
                {'protocol_error': 'bad'}, {'tracking_errors': ['unaccounted']}, {'boundary_failures': ['failure']},
                {'timed_out': True}, {'cancelled': True}, {'observed_output_bytes': 1048576},
                {'protocol_record_limited': True}, {'protocol_record_limit': 8192}, {'protocol_records_observed': True}):
            self.c.replace_record(original, process=original['process'] | changes)
            with self.subTest(changes=changes), self.assertRaises(TaskAlongError):
                self.plan()
        self.c.replace_record(original)
        root = Path(original['output'])
        for name in ('response.json', 'proposed.patch', 'review.json', 'response-claim.json'):
            (root / name).write_text('{}')
            with self.assertRaises(TaskAlongError) as caught:
                self.plan()
            self.assertEqual(caught.exception.code, 'provider_successor_result_exists')
            (root / name).unlink()
        self.c.replace_record(original, process=original['process'])
        self.assertEqual(self.plan()['original_state'], 'failed')

    def test_changed_scope_deadline_and_history_refuse(self):
        for change in ({'attempt_seconds': 720}, {'reasoning_effort': 'max'}, {'context': 'native-only'}, {'max_proposal_bytes': 65536}):
            self.configure(**change)
            with self.subTest(change=change), self.assertRaises(TaskAlongError):
                self.plan()
        self.configure()
        proof = self.plan()
        event = Path(self.original['output']) / 'events/0001.json'
        raw = event.read_bytes()
        event.chmod(0o600)
        event.write_bytes(raw + b' ')
        event.chmod(0o400)
        with self.assertRaises(TaskAlongError):
            self.plan()
        event.chmod(0o600)
        event.write_bytes(raw)
        event.chmod(0o400)
        self.assertEqual(self.plan(), proof)

    def test_private_prefix_hash_and_full_journal_cancel_proofs_are_mandatory(self):
        proof = self.plan()
        path = self.c.original_journal
        raw = path.read_bytes()
        rows = [json.loads(line) for line in raw.splitlines()]
        invalid = [rows[:-1], rows + [rows[-1]], rows + [rows[1]],
            [rows[0], rows[1] | {'payload': rows[1]['payload'] | {'run_id': 'foreign'}}, rows[2]],
            [rows[0], rows[1] | {'payload': rows[1]['payload'] | {'event': rows[1]['payload']['event'] | {'toolset': {'active_tools': ['shell']}}}}, rows[2]],
            [rows[0], rows[1], rows[2] | {'payload': rows[2]['payload'] | {'event': {'kind': 'terminal', 'terminal': 'completed'}}}]]
        for value in invalid:
            path.write_bytes(b''.join(canonical_bytes(row) + b'\n' for row in value))
            with self.assertRaises(TaskAlongError):
                self.plan()
        path.write_bytes(raw[:-1])
        with self.assertRaises(TaskAlongError):
            self.plan()
        path.write_bytes(raw)
        self.assertEqual(self.plan(), proof)
        capture = Path(self.original['output']) / 'capture/stdout.bin'
        original = capture.read_bytes()
        capture.write_bytes(b'x' + original[1:])
        with self.assertRaises(TaskAlongError):
            self.plan()

    def test_preflight_failure_consumes_slot_and_repeated_command_only_observes(self):
        proof = self.plan()
        before = len(self.c.calls)
        with patch.object(muse, '_preflight', side_effect=TaskAlongError('denied', 'Synthetic preflight denial.')):
            with self.assertRaises(TaskAlongError):
                self.execute(proof)
        self.assertEqual(self.execute(proof)['state'], 'blocked')
        with self.assertRaises(TaskAlongError):
            self.execute(proof, key='second')
        self.assertEqual(len(self.c.calls), before)
        self.c.assert_original()

    def test_reserved_crash_restart_and_output_overlap_never_replay(self):
        proof = self.plan()
        with self.assertRaises(TaskAlongError):
            self.service.provider_successor(predecessor=self.original['run_id'], key='overlap', plan_digest=proof['digest'],
                output=str(Path(self.original['output'])/'child'), reason='capture')
        before = len(self.c.calls)
        with patch.object(muse, 'run', side_effect=OSError('Synthetic setup crash')), self.assertRaises(OSError):
            self.execute(proof)
        with RunService(self.service._store.root) as restarted:
            self.assertEqual(self.execute(proof, service=restarted)['state'], 'reserved_incomplete')
        self.assertEqual(len(self.c.calls), before)
        with self.assertRaises(TaskAlongError):
            self.execute(proof, key='another')
        self.c.assert_original()

    def test_full_journal_streaming_bound_and_change_fence(self):
        path = self.c.original_journal
        rows = [json.loads(line) for line in path.read_bytes().splitlines()]
        with path.open('wb') as stream:
            for row in rows[:2]:
                stream.write(canonical_bytes(row) + b'\n')
            for _ in range(5):
                stream.write(json.dumps({'payload': {'event': {'kind': 'output', 'text': 'x' * 1048576}}}, separators=(',', ':')).encode() + b'\n')
            stream.write(canonical_bytes(rows[-1]) + b'\n')
        self.assertGreater(path.stat().st_size, 4194304)
        with patch.object(muse, '_journal_source', side_effect=AssertionError('legacy four-MiB journal')):
            self.assertEqual(self.plan()['format'], 'manual-muse-successor-plan/3')
        original = muse._native_json
        changed = []
        def mutate(raw, **kwargs):
            result = original(raw, **kwargs)
            if not changed and result.get('payload', {}).get('kind') == 'metadata':
                changed.append(True)
                with path.open('ab') as stream:
                    stream.write(b'{"payload":{}}\n')
            return result
        with patch.object(muse, '_native_json', side_effect=mutate), self.assertRaises(TaskAlongError):
            self.plan()

    def test_independent_journal_resource_caps_do_not_reinterpret_old_profile(self):
        root = Path(self.original['output'])
        invocation = json.loads((root/'invocation.json').read_bytes())
        linked = json.loads((root/'capture/stdout.bin').read_bytes().splitlines()[0])
        native_run = linked['payload']['run_stream']['id']
        previous = self.service._store.setting('provider-config:' + self.original['configuration_digest'])
        path = self.c.original_journal
        original = path.read_bytes()
        head, terminal = original.rsplit(b'\n', 2)[:2]
        head += b'\n'
        terminal += b'\n'
        arguments = (previous, invocation['session_id'], native_run, self.original['process_receipt']['started_unix_ms'])
        empty = b'{"payload":{}}\n'
        with path.open('wb') as stream:
            stream.write(head)
            stream.write(empty * (131072 - 3))
            stream.write(terminal)
        self.assertEqual(len(recovery._journal(*arguments)), 64)
        with path.open('wb') as stream:
            stream.write(head)
            stream.write(empty * (131072 - 2))
            stream.write(terminal)
        with self.assertRaises(TaskAlongError):
            recovery._journal(*arguments)
        prefix, suffix = b'{"payload":{"padding":"', b'"}}\n'
        frame = prefix + b'x' * (16777216 + 1 - len(prefix) - len(suffix)) + suffix
        self.assertEqual(len(frame) - 1, 16777216)
        with path.open('wb') as stream:
            stream.write(head)
            stream.write(frame)
            stream.write(terminal)
        self.assertEqual(len(recovery._journal(*arguments)), 64)
        with path.open('wb') as stream:
            stream.write(head)
            stream.write(frame[:-4] + b'x' + frame[-4:])
            stream.write(terminal)
        with self.assertRaises(TaskAlongError):
            recovery._journal(*arguments)
        # Three almost-full frames plus one remainder hit the independent64MiB cap.
        physical = frame[:-5] + frame[-4:]
        self.assertEqual(len(physical), 16777216)
        remainder_size = 67108864 - len(original) - 3 * len(physical)
        remainder = prefix + b'x' * (remainder_size - len(prefix) - len(suffix)) + suffix
        with path.open('wb') as stream:
            stream.write(head)
            for _ in range(3):
                stream.write(physical)
            stream.write(remainder)
            stream.write(terminal)
        self.assertEqual(path.stat().st_size, 67108864)
        self.assertEqual(len(recovery._journal(*arguments)), 64)
        with path.open('ab') as stream:
            stream.write(b'\n')
        with self.assertRaises(TaskAlongError):
            recovery._journal(*arguments)
        self.assertEqual(previous['format'], 'local-muse-provider/5')

    def test_copied_and_restored_state_cannot_reopen_anchor(self):
        proof = self.plan()
        with RunService(self.root / 'copied-state') as copied:
            self.service._store.db.backup(copied._store.db)
            self.c.mode = 'success'
            with patch.object(muse, 'run_foreground_experiment', side_effect=self.child):
                self.execute(proof)
            with self.assertRaises(TaskAlongError):
                copied.provider_successor_plan(predecessor=self.original['run_id'], reason='capture')
            copied._store.db.backup(self.service._store.db)
            with self.assertRaises(TaskAlongError):
                self.plan()

    def test_key_conflicts_and_concurrent_commands_reserve_one_slot(self):
        proof = self.plan()
        self.c.mode = 'success'
        barrier = threading.Barrier(2)
        def run(key):
            with RunService(self.service._store.root) as service:
                barrier.wait(timeout=10)
                try:
                    return self.execute(proof, key=key, service=service)['run_id']
                except TaskAlongError:
                    return None
        before = len(self.c.calls)
        with patch.object(muse, 'run_foreground_experiment', side_effect=self.child), concurrent.futures.ThreadPoolExecutor(2) as pool:
            values = list(pool.map(run, ('racer-one', 'racer-two')))
        self.assertEqual(sum(value is not None for value in values), 1)
        self.assertEqual(len(self.c.calls), before + 1)
        self.c.assert_original()


if __name__ == '__main__':
    unittest.main()
