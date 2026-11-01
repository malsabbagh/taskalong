"""Configured provider integration with synthetic process fixtures; no inference."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from taskalong.api import RunService
from taskalong import muse_experimental as muse
from taskalong import supervised_pilot as pilot
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, validate, digest, loads


def request(model='muse-wonder-full-1.0'):
    return {'base_commit':'a'*40,'task':'Change greeting.','provider':'muse','model':model,'reasoning_effort':'high','files':{'greeting.txt':'hello\n'}}


def native_output(session,response,*,terminal='completed',run='11111111-1111-4111-8111-111111111111'):
    base={'schema_version':1,'stream':{'kind':'session','id':session}}
    rows=[base|{'sequence':1,'payload_type':'session.run.linked','payload':{'kind':'session_run_linked','run_stream':{'kind':'run','id':run}}},
          base|{'sequence':2,'payload_type':'run.terminal.'+terminal,'payload':{'kind':'run_terminal','run_stream':{'kind':'run','id':run},'terminal':terminal,'text':response}}]
    return b''.join(canonical_bytes(v)+b'\n' for v in rows)


def large_native_records(session, response, *, count=2, padding=0, ascii_response=False):
    """Wire fixture deliberately bypasses the one-MiB authority serializer."""
    reference = {'kind': 'run', 'id': '11111111-1111-4111-8111-111111111111'}
    def row(sequence, kind, payload):
        value = {'schema_version': 1, 'stream': {'kind': 'session', 'id': session},
                 'sequence': sequence, 'payload_type': kind, 'payload': {'run_stream': reference, **payload}}
        return json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode() + b'\n'
    text = response if type(response) is str else json.dumps(response, ensure_ascii=ascii_response, separators=(',', ':'))
    yield row(1, 'session.run.linked', {'kind': 'session_run_linked'})
    for i in range(2, count):
        yield row(i, 'run.output.delta', {'kind': 'run_output_delta', 'text': ''})
    yield row(count, 'run.terminal.completed', {'kind': 'run_terminal', 'terminal': 'completed', 'text': text, 'padding': 'x' * padding})


def large_native_output(session, response, **options):
    return b''.join(large_native_records(session, response, **options))


def sized_response(bundle_digest, size, *, unicode=False):
    value = {'bundle_digest': bundle_digest, 'changes': {'greeting.txt': '\n'}}
    extra = size - len(canonical_bytes(value))
    value['changes']['greeting.txt'] = ('é' * (extra // 2) + 'x' * (extra % 2) if unicode else 'x' * extra) + '\n'
    return value


@unittest.skipUnless(os.name=='posix','Private descriptor staging requires POSIX')
class ExperimentalMuseTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.binary=self.root/'native';self.binary.write_text('Original synthetic executable fixture.\n');self.binary.chmod(0o700)
        self.home=self.root/'home';self.home.mkdir();self.data=self.root/'data/muse';self.data.mkdir(parents=True)
        self.service=self.enterContext(RunService(self.root/'state'))
        self.bundle=self.root/'bundle';pilot.prepare(request(),output=str(self.bundle))
        _,self.manifest=pilot._bundle(str(self.bundle))
        self.calls=[]

    def configure(self,**values):
        return self.service.configure_provider('muse',{'executable':str(self.binary),'account_home':str(self.home),'muse_home':str(self.data),**values})

    def large_process(self, response, *, broken=None):
        def process(argv, **options):
            result = self.process(argv, **options)
            session = argv[argv.index('--session-id') + 1]
            raw = large_native_output(session, response)
            if broken == 'partial':
                raw = raw[:-10]
            options['_on_output_chunk']('stdout', raw)
            for line in raw.splitlines():
                options['on_stdout_line'](line)
            result.stdout = b'' if options.get('_retain_output') is False else raw
            summary = result.to_dict() | {'output_bytes': len(raw)}
            if broken == 'cancelled':
                result.cancelled = True
                summary['cancelled'] = True
            result.to_dict = lambda: summary
            return result
        return process

    def test_megabyte_profile_is_explicit_fixed_envelope_and_preserves_timeouts(self):
        configured = self.configure(capture_profile='megabyte-proposal')
        self.assertEqual((configured['attempt_seconds'], configured['max_output_bytes'], configured['max_proposal_bytes'], configured['max_protocol_records']),
                         (720, 67108864, 1048576, 131072))
        sealed = muse._configuration(self.service._store)
        self.assertEqual(sealed['format'], 'local-muse-provider/6')
        self.assertEqual(sealed['digest'], digest(sealed))
        self.assertEqual(muse._checked_configuration(sealed), sealed)
        self.assertEqual(muse._budget(sealed, b'prompt')['response_fit_guaranteed'], False)
        with self.assertRaises(TaskAlongError) as caught:
            muse._budget(sealed, b'x' * 1048577)
        self.assertEqual(caught.exception.code, 'provider_prompt_too_large')
        for seconds in (1, 360, 720, 1440):
            for proposal in (1024, 1048576):
                value = self.configure(capture_profile='megabyte-proposal', attempt_seconds=seconds, max_proposal_bytes=proposal)
                self.assertEqual((value['attempt_seconds'], value['max_proposal_bytes']), (seconds, proposal))
        for field, value in (('attempt_seconds', True), ('attempt_seconds', 1441), ('attempt_seconds', 0),
                ('max_proposal_bytes', True), ('max_proposal_bytes', 1023), ('max_proposal_bytes', 1048577),
                ('max_output_bytes', 4194304), ('max_protocol_records', 8192), ('max_protocol_records', True)):
            with self.subTest(field=field, value=value), self.assertRaises(TaskAlongError):
                self.configure(capture_profile='megabyte-proposal', **{field: value})
            altered = sealed | {field: value}
            altered['digest'] = digest(altered)
            with self.assertRaises(TaskAlongError):
                muse._checked_configuration(altered)
        for old_format in ('local-muse-provider/3', 'local-muse-provider/4', 'local-muse-provider/5'):
            altered = sealed | {'format': old_format}
            altered['digest'] = digest(altered)
            with self.assertRaises(TaskAlongError):
                muse._checked_configuration(altered)

    def test_megabyte_canonical_exact_bound_and_escaped_transport_are_independent(self):
        response = sized_response('a' * 64, 1048576, unicode=True)
        raw = large_native_output('session', response, ascii_response=True)
        self.assertGreater(len(raw), 1048576)
        self.assertLess(len(raw), 4194304)
        with patch.object(muse, '_session_records', side_effect=AssertionError('materialized legacy decoder')):
            self.assertEqual(muse._decode(raw, 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)[0], response)
        self.assertEqual(len(canonical_bytes(response)), 1048576)
        response['changes']['greeting.txt'] += 'x'
        with self.assertRaises(TaskAlongError) as caught:
            muse._decode(large_native_output('session', response), 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)
        self.assertEqual(caught.exception.code, 'provider_proposal_too_large')
        with self.assertRaises(TaskAlongError):
            canonical_bytes(response)  # Global authority JSON ceiling is unchanged.

    def test_megabyte_wire_byte_and_record_boundaries(self):
        response = {'bundle_digest': 'a' * 64, 'changes': {'greeting.txt': 'x\n'}}
        first, terminal = large_native_output('session', response).splitlines(keepends=True)
        final = json.loads(terminal)
        final['sequence'] = 6
        terminal = json.dumps(final, separators=(',', ':')).encode() + b'\n'
        delta = final | {'payload_type': 'run.output.delta', 'payload': {'text': ''}}
        def padded(sequence, size):
            row = delta | {'sequence': sequence}
            empty = json.dumps(row, separators=(',', ':')).encode() + b'\n'
            row['payload'] = {'text': 'x' * (size - len(empty))}
            return json.dumps(row, separators=(',', ':')).encode() + b'\n'
        sizes = [16777216] * 3 + [16777216 - len(first) - len(terminal)]
        def records(extra=False):
            yield first[:-1]
            for i, size in enumerate(sizes):
                yield padded(i + 2, size)[:-1]
            yield terminal[:-1]
            if extra:
                yield b''
        self.assertEqual(len(first) + sum(sizes) + len(terminal), 67108864)
        self.assertEqual(muse._decode(records(), 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)[0], response)
        with self.assertRaises(TaskAlongError):
            muse._decode(records(extra=True), 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)
        # Per-frame count excludes its terminating LF, independently of aggregate.
        for extra in (0, 1):
            raw = large_native_output('session', response)
            terminal_size = len(raw.splitlines()[-1])
            raw = large_native_output('session', response, padding=16777216 - terminal_size + extra)
            if extra:
                with self.assertRaises(TaskAlongError):
                    muse._decode(raw, 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)
            else:
                self.assertEqual(muse._decode(raw, 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)[0], response)
        for count in (131072, 131073):
            records = (line[:-1] for line in large_native_records('session', response, count=count))
            if count == 131073:
                with self.assertRaises(TaskAlongError):
                    muse._decode(records, 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)
            else:
                self.assertEqual(muse._decode(records, 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)[0], response)

    def test_megabyte_decoder_refuses_ambiguous_framing_and_response_json(self):
        response = {'bundle_digest': 'a' * 64, 'changes': {'greeting.txt': 'x\n'}}
        raw = large_native_output('session', response)
        invalid = (raw[:-1], raw + raw.splitlines(keepends=True)[-1], raw + b'{}\n', b'\n' + raw,
            raw.replace(b'"sequence":1', b'"sequence":true', 1), raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1', 1),
            raw.replace(b'run.terminal.completed', b'run.terminal.failed'), raw.replace(b'"terminal":"completed"', b'"terminal":"failed"'),
            raw.replace(b'"schema_version":1', b'"schema_version":1.0', 1), raw.replace(b'"id":"session"', b'"id":"foreign"', 1),
            large_native_output('session', '{"x":1,"x":2}'), large_native_output('session', '{"x":1.0}'),
            large_native_output('session', '[]'), large_native_output('session', '{"x":"\\ud800"}'))
        for value in invalid:
            with self.subTest(prefix=value[:20]), self.assertRaises(TaskAlongError) as caught:
                muse._decode(value, 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)
            self.assertEqual(caught.exception.code, 'provider_response_unrecognized')

    def test_megabyte_raw_response_json_cap_counts_whitespace_before_normalizing(self):
        response = {'bundle_digest': 'a' * 64, 'changes': {'greeting.txt': 'x\n'}}
        text = json.dumps(response, separators=(',', ':'))
        text += ' ' * (4194304 - len(text.encode()))
        raw = large_native_output('session', text)
        self.assertEqual(muse._decode(raw, 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)[0], response)
        with self.assertRaises(TaskAlongError):
            muse._decode(large_native_output('session', text + ' '), 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)

    def test_megabyte_cumulative_prefix_framing_has_no_four_mib_fit_assumption(self):
        response = sized_response('a' * 64, 1048576)
        first, final = large_native_output('session', response).splitlines()
        terminal = json.loads(final)
        text = terminal['payload']['text']
        observed = 0
        def records():
            nonlocal observed
            observed += len(first) + 1
            yield first
            for i in range(1, 33):
                value = terminal | {'sequence': i + 1, 'payload_type': 'run.output.delta',
                                    'payload': {'kind': 'run_output_delta', 'text': text[:len(text) * i // 32]}}
                raw = json.dumps(value, separators=(',', ':')).encode()
                observed += len(raw) + 1
                yield raw
            terminal['sequence'] = 34
            raw = json.dumps(terminal, separators=(',', ':')).encode()
            observed += len(raw) + 1
            yield raw
        self.assertEqual(muse._decode(records(), 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)[0], response)
        self.assertGreater(observed, 16 * 1048576)
        self.assertLess(observed, 64 * 1048576)

    def test_megabyte_decoder_exhausts_capture_hash_fence_after_terminal(self):
        response = {'bundle_digest': 'a' * 64, 'changes': {'greeting.txt': 'x\n'}}
        def records():
            for line in large_native_records('session', response):
                yield line[:-1]
            raise TaskAlongError('private_capture_invalid', 'Synthetic final hash mismatch.')
        with self.assertRaises(TaskAlongError) as caught:
            muse._decode(records(), 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)
        self.assertEqual(caught.exception.code, 'provider_response_unrecognized')

    def test_megabyte_post_terminal_metadata_preserves_binding_and_exhausts_capture(self):
        response = {'bundle_digest': 'a' * 64, 'changes': {'greeting.txt': 'x\n'}}
        original = list(large_native_records('session', response))
        terminal = json.loads(original[-1])
        metadata = terminal | {'sequence': 3, 'payload_type': 'run.metadata',
                               'payload': {'run_stream': terminal['payload']['run_stream'], 'duration': 1.25}}
        encoded = json.dumps(metadata, separators=(',', ':')).encode() + b'\n'
        exhausted = []
        def records():
            for line in [*original, encoded]:
                yield line[:-1]
            exhausted.append(True)
        self.assertEqual(muse._decode(records(), 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)[0], response)
        self.assertEqual(exhausted, [True])
        invalid = [metadata | {'sequence': 2}, metadata | {'stream': {'kind': 'session', 'id': 'foreign'}},
                   metadata | {'payload': {'run_stream': {'kind': 'run', 'id': 'foreign'}}},
                   terminal | {'sequence': 3},
                   terminal | {'sequence': 3, 'payload_type': 'run.terminal.failed',
                               'payload': terminal['payload'] | {'terminal': 'failed'}}]
        for trailing in invalid:
            raw = b''.join(original) + json.dumps(trailing, separators=(',', ':')).encode() + b'\n'
            with self.assertRaises(TaskAlongError):
                muse._decode(raw, 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)
        with self.assertRaises(TaskAlongError):
            muse._decode(b''.join(original) + encoded[:-1], 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)
        def failed_fence():
            yield from (line[:-1] for line in [*original, encoded])
            raise TaskAlongError('private_capture_invalid', 'Synthetic metadata hash mismatch.')
        with self.assertRaises(TaskAlongError):
            muse._decode(failed_fence(), 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)

    def test_megabyte_native_frames_bound_shape_and_unicode_preserving_decimal_text(self):
        def parse(value):
            return muse._native_json(json.dumps(value).encode(), max_bytes=16777216)
        self.assertEqual(muse._native_json(b'{"duration":1.25}', max_bytes=16777216), {'duration': '1.25'})
        self.assertEqual(muse._native_json(b'{"duration":1.25}'), {'duration': '1.25'})
        self.assertEqual(parse({'x': [0] * 4096})['x'], [0] * 4096)
        nested = 0
        for _ in range(63):
            nested = [nested]
        self.assertEqual(parse({'x': nested}), {'x': nested})
        # Root + key + outer list + 16 inner lists + 65517 integers = 65536.
        nodes = [[0] * 4096 for _ in range(15)] + [[0] * 4077]
        self.assertEqual(parse({'x': nodes}), {'x': nodes})
        invalid = ({'x': [0] * 4097}, {'x': [nested]}, {'x': nodes[:-1] + [[0] * 4078]},
                   {'\ud800': 'x'}, {'x': '\ud800'}, {'x': 2**53})
        for value in invalid:
            with self.assertRaises((ValueError, UnicodeError)):
                parse(value)
        for raw in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1,"x":2}', b'[]', b'\xff', '{"x":1}'.encode('utf-16')):
            with self.assertRaises((ValueError, UnicodeError)):
                muse._native_json(raw, max_bytes=16777216)
        response = {'bundle_digest': 'a' * 64, 'changes': {'greeting.txt': 'x\n'}}
        raw = large_native_output('session', response).replace(b'"schema_version":1', b'"schema_version":1,"duration":1.25', 1)
        self.assertEqual(muse._decode(raw, 'session', max_proposal_bytes=1048576, max_records=131072, megabyte=True)[0], response)

    def test_megabyte_pipeline_externalizes_exact_bound_and_retains_small_receipts(self):
        self.configure(capture_profile='megabyte-proposal', attempt_seconds=1440)
        response = sized_response(self.manifest['digest'], 1048576)
        with patch.object(muse.sys, 'platform', 'darwin'), patch.object(muse, '_preflight', return_value={}), \
                patch.object(muse, 'run_foreground_experiment', side_effect=self.large_process(response)), \
                patch.object(muse, '_journal', return_value=([], [{}], {'provider_id': 'meta', 'model_id': 'muse-wonder-full-1.0'})):
            result = self.service.run_provider('muse', bundle=str(self.bundle), output=str(self.root/'large-output'))
        self.assertEqual(result['state'], 'proposal_ready')
        self.assertLess(len(canonical_bytes(result)), 16384)
        self.assertEqual(result['response_ref']['bytes'], 1048576)
        self.assertEqual(result['response_ref']['path'], 'response.json')
        self.assertEqual(result['response_ref']['sha256'], hashlib.sha256(canonical_bytes(response)).hexdigest())
        self.assertEqual(loads((self.root/'large-output/response.json').read_bytes()), response)
        self.assertEqual((self.root/'large-output/proposal/response.json').stat().st_size, 1048576)
        self.assertTrue(result['process']['process_stream_complete'])
        self.assertFalse((self.root/'large-output/stdout.bin').exists())
        self.assertFalse((self.root/'large-output/stderr.bin').exists())
        self.assertTrue((self.root/'large-output/capture/stdout.bin').exists())
        self.assertFalse(self.calls[0][1]['_retain_output'])
        self.assertFalse(result['acceptance_allowed'])
        self.assertEqual(self.calls[0][1]['timeout_seconds'], 1440)
        review = loads((self.root/'large-output/proposal/review.json').read_bytes())
        self.assertEqual(review['replacement_profile'], 'megabyte-proposal/1')
        self.configure(capture_profile='megabyte-proposal', max_proposal_bytes=1024)
        with patch.object(muse, 'run_foreground_experiment') as native, self.assertRaises(TaskAlongError) as caught:
            self.service.run_provider('muse', bundle=str(self.bundle), output=str(self.root/'retry'))
        self.assertEqual(caught.exception.code, 'provider_already_submitted')
        native.assert_not_called()

    def test_megabyte_partial_and_cancel_preserve_uncertain_claim_without_staging(self):
        self.configure(capture_profile='megabyte-proposal')
        response = {'bundle_digest': self.manifest['digest'], 'changes': {'greeting.txt': 'x\n'}}
        for broken in ('partial', 'cancelled'):
            # Use independent original task intents, never a recovery redispatch.
            bundle = self.bundle if broken == 'partial' else self.root/'second-bundle'
            if broken != 'partial':
                pilot.prepare(request() | {'task': 'A separately scoped task.'}, output=str(bundle))
                _, manifest = pilot._bundle(str(bundle))
                response = response | {'bundle_digest': manifest['digest']}
            output = self.root/broken
            with patch.object(muse.sys, 'platform', 'darwin'), patch.object(muse, '_preflight', return_value={}), \
                    patch.object(muse, 'run_foreground_experiment', side_effect=self.large_process(response, broken=broken)):
                if broken == 'partial':
                    with self.assertRaises(TaskAlongError) as caught:
                        self.service.run_provider('muse', bundle=str(bundle), output=str(output))
                    self.assertEqual(caught.exception.effect_outcome, 'uncertain')
                else:
                    self.assertEqual(self.service.run_provider('muse', bundle=str(bundle), output=str(output))['state'], 'failed')
            self.assertTrue((bundle/'provider-submission.json').exists())
            self.assertTrue((output/'capture/stdout.bin').exists())
            self.assertFalse((output/'proposal').exists())

    def test_megabyte_proposal_overflow_keeps_capture_and_consumed_claim(self):
        self.configure(capture_profile='megabyte-proposal')
        response = sized_response(self.manifest['digest'], 1048577)
        output = self.root/'overlarge-proposal'
        with patch.object(muse.sys, 'platform', 'darwin'), patch.object(muse, '_preflight', return_value={}), \
                patch.object(muse, 'run_foreground_experiment', side_effect=self.large_process(response)), self.assertRaises(TaskAlongError) as caught:
            self.service.run_provider('muse', bundle=str(self.bundle), output=str(output))
        self.assertEqual((caught.exception.code, caught.exception.effect_outcome), ('provider_proposal_too_large', 'uncertain'))
        self.assertTrue((output/'capture').is_dir())
        self.assertTrue((output/'capture/stdout.bin').exists())
        self.assertTrue((self.bundle/'provider-submission.json').exists())
        self.assertFalse((output/'proposal').exists())

    def process(self,argv,**options):
        self.calls.append((argv,options))
        session=argv[argv.index('--session-id')+1]
        response={'bundle_digest':self.manifest['digest'],'changes':{'greeting.txt':'hello world\n'}}
        raw=native_output(session,json.dumps(response))
        receipt=SimpleNamespace(to_dict=lambda:{'pid':123,'executable_sha256':'fixture','invocation_id':'synthetic'})
        if options.get('on_spawn'):options['on_spawn'](receipt)
        summary={'root_exit_code':0,'root_exit_observed':True,'group_termination_confirmed':True,'fork_observed':True,
                 'descendant_cessation':'unknown','termination_confirmed':False,'tracking_errors':[],'boundary_failures':[],
                 'stdout':'fixture','stderr':'','output_bytes':len(raw),'timed_out':False,'cancelled':False,'output_limited':False}
        return SimpleNamespace(stdout=raw,stderr=b'',root_exit_code=0,timed_out=False,cancelled=False,output_limited=False,to_dict=lambda:summary)

    def run_fixture(self):
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'_preflight',return_value={'context':'include','catalog_entries':0}),\
             patch.object(muse,'run_foreground_experiment',side_effect=self.process),\
             patch.object(muse,'_journal',return_value=([],[{}],{'provider_id':'meta','model_id':'muse-wonder-full-1.0'})):
            return self.service.run_provider('muse',bundle=str(self.bundle),output=str(self.root/'output'))

    def test_configuration_alone_enables_normal_run_without_activation_or_qualification(self):
        config=self.configure();self.assertFalse(config['activation_required']);self.assertEqual(config['context'],'include')
        self.assertTrue(self.service.providers()['providers'][0]['configured'])
        result=self.run_fixture()
        self.assertEqual(result['state'],'proposal_ready');self.assertTrue(Path(result['proposal_path']).exists())
        self.assertFalse(result['patch_applied']);self.assertFalse(result['acceptance_allowed']);self.assertFalse(result['production_dispatch_allowed'])
        self.assertEqual(result['remote_usage'],'unknown');self.assertEqual(result['descendant_cessation'],'unknown')
        self.assertEqual(result['native_internal_retries'],'unknown');self.assertEqual(result['controller_submissions'],1)
        self.assertEqual(self.service.inspect(result['run_id']),result);self.assertEqual(self.service.result(result['run_id']),result)

    def test_live_call_has_fixed_provider_model_bounds_and_minimal_environment(self):
        self.configure();self.run_fixture();self.assertEqual(len(self.calls),1)
        argv,options=self.calls[0]
        self.assertEqual(argv[argv.index('--provider')+1],'meta');self.assertEqual(argv[argv.index('--model')+1],'muse-wonder-full-1.0')
        self.assertNotIn('--no-foreign-personal-context',argv)
        for flag in ('--disable-write','--disable-shell','--disable-web-tools','--disable-reminders','--no-parallel-tool-calls'):
            self.assertIn(flag,argv)
        self.assertEqual(options['timeout_seconds'],20);self.assertEqual(options['max_output_bytes'],65536)
        self.assertEqual(options['env']['HOME'],str(self.home));self.assertNotIn('GITHUB_TOKEN',options['env'])
        self.assertTrue((self.bundle/'provider-submission.json').exists())
        self.assertEqual((self.root/'output/prompt.txt').stat().st_mode&0o777,0o400)

    def test_repeated_bundle_refuses_without_another_provider_or_preflight_call(self):
        self.configure();self.run_fixture()
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'_preflight') as preflight,patch.object(muse,'run_foreground_experiment') as owner,self.assertRaises(TaskAlongError) as exc:
            self.service.run_provider('muse',bundle=str(self.bundle),output=str(self.root/'second'))
        self.assertEqual(exc.exception.code,'provider_already_submitted');owner.assert_not_called();preflight.assert_not_called()
        self.assertFalse((self.root/'second').exists())

    def test_context_exclusion_is_honestly_unsupported_and_never_dispatches(self):
        self.configure(context='exclude')
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'run_foreground_experiment') as owner,self.assertRaises(TaskAlongError) as exc:
            self.service.run_provider('muse',bundle=str(self.bundle),output=str(self.root/'output'))
        self.assertEqual(exc.exception.code,'provider_context_exclusion_unsupported');owner.assert_not_called()
        self.assertEqual(exc.exception.effect_outcome,'not_sent')

    def test_native_only_is_explicit_partial_exclusion(self):
        self.configure(context='native-only');self.run_fixture()
        self.assertIn('--no-foreign-personal-context',self.calls[0][0])

    def test_unconfigured_and_unknown_providers_fail_with_configuration_errors(self):
        with self.assertRaises(TaskAlongError) as exc:self.service.run_provider('muse',bundle=str(self.bundle))
        self.assertEqual(exc.exception.code,'provider_not_configured')
        with self.assertRaises(TaskAlongError) as exc:self.service.configure_provider('other',{})
        self.assertEqual(exc.exception.code,'provider_unavailable')

    def test_non_mac_host_refuses_without_owner_call_or_task_claim(self):
        self.configure()
        with patch.object(muse.sys,'platform','linux'),patch.object(muse,'run_foreground_experiment') as owner,self.assertRaises(TaskAlongError) as exc:
            self.service.run_provider('muse',bundle=str(self.bundle),output=str(self.root/'output'))
        self.assertEqual(exc.exception.code,'provider_platform_unsupported');owner.assert_not_called()
        self.assertFalse((self.root/'output').exists());self.assertFalse((self.bundle/'provider-submission.json').exists())

    def test_binary_or_model_changes_are_normal_validation_not_fallback(self):
        self.configure(model='another-model')
        with patch.object(muse.sys,'platform','darwin'),self.assertRaises(TaskAlongError) as exc:
            self.service.run_provider('muse',bundle=str(self.bundle))
        self.assertEqual(exc.exception.code,'provider_task_model_mismatch')
        self.configure();self.binary.write_text('changed fixture\n')
        with self.assertRaises(TaskAlongError) as exc:self.service.run_provider('muse',bundle=str(self.bundle))
        self.assertEqual(exc.exception.code,'provider_executable_changed')

    def test_secret_inputs_or_credential_config_fields_refuse_before_execution(self):
        with self.assertRaises(TaskAlongError):self.configure(api_key='fixture-only')
        self.configure()
        sensitive=request();sensitive['files']['greeting.txt']='password=abcdefghijk\n'
        with patch.object(muse,'run_foreground_experiment') as owner,self.assertRaises(TaskAlongError):
            self.service.run_provider('muse',request=sensitive,output=str(self.root/'output'))
        owner.assert_not_called()

    def test_failure_retains_one_use_claim_and_never_retries(self):
        self.configure()
        def failed(argv,**options):
            value=self.process(argv,**options);value.root_exit_code=1;return value
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'_preflight',return_value={}),patch.object(muse,'run_foreground_experiment',side_effect=failed):
            result=self.service.run_provider('muse',bundle=str(self.bundle),output=str(self.root/'output'))
        self.assertEqual(result['state'],'failed');self.assertEqual(result['remote_usage'],'unknown');self.assertEqual(len(self.calls),1)
        self.assertTrue((self.root/'output/stdout.bin').exists());self.assertTrue((self.bundle/'provider-submission.json').exists())
        with self.assertRaises(TaskAlongError):self.service.run_provider('muse',bundle=str(self.bundle),output=str(self.root/'retry'))

    def test_bad_response_is_retained_and_cannot_trigger_another_submission(self):
        self.configure()
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'_preflight',return_value={}),\
             patch.object(muse,'run_foreground_experiment',side_effect=self.process),patch.object(muse,'_decode',side_effect=TaskAlongError('fixture_parse','Synthetic parse failure.')):
            with self.assertRaises(TaskAlongError):self.service.run_provider('muse',bundle=str(self.bundle),output=str(self.root/'output'))
        self.assertTrue((self.root/'output/stdout.bin').exists());self.assertEqual(len(self.calls),1)
        with self.assertRaises(TaskAlongError):self.service.run_provider('muse',bundle=str(self.bundle),output=str(self.root/'retry'))

    def test_startup_context_pin_is_data_scope_not_a_production_receipt(self):
        self.configure(catalog_digest='a'*64)
        config=muse._configuration(self.service._store)
        root=self.root/'probe';root.mkdir(mode=0o700);(root/'workspace').mkdir();(root/'tmp').mkdir()
        event={'toolset':{'active_tools':[]},'reminder_roster':{'agents':[]},'run_context_messages':[]}
        with patch.object(muse,'run_foreground_experiment',side_effect=self.process),patch.object(muse,'_journal',return_value=([],[event],{})),self.assertRaises(TaskAlongError) as exc:
            muse._preflight(config,root)
        self.assertEqual(exc.exception.code,'provider_context_changed');self.assertTrue((root/'context-check/context.json').exists())
        self.assertNotIn('--no-foreign-personal-context',self.calls[0][0])

    def test_preflight_records_context_but_blocks_recognizable_secrets(self):
        self.configure();config=muse._configuration(self.service._store)
        root=self.root/'probe';root.mkdir(mode=0o700);(root/'workspace').mkdir();(root/'tmp').mkdir()
        event={'toolset':{'active_tools':[]},'reminder_roster':{'agents':[]},'run_context_messages':[{'id':'fixture','source':'fixture','text':'password=abcdefghijk'}]}
        with patch.object(muse,'run_foreground_experiment',side_effect=self.process),patch.object(muse,'_journal',return_value=([],[event],{})),self.assertRaises(TaskAlongError) as exc:muse._preflight(config,root)
        self.assertEqual(exc.exception.code,'sensitive_input');self.assertFalse((root/'context-check/context.json').exists())

    def test_public_context_snapshot_never_submits_or_claims_task(self):
        self.configure()
        event={'toolset':{'active_tools':[]},'reminder_roster':{'agents':[]},
               'run_context_messages':[{'id':'skills_catalog','source':'skills','text':'Synthetic public catalog.'}]}
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'run_foreground_experiment',side_effect=self.process),\
             patch.object(muse,'_journal',return_value=([],[event],{})):
            result=self.service.provider_context(output=str(self.root/'context'))
        self.assertTrue(result['model_free']);self.assertEqual(result['context'],'include')
        self.assertEqual(len(self.calls),1)
        self.assertEqual(self.calls[0][0][self.calls[0][0].index('--provider')+1],'echo')
        self.assertNotIn('--no-foreign-personal-context',self.calls[0][0])
        self.assertTrue(Path(result['review_file']).exists())
        self.assertFalse((self.bundle/'provider-submission.json').exists())
        with self.service._store.transaction() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM settings WHERE name LIKE 'provider-claim:%'").fetchone()[0],0)

    def test_conflicting_overlapping_context_pins_refuse_and_identical_pins_remain_valid(self):
        with self.assertRaises(TaskAlongError) as exc:
            self.configure(public_context_hashes={'security_mode':'a'*64},context_hashes={'security_mode':'b'*64})
        self.assertEqual(exc.exception.code,'provider_config_invalid')
        result=self.configure(public_context_hashes={'security_mode':'a'*64},context_hashes={'security_mode':'a'*64})
        self.assertTrue(result['configured'])

    def test_full_include_rules_pin_does_not_force_foreign_context_exclusion(self):
        import hashlib
        text='Synthetic public user rules.'
        self.configure(catalog_digest=hashlib.sha256(canonical_bytes([])).hexdigest(),
                       context_hashes={'rules_file':hashlib.sha256(text.encode()).hexdigest()})
        event={'toolset':{'active_tools':[]},'reminder_roster':{'agents':[]},
               'run_context_messages':[{'id':'rules_file','source':'rules_file','text':text}]}
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'run_foreground_experiment',side_effect=self.process),\
             patch.object(muse,'_journal',return_value=([],[event],{})):
            result=self.service.provider_context(output=str(self.root/'rules-context'))
        self.assertTrue(result['model_free']);self.assertNotIn('--no-foreign-personal-context',self.calls[0][0])
        event['run_context_messages'][0]['text']='Changed synthetic rule.'
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'run_foreground_experiment',side_effect=self.process),\
             patch.object(muse,'_journal',return_value=([],[event],{})),self.assertRaises(TaskAlongError) as exc:
            self.service.provider_context(output=str(self.root/'changed-context'))
        self.assertEqual(exc.exception.code,'provider_context_changed')

    def test_native_decoder_accepts_one_bound_final_json_and_fenced_json(self):
        response={'bundle_digest':self.manifest['digest'],'changes':{'greeting.txt':'new\n'}}
        for text in (json.dumps(response),'```json\n'+json.dumps(response)+'\n```'):
            value,_=muse._decode(native_output('session',text),'session');self.assertEqual(value,response)
        for raw in (native_output('foreign',json.dumps(response)),native_output('session',json.dumps(response),terminal='failed'),b'not-json'):
            with self.assertRaises(TaskAlongError):muse._decode(raw,'session')

    def test_explicit_owner_failure_blocks_preflight_and_proposal(self):
        self.configure();config=muse._configuration(self.service._store)
        root=self.root/'probe';root.mkdir(mode=0o700);(root/'workspace').mkdir();(root/'tmp').mkdir()
        def broken(argv,**options):
            value=self.process(argv,**options);value.failure_code='process_cleanup_failed';return value
        with patch.object(muse,'run_foreground_experiment',side_effect=broken),self.assertRaises(TaskAlongError) as exc:
            muse._preflight(config,root)
        self.assertEqual(exc.exception.code,'provider_context_check_failed')
        self.calls=[]
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'_preflight',return_value={}),patch.object(muse,'run_foreground_experiment',side_effect=broken):
            result=self.service.run_provider('muse',bundle=str(self.bundle),output=str(self.root/'output'))
        self.assertEqual(result['state'],'failed');self.assertNotIn('proposal_path',result);self.assertEqual(len(self.calls),1)

    def test_native_data_root_and_explicit_config_root_reach_child_environment(self):
        custom=self.root/'native-data/muse';custom.mkdir(parents=True)
        configroot=self.root/'custom-config';configroot.mkdir()
        self.configure(muse_home=str(custom),native_roots={'XDG_CONFIG_HOME':str(configroot)})
        self.run_fixture();env=self.calls[0][1]['env']
        self.assertEqual(env['XDG_DATA_HOME'],str(custom.parent));self.assertEqual(env['XDG_CONFIG_HOME'],str(configroot))

    def test_missing_or_duplicate_pinned_message_refuses_before_meta(self):
        self.configure(public_context_hashes={'security_mode':'a'*64});config=muse._configuration(self.service._store)
        root=self.root/'probe';root.mkdir(mode=0o700);(root/'workspace').mkdir();(root/'tmp').mkdir()
        event={'toolset':{'active_tools':[]},'reminder_roster':{'agents':[]},'run_context_messages':[]}
        with patch.object(muse,'run_foreground_experiment',side_effect=self.process),patch.object(muse,'_journal',return_value=([],[event],{})),self.assertRaises(TaskAlongError) as exc:
            muse._preflight(config,root)
        self.assertEqual(exc.exception.code,'provider_context_changed')

    def test_updater_wrappers_refuse_without_executing(self):
        self.binary.write_text('#!/bin/sh\nexit 0\n')
        with patch.object(muse,'run_foreground_experiment') as owner,self.assertRaises(TaskAlongError) as exc:self.configure()
        self.assertEqual(exc.exception.code,'provider_native_binary_required');owner.assert_not_called()

    def test_cli_configure_and_run_use_same_normal_service(self):
        from taskalong.cli import main
        config=self.root/'config.json';config.write_bytes(canonical_bytes({'executable':str(self.binary),'account_home':str(self.home),'muse_home':str(self.data)}))
        def cli(args):
            output=io.StringIO()
            with contextlib.redirect_stdout(output):code=main(['--json','--state-dir',str(self.root/'state'),*args])
            value=json.loads(output.getvalue());validate('command-result',value);return code,value
        code,value=cli(['configure-provider','muse','--config',str(config)]);self.assertEqual(code,0);self.assertFalse(value['data']['activation_required'])
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'_preflight',return_value={}),patch.object(muse,'run_foreground_experiment',side_effect=self.process),patch.object(muse,'_journal',return_value=([],[{}],{'provider_id':'meta','model_id':'muse-wonder-full-1.0'})):
            code,value=cli(['run','--provider','muse','--bundle',str(self.bundle),'--output',str(self.root/'output')])
        self.assertEqual(code,0);self.assertEqual(value['data']['state'],'proposal_ready')
        code,value=cli(['status',value['data']['run_id']]);self.assertEqual(code,0);self.assertEqual(value['data']['state'],'proposal_ready')

    def large_request(self):
        value=request()
        value['files']={'first.txt':'x'*60000+'\n','second.txt':'x'*60000+'\n','third.txt':'x\n'}
        _,prompt=pilot._manifest(value)
        value['files']['third.txt']='x'*(1+132870-len(prompt))+'\n'
        self.assertEqual(len(pilot._manifest(value)[1]),132870)
        return value

    def test_realistic_large_prompt_refuses_before_any_process_claim_or_output(self):
        self.configure();value=self.large_request()
        with patch.object(muse,'run_foreground_experiment') as owner,patch.object(muse,'_preflight') as preflight:
            report=self.service.provider_budget(request=value)
            self.assertFalse(report['input_echoes_fit']);self.assertGreater(report['minimum_input_echo_bytes'],265740)
            self.assertEqual(report['controller_submissions'],0);self.assertFalse(report['response_fit_guaranteed'])
            with patch.object(muse.sys,'platform','darwin'),self.assertRaises(TaskAlongError) as exc:
                self.service.run_provider(request=value,output=str(self.root/'large-output'))
        self.assertEqual(exc.exception.code,'provider_capture_budget_insufficient');self.assertEqual(exc.exception.effect_outcome,'not_sent')
        owner.assert_not_called();preflight.assert_not_called();self.assertFalse((self.root/'large-output').exists())
        with self.service._store.transaction() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM settings WHERE name LIKE 'provider-claim:%' OR name LIKE 'provider-run:%'").fetchone()[0],0)

    def test_existing_one_mib_configuration_admits_echo_space_without_promising_result_fit(self):
        self.configure(max_output_bytes=1048576,max_proposal_bytes=12288)
        with patch.object(muse,'run_foreground_experiment') as owner:
            report=self.service.provider_budget(request=self.large_request())
        owner.assert_not_called();self.assertTrue(report['input_echoes_fit']);self.assertFalse(report['response_fit_guaranteed'])
        self.assertEqual(report['max_output_bytes'],1048576);self.assertEqual(report['max_proposal_bytes'],12288)
        self.assertGreater(report['remaining_after_minimum_echo_bytes'],700000)

    def test_echo_lower_bound_counts_escaping_utf8_and_each_json_frame(self):
        # Independent literal JSON wire oracle: quote, LF, backslash, tab, Arabic.
        prompt='"\n\\\tع'.encode()
        encoded=b'"\\"\\n\\\\\\t\xd8\xb9"'
        expected=sum(len(b'{"payload_type":"'+kind+b'","payload":{"prompt":'+encoded+b'}}\n')
                     for kind in (b'turn.input.user',b'run.lifecycle.started'))
        report=muse._budget({'max_output_bytes':expected},prompt)
        self.assertEqual(report['minimum_input_echo_bytes'],expected)
        self.assertFalse(report['input_echoes_fit'])
        self.assertTrue(muse._budget({'max_output_bytes':expected+1},prompt)['input_echoes_fit'])

    def test_whole_capture_and_decoded_proposal_have_independent_finite_ranges(self):
        for key,good,bad in [('max_output_bytes',(1024,1048576),(True,1023,1048577)),
                             ('max_proposal_bytes',(1024,262144),(True,1023,262145))]:
            for value in good:self.assertTrue(self.configure(**{key:value})['configured'])
            for value in bad:
                with self.subTest(key=key,value=value),self.assertRaises(TaskAlongError) as exc:self.configure(**{key:value})
                self.assertEqual(exc.exception.code,'provider_config_invalid')
        self.configure();self.assertTrue(self.service.provider_budget(request=request())['input_echoes_fit'])

    def test_decoded_proposal_cap_measures_complete_canonical_json_utf8(self):
        response={'bundle_digest':self.manifest['digest'],'changes':{'greeting.txt':'ع'*600+'\n'}}
        raw=native_output('session',json.dumps(response,ensure_ascii=True,indent=2))
        size=len(canonical_bytes(response))
        self.assertEqual(muse._decode(raw,'session',max_proposal_bytes=size)[0],response)
        with self.assertRaises(TaskAlongError) as exc:muse._decode(raw,'session',max_proposal_bytes=size-1)
        self.assertEqual(exc.exception.code,'provider_proposal_too_large')

    def test_oversized_proposal_preserves_capture_and_claim_without_staging(self):
        self.configure(max_output_bytes=1048576,max_proposal_bytes=1024)
        original=self.process
        def oversized(argv,**options):
            value=original(argv,**options);session=argv[argv.index('--session-id')+1]
            value.stdout=native_output(session,json.dumps({'bundle_digest':self.manifest['digest'],'changes':{'greeting.txt':'x'*2048+'\n'}}))
            return value
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'_preflight',return_value={}),patch.object(muse,'run_foreground_experiment',side_effect=oversized),self.assertRaises(TaskAlongError) as exc:
            self.service.run_provider(bundle=str(self.bundle),output=str(self.root/'oversized'))
        self.assertEqual(exc.exception.code,'provider_proposal_too_large');self.assertEqual(exc.exception.effect_outcome,'uncertain')
        self.assertTrue((self.root/'oversized/stdout.bin').exists());self.assertFalse((self.root/'oversized/proposal').exists())
        self.assertEqual(self.service.result(exc.exception.recovery[0]['run_id'])['state'],'failed')
        self.assertTrue((self.bundle/'provider-submission.json').exists());self.assertEqual(len(self.calls),1)

    def test_overflow_and_cancel_keep_truncation_failure_and_explicit_byte_counts(self):
        self.configure()
        for index,flag in enumerate(('output_limited','cancelled')):
            value=request();value['task']+=str(index)
            root=self.root/f'failure-{index}'
            def stopped(argv,**options):
                result=self.process(argv,**options)
                result.stdout=b'partial JSON';result.stderr=b'error';result.root_exit_code=130
                setattr(result,flag,True)
                before=result.to_dict()
                result.to_dict=lambda:{**before,'root_exit_code':130,flag:True,'output_bytes':288338}
                return result
            with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'_preflight',return_value={}),patch.object(muse,'run_foreground_experiment',side_effect=stopped),patch.object(muse,'_decode') as decoder:
                result=self.service.run_provider(request=value,output=str(root))
            decoder.assert_not_called();self.assertEqual(result['state'],'failed');self.assertEqual(result['remote_usage'],'unknown')
            self.assertEqual(result['process']['observed_output_bytes'],288338)
            self.assertEqual(result['process']['retained_output_bytes'],17)
            self.assertEqual(result['process']['retained_stdout_bytes'],12);self.assertEqual(result['process']['retained_stderr_bytes'],5)
            self.assertEqual((root/'stdout.bin').read_bytes(),b'partial JSON');self.assertFalse((root/'proposal').exists())
            with patch.object(muse.sys,'platform','darwin'),self.assertRaises(TaskAlongError) as exc:
                self.service.run_provider(bundle=result['bundle'],output=str(self.root/f'retry-{index}'))
            self.assertEqual(exc.exception.code,'provider_already_submitted')

    def test_cli_budget_is_local_and_run_cannot_dispatch_an_insufficient_request(self):
        from taskalong.cli import main
        self.configure();path=self.root/'large.json';path.write_bytes(canonical_bytes(self.large_request()))
        def cli(arguments):
            output=io.StringIO()
            with contextlib.redirect_stdout(output):code=main(['--json','--state-dir',str(self.root/'state'),*arguments])
            value=json.loads(output.getvalue());validate('command-result',value);return code,value
        with patch.object(muse.sys,'platform','darwin'),patch.object(muse,'run_foreground_experiment') as owner:
            code,result=cli(['provider-budget','muse','--request',str(path)])
            self.assertEqual(code,0);self.assertFalse(result['data']['input_echoes_fit'])
            code,result=cli(['run','--request',str(path),'--output',str(self.root/'cli-output')])
            self.assertEqual(code,3);self.assertEqual(result['errors'][0]['code'],'provider_capture_budget_insufficient')
        owner.assert_not_called();self.assertFalse((self.root/'cli-output').exists())

    def test_existing_configuration_without_proposal_field_remains_readable(self):
        from taskalong.validation import digest
        self.configure();old=self.service._store.setting('provider:muse');old.pop('max_proposal_bytes');old['format']='local-muse-provider/1';old['digest']=digest(old)
        self.service._store.set_setting('provider:muse',old)
        self.assertEqual(self.service.provider_budget(request=request())['max_proposal_bytes'],65536)
        self.assertEqual(self.service._store.setting('provider:muse'),old)
        self.assertEqual(self.run_fixture()['state'],'proposal_ready')

    def test_new_format_fences_rollback_and_requires_explicit_valid_proposal_limit(self):
        from taskalong.validation import digest
        self.configure();value=self.service._store.setting('provider:muse')
        self.assertEqual(value['format'],'local-muse-provider/3')
        for field in (None,True,0,262145):
            bad=dict(value)
            if field is None:bad.pop('max_proposal_bytes')
            else:bad['max_proposal_bytes']=field
            bad['digest']=digest(bad);self.service._store.set_setting('provider:muse',bad)
            with patch.object(muse,'run_foreground_experiment') as owner,self.assertRaises(TaskAlongError) as exc:
                self.service.provider_budget(request=request())
            self.assertEqual(exc.exception.code,'provider_configuration_changed');owner.assert_not_called()
        bad={**value,'format':'local-muse-provider/999'};bad['digest']=digest(bad)
        self.service._store.set_setting('provider:muse',bad)
        with self.assertRaises(TaskAlongError) as exc:self.service.provider_budget(request=request())
        self.assertEqual(exc.exception.code,'provider_configuration_changed')
