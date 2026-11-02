"""One explicit schema-transport successor of a complete malformed response.

Completion is evidence of a finished native turn, never cancellation or remote
settlement. No provider text is repaired, staged, executed or accepted here.
"""
from __future__ import annotations

import hashlib
import json

from . import muse_experimental as muse, muse_successor as successor
from . import muse_capture_recovery as capture_proof, supervised_pilot as pilot
from . import muse_response_schema as schema
from .artifact_io import read_regular
from .local_provider_capture import read_capture
from .muse_native_lifecycle import NativeModelTaskGuard
from .validation import canonical_bytes, digest, loads
from .errors import TaskAlongError

REASON = 'malformed-response'
FORMAT = 'manual-muse-successor/6'
PLAN = 'manual-muse-successor-plan/6'


def derive(previous):
    if previous.get('format') != muse._MEGABYTE or 'response_contract' in previous:
        successor._fail('provider_successor_configuration_mismatch')
    value = {**previous, 'format':schema.FORMAT, 'response_contract':schema.CONTRACT}
    value['digest'] = digest(value)
    return value


def _material(store, predecessor, config):
    record, root = successor._read_run(store, predecessor)
    if (record.get('format') != 'local-provider-run/1' or record.get('manual_successor') is not None
            or record.get('state') != 'failed' or record.get('error') != 'provider_response_unrecognized'
            or type(record.get('controller_submissions')) is not int or record['controller_submissions'] != 1
            or any(record.get(k) != 'unknown' for k in ('remote_usage','native_internal_retries','descendant_cessation'))
            or any(record.get(k) is not False for k in ('automatic_retry_allowed','patch_applied','acceptance_allowed','production_dispatch_allowed'))):
        successor._fail()
    previous = store.setting('provider-config:' + record['configuration_digest'])
    if previous != config or previous.get('digest') != record['configuration_digest']:
        successor._fail('provider_successor_configuration_mismatch')
    candidate = muse._checked_configuration(derive(previous))
    bundle, manifest = pilot._bundle(record['bundle'])
    if manifest['digest'] != record['bundle_digest']:
        successor._fail('provider_successor_history_changed')
    for path in [root/name for name in ('response.json','proposal','response-claim.json','proposed.patch','review.json')] + [bundle/'response-claim.json']:
        if path.exists() or path.is_symlink():
            successor._fail('provider_successor_result_exists')
    if store.setting('provider-result-recovery:muse:' + predecessor) is not None:
        successor._fail('provider_successor_result_exists')
    artifacts = {'events':capture_proof._events(root, record)}
    def read(name, maximum=1048576):
        raw = read_regular(root,name,max_bytes=maximum,private=True,expected_mode=0o400)
        artifacts[name] = hashlib.sha256(raw).hexdigest()
        return raw
    # Decode failures are recorded after process.json is sealed. Older records
    # legitimately omit its body, but any embedded body must agree exactly.
    process = loads(read('process.json'))
    if record.get('process', process) != process:
        successor._fail('provider_successor_history_changed')
    if (process.get('root_exit_observed') is not True or type(process.get('root_exit_code')) is not int
            or process['root_exit_code'] != 0 or process.get('group_termination_confirmed') is not True
            or any(process.get(k) is not False for k in ('timed_out','cancelled','output_limited','protocol_record_limited'))
            or process.get('mode') != 'darwin-foreground-experiment/1'
            or process.get('tracking_errors') != [] or process.get('boundary_failures') != []
            or process.get('failure_code') is not None or process.get('protocol_error') is not None
            or process.get('process_stream_complete') is not True
            or process.get('protocol_record_limit') != previous['max_protocol_records']):
        successor._fail()
    receipt = process.get('receipt')
    if (type(receipt) is not dict or receipt != record.get('process_receipt')
            or receipt.get('executable_sha256') != previous['binary']['sha256']
            or type(receipt.get('started_unix_ms')) is not int or receipt['started_unix_ms'] <= 0):
        successor._fail('provider_successor_history_changed')
    for number,state in enumerate(('preflight','starting','running','failed'),1):
        event = loads(read(f'events/{number:04d}.json'))
        if (record['revision'] != 4 or event.get('state') != state
                or any(event.get(k) != record[k] for k in ('format','run_id','configuration_digest','bundle_digest','bundle','output'))
                or event.get('manual_successor') is not None
                or type(event.get('controller_submissions')) is not int or event['controller_submissions'] != (0 if number==1 else 1)):
            successor._fail('provider_successor_history_changed')
    invocation = loads(read('invocation.json'))
    session = successor._id(invocation.get('session_id'))
    if invocation != {'argv':muse._argv(previous,provider='meta',workspace=root/'workspace',prompt=root/'prompt.txt',session=session),
            'session_id':session,'configuration_digest':previous['digest'],'bundle_digest':manifest['digest']}:
        successor._fail('provider_successor_history_changed')
    prompt = read('prompt.txt')
    if prompt != pilot._prompt(manifest['request'],manifest['digest']):
        successor._fail('provider_successor_history_changed')
    capture = read_capture(root/'capture')
    if (capture != process.get('private_capture') or capture.get('status') != 'closed'
            or capture.get('byte_closure') is not True or capture.get('observed_counts_complete') is not True
            or capture.get('metadata_limited') is not False or capture.get('output_limited') is not False):
        successor._fail('provider_successor_history_changed')
    streams = capture['streams']; raw = {}
    for stream in ('stdout','stderr','result'):
        ref = streams[stream]
        raw[stream] = read_regular(root/'capture',stream+'.bin',max_bytes=previous['max_output_bytes'],private=True,
            expected_mode=0o600,expected_sha256=ref['sha256'],expected_bytes=ref['retained_bytes'])
        if ref['observed_bytes'] != len(raw[stream]):
            successor._fail('provider_successor_history_changed')
    total = len(raw['stdout']) + len(raw['stderr'])
    if (raw['result'] or not 0 < total <= previous['max_output_bytes']
            or process.get('observed_output_bytes') != total or process.get('retained_output_bytes') != total
            or any(process.get('retained_'+s+'_bytes') != len(raw[s]) for s in ('stdout','stderr'))
            or read_capture(root/'capture') != capture):
        successor._fail('provider_successor_history_changed')
    guard = schema.SingleAttemptGuard(session,max_records=previous['max_protocol_records'],max_frame_bytes=muse._MEGABYTE_FRAME)
    if not raw['stdout'].endswith(b'\n'):
        successor._fail('provider_successor_capture_unrecognized')
    # Split only on LF: escaped and literal Unicode line separators are content.
    lines = raw['stdout'][:-1].split(b'\n')
    for line in lines:
        guard.observe(line)
    if (not guard.completed_single_model(full=True) or guard.stop_requested
            or guard.summary()['tracked_tasks'] != 1 or process.get('protocol_records_observed') != len(lines)):
        successor._fail('provider_successor_capture_unrecognized')
    text, native_run = muse._decode_megabyte(iter(lines),session,max_proposal_bytes=previous['max_proposal_bytes'],
        max_records=previous['max_protocol_records'],_terminal_only=True)
    from .muse_result_recovery import _activity_markers
    fragments = []
    terminal_seen = False
    for line in lines:
        row = muse._native_json(line,max_bytes=muse._MEGABYTE_FRAME)
        payload = row["payload"]
        markers = _activity_markers(row)
        if markers and (len(markers) != 1 or markers[0] is not payload or row["payload_type"] != "run.output.delta"):
            successor._fail("provider_successor_capture_unrecognized")
        outcome = capture_proof._terminal(row)
        if outcome is not None:
            if terminal_seen or outcome != ("session","completed") or payload.get("text") != text:
                successor._fail("provider_successor_capture_unrecognized")
            terminal_seen = True
        elif terminal_seen and not capture_proof._trailing_metadata(row):
            successor._fail("provider_successor_capture_unrecognized")
        elif row["payload_type"] == "run.output.delta":
            if (payload.get("kind") != "run_output_delta" or type(payload.get("text")) is not str
                    or payload.get("command_id") != native_run):
                successor._fail("provider_successor_capture_unrecognized")
            fragments.append(payload["text"])
        elif payload.get("kind") == "run_output_delta":
            successor._fail("provider_successor_capture_unrecognized")
    if not fragments or "".join(fragments) != text:
        successor._fail("provider_successor_capture_unrecognized")
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        # Narrowly cover demonstrated escaping defects, not all semantic errors
        # or arbitrary truncated/empty/model refusal responses.
        if not (exc.msg == 'Invalid \\escape' or exc.msg.startswith('Invalid control character')) or not schema.escaping_failure(text):
            successor._fail('provider_successor_capture_unrecognized')
        malformed = {'kind':'invalid_escape' if exc.msg == 'Invalid \\escape' else 'unescaped_control_character',
                     'text_sha256':hashlib.sha256(text.encode()).hexdigest(),'text_bytes':len(text.encode())}
    else:
        successor._fail('provider_successor_result_exists')
    from .muse_result_recovery import _journal
    journal_material = {'record':record,'config':previous,'session':session,
        'validated_native_lifecycle':guard.summary(),'single_native_attempt':True,'model_task_sha256':guard.completed_model_task_sha256()}
    committed, journal = _journal(journal_material,native_run)
    if committed != text:
        successor._fail('provider_successor_history_changed')
    marker = read_regular(bundle,'provider-submission.json',max_bytes=65536,private=True,expected_mode=0o400)
    if (marker != canonical_bytes({'provider':'muse','run_id':predecessor,'bundle_digest':manifest['digest']})
            or store.setting('provider-claim:muse:'+manifest['digest']) != {
                'run_id':predecessor,'output':str(root),'bundle_digest':manifest['digest']}):
        successor._fail('provider_successor_history_changed')
    artifacts.update(capture=digest(capture),journal=digest(journal),submission_marker=hashlib.sha256(marker).hexdigest())
    enrollment = {'format':'manual-muse-ladder/6','reason':REASON,'root_run_id':predecessor,
        'root_record_digest':record['digest'],'bundle_digest':manifest['digest'],
        'state_scope':hashlib.sha256(str(store.root).encode()).hexdigest(),
        'deadlines_seconds':[previous['attempt_seconds']],'max_new_controller_submissions':1,
        'native_lifecycle_policy':muse._NATIVE_STOP_POLICY,'response_contract':schema.CONTRACT}
    successor._anchor_view(store,record,enrollment)
    value = {'format':PLAN,'reason':REASON,'provider':'muse','predecessor_run_id':predecessor,
        'predecessor_digest':record['digest'],'root_run_id':predecessor,'ordinal':1,
        'bundle_digest':manifest['digest'],'configuration_digest':candidate['digest'],
        'original_configuration_digest':previous['digest'],'response_contract':schema.CONTRACT,
        'attempt_seconds':previous['attempt_seconds'],'max_output_bytes':previous['max_output_bytes'],
        'max_protocol_records':previous['max_protocol_records'],'max_proposal_bytes':previous['max_proposal_bytes'],
        'artifact_hashes':artifacts,'malformed_response':malformed,'enrollment':enrollment,
        'native_lifecycle_policy':muse._NATIVE_STOP_POLICY,
        'history':[{'run_id':predecessor,'controller_submissions':1,'remote_usage':'unknown',
            'descendant_cessation':'unknown','native_internal_retries':'unknown'}],
        'remaining_controller_slots_including_this':1,'remaining_local_meta_seconds_including_this':previous['attempt_seconds'],
        'automatic_retry_allowed':False,'remote_usage_settled':False,'complete_descendant_cessation_proven':False,'model_free':True}
    value['digest'] = digest(value)
    return value,record,root,manifest


def material(store, predecessor, config):
    try:
        return _material(store,predecessor,config)
    except (TaskAlongError,OSError,ValueError,TypeError,KeyError,AttributeError,UnicodeError,RecursionError) as exc:
        if isinstance(exc,TaskAlongError) and exc.code.startswith('provider_successor_'):
            raise
        successor._fail('provider_successor_capture_unrecognized')
