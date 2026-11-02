"""Synthetic permission frames, exact raw checksum and fail-closed dialect."""
import copy
import hashlib
import json
import unittest
import uuid
from taskalong import muse_retained_frames as frames
from taskalong.validation import canonical_bytes

SESSION='11111111-1111-4111-8111-111111111111'

def fixture(session=SESSION):
    # Deterministic content vectors for the explicit built-in public policy,
    # independent of synthetic session identity, timestamp or account.
    payload={'schema_version':1,'permission_epoch':1,'source':{'kind':'built_in','id':':read-only','display_name':'Read only'},
        'resolved_snapshot':{'schema_version':1,'filesystem':{'mode':'managed','minimal_runtime_set_version':1,'workspace_roots':[],
            'rules':[{'subject':{'kind':'special','value':p},'access':'read'} for p in (':minimal',':root',':workspace_roots')],
            'protected_metadata':True},'local_command_network':{'mode':'restricted','targets':[],'unix_sockets':[]},
            'approval':'on_request','reviewer':'human'},'definition_sha256':'sha256:dbc239a9e17982ce71a2458f6e17f0f39f190387a94316d44b6f102571d4fed2','managed_ancestor_sha256':[],
        'managed_enforcement':{'schema_version':1,'constraint_epoch':0,'constraint_sha256':'sha256:59b1b03f052965a55de5fd072b4e03118eb5b7302d48caa89e9b8e5ae34d0530',
            'component_ceilings':{'filesystem_modes':['managed','unrestricted'],'network_modes':['restricted','proxy_only','enabled'],
                'approval':['on_request','prompt_unmatched','allow_all'],'reviewer':['human','auto_review','none']},
            'filesystem_rules':[],'network_targets':[],'unix_sockets':[],'managed_targets_only':False,'platform':'macos','backend_id':'legacy-v1'},
        'resulting_snapshot_sha256':'sha256:a2f8267d9ff52174a5032cfecd0f22f47e6aa71470df1608932a603f0dbfded7','cause':'launch_cli','actor':{'kind':'runtime','id':None},
        'command':None,'pending_action_cancellations':[]}
    rows=[]
    for index,(kind,body) in enumerate((('runtime.session.permission_format_declared',{'schema_version':1,'format':'profile_v1'}),
            ('runtime.session.permission_profile_committed',payload)),1):
        rows.append({'schema_version':1,'id':f'{index:08x}-1111-4111-8111-111111111111',
            'stream':{'kind':'session','id':session},'sequence':index,'recorded_at':1000000,
            'record_type':'event','durability':'durable','causation_id':None,'payload_type':kind,'payload_schema_version':1,'payload':body})
    frame={'retained_frame':'session_permission_transaction','frame_schema_version':1,'outer_log_ordinal':1,
        'transaction_id':'33333333-3333-4333-8333-333333333333','children':[
            {'child_index':index,'record_json':canonical_bytes(row).decode()} for index,row in enumerate(rows)]}
    checksum(frame)
    return frame,rows


def checksum(frame):
    # Exact independently specified native byte layout, not canonicalized children.
    parts=[b'muse.session_permission_transaction.v1\0',frame['outer_log_ordinal'].to_bytes(8,'big'),
        uuid.UUID(frame['transaction_id']).bytes,len(frame['children']).to_bytes(4,'big')]
    for child in frame['children']:
        raw=child['record_json'].encode()
        parts.extend([child['child_index'].to_bytes(4,'big'),len(raw).to_bytes(8,'big'),raw])
    frame['content_sha256']='sha256:'+hashlib.sha256(b''.join(parts)).hexdigest()


def changed(frame,index,mutation):
    row=json.loads(frame['children'][index]['record_json']);mutation(row)
    frame['children'][index]['record_json']=canonical_bytes(row).decode();checksum(frame)


class RetainedFrameTests(unittest.TestCase):
    def test_exact_raw_checksum_and_closed_read_only_startup(self):
        frame,rows=fixture()
        self.assertEqual(frames.expand(frame,ordinal=1,session=SESSION),rows)
        alternate=copy.deepcopy(frame)
        alternate['children'][0]['record_json']=json.dumps(rows[0],indent=1)
        with self.assertRaises(ValueError): frames.expand(alternate,ordinal=1,session=SESSION)
        checksum(alternate)
        self.assertEqual(frames.expand(alternate,ordinal=1,session=SESSION),rows)

    def test_outer_version_ordinal_extra_keys_indices_and_checksum_refuse(self):
        base,_=fixture()
        mutations=[lambda f:f.update(frame_schema_version=True),lambda f:f.update(frame_schema_version=2),
            lambda f:f.update(outer_log_ordinal=2),lambda f:f.update(outer_log_ordinal=True),lambda f:f.update(extra=1),
            lambda f:f.update(retained_frame='unknown'),lambda f:f.update(content_sha256='sha256:'+'0'*64),
            lambda f:f['children'][0].update(child_index=True),lambda f:f['children'].reverse(),
            lambda f:f['children'].append(copy.deepcopy(f['children'][0])),lambda f:f['children'][0].update(extra=True)]
        for mutate in mutations:
            frame=copy.deepcopy(base);mutate(frame)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):frames.expand(frame,ordinal=1,session=SESSION)
        with self.assertRaises(ValueError):frames.expand(base,ordinal=2,session=SESSION)

    def test_bound_child_identity_sequence_durability_and_nested_frames(self):
        mutations=[lambda r:r.update(sequence=True),lambda r:r.update(sequence=5),lambda r:r.update(record_type='snapshot'),
            lambda r:r.update(durability='ephemeral'),lambda r:r.update(payload_schema_version=2),lambda r:r.update(extra=True),
            lambda r:r['stream'].update(id='44444444-4444-4444-8444-444444444444'),
            lambda r:r.update(causation_id='44444444-4444-4444-8444-444444444444'),
            lambda r:r.update(id='33333333-3333-4333-8333-333333333333'),
            lambda r:r['payload'].update(hidden={'record_json':'{}'})]
        for mutate in mutations:
            frame,_=fixture();changed(frame,0,mutate)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):frames.expand(frame,ordinal=1,session=SESSION)
        frame,rows=fixture();changed(frame,1,lambda r:r.update(id=rows[0]['id']))
        with self.assertRaises(ValueError):frames.expand(frame,ordinal=1,session=SESSION)

    def test_effective_write_network_approval_or_unrelated_activity_refuse_even_with_valid_checksum(self):
        mutations=[lambda p:p['resolved_snapshot']['filesystem']['rules'][0].update(access='write'),
            lambda p:p['resolved_snapshot']['filesystem'].update(mode='unrestricted'),
            lambda p:p['resolved_snapshot']['local_command_network'].update(mode='enabled'),
            lambda p:p['resolved_snapshot']['local_command_network']['targets'].append('example.invalid'),
            lambda p:p['resolved_snapshot'].update(approval='allow_all'),lambda p:p.update(permission_epoch=True),
            lambda p:p.update(permission_epoch=2),lambda p:p['source'].update(id='custom'),
            lambda p:p.update(command={'kind':'model_request_configured'}),lambda p:p.update(hidden={'terminal':'completed'})]
        for mutate in mutations:
            frame,_=fixture();changed(frame,1,lambda r:mutate(r['payload']))
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):frames.expand(frame,ordinal=1,session=SESSION)

    def test_flat_durable_records_remain_but_hidden_frame_strings_refuse(self):
        row={'record_type':'event','durability':'durable','payload':{'kind':'metadata'}}
        self.assertEqual(frames.expand(row,ordinal=4,session=SESSION),[row])
        for hidden in ({'record_json':'{}'},{'retained_frame':'unknown'}):
            with self.subTest(hidden=hidden),self.assertRaises(ValueError):
                frames.expand({**row,'hidden':hidden},ordinal=4,session=SESSION)

    def test_sorted_outer_object_is_not_the_native_closed_frame_dialect(self):
        frame,_=fixture()
        sorted_frame=json.loads(canonical_bytes(frame))
        with self.assertRaises(ValueError):frames.expand(sorted_frame,ordinal=1,session=SESSION)

    def test_declared_internal_hashes_must_match_typed_content_encoding(self):
        frame,rows=fixture();payload=rows[1]['payload']
        values=frames.permission_hashes(payload)
        self.assertEqual(values['definition_sha256'],payload['definition_sha256'])
        self.assertEqual(values['resulting_snapshot_sha256'],payload['resulting_snapshot_sha256'])
        self.assertEqual(values['constraint_sha256'],payload['managed_enforcement']['constraint_sha256'])
        for field in ('definition_sha256','resulting_snapshot_sha256'):
            bad,_=fixture();changed(bad,1,lambda r:r['payload'].update({field:'sha256:'+'0'*64}))
            with self.subTest(field=field),self.assertRaises(ValueError):frames.expand(bad,ordinal=1,session=SESSION)
        bad,_=fixture();changed(bad,1,lambda r:r['payload']['managed_enforcement'].update(constraint_sha256='sha256:'+'0'*64))
        with self.assertRaises(ValueError):frames.expand(bad,ordinal=1,session=SESSION)

    def test_cr_or_lf_terminated_nested_record_is_rejected_even_with_matching_checksum(self):
        for suffix in ('\r','\n'):
            frame,_=fixture();frame['children'][0]['record_json']+=suffix;checksum(frame)
            with self.subTest(suffix=suffix),self.assertRaises(ValueError):frames.expand(frame,ordinal=1,session=SESSION)
