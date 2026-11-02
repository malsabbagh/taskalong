"""Closed startup permission frames from the pinned native journal dialect.

The checksum binds EXACT UTF-8 child bytes, not their reserialized JSON. Internal
content fingerprints use the independently checked native typed encodings.
They are content bindings, not policy signatures or proof of OS containment.
"""
from __future__ import annotations
import hashlib
import re
import uuid
from .validation import canonical_bytes

_DOMAIN = b'muse.session_permission_transaction.v1\0'
_MAXIMUM = 16 * 1048576
_ENVELOPE = {'schema_version','id','stream','sequence','recorded_at','record_type','durability',
             'causation_id','payload_type','payload_schema_version','payload'}
_SNAPSHOT = {'schema_version':1,'filesystem':{'mode':'managed','minimal_runtime_set_version':1,
    'workspace_roots':[], 'rules':[{'subject':{'kind':'special','value':p},'access':'read'}
        for p in (':minimal',':root',':workspace_roots')],'protected_metadata':True},
    'local_command_network':{'mode':'restricted','targets':[],'unix_sockets':[]},
    'approval':'on_request','reviewer':'human'}
_ENFORCEMENT = {'schema_version':1,'constraint_epoch':0,
    'component_ceilings':{'filesystem_modes':['managed','unrestricted'],
        'network_modes':['restricted','proxy_only','enabled'],
        'approval':['on_request','prompt_unmatched','allow_all'], 'reviewer':['human','auto_review','none']},
    'filesystem_rules':[],'network_targets':[],'unix_sockets':[],'managed_targets_only':False,
    'platform':'macos','backend_id':'legacy-v1'}


def _uuid(value):
    if type(value) is not str or str(uuid.UUID(value)) != value:
        raise ValueError('retained frame identity')
    return uuid.UUID(value)


def _fingerprint(value):
    if type(value) is not str or re.fullmatch(r'sha256:[a-f0-9]{64}',value) is None:
        raise ValueError('retained permission fingerprint')
    return value


def _no_embedded_frames(row):
    pending=[row]
    while pending:
        item=pending.pop()
        if type(item) is dict:
            if {'retained_frame','record_json'}.intersection(item):
                raise ValueError('nested retained frame')
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)


def expand(row, *, ordinal, session):
    """Normalize one known first-line frame, or validate a flat durable row."""
    if 'retained_frame' not in row:
        if type(row.get('payload_type')) is str and row['payload_type'].startswith('runtime.session.permission_'):
            raise ValueError('permission changes must be the closed startup transaction')
        _no_embedded_frames(row)
        if row.get('record_type') != 'event' or row.get('durability') != 'durable':
            raise ValueError('journal record is not durable')
        return [row]
    if (tuple(row) != ('retained_frame','frame_schema_version','outer_log_ordinal','transaction_id','children','content_sha256')
            or row['retained_frame'] != 'session_permission_transaction'
            or type(row['frame_schema_version']) is not int or row['frame_schema_version'] != 1
            or type(row['outer_log_ordinal']) is not int or row['outer_log_ordinal'] != ordinal or ordinal != 1
            or type(row['children']) is not list or len(row['children']) != 2):
        raise ValueError('unsupported retained permission frame')
    transaction=_uuid(row['transaction_id'])
    hashed=hashlib.sha256(_DOMAIN + ordinal.to_bytes(8,'big') + transaction.bytes + (2).to_bytes(4,'big'))
    children=[];size=0
    from .muse_experimental import _native_json
    for index,child in enumerate(row['children']):
        if (type(child) is not dict or set(child) != {'child_index','record_json'}
                or type(child['child_index']) is not int or child['child_index'] != index
                or type(child['record_json']) is not str):
            raise ValueError('retained child envelope')
        raw=child['record_json'].encode('utf-8',errors='strict');size+=len(raw)
        if not raw or raw.endswith((b'\n',b'\r')) or size > _MAXIMUM:
            raise ValueError('retained child bound')
        hashed.update(index.to_bytes(4,'big') + len(raw).to_bytes(8,'big') + raw)
        event=_native_json(raw,max_bytes=_MAXIMUM,_journal_numbers=True)
        if (set(event) != _ENVELOPE or type(event['schema_version']) is not int or event['schema_version'] != 1
                or type(event['payload_schema_version']) is not int or event['payload_schema_version'] != 1
                or type(event['sequence']) is not int or event['sequence'] != index+1
                or event['stream'] != {'kind':'session','id':session}
                or event['record_type'] != 'event' or event['durability'] != 'durable'
                or event['causation_id'] is not None or _uuid(event['id']) == transaction
                or type(event['recorded_at']) is not int or not 0 < event['recorded_at'] <= 2**53-1):
            raise ValueError('retained child event')
        _no_embedded_frames(event);children.append(event)
    if (_fingerprint(row['content_sha256']) != 'sha256:'+hashed.hexdigest()
            or children[0]['id'] == children[1]['id'] or children[0]['recorded_at'] != children[1]['recorded_at']):
        raise ValueError('retained frame checksum or identity')
    first,second=children
    if (first['payload_type'] != 'runtime.session.permission_format_declared'
            or canonical_bytes(first['payload']) != canonical_bytes({'schema_version':1,'format':'profile_v1'})
            or second['payload_type'] != 'runtime.session.permission_profile_committed'):
        raise ValueError('retained permission grammar')
    payload=second['payload']
    if type(payload) is not dict or type(payload.get('managed_enforcement')) is not dict:
        raise ValueError('retained permission payload')
    expected={'schema_version':1,'permission_epoch':1,
        'source':{'kind':'built_in','id':':read-only','display_name':'Read only'},
        'resolved_snapshot':_SNAPSHOT,'managed_ancestor_sha256':[],
        'definition_sha256':_fingerprint(payload.get('definition_sha256')),
        'managed_enforcement':{**_ENFORCEMENT,'constraint_sha256':_fingerprint(payload['managed_enforcement'].get('constraint_sha256'))},
        'resulting_snapshot_sha256':_fingerprint(payload.get('resulting_snapshot_sha256')),
        'cause':'launch_cli','actor':{'kind':'runtime','id':None},'command':None,'pending_action_cancellations':[]}
    # Canonical bytes preserve bool/int distinctions throughout nested policy.
    if canonical_bytes(payload) != canonical_bytes(expected):
        raise ValueError('retained frame is not the closed read-only startup policy')
    calculated = permission_hashes(payload)
    if any(payload[key] != value for key,value in calculated.items() if key != "constraint_sha256") or payload['managed_enforcement']['constraint_sha256'] != calculated['constraint_sha256']:
        raise ValueError('retained permission content fingerprint mismatch')
    return children


def permission_hashes(payload):
    """Content hashes for this closed native-v1 policy, never an attestation."""
    def u32(number): return number.to_bytes(4,'big')
    def u64(number): return number.to_bytes(8,'big')
    def lp(text):
        raw=text.encode('utf-8');return u32(len(raw))+raw
    def strings(values): return u32(len(values))+b''.join(lp(v) for v in values)
    def hashed(domain,raw): return 'sha256:'+hashlib.sha256(domain.encode()+b'\0'+raw).hexdigest()
    snapshot=payload['resolved_snapshot'];fs=snapshot['filesystem'];network=snapshot['local_command_network']
    # Structural validation above fixes the supported option/list alternatives;
    # no unretained ancestor definitions or OS settings are inferred.
    body=(u64(snapshot['schema_version'])+lp(fs['mode'])+b'\1'+u64(fs['minimal_runtime_set_version'])
        +strings(fs['workspace_roots'])+u32(len(fs['rules']))
        +b''.join(lp(rule['subject']['kind'])+lp(rule['subject']['value'])+lp(rule['access']) for rule in fs['rules'])
        +bytes([fs['protected_metadata']])+lp(network['mode'])+strings(network['targets'])+strings(network['unix_sockets'])
        +lp(snapshot['approval'])+lp(snapshot['reviewer']))
    source=payload['source'];prefix=u64(snapshot['schema_version'])+lp(source['kind'])+b'\1'+lp(source['id'])
    definition=hashed('muse.permission.definition.v1',prefix+body)
    enforcement=payload['managed_enforcement'];ceilings=enforcement['component_ceilings']
    components=(b''.join(strings(ceilings[key]) for key in ('filesystem_modes','network_modes','approval','reviewer'))
        +u32(len(enforcement['filesystem_rules']))+u32(len(enforcement['network_targets']))
        +u32(len(enforcement['unix_sockets']))+bytes([enforcement['managed_targets_only']]))
    constraint=hashed('muse.permission.managed_enforcement.v1',u64(enforcement['schema_version'])+components)
    complete=(u64(enforcement['schema_version'])+u64(enforcement['constraint_epoch'])+lp(constraint)+components
        +lp(enforcement['platform'])+lp(enforcement['backend_id']))
    resulting=hashed('muse.permission.snapshot.v1',prefix+body+lp(definition)+strings(payload['managed_ancestor_sha256'])+complete)
    return {'definition_sha256':definition,'constraint_sha256':constraint,'resulting_snapshot_sha256':resulting}
