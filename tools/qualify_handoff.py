#!/usr/bin/env python3
"""Prepare a bounded two-harness campaign; never dispatch or grant authority.

This wrapper validates existing M9 documents and the M11 2.10 task contract.
An operator may supply existing trust and destination inputs independently of
the manifest. They support offline assessment only, not execution admission.
No credentials, runtime discovery, process launch, state access or write occurs.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

MAX_MANIFEST = 1_048_576
MAX_ARTIFACT = 1_048_576
MAX_TOTAL_ARTIFACTS = 16_777_216
MODES = ('start', 'observe', 'cancel', 'result')
_ID = re.compile(r'[a-z][a-z0-9_.-]{0,63}\Z')
_SHA = re.compile(r'[a-f0-9]{64}\Z')


class CampaignError(ValueError):
    def __init__(self, code, field):
        self.code, self.field = code, field
        super().__init__(code + ': ' + field)


def _require(condition, field, code='campaign_manifest_invalid'):
    if not condition:
        raise CampaignError(code, field)


def _closed(value, fields, field):
    _require(type(value) is dict and set(value) == set(fields.split()), field)


def _time(value, field):
    _require(type(value) is str and bool(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z', value)), field)
    try:
        return datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError:
        raise CampaignError('campaign_manifest_invalid', field) from None


def _ref(value, field):
    from taskalong.paths import safe_relative
    _closed(value, 'path sha256 size_bytes media_type classification', field)
    _require(type(value['sha256']) is str and bool(_SHA.fullmatch(value['sha256'])), field)
    _require(type(value['size_bytes']) is int and 0 <= value['size_bytes'] <= MAX_ARTIFACT, field)
    _require(value['media_type'] in ('application/json', 'text/plain'), field)
    _require(value['classification'] == 'public', field)
    safe_relative(value['path'])


def _models():
    from taskalong.artifact_handoff import ArtifactTaskSpec
    from taskalong.bindings import ExecutionBinding, HarnessInstallation, ProviderProfile
    from taskalong.qualification import QualificationReceipt, TrustPolicy, EvidenceStore, evaluate
    from taskalong.validation import canonical_bytes, loads, screen_sensitive
    return (ArtifactTaskSpec, ExecutionBinding, HarnessInstallation, ProviderProfile,
            QualificationReceipt, TrustPolicy, EvidenceStore, evaluate,
            canonical_bytes, loads, screen_sensitive)


def validate_manifest(document):
    """Validate declarations, not runtime truth or consent. Never seal a task."""
    (Task, Binding, Installation, Provider, Receipt, _, _, _, canonical, loads, sensitive) = _models()
    try:
        encoded = canonical(document)
        _require(len(encoded) <= MAX_MANIFEST, 'manifest')
        value = loads(encoded)
        sensitive(value)
        _closed(value, 'kind schema_version campaign_id source task_spec routes fixture artifacts handoff_artifact limits cleanup', 'manifest')
        _require(value['kind'] == 'handoff_campaign_preparation' and value['schema_version'] == '1.0', 'manifest.version')
        _require(type(value['campaign_id']) is str and bool(_ID.fullmatch(value['campaign_id'])), 'campaign_id')
        source = value['source']
        _closed(source, 'commit wheel_sha256 sdist_sha256 dependency_lock_sha256', 'source')
        _require(type(source['commit']) is str and bool(re.fullmatch(r'[a-f0-9]{40}', source['commit'])), 'source.commit')
        for name in ('wheel_sha256', 'sdist_sha256', 'dependency_lock_sha256'):
            _require(type(source[name]) is str and bool(_SHA.fullmatch(source[name])), 'source.' + name)
        task = Task.from_dict(value['task_spec']).to_dict()
        _require(task['publication'] is None, 'task_spec.publication')
        _require(len(task['steps']) == 2 and len(task['execution']['routes']) == 2, 'task_spec.routes')
        _require(task['steps'][0]['route_id'] != task['steps'][1]['route_id'], 'task_spec.steps')
        limits = value['limits']
        _closed(limits, 'provider_submissions wall_seconds capture_bytes artifact_bytes', 'limits')
        for key, ceiling in [('provider_submissions', 8), ('wall_seconds', 1440),
                             ('capture_bytes', 67_108_864), ('artifact_bytes', MAX_ARTIFACT)]:
            _require(type(limits[key]) is int and 0 < limits[key] <= ceiling, 'limits.' + key)
        _require(task['budget']['max_attempts'] <= limits['provider_submissions'], 'limits.provider_submissions')
        # M11 already funds final verification inside total_active_seconds.
        _require(task['budget']['total_active_seconds'] <= limits['wall_seconds'], 'limits.wall_seconds')
        _require(task['budget']['max_output_bytes'] <= limits['capture_bytes'], 'limits.capture_bytes')
        _closed(value['cleanup'], 'local_cessation unknown_effects native_resume cross_harness_resume', 'cleanup')
        _require(value['cleanup'] == {'local_cessation': 'required', 'unknown_effects': 'block',
                                    'native_resume': 'unsupported', 'cross_harness_resume': 'unsupported'}, 'cleanup')
        _require(type(value['artifacts']) is list and 1 <= len(value['artifacts']) <= 128, 'artifacts')
        for item in value['artifacts']:
            _ref(item, 'artifacts')
        _require(len({r['path'] for r in value['artifacts']}) == len(value['artifacts']), 'artifacts.paths')
        _require(len({r['sha256'] for r in value['artifacts']}) == len(value['artifacts']), 'artifacts.digests')
        _require(sum(r['size_bytes'] for r in value['artifacts']) <= MAX_TOTAL_ARTIFACTS, 'artifacts.bytes')
        _ref(value['fixture'], 'fixture')
        _require(value['fixture'] in value['artifacts'] and value['fixture']['media_type'] == 'application/json', 'fixture')
        if value['handoff_artifact'] is not None:
            _ref(value['handoff_artifact'], 'handoff_artifact')
            _require(value['handoff_artifact'] in value['artifacts'] and value['handoff_artifact']['media_type'] == 'text/plain', 'handoff_artifact')
        _require(type(value['routes']) is list and len(value['routes']) == 2, 'routes')
        declared = {r['route_id']: r for r in task['execution']['routes']}
        harnesses, identities, route_attempts = set(), set(), 0
        for route in value['routes']:
            _closed(route, 'route_id installation provider_profile binding configuration_digest context receipts', 'routes')
            name = route['route_id']
            _require(type(name) is str and name in declared and name not in identities, 'routes.route_id')
            identities.add(name)
            installation = Installation.from_dict(route['installation'])
            provider = Provider.from_dict(route['provider_profile'])
            binding = Binding.from_dict(route['binding'])
            i, p, b = installation.to_dict(), provider.to_dict(), binding.to_dict()
            _require(i['harness'] == p['harness'] and i['harness'] not in harnesses, 'routes.harness')
            harnesses.add(i['harness'])
            _require(b['installation_digest'] == installation.digest and b['provider_profile_digest'] == provider.digest, 'routes.binding')
            _require(declared[name]['binding_digest'] == binding.digest and declared[name]['configuration_digest'] == route['configuration_digest'], 'routes.task_binding')
            _require(b['budget']['wall_seconds'] <= limits['wall_seconds'] and b['budget']['max_attempts'] <= limits['provider_submissions'], 'routes.budget')
            route_attempts += b['budget']['max_attempts']
            _closed(route['context'], 'artifact_digest host_digest effective_context_digest test_inputs_digest session_digest prior_invocation_digest', 'routes.context')
            for key in ('artifact_digest', 'host_digest', 'effective_context_digest', 'test_inputs_digest'):
                _require(type(route['context'][key]) is str and bool(_SHA.fullmatch(route['context'][key])), 'routes.context.' + key)
            _require(route['context']['artifact_digest'] == source['wheel_sha256'] and route['context']['test_inputs_digest'] == value['fixture']['sha256'], 'routes.context.source')
            _require(route['context']['session_digest'] is None and route['context']['prior_invocation_digest'] is None, 'routes.context.fresh_session')
            _require(type(route['receipts']) is list and len(route['receipts']) <= 16, 'routes.receipts')
            receipts = [Receipt.from_dict(r) for r in route['receipts']]
            _require(len({r.digest for r in receipts}) == len(receipts), 'routes.receipts.duplicates')
            _require(all(r.to_dict()['mode'] in MODES for r in receipts), 'routes.receipts.mode')
        _require(route_attempts <= limits['provider_submissions'], 'routes.total_attempts')
        return value
    except CampaignError:
        raise
    except (ValueError, TypeError, KeyError):
        # Existing TaskAlong errors carry private input detail; don't echo it.
        raise CampaignError('campaign_manifest_invalid', 'contracts') from None
    except Exception as exc:
        from taskalong.errors import TaskAlongError
        if isinstance(exc, TaskAlongError):
            raise CampaignError('campaign_manifest_invalid', 'contracts') from None
        raise


def prepare(document, *, blobs, now, approved_destinations=frozenset(), trust=None):
    """Assess explicit immutable snapshots. This result can never start work."""
    value = validate_manifest(document)
    (_, Binding, Installation, Provider, Receipt, Trust, Evidence, evaluate, canonical, loads, sensitive) = _models()
    when = _time(now, 'now')
    _require(type(approved_destinations) is frozenset and all(type(x) is str and x.isprintable() and 0 < len(x) <= 128 for x in approved_destinations), 'operator.destinations')
    _require(trust is None or type(trust) is Trust, 'operator.trust')
    _require(type(blobs) is dict and len(blobs) <= 128, 'blobs')
    _require(sum(len(b) for b in blobs.values() if type(b) is bytes) <= MAX_TOTAL_ARTIFACTS, 'blobs.bytes')
    declared = {r['sha256']: r for r in value['artifacts']}
    _require(set(blobs) <= set(declared), 'blobs.undeclared')
    issues, checked = [], {}
    def issue(code, *, route=None, mode=None, artifact=None, receipt=None):
        item = {'code': code}
        if route is not None: item['route_id'] = route
        if mode is not None: item['mode'] = mode
        if artifact is not None: item['artifact_digest'] = artifact
        if receipt is not None: item['receipt_digest'] = receipt
        if item not in issues: issues.append(item)
    for sha, ref in declared.items():
        raw = blobs.get(sha)
        if sha not in blobs: issue('artifact_missing', artifact=sha)
        elif raw is None: issue('artifact_unavailable', artifact=sha)
        elif type(raw) is not bytes or len(raw) != ref['size_bytes'] or len(raw) > MAX_ARTIFACT or hashlib.sha256(raw).hexdigest() != sha:
            issue('artifact_tampered', artifact=sha)
        else: checked[sha] = raw
    fixture = checked.get(value['fixture']['sha256'])
    if fixture is not None:
        try:
            f = loads(fixture); _closed(f, 'files', 'fixture.content')
            _require(type(f['files']) is dict and 1 <= len(f['files']) <= 16, 'fixture.files')
            from taskalong.paths import safe_relative
            for path, text in f['files'].items():
                safe_relative(path); _require(type(text) is str and len(text.encode()) <= 65536, 'fixture.files')
            sensitive(f)
        except Exception:
            issue('fixture_invalid')
    handoff = value['handoff_artifact']
    if handoff is None: issue('producer_artifact_missing')
    elif handoff['size_bytes'] > value['limits']['artifact_bytes']:
        issue('handoff_artifact_too_large')
    task = value['task_spec']; producer, consumer = task['steps']
    selectors = [x for x in consumer['inputs'] if x.get('kind') == 'step_output']
    _require(len(producer['outputs']) == 1 and len(selectors) == 1, 'task_spec.handoff')
    output, selector = producer['outputs'][0], selectors[0]
    _require(selector['from_step_id'] == producer['step_id'] and selector['output_id'] == output['output_id'] and output['artifact_kind'] == 'utf8_text', 'task_spec.handoff')
    if handoff is not None and (handoff['size_bytes'] > output['max_bytes'] or handoff['size_bytes'] > selector['max_bytes']):
        issue('handoff_artifact_mismatch')
    route_refs = {r['route_id']: r for r in task['execution']['routes']}
    reports = []
    evidence = Evidence.from_blobs({sha: raw for sha, raw in checked.items() if raw})
    for route in value['routes']:
        name = route['route_id']; binding = Binding.from_dict(route['binding'])
        installation = Installation.from_dict(route['installation']); provider = Provider.from_dict(route['provider_profile'])
        i, p, b = installation.to_dict(), provider.to_dict(), binding.to_dict()
        if route_refs[name]['disclosure_destination_id'] not in approved_destinations:
            issue('destination_not_authorized', route=name)
        expected = {k:b[k] for k in ('installation_digest','provider_profile_digest','instruction_bundle_digest','tool_policy_digest','worker_sandbox_digest','check_binding_digest')}
        expected.update(binding_digest=binding.digest, runtime_closure_digest=i['runtime_closure_digest'], backend_id=i['platform']['backend_id'], provider=p['provider'], model_digest=p['model']['resolved_digest'], native_resume_compatibility_digest=b['native_resume']['compatibility_digest'] if b['native_resume'] else None, **route['context'])
        for mode in MODES:
            receipts = [r for r in route['receipts'] if r['mode'] == mode]
            if not receipts: issue('mode_receipt_missing', route=name, mode=mode)
            for receipt in receipts:
                if receipt['subject'] != expected: issue('proof_subject_mismatch', route=name, mode=mode, receipt=receipt['digest'])
                if not _time(receipt['valid_from'], 'receipt.valid_from') <= when < _time(receipt['valid_until'], 'receipt.valid_until'):
                    issue('proof_not_current', route=name, mode=mode, receipt=receipt['digest'])
                if receipt['evidence_level'] != 'actual_provider': issue('proof_not_actual_provider', route=name, mode=mode, receipt=receipt['digest'])
            if trust is None:
                issue('operator_trust_missing', route=name, mode=mode)
            else:
                evaluation = evaluate(binding, installation=installation, provider=provider, context=route['context'], mode=mode, receipts=receipts, trust=trust, evidence=evidence, now=now, minimum_level='actual_provider')
                decision = evaluation.decision.to_dict()
                for rejected in decision['rejected_receipts']:
                    issue('m9_' + rejected['reason_code'], route=name, mode=mode,
                          receipt=receipts[rejected['input_index']]['digest'])
                if not decision['requirements_satisfied']:
                    for cap in evaluation.report.to_dict()['capability_results']:
                        for reason in cap['reason_codes']:
                            if cap['outcome'] != 'supported': issue('m9_' + reason, route=name, mode=mode)
        reports.append({'route_id': name, 'harness': i['harness'], 'native_resume': 'unsupported'})
    return {'kind':'handoff_campaign_dry_run','schema_version':'1.0','campaign_digest':hashlib.sha256(canonical(value)).hexdigest(),
            'operator_inputs_digest':hashlib.sha256(canonical({'trust_policy_digest':trust.digest if trust else None,
                                                              'approved_destinations':sorted(approved_destinations)})).hexdigest(),
            'status':'blocked' if issues else 'preparation_valid',
            'as_of':now,'preparation_checks_passed':not issues,'issues':issues,'routes':reports,
            'qualification':'preparation_only','execution_admitted':False,'production_dispatch_allowed':False,
            'controller_submissions':0,'state_mutated':False,'producer_association_verified':False,'source_identity_verified':False,
            'execution_blockers':['actual_campaign_not_implemented','authoritative_producer_association_not_verified'],
            'limitations':['Source/build hashes are declarations; no source or runtime authentication was performed.',
                           'No live runtime, account, containment or remote settlement was observed.',
                           'Trust input is operator-supplied offline evidence, never an execution grant.',
                           'M11 2.10 remains its existing synthetic contract; this tool does not enable an actual route.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--dry-run', action='store_true', required=True)
    parser.add_argument('--evidence-root', type=Path)
    parser.add_argument('--allow-destination', action='append', default=[])
    parser.add_argument('--trust-policy', type=Path, help='Existing operator-controlled M9 policy; never read from the manifest.')
    args = parser.parse_args(argv)
    try:
        from taskalong.artifact_io import read_regular
        from taskalong.validation import loads
        from taskalong.qualification import TrustPolicy
        raw = read_regular(args.manifest.parent, args.manifest.name, max_bytes=MAX_MANIFEST)
        value = validate_manifest(loads(raw))
        evidence_root = args.evidence_root or args.manifest.parent
        blobs = {}
        for ref in value['artifacts']:
            try:
                # Bound actual reads by the admitted size, not only by the
                # per-file ceiling: false small declarations cannot amplify
                # the 16 MiB aggregate into 128 separate 1 MiB reads.
                blobs[ref['sha256']] = read_regular(evidence_root, ref['path'], max_bytes=ref['size_bytes'])
            except Exception:
                # No raw paths or OS error strings in the safe diagnostic.
                blobs[ref['sha256']] = None
        trust = None
        if args.trust_policy:
            trust = TrustPolicy.from_dict(loads(read_regular(args.trust_policy.parent, args.trust_policy.name, max_bytes=MAX_MANIFEST, private=True)))
        result = prepare(value, blobs=blobs, now=datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z'),
                         approved_destinations=frozenset(args.allow_destination), trust=trust)
        print(json.dumps(result, sort_keys=True))
        # A well-formed denial is not a successful campaign or execution gate.
        return 0 if result['preparation_checks_passed'] else 3
    except Exception as exc:
        if isinstance(exc, CampaignError): code, field = exc.code, exc.field
        else: code, field = 'campaign_input_unavailable', 'input'
        print(json.dumps({'kind':'handoff_campaign_dry_run','schema_version':'1.0','qualification':'preparation_only',
                          'execution_admitted':False,'controller_submissions':0,'state_mutated':False,
                          'error':{'code':code,'field':field}}, sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
