"""Synthetic protocol qualification only; no runtime/account authority."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from taskalong import supervised_muse_runner as runner
from taskalong import supervised_pilot as pilot
from taskalong.errors import TaskAlongError
from taskalong.validation import canonical_bytes, digest


def request():
    return {'base_commit':'a'*40,'task':'Change greeting.','provider':'muse','model':'wonder-full','reasoning_effort':'high','files':{'hello.txt':'hello\n'}}


@unittest.skipUnless(os.name=='posix','Private artifact descriptors require POSIX')
class SupervisedMuseRunnerTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.bundle=self.root/'bundle';self.planroot=self.root/'plan'
        pilot.prepare(request(),output=str(self.bundle))
        identity={'path':'/fixed/native','sha256':runner.BINARY_SHA256,'bytes':1,'mode':448}
        with patch.object(runner,'_observe_file',return_value=identity):
            self.prepared=runner.prepare(bundle=str(self.bundle),executable='/fixed/native',output=str(self.planroot))
        self.plan=runner.load_plan(self.prepared['plan_path']);_,self.manifest=pilot._bundle(str(self.bundle))
        self.sid=self.plan['session_id'];self.tid=self.plan['turn_command_id']

    def fold(self):
        return runner.TurnFold(session_id=self.sid,turn_id=self.tid,interrupt_id=self.plan['interrupt_command_id'])

    def event(self,method,*,turn=True,**params):
        base={'sessionId':self.sid,'viewCursor':'v'+str(len(str(params))),'sourceRange':{'stream':{'kind':'session','id':self.sid},'first':{'id':'record','sequence':1},'last':{'id':'record','sequence':1}}}
        if turn:base['turnId']=self.tid
        return {'jsonrpc':'2.0','method':method,'params':base|params}

    def final(self,text=None,**changes):
        response={'bundle_digest':self.manifest['digest'],'changes':{'hello.txt':'hello world\n'}}
        item={'itemId':'original-message','turnId':self.tid,'revision':2,'kind':'agentMessage','status':'completed','messagePhase':'finalAnswer','text':json.dumps(response) if text is None else text,**changes}
        return self.event('item/completed',turn=False,item=item,viewCursor='v-final')

    def transcript(self):
        init={'serverInfo':{'name':'muse','version':'1.4.10'},'platformFamily':'unix','platformOs':'macos','schema':{'version':1,'fingerprint':runner.SCHEMA_FINGERPRINT},'grantedCapabilities':[],'experimentalApi':True,'sandboxAvailability':'available','sessionDurability':'durable','museHome':self.plan['muse_home']}
        profiles={'profiles':[{'profileId':':read-only','available':True,'reviewerAuthority':'human'}]}
        catalog={'providerId':'meta','source':'bundledCatalog','models':[{'providerId':'meta','modelId':'wonder-full','variants':['high']}]}
        session={'session':{'sessionId':self.sid,'workspaceRoot':self.plan['workspace'],'providerId':'meta','modelId':'wonder-full','status':'idle','activeTurnId':None,'turnCount':0,'forkedFrom':None,'permissionState':{'profileId':':read-only','axes':dict(runner.AXES),'reviewerAuthority':'human','reviewerAttached':True}}}
        ack={'commandId':self.plan['turn_command_id'],'status':'accepted','turnId':self.tid,'disposition':'started','startedNewTurn':True}
        responses=[{'jsonrpc':'2.0','id':i+1,'result':v} for i,v in enumerate([init,profiles,catalog,{},session,ack])]
        return {'responses':responses,'notifications':[self.final(),self.event('turn/completed',terminal='completed',viewCursor='v-terminal')]}

    def test_plan_is_bound_restrictive_and_explicitly_non_executable(self):
        self.assertEqual(self.plan['limits']['turn_submissions'],1);self.assertFalse(self.plan['limits']['aggregate_inference_cap_enforced'])
        for name in ('--disable-write','--disable-shell','--disable-request-user-input'):self.assertIn(name,self.plan['argv'])
        self.assertNotIn('--trust-workspace',self.plan['argv']);self.assertNotIn('--disable-sandbox',self.plan['argv'])
        self.assertFalse(self.plan['live_dispatch_allowed']);self.assertEqual(self.plan['account_binding'],'unresolved')
        self.assertEqual(runner.initialize_request()['params']['capabilities']['requestedCapabilities'],[])
        self.assertEqual(runner.turn_request(self.plan)['params']['reasoningEffort'],'high')
        self.assertEqual(runner.session_request(self.plan)['params']['permissionProfile'],':read-only')

    def test_tampered_or_resealed_weakened_plan_refuses(self):
        path=Path(self.prepared['plan_path']);original=path.read_bytes()
        for key,value in [('live_dispatch_allowed',True),('limits',dict(runner.LIMITS,turn_submissions=True))]:
            altered=json.loads(original);altered[key]=value;altered['digest']=digest(altered)
            path.chmod(0o600);path.write_bytes(canonical_bytes(altered));path.chmod(0o400)
            with self.assertRaises(TaskAlongError):runner.load_plan(str(path))
        path.chmod(0o600);path.write_bytes(original);path.chmod(0o400)

    def test_replay_extracts_unverified_response_only_after_terminal(self):
        value=runner.replay(plan_path=self.prepared['plan_path'],bundle=str(self.bundle),transcript=self.transcript(),output=str(self.root/'replay'))
        self.assertEqual(value['response']['changes'],{'hello.txt':'hello world\n'})
        self.assertFalse(value['projected_requests_sent']);self.assertFalse(value['remote_usage_settled']);self.assertIsNone(value['reported_usage'])
        self.assertFalse(value['preflight_observations']['account_binding_qualified'])
        self.assertEqual(value['descendant_cessation'],'unknown')
        projected=json.loads((self.root/'replay/projected-requests.json').read_bytes())
        self.assertEqual(sum(r.get('method')=='turn/start' for r in projected['requests']),1)
        self.assertFalse(projected['sent'])

    def test_final_and_foreground_completion_do_not_settle_turn_or_usage(self):
        fold=self.fold();fold.feed(self.final());fold.feed(self.event('turn/foregroundCompleted',viewCursor='v-background'))
        value=fold.result(manifest=self.manifest)
        self.assertIsNone(value['response']);self.assertIn('turn_terminal_unobserved',value['blockers'])
        self.assertIsNone(value['reported_usage']);self.assertFalse(value['remote_usage_settled'])

    def test_auxiliary_or_tool_activity_interrupts_once_and_quarantines_even_completed(self):
        for kind in ('reminderChild','subagent','toolCall','workflow','hookRun','unknown'):
            fold=self.fold()
            frame=self.event('item/started',turn=False,item={'kind':kind,'turnId':self.tid},viewCursor='v-child')
            interrupt=fold.feed(frame)
            self.assertEqual(interrupt['method'],'turn/interrupt');self.assertEqual(interrupt['params']['turnId'],self.tid)
            self.assertIsNone(fold.feed(frame));fold.feed(self.final());fold.feed(self.event('turn/completed',terminal='completed',viewCursor='v-terminal'))
            value=fold.result(manifest=self.manifest);self.assertIsNone(value['response']);self.assertIn('unexpected_activity:'+kind,value['blockers'])

    def test_interrupt_ack_is_not_cancellation_completion(self):
        fold=self.fold();fold.interrupt('local_deadline')
        fold.acknowledge_interrupt({'commandId':self.plan['interrupt_command_id'],'turnId':self.tid,'status':'accepted'})
        value=fold.result(manifest=self.manifest)
        self.assertTrue(value['interrupt_acknowledged']);self.assertIsNone(value['terminal_observed']);self.assertFalse(value['remote_usage_settled'])
        fold.feed(self.event('turn/completed',terminal='cancelled',viewCursor='v-cancelled'))
        value=fold.result(manifest=self.manifest);self.assertEqual(value['terminal_observed'],'cancelled');self.assertFalse(value['remote_usage_settled'])
        self.assertIsNone(fold.interrupt('second_stop'))

    def test_wrong_session_turn_and_server_requests_are_never_granted(self):
        frames=[self.event('turn/completed',sessionId=self.plan['interrupt_command_id'],terminal='completed'),
                self.event('turn/completed',turnId=self.plan['interrupt_command_id'],terminal='completed'),
                {'jsonrpc':'2.0','id':'server-request','method':'approval/request','params':{}}]
        for frame in frames:
            fold=self.fold();action=fold.feed(frame);self.assertEqual(action['method'],'turn/interrupt')
            self.assertTrue(fold.blockers);self.assertIsNone(fold.result(manifest=self.manifest)['response'])

    def test_truncated_cutoff_partial_or_ambiguous_messages_refuse(self):
        for changed in ({'truncated':True},{'cutOff':True},{'status':'failed'},{'messagePhase':'commentary'},{'revision':True}):
            fold=self.fold();self.assertEqual(fold.feed(self.final(**changed))['method'],'turn/interrupt')
        fold=self.fold();fold.feed(self.final());other=self.final(itemId='another');other['params']['viewCursor']='v-other'
        self.assertEqual(fold.feed(other)['method'],'turn/interrupt')

    def test_malformed_response_and_out_of_scope_json_never_yield_proposal(self):
        for text in ('not json',json.dumps({'bundle_digest':self.manifest['digest'],'changes':{'outside':'x\n'}})):
            fold=self.fold();fold.feed(self.final(text));fold.feed(self.event('turn/completed',terminal='completed',viewCursor='v-terminal'))
            with self.assertRaises(TaskAlongError):fold.result(manifest=self.manifest)

    def test_output_limit_and_conflicting_cursor_do_not_retry(self):
        fold=self.fold();frame=self.final();fold.feed(frame)
        conflicting=copy.deepcopy(frame);conflicting['params']['item']['text']='changed'
        self.assertEqual(fold.feed(conflicting)['method'],'turn/interrupt')
        fold=self.fold();frame=self.event('item/delta',text='x'*65536)
        self.assertEqual(fold.feed(frame)['method'],'turn/interrupt');self.assertIsNone(fold.feed(frame))

    def test_missing_durable_source_and_unknown_terminal_refuse(self):
        fold=self.fold();frame=self.final();frame['params'].pop('sourceRange')
        self.assertEqual(fold.feed(frame)['method'],'turn/interrupt')
        fold=self.fold();self.assertEqual(fold.feed(self.event('turn/completed',terminal='future'))['method'],'turn/interrupt')

    def test_empty_catalog_or_unavailable_sandbox_refuse_before_response_staging(self):
        for changed in ('catalog','sandbox','grants','profile','queue','rpc_id'):
            transcript=self.transcript()
            if changed=='catalog':transcript['responses'][2]['result']['models']=[]
            if changed=='sandbox':transcript['responses'][0]['result']['sandboxAvailability']='unavailable'
            if changed=='grants':transcript['responses'][0]['result']['grantedCapabilities']=['userShell']
            if changed=='profile':transcript['responses'][4]['result']['session']['permissionState']['profileId']=':unrestricted'
            if changed=='queue':transcript['responses'][5]['result']['disposition']='queued'
            if changed=='rpc_id':transcript['responses'][0]['id']=True
            with self.subTest(changed=changed),self.assertRaises(TaskAlongError):runner.replay(plan_path=self.prepared['plan_path'],bundle=str(self.bundle),transcript=transcript,output=str(self.root/'bad'))
        self.assertFalse((self.root/'bad').exists())

    def test_usage_snapshot_is_preserved_as_reported_without_turn_count_invention(self):
        transcript=self.transcript();usage={'tier':'fixture','observedAtMs':1,'window':{'usedPercent':120,'resetsAtMs':2,'windowDurationMins':300},'weekly':{'usedPercent':3}}
        transcript['responses'][3]['result']={'usage':usage}
        result=runner.replay(plan_path=self.prepared['plan_path'],bundle=str(self.bundle),transcript=transcript,output=str(self.root/'usage'))
        self.assertEqual(result['preflight_observations']['reported_subscription_usage'],usage)
        self.assertIsNone(result['reported_usage']);self.assertFalse(result['inference_bound_qualified'])

    def test_background_agents_and_foreign_usage_are_quarantined(self):
        for frame in (self.event('turn/foregroundCompleted',blockingAgents=['goal-reminder']),
                      self.event('session/tokenUsage',turnId=self.plan['interrupt_command_id'])):
            fold=self.fold();action=fold.feed(frame)
            self.assertIsNotNone(action);self.assertEqual(action['method'],'turn/interrupt')
            fold.feed(self.final());fold.feed(self.event('turn/completed',terminal='completed',viewCursor='v-terminal'))
            self.assertIsNone(fold.result(manifest=self.manifest)['response'])

    def test_malformed_enum_values_produce_controlled_interrupts(self):
        for changed in ([], {}, True, 1, None):
            frame=self.event('unknown');frame['method']=changed
            fold=self.fold();self.assertEqual(fold.feed(frame)['method'],'turn/interrupt')
            frame=self.event('item/started',turn=False,item={'kind':changed,'turnId':self.tid})
            fold=self.fold();self.assertEqual(fold.feed(frame)['method'],'turn/interrupt')
            frame=self.event('turn/completed',terminal=changed)
            fold=self.fold();self.assertEqual(fold.feed(frame)['method'],'turn/interrupt')

    def test_incomplete_or_reversed_durable_provenance_refuses(self):
        source=self.final()['params']['sourceRange']
        bad=[{}, dict(source,stream={}), dict(source,first={}),dict(source,last={}),
             dict(source,first={'id':'record','sequence':True}),
             dict(source,first={'id':'record','sequence':2},last={'id':'record','sequence':1})]
        for value in bad:
            for method in ('item/completed','turn/completed'):
                fold=self.fold();frame=self.final() if method=='item/completed' else self.event('turn/completed',terminal='completed')
                frame['params']['sourceRange']=value
                self.assertEqual(fold.feed(frame)['method'],'turn/interrupt')

    def test_cutoff_or_truncation_is_sticky_from_updates(self):
        for key in ('cutOff','truncated'):
            fold=self.fold();frame=self.final(**{key:True});frame['method']='item/updated';frame['params']['viewCursor']='v-partial'
            self.assertEqual(fold.feed(frame)['method'],'turn/interrupt')
            fold.feed(self.final());fold.feed(self.event('turn/completed',terminal='completed',viewCursor='v-terminal'))
            self.assertIsNone(fold.result(manifest=self.manifest)['response'])

    def test_account_metadata_projects_no_secrets_or_admission(self):
        value=runner.observe_account({'state':'accountLogin','credentialRequired':True,'label':'fixture@example.invalid','avatarUrl':'https://example.invalid/avatar'})
        self.assertEqual(value['credential_lane'],'accountLogin');self.assertTrue(value['display_identity_present'])
        self.assertNotIn('label',value);self.assertNotIn('avatarUrl',value)
        self.assertFalse(value['account_endpoint_bound']);self.assertFalse(value['allowance_or_cap_qualified']);self.assertFalse(value['live_dispatch_allowed'])
        self.assertEqual([v['method'] for v in runner.metadata_requests()],['account/read','settings/readSchema','settings/read'])

    def test_unknown_account_lane_is_unknown_not_authenticated(self):
        value=runner.observe_account({'state':'future','credentialRequired':False})
        self.assertEqual(value['credential_lane'],'unknown');self.assertFalse(value['account_endpoint_bound'])
        value=runner.observe_account({'state':'loggedOut','credentialRequired':True})
        self.assertEqual(value['credential_lane'],'loggedOut');self.assertFalse(value['live_dispatch_allowed'])

    def test_account_key_material_or_numeric_boolean_is_rejected(self):
        for value in ({'state':'apiKey','credentialRequired':True,'apiKey':'fixture-only'},
                      {'state':'loggedOut','credentialRequired':0}):
            with self.assertRaises(TaskAlongError):runner.observe_account(value)

    def test_exec_projection_uses_supported_control_combination_without_alias_fallback(self):
        argv=runner.exec_argv(executable='/fixed/native',workspace='/fixed/workspace',prompt_file='/fixed/prompt',model_id='muse-wonder-full-1.0')
        for flag in ('--disable-reminders','--disable-web-tools','--no-foreign-personal-context','--disable-shell','--disable-write','--no-parallel-tool-calls'):
            self.assertIn(flag,argv)
        self.assertEqual(argv[argv.index('--preset')+1],'empty');self.assertEqual(argv[argv.index('--max-model-steps')+1],'1')
        self.assertEqual(argv[argv.index('--reasoning-effort')+1],'high')
        self.assertNotIn('--sandbox-network',argv);self.assertNotIn('--approval-judge',argv)
        self.assertNotIn('--trust-workspace',argv);self.assertNotIn('--disable-sandbox',argv)
        with self.assertRaises(TaskAlongError):runner.exec_argv(executable='/fixed/native',workspace='/fixed/workspace',prompt_file='/fixed/prompt',model_id='wonder-full')

    def test_exec_plan_and_cli_are_intent_only_and_do_not_claim_context_isolation(self):
        from taskalong.cli import main
        identity={'path':'/fixed/native','sha256':runner.BINARY_SHA256,'bytes':1,'mode':448}
        stream=io.StringIO()
        with patch.object(runner,'_observe_file',return_value=identity),contextlib.redirect_stdout(stream),patch('taskalong.api.RunService',side_effect=AssertionError('Store opened')):
            code=main(['--json','supervised-muse-exec-plan','--bundle',str(self.bundle),'--executable','/fixed/native','--model-id','muse-wonder-full-1.0','--output',str(self.root/'exec')])
        self.assertEqual(code,0);value=json.loads(stream.getvalue())['data']
        self.assertFalse(value['live_transport_admitted']);self.assertFalse(value['account_context_admitted'])
        self.assertTrue(value['echo_observations']['personal_skill_catalog_not_excluded'])
        self.assertFalse(value['native_internal_http_retry_policy_qualified']);self.assertFalse(value['live_dispatch_allowed'])
        self.assertEqual((self.root/'exec/exec-plan.json').stat().st_mode&0o777,0o400)

    def test_observed_canonical_unknown_effort_catalog_does_not_qualify_alias(self):
        transcript=self.transcript();row=transcript['responses'][2]['result']['models'][0]
        row['modelId']='muse-wonder-full-1.0';row['variants']='unknown'
        with self.assertRaises(TaskAlongError):runner.replay(plan_path=self.prepared['plan_path'],bundle=str(self.bundle),transcript=transcript,output=str(self.root/'canonical'))
        self.assertFalse((self.root/'canonical').exists())

    def test_cli_plan_and_replay_open_no_store_and_do_not_launch(self):
        from taskalong.cli import main
        transcript=self.root/'transcript.json';transcript.write_bytes(canonical_bytes(self.transcript()))
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream),patch('taskalong.api.RunService',side_effect=AssertionError('Store opened')):
            code=main(['--json','supervised-muse-replay','--plan',self.prepared['plan_path'],'--bundle',str(self.bundle),'--transcript',str(transcript),'--output',str(self.root/'cli')])
        self.assertEqual(code,0);self.assertFalse(json.loads(stream.getvalue())['data']['live_dispatch_allowed'])
