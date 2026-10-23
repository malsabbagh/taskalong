"""Independent current evidence, never worker claims or stale receipts."""
import copy
import unittest
import uuid

from taskalong.evidence import acceptance_reasons, canonical_subject
from taskalong.validation import digest


def identity():
    return str(uuid.uuid4())


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.run_id,self.attempt=identity(),identity()
        self.candidate={"commit":"1"*40,"tree":"2"*40,"base_commit":"3"*40,"diff_sha256":"4"*64}
        self.subject=canonical_subject(self.candidate)
        self.check={"id":"unit","argv":["/usr/bin/true"],"cwd":".","timeout_seconds":10,
                    "expected_exit_code":0,"criterion_ids":["behavior"],"required":True}
        self.spec={"revision":1,"digest":"5"*64,"qualification":"synthetic",
                   "repository":{"base_commit":"3"*40},"execution":{"profile_digest":"6"*64},
                   "checks":[self.check],"criteria":[{"id":"behavior","check_ids":["unit"]}],
                   "review":{"required":True,"contract":"0.8.8/v1","config_digest":"7"*64}}
        self.run={"run_id":self.run_id,"spec_digest":"5"*64,"task_revision":1,"qualification":"synthetic",
                  "candidate":self.candidate,"active_attempt_id":None,"attempts":[{"attempt_id":self.attempt}],
                  "pending_effect_ids":[],"state":"verifying","blockers":[]}
        self.packet="8"*64
        self.owned=set()
        self.records=[self.record("scope"), self.record("command"), self.record("review")]
        command=self.records[1]
        command["criterion_ids"]=["behavior"]
        command["inputs"]["check_digest"]=digest(self.check)
        command["command"]={"argv_digest":digest(self.check["argv"]),"cwd_relative":".","exit_code":0,"timed_out":False}
        review=self.records[2]
        review["producer"].update(tool="review-sensei",version="0.8.8")
        review["inputs"]["review_config_digest"]="7"*64
        review["extensions"]["taskalong:review"]={"invocation_id":review["producer"]["invocation_id"],
              "executable_sha256":review["producer"]["executable_sha256"],"version":"0.8.8","provider":"fixture",
              "config_digest":"7"*64,"subject":self.subject,"qualification":"synthetic",
              "assurance":"full-reviewed-diff-v1","producer_role":"verifier","result":"passed"}

    def record(self,kind):
        invocation=identity();self.owned.add(invocation)
        return {"kind":"evidence","schema_version":"1.0","extensions":{},"evidence_id":identity(),
                "run_id":self.run_id,"task_revision":1,"spec_digest":"5"*64,"attempt_id":self.attempt,
                "packet_digest":self.packet,"lease_generation":1,"producer":{"role":"verifier",
                "invocation_id":invocation,"tool":"taskalong","version":"0.1.0a1","executable_sha256":"9"*64},
                "type":kind,"criterion_ids":[],"subject":self.subject,"inputs":{"check_digest":None,
                "review_config_digest":None,"runtime_profile_digest":"6"*64},"result":"passed",
                "started_at":"2026-10-22T00:00:00Z","finished_at":"2026-10-22T00:00:01Z","duration_ms":1000,
                "artifacts":[{"sha256":"a"*64,"bytes":1,"media_type":"application/json","redaction_version":"1"}],
                "command":None,"qualification":"synthetic"}

    def reasons(self, **kwargs):
        defaults={"workspace_quiescent":True,"current_subject":self.candidate,"packet_digest":self.packet,
                  "lease_generation":1,"owned_invocation_ids":self.owned}
        defaults.update(kwargs)
        return acceptance_reasons(self.spec,self.run,self.records,**defaults)

    def codes(self, **kwargs):
        return {r["code"] for r in self.reasons(**kwargs)}

    def test_complete_owned_current_evidence_is_eligible(self):
        self.assertEqual(self.reasons(),[])

    def test_each_stale_binding_blocks(self):
        for field,value in (("packet_digest","b"*64),("lease_generation",2),("spec_digest","c"*64),
                            ("attempt_id",identity()),("task_revision",2),("run_id",identity())):
            old=self.records[1][field];self.records[1][field]=value
            with self.subTest(field=field):
                self.assertIn("evidence_stale",self.codes())
            self.records[1][field]=old
        self.assertIn("evidence_stale",self.codes(lease_generation=2))

    def test_worker_self_acceptance_cannot_become_a_verifier_receipt(self):
        self.records[1]["producer"]["role"]="executor"
        self.assertIn("evidence_producer_unowned",self.codes())
        self.records[1]["producer"]["role"]="verifier"
        self.records[1]["producer"]["invocation_id"]=identity()
        self.assertIn("evidence_producer_unowned",self.codes())

    def test_required_check_nonzero_timeout_config_and_criteria_fail(self):
        for key,value in (("exit_code",1),("timed_out",True),("argv_digest","d"*64),("cwd_relative","other")):
            old=self.records[1]["command"][key];self.records[1]["command"][key]=value
            with self.subTest(key=key):
                self.assertIn("required_check_mismatch",self.codes())
            self.records[1]["command"][key]=old
        self.records[1]["inputs"]["check_digest"]="c"*64
        self.assertIn("required_check_missing",self.codes())

    def test_review_missing_wrong_release_or_forged_receipt_blocks(self):
        review=self.records.pop()
        self.assertIn("required_review_missing",self.codes())
        self.records.append(review)
        review["producer"]["version"]="0.9.0"
        self.assertIn("review_receipt_mismatch",self.codes())
        review["producer"]["version"]="0.8.8"
        review["extensions"]["taskalong:review"]["invocation_id"]=identity()
        self.assertIn("review_receipt_mismatch",self.codes())

    def test_production_rejects_fixture_evidence(self):
        self.run["qualification"]=self.spec["qualification"]="production"
        for record in self.records:
            record["qualification"]="production"
        self.records[2]["extensions"]["taskalong:review"]["qualification"]="production"
        self.assertIn("fixture_in_production",self.codes())

    def test_scope_missing_unquiescent_and_pending_effects_block(self):
        self.assertIn("workspace_not_quiescent",self.codes(workspace_quiescent=False))
        self.records.pop(0)
        self.assertIn("scope_evidence_missing",self.codes())
        self.run["pending_effect_ids"]=[identity()]
        self.assertIn("effect_unreconciled",self.codes())

    def test_producer_and_packet_context_cannot_be_inferred_from_claims(self):
        self.assertIn("producer_provenance_missing",self.codes(owned_invocation_ids=None))
        self.assertIn("evidence_binding_missing",self.codes(packet_digest=None))


if __name__ == "__main__":
    unittest.main()
