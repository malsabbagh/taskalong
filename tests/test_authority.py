"""Authority comes from the trusted OS control plane and exact immutable intent."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
import unittest

from taskalong.errors import TaskAlongError
from taskalong.store import identifier, now
from taskalong.validation import seal
from taskalong.workflow import Workflow
from test_store import StoreFixture


def timestamp(seconds):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat(timespec="seconds").replace("+00:00", "Z")


class AuthorityTests(StoreFixture):
    def authority_document(self, **changes):
        record = {"authority_id": identifier(), "run_id": self.run["run_id"], "source": "local_operator",
                  "principal": str(os.getuid()), "decision": "authorized", "scope": ["execute", "verify", "commit_candidate"],
                  "intent_digest": self.spec["digest"], "issued_at": timestamp(-10), "expires_at": timestamp(600),
                  "human_decision_observed": False, "qualification": "synthetic"}
        record.update(changes)
        return seal("authority", record)

    def test_operator_admission_binds_exact_run_digest_scope_and_os_principal(self):
        record = Workflow(self.store).authorize(self.run["run_id"], decision_digest=self.spec["digest"], scope=["execute", "verify", "commit_candidate"])
        self.assertEqual(record["principal"], str(os.getuid()))
        self.assertEqual(record["source"], "local_operator")
        self.assertFalse(record["human_decision_observed"])
        self.assertEqual(self.store.authority(self.run, {"execute", "verify"}, self.spec["digest"])["authority_id"], record["authority_id"])
        with self.assertRaises(TaskAlongError):
            self.store.authority(self.run, {"create_draft_pr"}, self.spec["digest"])
        with self.assertRaises(TaskAlongError):
            self.store.authority(self.run, {"execute"}, "f" * 64)

    def test_worker_permissions_or_names_never_admit_authority(self):
        with self.assertRaises(TaskAlongError) as failure:
            self.store.authority(self.run, {"execute"}, self.spec["digest"])
        self.assertEqual(failure.exception.code, "authority_missing")
        for change in ({"principal": "approved_by_operator"}, {"source": "trusted_orchestrator"}, {"qualification": "production"}, {"run_id": identifier()}):
            document = self.authority_document(**change)
            self.store.add_authority(self.run["run_id"], document)
            with self.subTest(change=change), self.assertRaises(TaskAlongError):
                self.store.authority(self.run, {"execute"}, self.spec["digest"], document["authority_id"])

    def test_denied_expired_future_and_tampered_records_cannot_authorize(self):
        records = [self.authority_document(decision="denied"),
                   self.authority_document(issued_at=timestamp(-600), expires_at=timestamp(-10)),
                   self.authority_document(issued_at=timestamp(10), expires_at=timestamp(600))]
        tampered = self.authority_document()
        tampered["scope"] = ["execute", "verify", "commit_candidate", "create_draft_pr"]
        records.append(tampered)
        for record in records:
            with self.subTest(identity=record["authority_id"]):
                # A defensive store can reject invalid authority at insertion or
                # admission; neither outcome may grant its effect.
                try:
                    self.store.add_authority(self.run["run_id"], record)
                except TaskAlongError:
                    continue
                with self.assertRaises(TaskAlongError):
                    self.store.authority(self.run, {"execute"}, self.spec["digest"], record["authority_id"])

    def test_authorization_cannot_expand_spec_policy_or_change_qualification(self):
        for scope, qualification, decision in ((["create_draft_pr"], None, self.spec["digest"]),
                                               (["execute"], "production", self.spec["digest"]),
                                               (["execute"], None, "f" * 64)):
            with self.subTest(scope=scope, qualification=qualification), self.assertRaises(TaskAlongError):
                Workflow(self.store).authorize(self.run["run_id"], decision_digest=decision, scope=scope, qualification=qualification)
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM authorities").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
