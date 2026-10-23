"""Real local Git branch creation plus the fake gh subprocess boundary."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid

from taskalong.errors import TaskAlongError
from taskalong.integrations.github import GitHubPublisher, build_publish_intent
from taskalong.validation import digest, seal


class PublicationFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.remote = self.root / "remote.git"
        self.git("init", "-q", "-b", "main", str(self.repo), cwd=self.root)
        self.git("init", "-q", "--bare", str(self.remote), cwd=self.root)
        self.git("config", "user.name", "Synthetic operator")
        self.git("config", "user.email", "synthetic@example.invalid")
        (self.repo / "answer.py").write_text("answer = 1\n")
        self.git("add", "answer.py")
        self.git("commit", "-q", "-m", "base")
        self.base = self.git("rev-parse", "HEAD").strip()
        (self.repo / "answer.py").write_text("answer = 2\n")
        self.git("add", "answer.py")
        self.git("commit", "-q", "-m", "candidate")
        self.head = self.git("rev-parse", "HEAD").strip()
        self.tree = self.git("rev-parse", "HEAD^{tree}").strip()
        self.state_path = self.root / "gh-state.json"
        self.write_state({"repository_full_name":"fixture/repository", "repository_id":4242,
                          "base_commit":self.base, "git_remote":str(self.remote), "prs":[]})
        fixture = Path(__file__).parent / "fixtures" / "fake_gh.py"
        self.gh = self.root / "fake-gh"
        self.gh.write_text(f"#!{sys.executable}\nimport os,runpy\nos.environ['TASKALONG_FAKE_GH_STATE']={str(self.state_path)!r}\nrunpy.run_path({str(fixture)!r},run_name='__main__')\n")
        self.gh.chmod(0o700)
        self.publisher = GitHubPublisher(self.gh, git_remote=self.remote, qualification="synthetic")
        self.run = {"run_id":str(uuid.uuid4()), "state":"accepted", "qualification":"synthetic",
                    "candidate":{"commit":self.head,"tree":self.tree,"base_commit":self.base,"diff_sha256":"1"*64}}
        self.spec = {"digest":"2"*64,"review":{"required":True},"repository":{"base_commit":self.base},"publication":{"host":"github.com","repository_id":4242,
                     "repository_full_name":"fixture/repository","base_branch":"main","title":"Synthetic bounded change",
                     "body_template_digest":hashlib.sha256(b"TaskAlong independently accepted this bounded candidate.").hexdigest()}}
        self.acceptance = seal("acceptance", {"acceptance_id":str(uuid.uuid4()),"run_id":self.run["run_id"],"spec_digest":self.spec["digest"],"candidate":self.run["candidate"],"policy_digest":digest(self.spec["review"]),"evidence_ids":[],"evidence_set_digest":digest([]),"verifier":{"identity":"synthetic-core","version":"0.1.0a1"},"decision":"accepted","reasons":[],"at":"2026-10-22T00:00:00Z","qualification":"synthetic"})
        self.run["acceptance_id"] = self.acceptance["acceptance_id"]
        self.intent = build_publish_intent(self.run,self.spec,self.acceptance)
        self.effects = {}
        self.events = []

    def git(self, *args, cwd=None):
        result = subprocess.run([shutil.which("git"), *args], cwd=cwd or self.repo,
                                capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr)
        return result.stdout

    def read_state(self):
        return json.loads(self.state_path.read_text())

    def write_state(self, state):
        self.state_path.write_text(json.dumps(state))

    def record(self, kind, phase, data):
        self.effects.setdefault(kind, {}).update(data)
        self.effects[kind]["phase"] = phase
        self.events.append((kind, phase))

    def publish(self, **kwargs):
        return self.publisher.publish(self.intent, workspace=self.repo, effects=self.effects,
                                      record=self.record, **kwargs)


class PublicationTests(PublicationFixture):
    def test_create_read_back_and_idempotent_reconciliation(self):
        first = self.publish()
        second = self.publish()
        self.assertEqual(first, second)
        self.assertEqual(first["kind"], "fixture")
        self.assertEqual(self.read_state()["create_calls"], 1)
        self.assertEqual(self.git("--git-dir",str(self.remote),"rev-parse",f"refs/heads/{self.intent['branch']}",cwd=self.root).strip(),self.head)
        self.assertEqual(self.git("rev-parse","HEAD").strip(), self.head)

    def test_stale_acceptance_for_another_exact_candidate_blocks(self):
        self.run["candidate"] = dict(self.run["candidate"], commit=self.base)
        with self.assertRaises(TaskAlongError) as exc:
            build_publish_intent(self.run,self.spec,self.acceptance)
        self.assertEqual(exc.exception.code,"acceptance_stale")

    def test_changed_payload_without_fresh_intent_blocks_before_effect(self):
        self.intent["body"] += "\nchanged"
        with self.assertRaises(TaskAlongError) as exc:
            self.publish()
        self.assertEqual(exc.exception.code,"publication_intent_changed")
        self.assertEqual(self.events,[])
        self.assertEqual(self.read_state().get("create_calls",0),0)

    def test_foreign_remote_branch_is_never_replaced(self):
        self.git("--git-dir",str(self.remote),"fetch",str(self.repo),f"{self.base}:refs/heads/{self.intent['branch']}",cwd=self.root)
        with self.assertRaises(TaskAlongError) as exc:
            self.publish()
        self.assertEqual(exc.exception.code,"publication_branch_conflict")
        self.assertEqual(self.git("--git-dir",str(self.remote),"rev-parse",f"refs/heads/{self.intent['branch']}",cwd=self.root).strip(),self.base)

    def test_target_privacy_id_permission_and_base_block(self):
        for key,value in (("private",False),("repository_id",999),("push",False),("base_commit","4"*40)):
            state=self.read_state(); original=copy.deepcopy(state);state[key]=value;self.write_state(state)
            with self.subTest(key=key),self.assertRaises(TaskAlongError):
                self.publish()
            self.write_state(original)
        self.assertEqual(self.events,[])

    def test_closed_nondraft_mismatched_existing_prs_block(self):
        self.publish()
        original=self.read_state()
        for key,value in (("state","closed"),("draft",False),("title","Another intent"),("body","foreign marker")):
            state=copy.deepcopy(original);state["prs"][0][key]=value;self.write_state(state)
            with self.subTest(key=key),self.assertRaises(TaskAlongError) as exc:
                self.publish()
            self.assertEqual(exc.exception.code,"publication_pr_conflict")
            self.assertEqual(self.read_state()["create_calls"],1)

    def test_synthetic_transport_rejected_by_production_configuration(self):
        with self.assertRaises(TaskAlongError) as exc:
            GitHubPublisher(self.gh,git_remote=self.remote,qualification="production")
        self.assertEqual(exc.exception.code,"fixture_in_production")


if __name__ == "__main__":
    unittest.main()
