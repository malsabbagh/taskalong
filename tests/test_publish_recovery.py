import copy
from taskalong.errors import TaskAlongError
from test_publish import PublicationFixture


class PublicationRecoveryTests(PublicationFixture):
    def test_lost_create_response_is_reused_without_another_post(self):
        state=self.read_state();state["lose_create_response"]=True;self.write_state(state)
        with self.assertRaises(TaskAlongError) as exc:
            self.publish()
        self.assertEqual(exc.exception.exit_code,5)
        self.assertEqual(self.effects["create_draft_pr"]["phase"],"unknown")
        self.assertEqual(self.read_state()["create_calls"],1)
        receipt=self.publish(reconcile_only=True)
        self.assertEqual(receipt["number"],1)
        self.assertEqual(self.read_state()["create_calls"],1)

    def test_unknown_negative_lookup_never_reissues_create(self):
        self.publish()
        state=self.read_state();state["prs"]=[];self.write_state(state)
        self.effects["create_draft_pr"]["phase"]="unknown"
        for _ in range(2):
            with self.assertRaises(TaskAlongError) as exc:
                self.publish()
            self.assertEqual(exc.exception.exit_code,5)
        self.assertEqual(self.read_state()["create_calls"],1)

    def test_prepared_branch_without_receipt_never_dispatches_again(self):
        self.effects["push_branch"]={"phase":"prepared"}
        with self.assertRaises(TaskAlongError) as exc:
            self.publish()
        self.assertEqual(exc.exception.exit_code,5)
        self.assertEqual(self.events,[])
        self.assertEqual(self.read_state().get("create_calls",0),0)

    def test_multiple_existing_matching_prs_block_without_post(self):
        self.publish()
        state=self.read_state();state["prs"].append(copy.deepcopy(state["prs"][0]));self.write_state(state)
        with self.assertRaises(TaskAlongError) as exc:
            self.publish()
        self.assertEqual(exc.exception.code,"publication_pr_conflict")
        self.assertEqual(self.read_state()["create_calls"],1)

    def test_existing_same_head_on_wrong_base_blocks_without_another_post(self):
        self.publish()
        state=self.read_state();state["prs"][0]["base"]["ref"]="other-base";self.write_state(state)
        with self.assertRaises(TaskAlongError) as exc:
            self.publish()
        self.assertEqual(exc.exception.code,"publication_pr_conflict")
        self.assertEqual(self.read_state()["create_calls"],1)

    def test_existing_run_marker_on_another_head_blocks_without_post(self):
        self.publish()
        state=self.read_state();state["prs"][0]["head"]["ref"]="foreign-head";self.write_state(state)
        with self.assertRaises(TaskAlongError) as exc:
            self.publish()
        self.assertEqual(exc.exception.code,"publication_pr_conflict")
        self.assertEqual(self.read_state()["create_calls"],1)
