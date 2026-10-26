"""Offline Muse argument contract; no vendor executable or inference is run."""
import unittest

from taskalong.errors import TaskAlongError


class MuseProjectionTests(unittest.TestCase):
    def test_plain_capture_projection_omits_json_without_changing_other_arguments(self):
        from taskalong.executors.muse_protocol import project_exec_argv, project_plain_exec_argv
        options = dict(executable="/opt/vendor/muse", build="1.4.10-R6427.1",
                       workspace="/generated/workspace", prompt_file="/private/control/task.json",
                       model="observed-model", permission_profile="observed-profile", max_model_steps=1)
        plain = project_plain_exec_argv(**options)
        self.assertNotIn("--json", plain)
        self.assertEqual(plain[:2] + ("--json",) + plain[2:], project_exec_argv(**options))

    def test_explicit_headless_arguments_keep_protective_flags_and_prompt_file(self):
        from taskalong.executors.muse_protocol import project_exec_argv

        actual = project_exec_argv(
            executable="/opt/vendor/muse", build="1.4.10-R6427.1",
            workspace="/generated/workspace", prompt_file="/private/control/task.json",
            model="observed-model", permission_profile="observed-profile", max_model_steps=2)
        self.assertEqual(actual, (
            "/opt/vendor/muse", "exec", "--json", "--provider", "meta",
            "--workspace", "/generated/workspace", "--prompt-file", "/private/control/task.json",
            "--model", "observed-model", "--permission-profile", "observed-profile",
            "--max-model-steps", "2", "--approval-mode", "untrusted",
            "--sandbox-network", "proxy-only", "--disable-request-user-input"))
        self.assertIsInstance(actual, tuple)

    def test_unobserved_build_unbounded_steps_and_option_like_values_refuse_before_dispatch(self):
        from taskalong.executors.muse_protocol import project_exec_argv

        inputs = dict(executable="/opt/vendor/muse", build="1.4.10-R6427.1",
                      workspace="/generated/workspace", prompt_file="/private/control/task.json",
                      model="observed-model", permission_profile="observed-profile", max_model_steps=2)
        for field, values in {
            "build": ["1.4.10", "1.4.11-R1", None],
            "max_model_steps": [0, -1, True, 1.5, "2", 9, None],
            "executable": ["muse", "/", "/a/../muse", "/a/./muse", "/a//muse", "/a\x00b"],
            "workspace": [".", "/", "/a/../workspace", "/a\x00b", None],
            "prompt_file": ["task.json", "/", "/a/../task.json", "/a\x00b", None],
            "model": ["", "--yolo", "x\x00y", "x\ny", "x" * 257, None],
            "permission_profile": ["", "--disable-sandbox", "x\ny", None],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(TaskAlongError) as failure:
                        project_exec_argv(**(inputs | {field: value}))
                    self.assertEqual(failure.exception.effect_outcome, "not_sent")

    def test_paths_are_literal_arguments_not_shell_commands(self):
        from taskalong.executors.muse_protocol import project_exec_argv

        workspace = "/generated/a workspace;$(untrusted)"
        prompt = "/private/control/quote' and space.json"
        argv = project_exec_argv(executable="/opt/vendor/muse", build="1.4.10-R6427.1",
                                 workspace=workspace, prompt_file=prompt, model="observed-model",
                                 permission_profile="observed-profile", max_model_steps=1)
        self.assertEqual(argv[argv.index("--workspace") + 1], workspace)
        self.assertEqual(argv[argv.index("--prompt-file") + 1], prompt)


if __name__ == "__main__":
    unittest.main()
