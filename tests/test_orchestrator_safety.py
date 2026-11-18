import unittest
from unittest.mock import patch

import orchestrator


class OrchestratorSafetyTests(unittest.TestCase):
    def test_credential_values_are_redacted_from_usage_text(self):
        result = orchestrator.format_creds_for_prompt(
            {"SESSION_TOKEN": "secret-value-123"},
            "program.env",
            "Use SESSION_TOKEN=secret-value-123 in the test client.",
        )
        self.assertIn("[REDACTED]", result)
        self.assertNotIn("secret-value-123", result)

    def test_prompt_content_is_not_logged_and_missing_cli_returns_failure(self):
        output = []
        with patch.object(orchestrator, "read_agent_context", return_value="agent rules"), \
             patch.object(orchestrator, "_run_streaming", side_effect=FileNotFoundError("claude")):
            result = orchestrator.run_agent(
                "recon", "do not print this private target token", out_fn=output.append,
            )
        self.assertFalse(result)
        joined = "\n".join(output)
        self.assertNotIn("private target token", joined)
        self.assertIn("Prompt preparado", joined)

    def test_parallel_agents_reject_duplicate_names_and_accept_empty_batch(self):
        self.assertEqual(orchestrator.run_parallel_agents([]), {})
        with self.assertRaises(ValueError):
            orchestrator.run_parallel_agents([("recon", "one"), ("recon", "two")])
        too_many = [(f"agent-{index}", "prompt") for index in range(orchestrator.MAX_PARALLEL_AGENTS + 1)]
        with self.assertRaises(ValueError):
            orchestrator.run_parallel_agents(too_many)

    def test_claude_legacy_command_keeps_permission_prompts_enabled(self):
        with patch.object(orchestrator, "read_agent_context", return_value="agent rules"), \
             patch.object(orchestrator, "_run_streaming", return_value=True) as runner:
            self.assertTrue(orchestrator.run_agent("recon", "bounded task", out_fn=lambda *_args, **_kwargs: None))
        command = runner.call_args.args[1]
        self.assertNotIn("--dangerously-skip-permissions", command)
        self.assertNotIn("--allowedTools", command)

    def test_codex_legacy_command_requires_on_request_approval(self):
        with patch.object(orchestrator, "read_agent_context", return_value="agent rules"), \
             patch.object(orchestrator, "_run_plain_command", return_value=True) as runner:
            self.assertTrue(orchestrator.run_agent("recon", "bounded task", provider="codex", out_fn=lambda *_args, **_kwargs: None))
        command = runner.call_args.args[1]
        self.assertIn("on-request", command)
        self.assertNotIn("never", command)

    def test_opencode_legacy_command_does_not_auto_approve_tools(self):
        with patch.object(orchestrator, "read_agent_context", return_value="agent rules"), \
             patch.object(orchestrator, "_run_plain_command", return_value=True) as runner:
            self.assertTrue(orchestrator.run_agent("recon", "bounded task", provider="opencode", out_fn=lambda *_args, **_kwargs: None))
        command = runner.call_args.args[1]
        self.assertNotIn("--auto", command)


if __name__ == "__main__":
    unittest.main()
