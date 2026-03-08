"""Tests for the Codex OAuth-backed provider bridge."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pydantic import BaseModel

from llm.codex_provider import CodexOAuthProvider


class EchoSchema(BaseModel):
    answer: str


class TestCodexOAuthProvider(unittest.TestCase):
    def test_raw_uses_codex_exec_and_reads_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = Path(tmp) / "auth.json"
            auth_path.write_text(json.dumps({
                "auth_mode": "chatgpt",
                "tokens": {"access_token": "access"},
            }))

            provider = CodexOAuthProvider(
                config={"codex": {"auth_file": str(auth_path)}},
                model_name="gpt-5",
                timeout=15,
            )

            def fake_run(cmd, check, capture_output, text, timeout, cwd):
                self.assertEqual(cmd[0:2], ["codex", "exec"])
                self.assertIn("--output-last-message", cmd)
                self.assertIn("--skip-git-repo-check", cmd)
                self.assertIn("--sandbox", cmd)
                self.assertIn("read-only", cmd)
                self.assertEqual(cmd[cmd.index("--model") + 1], "gpt-5")
                output_path = Path(cmd[cmd.index("--output-last-message") + 1])
                output_path.write_text("oauth bridge ok")

                class Result:
                    stdout = ""
                    stderr = ""
                    returncode = 0

                return Result()

            with patch("llm.codex_provider.subprocess.run", side_effect=fake_run):
                out = provider.raw(system="sys", user="user")

            self.assertEqual(out, "oauth bridge ok")

    def test_parse_writes_schema_and_validates_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = Path(tmp) / "auth.json"
            auth_path.write_text(json.dumps({
                "auth_mode": "chatgpt",
                "tokens": {"access_token": "access"},
            }))

            provider = CodexOAuthProvider(
                config={"codex": {"auth_file": str(auth_path)}},
                model_name="gpt-5",
                timeout=15,
            )

            def fake_run(cmd, check, capture_output, text, timeout, cwd):
                schema_path = Path(cmd[cmd.index("--output-schema") + 1])
                output_path = Path(cmd[cmd.index("--output-last-message") + 1])
                schema = json.loads(schema_path.read_text())
                self.assertEqual(schema["type"], "object")
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(schema["required"], ["answer"])
                output_path.write_text(json.dumps({"answer": "structured ok"}))

                class Result:
                    stdout = ""
                    stderr = ""
                    returncode = 0

                return Result()

            with patch("llm.codex_provider.subprocess.run", side_effect=fake_run):
                out = provider.parse(system="sys", user="user", schema=EchoSchema)

            self.assertEqual(out.answer, "structured ok")
