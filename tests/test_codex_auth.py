"""Tests for Codex OAuth auth discovery helpers."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from llm.codex_auth import get_codex_auth_state, has_codex_oauth


class TestCodexAuth(unittest.TestCase):
    def test_detects_chatgpt_oauth_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = Path(tmp) / "auth.json"
            auth_path.write_text(json.dumps({
                "auth_mode": "chatgpt",
                "tokens": {
                    "access_token": "access",
                    "refresh_token": "refresh",
                },
            }))

            state = get_codex_auth_state(auth_path)
            self.assertTrue(state.available)
            self.assertEqual(state.auth_mode, "chatgpt")
            self.assertFalse(state.has_openai_api_key)
            self.assertTrue(has_codex_oauth({"codex": {"auth_file": str(auth_path)}}))

    def test_missing_access_token_disables_oauth(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = Path(tmp) / "auth.json"
            auth_path.write_text(json.dumps({
                "auth_mode": "chatgpt",
                "tokens": {
                    "refresh_token": "refresh",
                },
            }))

            state = get_codex_auth_state(auth_path)
            self.assertFalse(state.available)
            self.assertFalse(has_codex_oauth({"codex": {"auth_file": str(auth_path)}}))

    def test_env_overrides_default_auth_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = Path(tmp) / "auth.json"
            auth_path.write_text(json.dumps({
                "auth_mode": "chatgpt",
                "tokens": {"access_token": "access"},
            }))

            with patch.dict(os.environ, {"CODEX_AUTH_FILE": str(auth_path)}, clear=False):
                state = get_codex_auth_state()
                self.assertTrue(state.available)
                self.assertEqual(state.path, auth_path)
