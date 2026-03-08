"""Helpers for discovering Codex OAuth credentials."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CodexAuthState:
    """Resolved Codex auth state."""

    path: Path
    auth_mode: str | None
    has_access_token: bool
    has_refresh_token: bool
    has_openai_api_key: bool

    @property
    def available(self) -> bool:
        return bool(self.auth_mode in {"chatgpt", "oauth"} and self.has_access_token)


def resolve_codex_auth_file(config: dict[str, Any] | None = None) -> Path:
    """Resolve the Codex auth.json path."""
    codex_cfg = config.get("codex", {}) if isinstance(config, dict) else {}
    configured = os.environ.get("CODEX_AUTH_FILE") or codex_cfg.get("auth_file")
    if configured:
        return Path(configured).expanduser()
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        return Path(codex_home).expanduser() / "auth.json"
    return Path.home() / ".codex" / "auth.json"


def get_codex_auth_state(auth_file: str | Path | None = None) -> CodexAuthState:
    """Read Codex auth state from disk."""
    path = Path(auth_file).expanduser() if auth_file else resolve_codex_auth_file()
    if not path.exists():
        return CodexAuthState(
            path=path,
            auth_mode=None,
            has_access_token=False,
            has_refresh_token=False,
            has_openai_api_key=False,
        )

    try:
        payload = json.loads(path.read_text())
    except Exception:
        payload = {}
    tokens = payload.get("tokens") or {}
    return CodexAuthState(
        path=path,
        auth_mode=payload.get("auth_mode"),
        has_access_token=bool(tokens.get("access_token")),
        has_refresh_token=bool(tokens.get("refresh_token")),
        has_openai_api_key=bool(payload.get("OPENAI_API_KEY")),
    )


def has_codex_oauth(config: dict[str, Any] | None = None) -> bool:
    """Return True when Codex ChatGPT OAuth tokens are available."""
    return get_codex_auth_state(resolve_codex_auth_file(config)).available
