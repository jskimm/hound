"""Codex CLI-backed provider using local ChatGPT OAuth credentials."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

from .base_provider import BaseLLMProvider
from .codex_auth import has_codex_oauth

T = TypeVar("T", bound=BaseModel)


class CodexOAuthProvider(BaseLLMProvider):
    """Bridge provider that shells out to `codex exec`."""

    def __init__(
        self,
        config: dict[str, Any],
        model_name: str,
        timeout: int = 120,
        retries: int = 1,
        **kwargs,
    ):
        self.config = config
        self.model_name = model_name
        self.timeout = timeout
        self.retries = retries
        codex_cfg = config.get("codex", {}) if isinstance(config, dict) else {}
        self.command = codex_cfg.get("command", "codex")
        self.exec_model = codex_cfg.get("model") or self._normalize_model_name(model_name)
        self.sandbox_mode = codex_cfg.get("sandbox", "read-only")
        self.cwd = str(Path(codex_cfg.get("working_dir", ".")).expanduser().resolve())
        if not has_codex_oauth(config):
            raise ValueError("Codex OAuth credentials not available")
        self._last_token_usage = None

    def parse(self, *, system: str, user: str, schema: type[T], reasoning_effort: str | None = None) -> T:
        with tempfile.TemporaryDirectory(prefix="hound-codex-") as tmp:
            tmpdir = Path(tmp)
            schema_path = tmpdir / "schema.json"
            output_path = tmpdir / "output.json"
            schema_path.write_text(json.dumps(self._prepare_schema(schema.model_json_schema())))
            self._run(prompt=self._build_prompt(system, user), output_path=output_path, schema_path=schema_path)
            return schema.model_validate_json(output_path.read_text())

    def raw(self, *, system: str, user: str, reasoning_effort: str | None = None) -> str:
        with tempfile.TemporaryDirectory(prefix="hound-codex-") as tmp:
            output_path = Path(tmp) / "output.txt"
            self._run(prompt=self._build_prompt(system, user), output_path=output_path)
            return output_path.read_text().strip()

    @property
    def provider_name(self) -> str:
        return "codex"

    @property
    def supports_thinking(self) -> bool:
        return False

    def get_last_token_usage(self) -> dict[str, int] | None:
        return self._last_token_usage

    def _build_prompt(self, system: str, user: str) -> str:
        return (
            "You are serving as an LLM backend for Hound. "
            "Answer the task directly and do not ask follow-up questions.\n\n"
            f"[SYSTEM]\n{system}\n\n[USER]\n{user}\n"
        )

    def _normalize_model_name(self, model_name: str) -> str:
        # Codex OAuth via ChatGPT does not accept all API model aliases.
        # Default to a broadly supported Codex/ChatGPT model unless explicitly overridden.
        normalized = (model_name or "").strip().lower()
        if normalized in {"gpt-5", "gpt-5-codex"}:
            return normalized
        return "gpt-5"

    def _prepare_schema(self, schema: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(schema, dict):
            return schema
        prepared: dict[str, Any] = {}
        for key, value in schema.items():
            if isinstance(value, dict):
                prepared[key] = self._prepare_schema(value)
            elif isinstance(value, list):
                prepared[key] = [
                    self._prepare_schema(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                prepared[key] = value
        if prepared.get("type") == "object":
            prepared["additionalProperties"] = False
            properties = prepared.get("properties")
            if isinstance(properties, dict):
                prepared["properties"] = {
                    name: self._prepare_schema(prop) if isinstance(prop, dict) else prop
                    for name, prop in properties.items()
                }
                prepared["required"] = list(prepared["properties"].keys())
        return prepared

    def _run(self, *, prompt: str, output_path: Path, schema_path: Path | None = None) -> None:
        cmd = [
            self.command,
            "exec",
            "--skip-git-repo-check",
            "--sandbox",
            self.sandbox_mode,
            "--model",
            self.exec_model,
        ]
        if schema_path:
            cmd.extend(["--output-schema", str(schema_path)])
        cmd.extend(["--output-last-message", str(output_path), prompt])

        last_err = None
        for _ in range(max(self.retries, 1)):
            try:
                subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    cwd=self.cwd,
                )
                return
            except subprocess.CalledProcessError as exc:
                last_err = exc
            except Exception as exc:  # pragma: no cover
                last_err = exc
        detail = ""
        if isinstance(last_err, subprocess.CalledProcessError):
            stderr = (last_err.stderr or "").strip()
            if stderr:
                detail = f" stderr={stderr[-1000:]}"
        raise RuntimeError(f"Codex OAuth bridge failed: {last_err}.{detail}")
