"""Helpers for canonical and legacy session file layouts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def canonical_session_dir(sessions_dir: Path, session_id: str) -> Path:
    """Return the canonical directory for a session id."""
    return Path(sessions_dir) / session_id


def canonical_session_file(sessions_dir: Path, session_id: str) -> Path:
    """Return the canonical summary file for a session id."""
    return canonical_session_dir(sessions_dir, session_id) / "session.json"


def legacy_session_file(sessions_dir: Path, session_id: str) -> Path:
    """Return the legacy flat session file path for a session id."""
    return Path(sessions_dir) / f"{session_id}.json"


def iter_session_summary_files(sessions_dir: Path) -> list[Path]:
    """List canonical and legacy session summaries, preferring canonical ones."""
    root = Path(sessions_dir)
    if not root.exists():
        return []

    preferred: dict[str, Path] = {}
    for child in root.iterdir():
        if child.is_dir():
            summary = child / "session.json"
            if summary.exists():
                preferred[child.name] = summary

    for legacy in root.glob("*.json"):
        if legacy.stem not in preferred:
            preferred[legacy.stem] = legacy

    return sorted(preferred.values(), key=lambda p: p.stat().st_mtime, reverse=True)


def count_sessions(sessions_dir: Path) -> int:
    """Count sessions across canonical and legacy layouts without double-counting."""
    return len(iter_session_summary_files(sessions_dir))


def resolve_session_summary_file(sessions_dir: Path, session_id: str) -> Path | None:
    """Resolve a session summary file by exact or prefix session id match."""
    sessions_dir = Path(sessions_dir)

    exact_canonical = canonical_session_file(sessions_dir, session_id)
    if exact_canonical.exists():
        return exact_canonical

    exact_legacy = legacy_session_file(sessions_dir, session_id)
    if exact_legacy.exists():
        return exact_legacy

    candidates: list[Path] = []
    for summary in iter_session_summary_files(sessions_dir):
        sid = summary.parent.name if summary.name == "session.json" else summary.stem
        if sid.startswith(session_id):
            candidates.append(summary)
    if not candidates:
        return None
    return sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True)[0]


def load_session_summary(path: Path) -> dict[str, Any]:
    """Load a session summary JSON file safely."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {}


def session_dir_from_summary_file(path: Path) -> Path:
    """Return the canonical session directory for a summary file path."""
    p = Path(path)
    return p.parent if p.name == "session.json" else p.parent / p.stem
