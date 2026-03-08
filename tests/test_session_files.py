import json
from pathlib import Path

from analysis.session_files import (
    canonical_session_file,
    count_sessions,
    iter_session_summary_files,
    load_session_summary,
    resolve_session_summary_file,
    session_dir_from_summary_file,
)


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_iter_session_summary_files_prefers_canonical_over_legacy(tmp_path):
    sessions_dir = tmp_path / "sessions"
    _write_json(sessions_dir / "sess_a" / "session.json", {"session_id": "sess_a", "status": "active"})
    _write_json(sessions_dir / "sess_a.json", {"session_id": "sess_a", "status": "legacy"})
    _write_json(sessions_dir / "sess_b.json", {"session_id": "sess_b", "status": "completed"})

    files = iter_session_summary_files(sessions_dir)

    assert [p.parent.name if p.name == "session.json" else p.stem for p in files] == ["sess_b", "sess_a"] or [
        p.parent.name if p.name == "session.json" else p.stem for p in files
    ] == ["sess_a", "sess_b"]
    assert canonical_session_file(sessions_dir, "sess_a") in files
    assert sessions_dir / "sess_a.json" not in files


def test_count_sessions_deduplicates_legacy_and_canonical(tmp_path):
    sessions_dir = tmp_path / "sessions"
    _write_json(sessions_dir / "sess_a" / "session.json", {"session_id": "sess_a"})
    _write_json(sessions_dir / "sess_a.json", {"session_id": "sess_a"})
    _write_json(sessions_dir / "sess_b.json", {"session_id": "sess_b"})

    assert count_sessions(sessions_dir) == 2


def test_resolve_session_summary_file_supports_prefix_for_canonical(tmp_path):
    sessions_dir = tmp_path / "sessions"
    canonical = sessions_dir / "session_20260308_001" / "session.json"
    _write_json(canonical, {"session_id": "session_20260308_001"})

    resolved = resolve_session_summary_file(sessions_dir, "session_20260308")

    assert resolved == canonical


def test_load_session_summary_returns_empty_dict_for_invalid_json(tmp_path):
    target = tmp_path / "broken.json"
    target.write_text("{not-json", encoding="utf-8")

    assert load_session_summary(target) == {}


def test_session_dir_from_summary_file_supports_legacy_and_canonical(tmp_path):
    canonical = tmp_path / "sessions" / "sess_a" / "session.json"
    legacy = tmp_path / "sessions" / "sess_b.json"

    assert session_dir_from_summary_file(canonical) == canonical.parent
    assert session_dir_from_summary_file(legacy) == legacy.parent / "sess_b"
