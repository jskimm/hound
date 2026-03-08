import json
from pathlib import Path

from commands.project import ProjectManager


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_list_projects_counts_canonical_sessions(monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", lambda: home)

    manager = ProjectManager()
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    manager.create_project("demo", str(source_dir))

    project_dir = manager.get_project_path("demo")
    assert project_dir is not None
    _write_json(project_dir / "sessions" / "sess_001" / "session.json", {"session_id": "sess_001"})

    projects = manager.list_projects()

    assert len(projects) == 1
    assert projects[0]["sessions"] == 1
