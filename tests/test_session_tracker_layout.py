import json

from analysis.session_tracker import SessionTracker


def test_session_tracker_writes_canonical_session_file(tmp_path):
    sessions_dir = tmp_path / "sessions"

    tracker = SessionTracker(sessions_dir, "sess_001")
    tracker.set_status("active")

    session_file = sessions_dir / "sess_001" / "session.json"
    assert session_file.exists()
    data = json.loads(session_file.read_text(encoding="utf-8"))
    assert data["session_id"] == "sess_001"
    assert data["status"] == "active"


def test_session_tracker_reads_legacy_session_file(tmp_path):
    sessions_dir = tmp_path / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    legacy = sessions_dir / "sess_legacy.json"
    legacy.write_text(
        json.dumps(
            {
                "session_id": "sess_legacy",
                "status": "completed",
                "coverage": {
                    "nodes": {"visited": 1, "total": 2, "percent": 50.0},
                    "cards": {"visited": 0, "total": 0, "percent": 0.0},
                    "visited_node_ids": ["node_1"],
                    "visited_card_ids": [],
                    "node_visit_counts": {"node_1": 1},
                },
            }
        ),
        encoding="utf-8",
    )

    tracker = SessionTracker(sessions_dir, "sess_legacy")

    assert tracker.session_data["status"] == "completed"
    assert "node_1" in tracker.coverage.visited_nodes


def test_session_tracker_accepts_canonical_session_dir(tmp_path):
    session_dir = tmp_path / "sessions" / "sess_dir"

    tracker = SessionTracker(session_dir, "sess_dir")
    tracker.set_models("scout/model", "strategist/model")

    session_file = session_dir / "session.json"
    assert session_file.exists()
    data = json.loads(session_file.read_text(encoding="utf-8"))
    assert data["models"]["scout"] == "scout/model"
    assert data["models"]["strategist"] == "strategist/model"


def test_session_tracker_persists_execution_policy(tmp_path):
    session_dir = tmp_path / "sessions" / "sess_policy"

    tracker = SessionTracker(session_dir, "sess_policy")
    tracker.set_execution_policy(allow_test_writes=True)

    session_file = session_dir / "session.json"
    data = json.loads(session_file.read_text(encoding="utf-8"))
    assert data["execution_policy"]["allow_test_writes"] is True
