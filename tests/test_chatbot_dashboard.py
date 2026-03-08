import json

from chatbot.run import create_app


def _write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_dashboard_includes_orchestrator_and_agents(tmp_path):
    project_dir = tmp_path / "demo_project"
    _write_json(
        project_dir / "sessions" / "sess_001" / "session.json",
        {
            "session_id": "sess_001",
            "status": "active",
            "planning_history": [],
            "investigations": [],
            "coverage": {},
            "token_usage": {"total_usage": {"total_tokens": 10, "call_count": 1}},
        },
    )
    _write_json(
        project_dir / "sessions" / "sess_001" / "orchestrator.json",
        {
            "session_id": "sess_001",
            "status": "active",
            "current_loop": 3,
            "current_phase": "Coverage",
            "enabled_roles": ["scout", "threat_modeler"],
            "agents": {
                "scout": {
                    "agent_role": "scout",
                    "agent_id": "agent_1",
                    "status": "running",
                    "current_goal": "Review Vault",
                }
            },
            "artifacts": {},
        },
    )
    _write_json(
        project_dir / "sessions" / "sess_001" / "proof_feedback.json",
        {
            "summary": {
                "failed": 2,
                "passed": 1,
            }
        },
    )
    _write_json(
        project_dir / "adaptive_memory.json",
        {
            "promoted_rules": [{"candidate_id": "cand_1"}],
            "deprioritized_patterns": [{"candidate_id": "cand_2"}],
            "execution_blockers": [{"candidate_id": "cand_3"}],
        },
    )

    app = create_app()
    client = app.test_client()
    response = client.get(f"/api/dashboard?project={project_dir}")

    assert response.status_code == 200
    data = response.get_json()
    assert data["orchestrator"]["current_loop"] == 3
    assert data["orchestrator"]["current_phase"] == "Coverage"
    assert data["orchestrator"]["phase"] == "Coverage"
    assert data["orchestrator"]["adaptive"]["promoted_rule_count"] == 1
    assert data["orchestrator"]["adaptive"]["deprioritized_pattern_count"] == 1
    assert data["orchestrator"]["adaptive"]["execution_blocker_count"] == 1
    assert data["orchestrator"]["adaptive"]["proof_feedback"]["failed"] == 2
    assert data["agents"][0]["agent_role"] == "scout"


def test_list_hypotheses_exposes_provenance_fields(tmp_path):
    project_dir = tmp_path / "demo_project"
    _write_json(project_dir / "sessions" / "sess_001" / "session.json", {"session_id": "sess_001"})
    _write_json(
        project_dir / "hypotheses.json",
        {
            "hypotheses": {
                "hyp_1": {
                    "id": "hyp_1",
                    "title": "Unsafe init",
                    "vulnerability_type": "initialization",
                    "description": "Writes before initialization",
                    "confidence": 0.9,
                    "status": "proposed",
                    "created_by": "agent_1",
                    "session_id": "sess_001",
                    "node_refs": [],
                }
            }
        },
    )

    app = create_app()
    client = app.test_client()
    response = client.post("/api/tool/list_hypotheses", json={"project_id": str(project_dir), "limit": 10})

    assert response.status_code == 200
    data = response.get_json()
    assert data["hypotheses"][0]["agent_id"] == "agent_1"
    assert data["hypotheses"][0]["created_by"] == "agent_1"
    assert data["hypotheses"][0]["session_id"] == "sess_001"
