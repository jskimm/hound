import json

from analysis.audit_orchestrator import (
    AgentProgress,
    AuditOrchestrator,
    ThreatModelerRole,
    build_default_registry,
    derive_invariants,
    derive_threat_lanes,
    detect_repo_harness,
    resolve_harness_project_dir,
)


def test_build_default_registry_contains_builtin_roles():
    registry = build_default_registry()

    assert "threat_modeler" in registry.names()
    assert "invariant_auditor" in registry.names()


def test_audit_orchestrator_persists_loop_and_agent_state(tmp_path):
    orch = AuditOrchestrator(tmp_path / "sess_001", "sess_001", enabled_roles=["scout", "strategist"])
    orch.begin_loop(2, "Coverage")
    orch.update_agent(
        AgentProgress(
            agent_role="scout",
            agent_id="agent_1",
            status="running",
            current_goal="Review Vault",
            loop_id=2,
            iteration=3,
            max_iterations=5,
        )
    )

    saved = json.loads((tmp_path / "sess_001" / "orchestrator.json").read_text(encoding="utf-8"))

    assert saved["current_loop"] == 2
    assert saved["current_phase"] == "Coverage"
    assert saved["agents"]["scout"]["current_goal"] == "Review Vault"
    assert saved["agents"]["scout"]["iteration"] == 3


def test_detect_repo_harness_prefers_foundry(tmp_path):
    (tmp_path / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")

    assert detect_repo_harness(tmp_path) == "foundry"


def test_resolve_harness_project_dir_prefers_project_source_path(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "project.json").write_text(json.dumps({"source_path": str(source_dir)}), encoding="utf-8")

    assert resolve_harness_project_dir(project_dir) == source_dir
    assert detect_repo_harness(project_dir) == "foundry"


def test_derive_threat_lanes_and_invariants_from_system_graph():
    loaded = {
        "system_graph": {
            "data": {
                "nodes": [
                    {
                        "id": "contract_Vault",
                        "label": "Vault",
                        "type": "contract",
                        "observations": ["initialize() sets admin"],
                        "assumptions": ["only owner may sweep funds"],
                    }
                ]
            }
        }
    }

    lanes = derive_threat_lanes(loaded)
    invariants = derive_invariants(lanes, "foundry")

    assert lanes[0]["lane_id"] == "lane_contract_Vault"
    assert "initialization" in lanes[0]["rule"].lower()
    assert invariants[0]["harness_status"] == "available"
    assert invariants[0]["contrast_checks"]


def test_threat_modeler_role_writes_session_artifacts(tmp_path):
    role = ThreatModelerRole()
    loaded = {
        "system_graph": {
            "data": {
                "nodes": [
                    {"id": "contract_Counter", "label": "Counter", "type": "contract", "observations": [], "assumptions": []}
                ]
            }
        }
    }
    (tmp_path / "project" / "foundry.toml").parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "project" / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")

    result = role.run(loaded_data=loaded, session_dir=tmp_path / "session", project_dir=tmp_path / "project")

    threat = json.loads(result["threat_model"].read_text(encoding="utf-8"))
    invariants = json.loads(result["invariants"].read_text(encoding="utf-8"))
    assert threat["lanes"][0]["asset"] == "Counter"
    assert invariants["invariants"][0]["harness_type"] == "foundry"
