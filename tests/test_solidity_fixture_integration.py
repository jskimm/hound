import json
import subprocess
from pathlib import Path

import pytest

from analysis.audit_orchestrator import ThreatModelerRole, detect_repo_harness
from analysis.test_proof_agent import TestProofAgentRole


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "solidity" / "vuln_counter_foundry"


@pytest.mark.integration
def test_foundry_fixture_compiles():
    result = subprocess.run(
        ["forge", "build"],
        cwd=str(FIXTURE_DIR),
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout


@pytest.mark.integration
def test_threat_modeler_writes_artifacts_for_solidity_fixture(tmp_path):
    assert detect_repo_harness(FIXTURE_DIR) == "foundry"

    loaded = {
        "system_graph": {
            "data": {
                "nodes": [
                    {
                        "id": "contract_VulnCounter",
                        "label": "VulnCounter",
                        "type": "contract",
                        "observations": [
                            "initialize() is publicly callable",
                            "state writes happen without initialization gating",
                        ],
                        "assumptions": [
                            "privileged actions should remain owner-gated",
                        ],
                    }
                ]
            }
        }
    }

    result = ThreatModelerRole().run(
        loaded_data=loaded,
        session_dir=tmp_path / "session",
        project_dir=FIXTURE_DIR,
    )

    threat_model = json.loads(result["threat_model"].read_text(encoding="utf-8"))
    invariants = json.loads(result["invariants"].read_text(encoding="utf-8"))

    assert threat_model["lanes"][0]["asset"] == "VulnCounter"
    assert invariants["invariants"][0]["harness_type"] == "foundry"


@pytest.mark.integration
def test_threat_modeler_can_generate_foundry_test_skeletons(tmp_path):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    src_dir = source_dir / "src"
    src_dir.mkdir()
    (src_dir / "VulnCounter.sol").write_text(
        """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VulnCounter {
    bool public initialized;
    uint256 public number;

    function initialize() external {
        initialized = true;
    }

    function setNumber(uint256 newNumber) external {
        number = newNumber;
    }
}
""",
        encoding="utf-8",
    )
    (project_dir / "project.json").write_text(json.dumps({"source_path": str(source_dir)}), encoding="utf-8")

    loaded = {
        "system_graph": {
            "data": {
                "nodes": [
                    {
                        "id": "contract_VulnCounter",
                        "label": "VulnCounter",
                        "type": "contract",
                        "observations": ["initialize() is publicly callable"],
                        "assumptions": ["privileged actions should remain owner-gated"],
                    }
                ]
            }
        }
    }

    result = ThreatModelerRole().run(
        loaded_data=loaded,
        session_dir=tmp_path / "session",
        project_dir=project_dir,
        allow_test_writes=True,
    )

    manifest = json.loads(result["test_skeletons"].read_text(encoding="utf-8"))
    skeleton = (source_dir / "test" / "security" / "HoundInvariantSkeleton.t.sol").read_text(encoding="utf-8")

    assert manifest["harness_type"] == "foundry"
    assert manifest["concrete_tests_generated"] >= 1
    assert "test/security/HoundInvariantSkeleton.t.sol" in manifest["generated_files"][0]
    assert 'require(!ok, "Expected init gate to block VulnCounter.setNumber before initialize");' in skeleton


@pytest.mark.integration
def test_test_proof_role_generates_feedback_and_adaptive_memory_for_fixture(tmp_path):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "project.json").write_text(json.dumps({"source_path": str(FIXTURE_DIR)}), encoding="utf-8")
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    cfg = {
        "models": {
            "test_proof": {
                "provider": "mock",
                "model": "mock",
                "mock_instance": type(
                    "FixturePlanner",
                    (),
                    {
                        "parse": lambda self, system, user, schema: schema(
                            harness_type="foundry",
                            loop_id=1,
                            summary="Probe init-gated write paths first.",
                            proof_cases=[
                                {
                                    "case_id": "case_001",
                                    "invariant_id": "inv_001",
                                    "contract_name": "VulnCounter",
                                    "function_name": "setNumber",
                                    "function_signature": "setNumber(uint256)",
                                    "args_expr": ", uint256(1)",
                                    "renderer_hint": "revert_before_initialize",
                                    "reasoning": "Contradiction: setNumber should not work before initialize.",
                                    "source_signals": [{"kind": "contradiction", "detail": "write path before initialize"}],
                                }
                            ],
                        )
                    },
                )(),
            }
        }
    }
    role = TestProofAgentRole(cfg)
    result = role.run(
        invariants=[
            {
                "invariant_id": "inv_001",
                "statement": "State-changing operations must be gated until initialization is complete.",
                "related_targets": ["contract_VulnCounter"],
            }
        ],
        session_dir=session_dir,
        project_dir=project_dir,
        loaded_data={"system_graph": {"data": {"nodes": [{"label": "VulnCounter"}]}}},
        allow_test_writes=True,
        loop_id=1,
        session_id="sess_fixture",
    )

    feedback = json.loads(result["proof_feedback"].read_text(encoding="utf-8"))
    adaptive = json.loads(result["adaptive_memory"].read_text(encoding="utf-8"))

    assert feedback["harness_type"] == "foundry"
    assert feedback["summary"]["failed"] >= 1
    assert adaptive["promoted_rules"][0]["session_id"] == "sess_fixture"
