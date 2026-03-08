import json

from analysis.test_proof_agent import TestProofAgent, TestProofAgentRole


class _MockProofPlanner:
    def parse(self, system: str, user: str, schema):
        return schema(
            harness_type="foundry",
            loop_id=2,
            summary="Focus on init-gated write paths.",
            covered_invariants=[],
            violation_models=[
                {
                    "model_id": "vm_001",
                    "title": "Init gate bypass",
                    "invariant_ids": ["inv_002"],
                    "targets": ["contract_VulnCounter"],
                    "reasoning": "Public write path contradicts init assumption.",
                    "source_signals": [{"kind": "contradiction", "detail": "write path before initialize"}],
                }
            ],
            proof_cases=[
                {
                    "case_id": "case_001",
                    "invariant_id": "inv_002",
                    "contract_name": "VulnCounter",
                    "function_name": "setNumber",
                    "function_signature": "setNumber(uint256)",
                    "args_expr": ", uint256(1)",
                    "value_expr": None,
                    "expected_outcome": "revert_before_initialize",
                    "renderer_hint": "revert_before_initialize",
                    "reasoning": "Write path should fail before initialize.",
                    "source_signals": [{"kind": "contradiction", "detail": "write path before initialize"}],
                }
            ],
        )


def test_test_proof_agent_returns_structured_plan():
    cfg = {
        "models": {
            "test_proof": {
                "provider": "mock",
                "model": "mock",
                "mock_instance": _MockProofPlanner(),
            }
        }
    }
    agent = TestProofAgent(cfg)

    plan = agent.plan_for_project(
        project_dir="/tmp/project",
        harness="foundry",
        invariants=[{"invariant_id": "inv_002", "statement": "State-changing operations must be gated until initialization is complete."}],
        graph_summary="System graph summary",
    )

    assert plan["harness_type"] == "foundry"
    assert plan["proof_cases"][0]["function_name"] == "setNumber"
    assert plan["violation_models"][0]["title"] == "Init gate bypass"


def test_test_proof_role_writes_plan_and_foundry_tests(tmp_path):
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
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "project.json").write_text(json.dumps({"source_path": str(source_dir)}), encoding="utf-8")
    session_dir = tmp_path / "session"
    session_dir.mkdir()

    cfg = {
        "models": {
            "test_proof": {
                "provider": "mock",
                "model": "mock",
                "mock_instance": _MockProofPlanner(),
            }
        }
    }
    role = TestProofAgentRole(cfg)
    invariants = [
        {
            "invariant_id": "inv_002",
            "statement": "State-changing operations must be gated until initialization is complete.",
            "forbidden_effect": "state write succeeds before initialization",
            "contrast_checks": ["Can any write path bypass initialization guards?"],
        }
    ]

    result = role.run(
        invariants=invariants,
        session_dir=session_dir,
        project_dir=project_dir,
        loaded_data={"system_graph": {"data": {"nodes": []}}},
        allow_test_writes=True,
        loop_id=2,
        session_id="sess_001",
    )

    plan = json.loads(result["test_proof_plan"].read_text(encoding="utf-8"))
    skeleton = (source_dir / "test" / "security" / "HoundInvariantSkeleton.t.sol").read_text(encoding="utf-8")
    feedback = json.loads(result["proof_feedback"].read_text(encoding="utf-8"))
    memory = json.loads(result["adaptive_memory"].read_text(encoding="utf-8"))

    assert plan["summary"] == "Focus on init-gated write paths."
    assert plan["loop_id"] == 2
    assert 'abi.encodeWithSignature("setNumber(uint256)", uint256(1))' in skeleton
    assert feedback["harness_type"] == "foundry"
    assert memory["promoted_rules"][0]["session_id"] == "sess_001"
