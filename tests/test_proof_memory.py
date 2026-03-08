import json

from analysis.proof_memory import (
    apply_reviewed_candidates,
    build_promotion_candidates,
    derive_threat_deltas,
    load_adaptive_memory,
    proof_case_fingerprint,
    proof_planning_config,
    rank_proof_cases,
    save_adaptive_memory,
    save_proof_feedback,
)


def test_rank_proof_cases_skips_already_resolved_fingerprints():
    case_a = {
        "case_id": "case_a",
        "invariant_id": "inv_001",
        "contract_name": "Counter",
        "function_name": "setNumber",
        "function_signature": "setNumber(uint256)",
        "args_expr": ", 1",
        "reasoning": "Contradiction: write bypasses initialization.",
    }
    prior = {
        "results": [
            {
                "case_id": "case_a",
                "fingerprint": proof_case_fingerprint(case_a),
                "status": "failed",
            }
        ]
    }

    selected, rejected = rank_proof_cases(
        [case_a],
        covered_invariants=[],
        prior_feedback=prior,
        adaptive_memory={"deprioritized_patterns": [], "execution_blockers": []},
        weights=proof_planning_config({})["weights"],
        max_cases=4,
    )

    assert selected == []
    assert rejected[0]["rejected_reason"] == "already_resolved"


def test_apply_reviewed_candidates_promotes_only_approved_items(tmp_path):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    memory = load_adaptive_memory(project_dir)
    candidates = [
        {
            "candidate_id": "cand_a",
            "invariant_id": "inv_001",
            "statement": "Writes must stay gated before initialization.",
            "fingerprint": "abc123",
            "score": 0.9,
        },
        {
            "candidate_id": "cand_b",
            "invariant_id": "inv_002",
            "statement": "Unauthorized callers must not sweep funds.",
            "fingerprint": "def456",
            "score": 0.3,
        },
    ]
    reviewed = [
        {"candidate_id": "cand_a", "decision": "approve", "rationale": "Project-specific rule."},
        {"candidate_id": "cand_b", "decision": "deprioritize", "rationale": "Too generic."},
    ]

    updated = apply_reviewed_candidates(
        memory,
        candidates=candidates,
        approvals=reviewed,
        session_id="sess_001",
        loop_id=3,
    )
    path = save_adaptive_memory(project_dir, updated)
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert len(payload["promoted_rules"]) == 1
    assert payload["promoted_rules"][0]["candidate_id"] == "cand_a"
    assert len(payload["deprioritized_patterns"]) == 1
    assert payload["deprioritized_patterns"][0]["candidate_id"] == "cand_b"


def test_load_adaptive_memory_migrates_legacy_rejected_patterns(tmp_path):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "adaptive_memory.json").write_text(
        json.dumps(
            {
                "promoted_rules": [],
                "rejected_patterns": [{"candidate_id": "legacy_1", "fingerprint": "fp_legacy"}],
            }
        ),
        encoding="utf-8",
    )

    memory = load_adaptive_memory(project_dir)

    assert memory["rejected_patterns"] == []
    assert len(memory["deprioritized_patterns"]) == 1
    assert memory["deprioritized_patterns"][0]["decision"] == "deprioritize"
    assert memory["deprioritized_patterns"][0]["decision_reason"] == "legacy_rejected_pattern"


def test_derive_threat_deltas_reports_unpromoted_rules_and_unresolved_feedback(tmp_path):
    feedback_path = save_proof_feedback(
        tmp_path,
        {
            "harness_type": "foundry",
            "results": [
                {
                    "case_id": "case_001",
                    "fingerprint": "fp1",
                    "status": "compile_failed",
                    "reason": "missing import",
                }
            ],
        },
    )
    assert feedback_path.exists()
    adaptive_memory = {
        "promoted_rules": [{"invariant_id": "inv_100"}],
        "promoted_patterns": [],
        "deprioritized_patterns": [],
        "execution_blockers": [],
        "metadata": {},
    }
    deltas = derive_threat_deltas(
        [{"invariant_id": "inv_001", "statement": "Write must remain gated."}],
        adaptive_memory,
        json.loads(feedback_path.read_text(encoding="utf-8")),
    )

    assert any(item["kind"] == "new_or_unpromoted_rule" for item in deltas)
    assert any(item["kind"] == "unresolved_proof_feedback" for item in deltas)


def test_build_promotion_candidates_uses_feedback_status():
    selected = [
        {
            "case_id": "case_001",
            "fingerprint": "fp1",
            "priority_score": 0.82,
            "invariant_id": "inv_001",
            "contract_name": "Counter",
            "function_name": "setNumber",
            "reasoning": "Contradiction between init assumption and write path.",
        }
    ]
    invariants = [{"invariant_id": "inv_001", "statement": "Write must remain gated."}]
    feedback = {"results": [{"case_id": "case_001", "fingerprint": "fp1", "status": "failed"}]}

    candidates = build_promotion_candidates(selected_cases=selected, invariants=invariants, feedback=feedback)

    assert candidates[0]["feedback_status"] == "failed"
    assert candidates[0]["statement"] == "Write must remain gated."


def test_apply_reviewed_candidates_routes_invalid_codegen_to_execution_blockers(tmp_path):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    memory = load_adaptive_memory(project_dir)
    candidates = [
        {
            "candidate_id": "cand_codegen",
            "invariant_id": "inv_001",
            "statement": "Write must remain gated.",
            "fingerprint": "fp_codegen",
            "score": 0.8,
        }
    ]

    updated = apply_reviewed_candidates(
        memory,
        candidates=candidates,
        approvals=[{"candidate_id": "cand_codegen", "decision": "invalid_codegen", "rationale": "Harness emitted invalid args."}],
        session_id="sess_001",
        loop_id=2,
    )

    assert updated["deprioritized_patterns"] == []
    assert len(updated["execution_blockers"]) == 1
    assert updated["execution_blockers"][0]["decision"] == "invalid_codegen"


def test_rank_proof_cases_soft_penalizes_deprioritized_patterns_but_allows_new_evidence():
    case = {
        "case_id": "case_a",
        "invariant_id": "inv_001",
        "contract_name": "Counter",
        "function_name": "setNumber",
        "function_signature": "setNumber(uint256)",
        "args_expr": ", 1",
        "reasoning": "Contradiction: write bypasses initialization.",
        "source_signals": [{"kind": "code_ref", "detail": "Counter.sol:12 no init guard"}],
    }
    fingerprint = proof_case_fingerprint(case)
    adaptive_memory = {
        "promoted_rules": [],
        "promoted_patterns": [],
        "deprioritized_patterns": [
            {
                "candidate_id": "cand_old",
                "fingerprint": fingerprint,
                "contract_name": "Counter",
                "function_name": "setNumber",
                "invariant_id": "inv_001",
                "source_signals": [{"kind": "code_ref", "detail": "Counter.sol:10 generic write path"}],
                "decision": "deprioritize",
            }
        ],
        "execution_blockers": [],
        "metadata": {},
    }

    selected, rejected = rank_proof_cases(
        [case],
        covered_invariants=[],
        prior_feedback={"results": []},
        adaptive_memory=adaptive_memory,
        weights=proof_planning_config({})["weights"],
        max_cases=1,
    )

    assert rejected == []
    assert selected[0]["selected"] is True
    assert selected[0]["priority_score"] > 0.0
    assert selected[0]["score_adjustments"]["deprioritized_penalty"] < 0.2
