"""Prompt-driven test proof planning for project-specific invariants."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .proof_memory import (
    apply_reviewed_candidates,
    build_promotion_candidates,
    derive_threat_deltas,
    load_adaptive_memory,
    load_proof_feedback,
    proof_case_fingerprint,
    proof_planning_config,
    rank_proof_cases,
    save_adaptive_memory,
    save_proof_feedback,
)
from .strategist import Strategist
from llm.unified_client import UnifiedLLMClient

from .audit_orchestrator import detect_repo_harness, resolve_harness_project_dir
from .test_writers import SkeletonWriterRegistry


class SourceSignal(BaseModel):
    kind: str = ""
    detail: str = ""


class ViolationModel(BaseModel):
    model_id: str
    title: str = ""
    invariant_ids: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    reasoning: str = ""
    source_signals: list[SourceSignal] = Field(default_factory=list)


class DeprioritizedCasePattern(BaseModel):
    case_id: str | None = None
    invariant_id: str | None = None
    fingerprint: str | None = None
    deprioritized_reason: str = ""
    selection_reason: str = ""
    priority_score: float = 0.0
    reasoning: str = ""


class ProofCase(BaseModel):
    case_id: str | None = None
    invariant_id: str
    contract_name: str
    function_name: str
    function_signature: str
    args_expr: str = ""
    value_expr: str | None = None
    expected_outcome: str = Field(default="revert_before_initialize")
    renderer_hint: str = Field(default="")
    reasoning: str = ""
    source_signals: list[SourceSignal] = Field(default_factory=list)


class ProofPlan(BaseModel):
    harness_type: str
    loop_id: int = 0
    summary: str = ""
    covered_invariants: list[str] = Field(default_factory=list)
    violation_models: list[ViolationModel] = Field(default_factory=list)
    novel_candidate_cases: list[ProofCase] = Field(default_factory=list)
    deprioritized_case_patterns: list[DeprioritizedCasePattern] = Field(default_factory=list)
    source_signals: list[SourceSignal] = Field(default_factory=list)
    proof_cases: list[ProofCase] = Field(default_factory=list)


def _choose_profile(cfg: dict[str, Any]) -> str:
    models = cfg.get("models", {}) if isinstance(cfg, dict) else {}
    for key in ("test_proof", "strategist", "lightweight"):
        if key in models:
            return key
    return "strategist"


class TestProofAgent:
    """LLM-backed planner that maps invariants to project-specific proof cases."""

    __test__ = False

    def __init__(self, config: dict[str, Any] | None = None, debug_logger=None):
        self.config = config or {}
        self.profile = _choose_profile(self.config)
        self.llm = UnifiedLLMClient(cfg=self.config, profile=self.profile, debug_logger=debug_logger)

    def plan_for_project(
        self,
        *,
        project_dir: str | Path,
        harness: str,
        invariants: list[dict[str, Any]],
        graph_summary: str,
        loop_id: int = 0,
        prior_feedback: dict[str, Any] | None = None,
        adaptive_memory: dict[str, Any] | None = None,
        threat_deltas: list[dict[str, Any]] | None = None,
        hypotheses: list[dict[str, Any]] | None = None,
        recent_investigations: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        system = (
            "You are a security test-proof planner.\n"
            "Turn project-specific invariants into concrete proof cases tailored to the current project and harness.\n"
            "Use the prior loop feedback, uncovered rules, and contradiction signals to evolve the next proof strategy.\n"
            "Prefer project-specific reasoning over generic vulnerability templates.\n"
            "Use outcome labels only as renderer hints, not as the main reasoning frame.\n"
            "For unsupported invariants, omit proof cases instead of guessing.\n"
        )
        user = json.dumps(
            {
                "project_dir": str(project_dir),
                "harness": harness,
                "loop_id": loop_id,
                "graph_summary": graph_summary,
                "invariants": invariants,
                "prior_feedback": prior_feedback or {},
                "adaptive_memory": adaptive_memory or {},
                "threat_deltas": threat_deltas or [],
                "hypotheses": hypotheses or [],
                "recent_investigations": recent_investigations or [],
            },
            indent=2,
        )
        plan = self.llm.parse(system=system, user=user, schema=ProofPlan)
        payload = plan.model_dump()
        payload.setdefault("loop_id", loop_id)
        payload.setdefault("violation_models", [])
        payload.setdefault("covered_invariants", [])
        payload.setdefault("novel_candidate_cases", list(payload.get("proof_cases") or []))
        if "rejected_case_patterns" in payload and "deprioritized_case_patterns" not in payload:
            payload["deprioritized_case_patterns"] = payload.get("rejected_case_patterns") or []
        payload.setdefault("deprioritized_case_patterns", [])
        payload.pop("rejected_case_patterns", None)
        payload.setdefault("source_signals", [])
        return payload


class TestProofAgentRole:
    """Session role that plans proof cases and optionally writes test files."""

    __test__ = False

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    def run(
        self,
        *,
        invariants: list[dict[str, Any]],
        session_dir: Path,
        project_dir: Path,
        loaded_data: dict[str, Any] | None = None,
        allow_test_writes: bool = False,
        loop_id: int = 0,
        session_id: str = "",
    ) -> dict[str, Path]:
        repo_dir = resolve_harness_project_dir(project_dir)
        harness = detect_repo_harness(project_dir)
        summary = self._graph_summary(loaded_data or {})
        planning_cfg = proof_planning_config(self.config)
        adaptive_memory = load_adaptive_memory(project_dir)
        prior_feedback = load_proof_feedback(session_dir)
        threat_deltas = derive_threat_deltas(invariants, adaptive_memory, prior_feedback)
        loaded = loaded_data or {}
        plan = TestProofAgent(self.config).plan_for_project(
            project_dir=repo_dir,
            harness=harness,
            invariants=invariants,
            graph_summary=summary,
            loop_id=loop_id,
            prior_feedback=prior_feedback,
            adaptive_memory=adaptive_memory,
            threat_deltas=threat_deltas,
            hypotheses=list((loaded.get("hypotheses") or [])[:10]),
            recent_investigations=list((loaded.get("recent_investigations") or [])[:10]),
        )
        selected_cases, rejected_cases = rank_proof_cases(
            list(plan.get("proof_cases") or []),
            covered_invariants=plan.get("covered_invariants") or [],
            prior_feedback=prior_feedback,
            adaptive_memory=adaptive_memory,
            weights=planning_cfg["weights"],
            max_cases=planning_cfg["max_concrete_cases_per_loop"],
        )
        plan["proof_cases"] = selected_cases
        plan["novel_candidate_cases"] = selected_cases
        plan["deprioritized_case_patterns"] = rejected_cases
        plan["violation_models"] = self._default_violation_models(plan, invariants)
        for index, case in enumerate(plan.get("proof_cases") or [], start=1):
            case.setdefault("case_id", f"case_{index:03d}")
            case.setdefault("fingerprint", proof_case_fingerprint(case))
        session_dir = Path(session_dir)
        session_dir.mkdir(parents=True, exist_ok=True)
        plan_path = session_dir / "test_proof_plan.json"
        plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
        artifacts = {"test_proof_plan": plan_path}
        if allow_test_writes and harness != "none":
            writer = SkeletonWriterRegistry().get(harness)
            if writer is not None:
                write_result = writer.write(
                    invariants=invariants,
                    project_dir=repo_dir,
                    session_dir=session_dir,
                    proof_plan=plan,
                )
                artifacts.update(write_result)
                if hasattr(writer, "collect_feedback"):
                    feedback = writer.collect_feedback(
                        project_dir=repo_dir,
                        session_dir=session_dir,
                        proof_plan=plan,
                    )
                    feedback_path = save_proof_feedback(session_dir, feedback)
                    artifacts["proof_feedback"] = feedback_path
                    review_path = session_dir / "adaptive_review.json"
                    candidates = build_promotion_candidates(
                        selected_cases=plan.get("proof_cases") or [],
                        invariants=invariants,
                        feedback=feedback,
                    )
                    approvals = self._review_candidates(
                        summary=summary,
                        candidates=candidates,
                        adaptive_memory=adaptive_memory,
                        threshold=planning_cfg["promotion_threshold"],
                        max_review=planning_cfg["max_review_candidates_per_loop"],
                    )
                    review_path.write_text(json.dumps({"decisions": approvals}, indent=2), encoding="utf-8")
                    artifacts["adaptive_review"] = review_path
                    memory = apply_reviewed_candidates(
                        adaptive_memory,
                        candidates=candidates,
                        approvals=approvals,
                        session_id=session_id,
                        loop_id=loop_id,
                    )
                    memory_path = save_adaptive_memory(project_dir, memory)
                    artifacts["adaptive_memory"] = memory_path
        return artifacts

    def _graph_summary(self, loaded_data: dict[str, Any]) -> str:
        system_graph = (loaded_data or {}).get("system_graph") or {}
        data = system_graph.get("data") or {}
        nodes = data.get("nodes") or []
        names = [str(node.get("label") or node.get("id") or "") for node in nodes[:20]]
        return ", ".join(n for n in names if n)

    def _default_violation_models(self, plan: dict[str, Any], invariants: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if plan.get("violation_models"):
            return list(plan.get("violation_models") or [])
        inv_map = {str(item.get("invariant_id") or ""): item for item in invariants or []}
        out: list[dict[str, Any]] = []
        for case in plan.get("proof_cases") or []:
            invariant = inv_map.get(str(case.get("invariant_id") or ""), {})
            out.append(
                {
                    "model_id": f"vm_{case.get('case_id') or case.get('invariant_id')}",
                    "title": invariant.get("statement") or case.get("reasoning") or case.get("function_name") or "Proof case",
                    "invariant_ids": [case.get("invariant_id")],
                    "targets": invariant.get("related_targets") or [case.get("contract_name")],
                    "reasoning": case.get("reasoning") or "",
                    "source_signals": list(case.get("source_signals") or []),
                }
            )
        return out

    def _review_candidates(
        self,
        *,
        summary: str,
        candidates: list[dict[str, Any]],
        adaptive_memory: dict[str, Any],
        threshold: float,
        max_review: int,
    ) -> list[dict[str, Any]]:
        if not candidates:
            return []
        shortlist = sorted(
            candidates,
            key=lambda item: float(item.get("score") or 0.0),
            reverse=True,
        )[:max_review]
        if self._has_strategist_profile():
            try:
                existing = json.dumps(
                    {
                        "promoted_rules": adaptive_memory.get("promoted_rules") or [],
                        "promoted_patterns": adaptive_memory.get("promoted_patterns") or [],
                        "deprioritized_patterns": adaptive_memory.get("deprioritized_patterns") or [],
                        "execution_blockers": adaptive_memory.get("execution_blockers") or [],
                    },
                    indent=2,
                )
                return Strategist(self.config).review_adaptive_candidates(
                    project_summary=summary or "(no graph summary)",
                    candidates=shortlist,
                    existing_memory_summary=existing,
                )
            except Exception:
                pass
        return [
            {
                "candidate_id": candidate.get("candidate_id"),
                "decision": (
                    "invalid_codegen"
                    if str(candidate.get("feedback_status") or "") in {"compile_failed", "unknown", "skipped"}
                    else "approve"
                    if float(candidate.get("score") or 0.0) >= threshold and str(candidate.get("feedback_status") or "") == "failed"
                    else "deprioritize"
                ),
                "rationale": "Fallback deterministic promotion gate",
            }
            for candidate in shortlist
        ]

    def _has_strategist_profile(self) -> bool:
        models = (self.config or {}).get("models", {}) if isinstance(self.config, dict) else {}
        return any(name in models for name in ("strategist", "guidance", "agent"))
