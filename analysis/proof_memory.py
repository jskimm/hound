"""Adaptive proof-planning memory, scoring, and persistence helpers."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_PROOF_WEIGHTS = {
    "contradiction": 0.35,
    "coverage": 0.20,
    "feedback": 0.25,
    "novelty": 0.20,
}


def proof_planning_config(cfg: dict[str, Any] | None) -> dict[str, Any]:
    raw = ((cfg or {}).get("proof_planning") or {}) if isinstance(cfg, dict) else {}
    weights = dict(DEFAULT_PROOF_WEIGHTS)
    for key, value in (raw.get("weights") or {}).items():
        if key in weights:
            try:
                weights[key] = float(value)
            except Exception:
                continue
    return {
        "max_concrete_cases_per_loop": max(1, int(raw.get("max_concrete_cases_per_loop", 8) or 8)),
        "max_review_candidates_per_loop": max(1, int(raw.get("max_review_candidates_per_loop", 3) or 3)),
        "promotion_threshold": float(raw.get("promotion_threshold", 0.75) or 0.75),
        "weights": weights,
    }


def adaptive_memory_path(project_dir: str | Path) -> Path:
    return Path(project_dir) / "adaptive_memory.json"


def load_adaptive_memory(project_dir: str | Path) -> dict[str, Any]:
    path = adaptive_memory_path(project_dir)
    default = {
        "version": "2.0",
        "promoted_rules": [],
        "promoted_patterns": [],
        "deprioritized_patterns": [],
        "execution_blockers": [],
        "rejected_patterns": [],
        "metadata": {
            "last_updated": None,
            "sessions": [],
        },
    }
    if not path.exists():
        return default
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default
    payload.setdefault("version", "2.0")
    payload.setdefault("promoted_rules", [])
    payload.setdefault("promoted_patterns", [])
    payload.setdefault("deprioritized_patterns", [])
    payload.setdefault("execution_blockers", [])
    legacy_rejected = list(payload.get("rejected_patterns") or [])
    if legacy_rejected:
        migrated = [
            {
                **item,
                "decision": "deprioritize",
                "decision_reason": item.get("decision_reason") or "legacy_rejected_pattern",
                "decision_confidence": float(item.get("decision_confidence", 0.5) or 0.5),
                "revisit_if": item.get("revisit_if") or "new contradiction or stronger code evidence appears",
                "source_scope": item.get("source_scope") or "function",
            }
            for item in legacy_rejected
        ]
        payload["deprioritized_patterns"] = _upsert_entries(
            payload.get("deprioritized_patterns") or [],
            migrated,
        )
    payload["rejected_patterns"] = []
    payload.setdefault("metadata", {})
    payload["metadata"].setdefault("last_updated", None)
    payload["metadata"].setdefault("sessions", [])
    return payload


def save_adaptive_memory(project_dir: str | Path, payload: dict[str, Any]) -> Path:
    path = adaptive_memory_path(project_dir)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def proof_feedback_path(session_dir: str | Path) -> Path:
    return Path(session_dir) / "proof_feedback.json"


def load_proof_feedback(session_dir: str | Path) -> dict[str, Any]:
    path = proof_feedback_path(session_dir)
    default = {
        "version": "1.0",
        "harness_type": "none",
        "results": [],
        "summary": {},
    }
    if not path.exists():
        return default
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default
    payload.setdefault("version", "1.0")
    payload.setdefault("harness_type", "none")
    payload.setdefault("results", [])
    payload.setdefault("summary", build_feedback_summary(payload.get("results") or []))
    return payload


def save_proof_feedback(session_dir: str | Path, payload: dict[str, Any]) -> Path:
    path = proof_feedback_path(session_dir)
    payload = dict(payload or {})
    payload.setdefault("version", "1.0")
    payload.setdefault("results", [])
    payload["summary"] = build_feedback_summary(payload.get("results") or [])
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def proof_case_fingerprint(case: dict[str, Any]) -> str:
    key = "|".join(
        str(case.get(name) or "")
        for name in (
            "invariant_id",
            "contract_name",
            "function_signature",
            "args_expr",
            "value_expr",
            "renderer_hint",
            "expected_outcome",
        )
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def build_feedback_summary(results: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(item.get("status") or "unknown") for item in results or [])
    return dict(counts)


def feedback_indexes(feedback: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    by_case_id: dict[str, list[dict[str, Any]]] = {}
    by_fingerprint: dict[str, list[dict[str, Any]]] = {}
    for item in feedback.get("results") or []:
        case_id = str(item.get("case_id") or "")
        fingerprint = str(item.get("fingerprint") or "")
        if case_id:
            by_case_id.setdefault(case_id, []).append(item)
        if fingerprint:
            by_fingerprint.setdefault(fingerprint, []).append(item)
    return by_case_id, by_fingerprint


def derive_threat_deltas(
    invariants: list[dict[str, Any]],
    adaptive_memory: dict[str, Any],
    feedback: dict[str, Any],
) -> list[dict[str, Any]]:
    promoted_invariants = {
        str(item.get("invariant_id") or "")
        for item in adaptive_memory.get("promoted_rules") or []
        if item.get("invariant_id")
    }
    unresolved = {
        str(item.get("fingerprint") or "")
        for item in feedback.get("results") or []
        if str(item.get("status") or "") in {"compile_failed", "unknown", "skipped"}
    }
    deltas: list[dict[str, Any]] = []
    for inv in invariants:
        invariant_id = str(inv.get("invariant_id") or "")
        if invariant_id and invariant_id not in promoted_invariants:
            deltas.append(
                {
                    "kind": "new_or_unpromoted_rule",
                    "invariant_id": invariant_id,
                    "statement": inv.get("statement"),
                    "targets": inv.get("related_targets") or [],
                }
            )
    for item in feedback.get("results") or []:
        fingerprint = str(item.get("fingerprint") or "")
        if fingerprint and fingerprint in unresolved:
            deltas.append(
                {
                    "kind": "unresolved_proof_feedback",
                    "case_id": item.get("case_id"),
                    "fingerprint": fingerprint,
                    "status": item.get("status"),
                    "reason": item.get("reason"),
                }
            )
    return deltas


def rank_proof_cases(
    proof_cases: list[dict[str, Any]],
    *,
    covered_invariants: list[str] | set[str],
    prior_feedback: dict[str, Any],
    adaptive_memory: dict[str, Any] | None,
    weights: dict[str, float],
    max_cases: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    covered = {str(item) for item in (covered_invariants or [])}
    _, by_fingerprint = feedback_indexes(prior_feedback or {})
    deprioritized = list((adaptive_memory or {}).get("deprioritized_patterns") or [])
    blockers = list((adaptive_memory or {}).get("execution_blockers") or [])
    ranked: list[dict[str, Any]] = []
    seen: set[str] = set()
    terminal = {"passed", "failed"}
    for index, raw in enumerate(proof_cases or [], start=1):
        case = dict(raw or {})
        case.setdefault("case_id", f"case_{index:03d}")
        fingerprint = proof_case_fingerprint(case)
        case["fingerprint"] = fingerprint
        if fingerprint in seen:
            case["selection_reason"] = "duplicate_fingerprint"
            case["priority_score"] = 0.0
            case["selected"] = False
            case["rejected_reason"] = "duplicate_fingerprint"
            ranked.append(case)
            continue
        seen.add(fingerprint)
        previous = by_fingerprint.get(fingerprint, [])
        statuses = {str(item.get("status") or "") for item in previous}
        contradiction_score = _contradiction_score(case)
        coverage_score = 0.0 if str(case.get("invariant_id") or "") in covered else 1.0
        novelty_score = 0.0 if previous else 1.0
        feedback_score = _feedback_score(previous)
        score = (
            contradiction_score * weights.get("contradiction", 0.0)
            + coverage_score * weights.get("coverage", 0.0)
            + feedback_score * weights.get("feedback", 0.0)
            + novelty_score * weights.get("novelty", 0.0)
        )
        penalty = _deprioritized_penalty(case, deprioritized)
        score = max(0.0, score - penalty)
        case["priority_score"] = round(score, 4)
        case["score_breakdown"] = {
            "contradiction": contradiction_score,
            "coverage": coverage_score,
            "feedback": feedback_score,
            "novelty": novelty_score,
        }
        case["score_adjustments"] = {
            "deprioritized_penalty": round(penalty, 4),
        }
        blocker = _matching_execution_blocker(case, blockers)
        if blocker:
            case["execution_blocker"] = {
                "decision": blocker.get("decision"),
                "decision_reason": blocker.get("decision_reason") or blocker.get("review_rationale"),
                "revisit_if": blocker.get("revisit_if"),
            }
        if statuses & terminal:
            case["selected"] = False
            case["selection_reason"] = "already_resolved"
            case["rejected_reason"] = "already_resolved"
        else:
            case["selected"] = True
            case["selection_reason"] = "ranked"
        ranked.append(case)

    ranked.sort(
        key=lambda item: (
            bool(item.get("selected")),
            float(item.get("priority_score") or 0.0),
            str(item.get("case_id") or ""),
        ),
        reverse=True,
    )
    selected: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for item in ranked:
        if item.get("selected") and len(selected) < max_cases:
            selected.append(item)
        else:
            item["selected"] = False
            item.setdefault("rejected_reason", "deprioritized")
            rejected.append(item)
    return selected, rejected


def build_promotion_candidates(
    *,
    selected_cases: list[dict[str, Any]],
    invariants: list[dict[str, Any]],
    feedback: dict[str, Any],
) -> list[dict[str, Any]]:
    invariant_map = {
        str(item.get("invariant_id") or ""): item
        for item in invariants or []
        if item.get("invariant_id")
    }
    _, by_fingerprint = feedback_indexes(feedback or {})
    candidates: list[dict[str, Any]] = []
    for case in selected_cases or []:
        invariant_id = str(case.get("invariant_id") or "")
        invariant = invariant_map.get(invariant_id, {})
        fingerprint = str(case.get("fingerprint") or proof_case_fingerprint(case))
        prior = by_fingerprint.get(fingerprint, [])
        feedback_status = ""
        if prior:
            feedback_status = str(prior[-1].get("status") or "")
        candidate_id = f"cand_{fingerprint}"
        candidates.append(
            {
                "candidate_id": candidate_id,
                "kind": "project_rule",
                "invariant_id": invariant_id,
                "statement": invariant.get("statement") or case.get("reasoning") or "",
                "contract_name": case.get("contract_name"),
                "function_name": case.get("function_name"),
                "score": float(case.get("priority_score") or 0.0),
                "feedback_status": feedback_status,
                "reasoning": case.get("reasoning") or "",
                "source_signals": list(case.get("source_signals") or []),
                "source_scope": _source_scope(case),
                "fingerprint": fingerprint,
            }
        )
    return candidates


def apply_reviewed_candidates(
    adaptive_memory: dict[str, Any],
    *,
    candidates: list[dict[str, Any]],
    approvals: list[dict[str, Any]],
    session_id: str,
    loop_id: int,
) -> dict[str, Any]:
    memory = json.loads(json.dumps(adaptive_memory))
    memory.setdefault("promoted_rules", [])
    memory.setdefault("promoted_patterns", [])
    memory.setdefault("deprioritized_patterns", [])
    memory.setdefault("execution_blockers", [])
    memory["rejected_patterns"] = []
    memory.setdefault("metadata", {})
    memory["metadata"]["last_updated"] = datetime.now().isoformat()
    sessions = set(memory["metadata"].get("sessions") or [])
    if session_id:
        sessions.add(session_id)
    memory["metadata"]["sessions"] = sorted(sessions)

    candidate_by_id = {str(item.get("candidate_id")): item for item in candidates or []}
    existing_rule_ids = {
        (str(item.get("invariant_id") or ""), str(item.get("fingerprint") or ""))
        for item in memory.get("promoted_rules") or []
    }
    existing_deprioritized = {
        str(item.get("fingerprint") or "")
        for item in memory.get("deprioritized_patterns") or []
    }
    existing_blockers = {
        str(item.get("fingerprint") or "")
        for item in memory.get("execution_blockers") or []
    }
    for decision in approvals or []:
        candidate = candidate_by_id.get(str(decision.get("candidate_id") or ""))
        if not candidate:
            continue
        normalized = str(decision.get("decision") or "").lower() or "deprioritize"
        entry = {
            **candidate,
            "decision": normalized,
            "decision_reason": decision.get("rationale") or "",
            "decision_confidence": float(decision.get("confidence", 0.5) or 0.5),
            "revisit_if": decision.get("revisit_if") or _default_revisit_if(normalized),
            "source_scope": candidate.get("source_scope") or "function",
            "session_id": session_id,
            "loop_id": loop_id,
            "reviewed_at": datetime.now().isoformat(),
        }
        fingerprint = str(candidate.get("fingerprint") or "")
        if normalized == "approve":
            key = (str(candidate.get("invariant_id") or ""), fingerprint)
            if key not in existing_rule_ids:
                memory["promoted_rules"].append(entry)
                existing_rule_ids.add(key)
            memory["promoted_patterns"] = _upsert_pattern(memory.get("promoted_patterns") or [], entry)
        elif normalized == "invalid_codegen":
            if fingerprint and fingerprint not in existing_blockers:
                memory["execution_blockers"].append(entry)
                existing_blockers.add(fingerprint)
        elif fingerprint and fingerprint not in existing_deprioritized:
            memory["deprioritized_patterns"].append(entry)
            existing_deprioritized.add(fingerprint)
    return memory


def _upsert_pattern(existing: list[dict[str, Any]], entry: dict[str, Any]) -> list[dict[str, Any]]:
    fingerprint = str(entry.get("fingerprint") or "")
    updated = [item for item in existing if str(item.get("fingerprint") or "") != fingerprint]
    updated.append(entry)
    return updated


def _upsert_entries(existing: list[dict[str, Any]], new_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = list(existing or [])
    for entry in new_entries or []:
        out = _upsert_pattern(out, entry)
    return out


def _contradiction_score(case: dict[str, Any]) -> float:
    signals = list(case.get("source_signals") or [])
    if signals:
        return min(1.0, 0.5 + (0.25 * len(signals)))
    text = " ".join(
        str(case.get(key) or "")
        for key in ("reasoning", "violation_reason", "expected_outcome", "renderer_hint")
    ).lower()
    if "contradiction" in text or "bypass" in text or "mismatch" in text:
        return 0.9
    return 0.4 if text else 0.2


def _feedback_score(previous: list[dict[str, Any]]) -> float:
    if not previous:
        return 0.8
    statuses = {str(item.get("status") or "") for item in previous}
    if statuses & {"compile_failed", "unknown", "skipped"}:
        return 0.9
    if statuses & {"duplicate_fingerprint"}:
        return 0.1
    if statuses & {"passed", "failed"}:
        return 0.0
    return 0.3


def _deprioritized_penalty(case: dict[str, Any], deprioritized: list[dict[str, Any]]) -> float:
    prior = next((item for item in deprioritized if _same_pattern(item, case)), None)
    if not prior:
        return 0.0
    if _has_new_evidence(case, prior):
        return 0.05
    return 0.25 if str(prior.get("fingerprint") or "") == str(case.get("fingerprint") or "") else 0.15


def _same_pattern(prior: dict[str, Any], case: dict[str, Any]) -> bool:
    prior_fp = str(prior.get("fingerprint") or "")
    case_fp = str(case.get("fingerprint") or "")
    if prior_fp and case_fp and prior_fp == case_fp:
        return True
    return (
        str(prior.get("contract_name") or "") == str(case.get("contract_name") or "")
        and str(prior.get("function_name") or "") == str(case.get("function_name") or "")
        and str(prior.get("invariant_id") or "") == str(case.get("invariant_id") or "")
    )


def _has_new_evidence(case: dict[str, Any], prior: dict[str, Any]) -> bool:
    current = {
        (str(item.get("kind") or ""), str(item.get("detail") or ""))
        for item in case.get("source_signals") or []
    }
    previous = {
        (str(item.get("kind") or ""), str(item.get("detail") or ""))
        for item in prior.get("source_signals") or []
    }
    if current - previous:
        return True
    text = " ".join(str(case.get(key) or "") for key in ("reasoning", "renderer_hint", "expected_outcome")).lower()
    return any(tok in text for tok in ("cross-module", "contradiction", "bypass", "new evidence"))


def _matching_execution_blocker(case: dict[str, Any], blockers: list[dict[str, Any]]) -> dict[str, Any] | None:
    for blocker in blockers or []:
        if _same_pattern(blocker, case):
            return blocker
    return None


def _source_scope(case: dict[str, Any]) -> str:
    signals = list(case.get("source_signals") or [])
    if len(signals) > 1:
        return "cross_module"
    return "function"


def _default_revisit_if(decision: str) -> str:
    if decision == "invalid_codegen":
        return "renderer, harness, or compile path is fixed"
    if decision == "duplicate":
        return "new edge path or stronger evidence appears"
    if decision == "insufficient_evidence":
        return "new contradiction or code reference appears"
    return "new contradiction or stronger project-specific evidence appears"
