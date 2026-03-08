"""Cooperative audit orchestrator and lightweight role helpers."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .test_writers import SkeletonWriterRegistry


def _now_iso() -> str:
    return datetime.now().isoformat()


@dataclass
class AgentProgress:
    agent_role: str
    agent_id: str
    status: str = "idle"
    current_goal: str = ""
    loop_id: int = 0
    iteration: int = 0
    max_iterations: int = 0
    planning_batch: int = 0
    investigation_index: int = 0
    investigation_total: int = 0
    last_message: str = ""
    updated_at: str = field(default_factory=_now_iso)


@dataclass
class OrchestratorState:
    session_id: str
    status: str = "idle"
    current_loop: int = 0
    current_phase: str = ""
    enabled_roles: list[str] = field(default_factory=list)
    agents: dict[str, dict[str, Any]] = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)
    updated_at: str = field(default_factory=_now_iso)


class RoleRegistry:
    """Simple registry for built-in and future audit roles."""

    def __init__(self):
        self._roles: dict[str, Any] = {}

    def register(self, name: str, role: Any) -> None:
        self._roles[name] = role

    def get(self, name: str) -> Any:
        return self._roles[name]

    def names(self) -> list[str]:
        return list(self._roles.keys())


def build_default_registry() -> RoleRegistry:
    registry = RoleRegistry()
    registry.register("threat_modeler", ThreatModelerRole())
    registry.register("invariant_auditor", InvariantAuditorRole())
    return registry


class AuditOrchestrator:
    """Persist cooperative loop state and per-role progress for a session."""

    def __init__(self, session_dir: Path, session_id: str, enabled_roles: list[str] | None = None):
        self.session_dir = Path(session_dir)
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.session_dir / "orchestrator.json"
        self.session_id = session_id
        self.state = self._load_or_init(enabled_roles or [])

    def _load_or_init(self, enabled_roles: list[str]) -> OrchestratorState:
        if self.state_path.exists():
            try:
                raw = json.loads(self.state_path.read_text(encoding="utf-8"))
                if enabled_roles:
                    raw["enabled_roles"] = enabled_roles
                return OrchestratorState(**raw)
            except Exception:
                pass
        return OrchestratorState(session_id=self.session_id, enabled_roles=enabled_roles)

    def save(self) -> None:
        self.state.updated_at = _now_iso()
        self.state_path.write_text(json.dumps(asdict(self.state), indent=2), encoding="utf-8")

    def begin_loop(self, loop_id: int, phase: str) -> None:
        self.state.status = "active"
        self.state.current_loop = loop_id
        self.state.current_phase = phase or ""
        self.save()

    def update_agent(self, progress: AgentProgress) -> None:
        progress.updated_at = _now_iso()
        self.state.agents[progress.agent_role] = asdict(progress)
        self.save()

    def attach_artifact(self, name: str, path: Path) -> None:
        self.state.artifacts[name] = str(Path(path))
        self.save()

    def finish(self, status: str) -> None:
        self.state.status = status
        self.save()


def detect_repo_harness(project_dir: Path) -> str:
    """Best-effort detection of a supported smart-contract test harness."""
    p = resolve_harness_project_dir(project_dir)
    if (p / "foundry.toml").exists():
        return "foundry"
    if (p / "hardhat.config.js").exists() or (p / "hardhat.config.ts").exists():
        return "hardhat"
    return "none"


def resolve_harness_project_dir(project_dir: Path) -> Path:
    """Resolve the actual repo root for harness detection."""
    p = Path(project_dir)
    project_file = p / "project.json"
    if project_file.exists():
        try:
            payload = json.loads(project_file.read_text(encoding="utf-8"))
            source_path = payload.get("source_path")
            if source_path:
                source_dir = Path(source_path).expanduser()
                if source_dir.exists():
                    return source_dir
        except Exception:
            pass
    return p


def derive_threat_lanes(loaded_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive coarse threat lanes from currently loaded graphs."""
    system_graph = (loaded_data or {}).get("system_graph") or {}
    graph_data = system_graph.get("data") or {}
    nodes = graph_data.get("nodes") or []
    lanes: list[dict[str, Any]] = []
    for node in nodes:
        node_id = str(node.get("id") or "")
        if not node_id:
            continue
        label = str(node.get("label") or node_id)
        node_type = str(node.get("type") or "")
        observations = list(node.get("observations") or [])
        assumptions = list(node.get("assumptions") or [])
        lane_id = f"lane_{node_id}"
        rule = _derive_rule(label, observations, assumptions)
        lanes.append(
            {
                "lane_id": lane_id,
                "asset": label,
                "loss_event": f"Integrity or control loss in {label}",
                "trust_boundary": node_type or "component",
                "rule": rule,
                "targets": [node_id],
                "status": "open",
                "evidence_refs": observations[:3],
            }
        )
    return lanes


def _derive_rule(label: str, observations: list[Any], assumptions: list[Any]) -> str:
    texts = " ".join(str(x).lower() for x in [label, *observations, *assumptions])
    if "init" in texts or "initialize" in texts:
        return "State-changing operations must be gated until initialization is complete."
    if any(tok in texts for tok in ("owner", "admin", "role", "auth", "permission")):
        return "Privileged state changes must remain authorization-gated."
    return f"Critical state transitions in {label} must preserve declared lifecycle and authorization checks."


def derive_invariants(lanes: list[dict[str, Any]], harness: str) -> list[dict[str, Any]]:
    """Create invariant specs and contrast checks from threat lanes."""
    invariants: list[dict[str, Any]] = []
    for idx, lane in enumerate(lanes, start=1):
        rule = lane.get("rule") or ""
        statement = str(rule)
        lower = statement.lower()
        if "initialization" in lower or "initialize" in lower:
            preconditions = ["initialization flag unset"]
            forbidden_effect = "state write succeeds before initialization"
            contrast_checks = ["Can any write path bypass initialization guards?"]
        elif "authorization" in lower or "privileged" in lower:
            preconditions = ["caller lacks required role"]
            forbidden_effect = "privileged effect succeeds for unauthorized caller"
            contrast_checks = ["Can any alternate path reach the privileged effect without the intended auth check?"]
        else:
            preconditions = ["normal control-flow assumptions broken"]
            forbidden_effect = "declared business rule is violated"
            contrast_checks = [f"Can any edge case violate the rule for {lane.get('asset', 'this target')}?"]

        invariants.append(
            {
                "invariant_id": f"inv_{idx:03d}",
                "lane_id": lane.get("lane_id"),
                "statement": statement,
                "preconditions": preconditions,
                "forbidden_effect": forbidden_effect,
                "related_targets": lane.get("targets") or [],
                "evidence_refs": lane.get("evidence_refs") or [],
                "contrast_checks": contrast_checks,
                "harness_status": "available" if harness != "none" else "unavailable",
                "harness_type": harness,
            }
        )
    return invariants


class ThreatModelerRole:
    """Generate session threat model and invariant artifacts."""

    def run(
        self,
        *,
        loaded_data: dict[str, Any],
        session_dir: Path,
        project_dir: Path,
        allow_test_writes: bool = False,
    ) -> dict[str, Path]:
        session_dir = Path(session_dir)
        session_dir.mkdir(parents=True, exist_ok=True)
        lanes = derive_threat_lanes(loaded_data)
        harness = detect_repo_harness(project_dir)
        invariants = derive_invariants(lanes, harness)
        threat_path = session_dir / "threat_model.json"
        inv_path = session_dir / "invariants.json"
        threat_path.write_text(json.dumps({"lanes": lanes}, indent=2), encoding="utf-8")
        inv_path.write_text(json.dumps({"invariants": invariants}, indent=2), encoding="utf-8")
        artifacts = {"threat_model": threat_path, "invariants": inv_path}
        if allow_test_writes and harness != "none":
            writer = SkeletonWriterRegistry().get(harness)
            if writer is not None:
                artifacts.update(
                    writer.write(
                        invariants=invariants,
                        project_dir=resolve_harness_project_dir(project_dir),
                        session_dir=session_dir,
                    )
                )
        return artifacts


class InvariantAuditorRole:
    """Refresh invariant contrast metadata for the current session."""

    def run(self, *, session_dir: Path) -> Path | None:
        inv_path = Path(session_dir) / "invariants.json"
        if not inv_path.exists():
            return None
        try:
            data = json.loads(inv_path.read_text(encoding="utf-8"))
        except Exception:
            return None
        changed = False
        for inv in data.get("invariants", []):
            if inv.get("contrast_checks"):
                continue
            inv["contrast_checks"] = [f"Can any alternate path violate: {inv.get('statement', 'invariant')}?"]
            changed = True
        if changed:
            inv_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return inv_path
