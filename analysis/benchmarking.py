"""Benchmark helpers for EVMBench-style A/B evaluation."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from llm.unified_client import UnifiedLLMClient


DEFAULT_BASELINE_REF = "c29890180b317b66b06342521c8e2d82117bb93b"
EVMBENCH_REPO_URL = "https://github.com/paradigmxyz/evmbench.git"
FRONTIER_EVALS_REPO_URL = "https://github.com/openai/frontier-evals.git"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def slugify(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", str(value or "").strip()).strip("-").lower()
    return text or "item"


def default_workspace_root() -> Path:
    return Path.home() / ".hound" / "benchmarks" / "evmbench"


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(read_text(path))


def write_json(path: Path, payload: Any) -> Path:
    ensure_dir(path.parent)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


@dataclass
class GoldFinding:
    finding_id: str
    title: str
    severity: str
    description: str
    affected_files: list[str] = field(default_factory=list)
    affected_functions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class BenchmarkTask:
    task_id: str
    contest_id: str
    split: str
    task_dir: str
    source_path: str | None
    metadata: dict[str, Any] = field(default_factory=dict)
    gold_findings: list[GoldFinding] = field(default_factory=list)


@dataclass
class ObservedFinding:
    finding_id: str
    title: str
    description: str
    vulnerability_type: str
    severity: str
    confidence: float
    affected_code: list[str] = field(default_factory=list)
    node_refs: list[str] = field(default_factory=list)
    supporting_evidence: list[Any] = field(default_factory=list)
    session_id: str | None = None
    status: str = "proposed"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FindingMatchDecision:
    gold_id: str
    observed_id: str
    strict_match: bool
    semantic_match: bool
    score: float
    rationale: str
    evidence_quality: float = 0.0


@dataclass
class BenchmarkMetrics:
    gold_total: int
    observed_total: int
    strict_matches: int
    semantic_matches: int
    false_positives: int
    proof_backed_strict_matches: int
    strict_recall: float
    strict_precision: float
    strict_f1: float
    semantic_recall: float
    semantic_precision: float


def workspace_layout(workspace_root: Path) -> dict[str, Path]:
    return {
        "root": workspace_root,
        "repos": ensure_dir(workspace_root / "repos"),
        "manifests": ensure_dir(workspace_root / "manifests"),
        "runs": ensure_dir(workspace_root / "runs"),
        "checkouts": ensure_dir(workspace_root / "checkouts"),
    }


def repo_paths(workspace_root: Path) -> dict[str, Path]:
    layout = workspace_layout(workspace_root)
    return {
        "evmbench": layout["repos"] / "evmbench",
        "frontier_evals": layout["repos"] / "frontier-evals",
    }


def run_subprocess(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def clone_or_update_repo(repo_url: str, dest: Path, *, branch: str = "main") -> Path:
    ensure_dir(dest.parent)
    if not dest.exists():
        result = run_subprocess(["git", "clone", "--depth", "1", "--branch", branch, repo_url, str(dest)])
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed for {repo_url}: {result.stderr.strip() or result.stdout.strip()}")
        return dest

    result = run_subprocess(["git", "-C", str(dest), "fetch", "origin", branch, "--depth", "1"])
    if result.returncode != 0:
        raise RuntimeError(f"git fetch failed for {dest}: {result.stderr.strip() or result.stdout.strip()}")
    result = run_subprocess(["git", "-C", str(dest), "checkout", branch])
    if result.returncode != 0:
        raise RuntimeError(f"git checkout failed for {dest}: {result.stderr.strip() or result.stdout.strip()}")
    result = run_subprocess(["git", "-C", str(dest), "pull", "--ff-only", "origin", branch])
    if result.returncode != 0:
        raise RuntimeError(f"git pull failed for {dest}: {result.stderr.strip() or result.stdout.strip()}")
    return dest


def parse_split_file(path: Path) -> list[str]:
    if not path.exists():
        return []
    tasks: list[str] = []
    for raw_line in read_text(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        tasks.append(line)
    return tasks


def infer_severity_from_id(finding_id: str) -> str:
    prefix = str(finding_id or "").strip().split("-")[0].lower()
    mapping = {"h": "high", "m": "medium", "l": "low", "c": "critical"}
    return mapping.get(prefix, prefix or "unknown")


def parse_finding_markdown(path: Path) -> GoldFinding:
    text = read_text(path)
    finding_id = path.stem
    title = ""
    description_parts: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") and not title:
            title = stripped.lstrip("#").strip()
            continue
        if stripped and not stripped.startswith("```"):
            description_parts.append(stripped)
        if len(" ".join(description_parts)) > 500:
            break
    return GoldFinding(
        finding_id=finding_id,
        title=title or finding_id,
        severity=infer_severity_from_id(finding_id),
        description=" ".join(description_parts[:10]).strip(),
    )


def infer_source_repo_url(task_dir: Path, config: dict[str, Any] | None = None) -> str | None:
    config = config or {}
    explicit = config.get("source_repo_url") or config.get("repo_url") or config.get("repository")
    if explicit:
        return str(explicit)
    findings_dir = task_dir / "findings"
    if not findings_dir.exists():
        return None
    pattern = re.compile(r"https://github\.com/([^/\s]+)/([^/\s]+)/blob/")
    for path in sorted(findings_dir.rglob("*.md")):
        match = pattern.search(read_text(path))
        if match:
            owner, repo = match.group(1), match.group(2)
            return f"https://github.com/{owner}/{repo}.git"
    return None


def resolve_source_path(task_dir: Path, *, evmbench_root: Path | None = None, config: dict[str, Any] | None = None) -> Path | None:
    config = config or {}
    keys = ("source_path", "repo_path", "code_path", "target_path", "path")
    for key in keys:
        candidate = config.get(key)
        if candidate:
            p = Path(candidate).expanduser()
            if not p.is_absolute():
                p = (task_dir / p).resolve()
            if p.exists():
                return p

    candidates = [
        task_dir / "repo",
        task_dir / "src",
        task_dir / "contracts",
        task_dir / "source",
    ]
    if evmbench_root is not None:
        candidates.extend(
            [
                evmbench_root / "audits" / task_dir.name,
                evmbench_root / task_dir.name,
                evmbench_root / "repos" / task_dir.name,
            ]
        )
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return None


def cached_source_checkout_path(
    workspace_root: Path,
    *,
    repo_url: str,
    base_commit: str | None = None,
    run_cmd_dir: str | None = None,
) -> Path:
    repo_slug = slugify(repo_url.replace("https://github.com/", "").replace(".git", ""))
    suffix = f"{repo_slug}-{(base_commit or 'head')[:12]}"
    root = ensure_dir(workspace_root / "sources" / suffix)
    return root / run_cmd_dir if run_cmd_dir else root


def ensure_source_checkout(
    workspace_root: Path,
    *,
    repo_url: str,
    base_commit: str | None = None,
    run_cmd_dir: str | None = None,
) -> Path:
    source_root = cached_source_checkout_path(workspace_root, repo_url=repo_url, base_commit=base_commit)
    ensure_dir(source_root.parent)
    if not source_root.exists():
        result = run_subprocess(["git", "clone", repo_url, str(source_root)])
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed for source repo {repo_url}: {result.stderr.strip() or result.stdout.strip()}")
    if base_commit:
        result = run_subprocess(["git", "-C", str(source_root), "checkout", base_commit])
        if result.returncode != 0:
            raise RuntimeError(f"git checkout failed for source repo {repo_url}: {result.stderr.strip() or result.stdout.strip()}")
    return source_root / run_cmd_dir if run_cmd_dir else source_root


def load_task(task_dir: Path, *, split: str, evmbench_root: Path | None = None) -> BenchmarkTask:
    config_path = task_dir / "config.yaml"
    config = {}
    if config_path.exists():
        config = yaml.safe_load(read_text(config_path)) or {}
    findings_dir = task_dir / "findings"
    findings = []
    if findings_dir.exists():
        for finding_path in sorted(findings_dir.glob("*.md")):
            findings.append(parse_finding_markdown(finding_path))

    source_repo_url = infer_source_repo_url(task_dir, config=config)
    source_path = resolve_source_path(task_dir, evmbench_root=evmbench_root, config=config)
    if source_repo_url:
        config["source_repo_url"] = source_repo_url
    return BenchmarkTask(
        task_id=task_dir.name,
        contest_id=str(config.get("contest_id") or config.get("name") or task_dir.name),
        split=split,
        task_dir=str(task_dir),
        source_path=str(source_path) if source_path else None,
        metadata=config,
        gold_findings=findings,
    )


def load_tasks(frontier_root: Path, *, split: str, evmbench_root: Path | None = None) -> list[BenchmarkTask]:
    base_dir = frontier_root / "project" / "evmbench"
    audits_dir = base_dir / "audits"
    split_path = base_dir / "splits" / f"{split}.txt"
    task_ids = parse_split_file(split_path)
    tasks: list[BenchmarkTask] = []
    for task_id in task_ids:
        task_dir = audits_dir / task_id
        if not task_dir.exists():
            continue
        tasks.append(load_task(task_dir, split=split, evmbench_root=evmbench_root))
    return tasks


def extract_observed_findings(project_dir: Path, session_ids: set[str] | None = None) -> list[ObservedFinding]:
    hypothesis_file = project_dir / "hypotheses.json"
    if not hypothesis_file.exists():
        return []
    payload = read_json(hypothesis_file)
    hypotheses = payload.get("hypotheses") or {}
    results: list[ObservedFinding] = []
    for hyp_id, raw in hypotheses.items():
        session_id = raw.get("session_id")
        if session_ids and session_id not in session_ids:
            continue
        evidence = raw.get("evidence") or raw.get("supporting_evidence") or []
        confidence = raw.get("confidence", 0.0)
        try:
            confidence_value = float(confidence)
        except Exception:
            confidence_value = 0.0
        results.append(
            ObservedFinding(
                finding_id=str(raw.get("id") or hyp_id),
                title=str(raw.get("title") or ""),
                description=str(raw.get("description") or ""),
                vulnerability_type=str(raw.get("vulnerability_type") or raw.get("type") or "unknown"),
                severity=str(raw.get("severity") or "unknown"),
                confidence=confidence_value,
                affected_code=[str(x) for x in (raw.get("affected_code") or raw.get("properties", {}).get("source_files") or [])],
                node_refs=[str(x) for x in (raw.get("node_refs") or raw.get("affected") or [])],
                supporting_evidence=list(evidence),
                session_id=session_id,
                status=str(raw.get("status") or "proposed"),
                metadata={k: v for k, v in raw.items() if k not in {"id", "title", "description", "vulnerability_type", "type", "severity", "confidence", "affected_code", "node_refs", "status"}},
            )
        )
    return results


def _tokens(value: str) -> set[str]:
    return {t for t in re.findall(r"[a-zA-Z_][a-zA-Z0-9_]+", (value or "").lower()) if len(t) > 2}


def _norm_paths(items: list[str]) -> set[str]:
    return {str(x).replace("\\", "/").lower() for x in items if x}


def deterministic_similarity(gold: GoldFinding, observed: ObservedFinding) -> tuple[float, float, str]:
    title_overlap = len(_tokens(gold.title) & _tokens(observed.title))
    desc_overlap = len(_tokens(gold.description) & (_tokens(observed.description) | _tokens(observed.vulnerability_type)))
    severity_bonus = 0.15 if gold.severity == observed.severity else 0.0
    file_overlap = len(_norm_paths(gold.affected_files) & _norm_paths(observed.affected_code))
    score = min(1.0, 0.18 * title_overlap + 0.08 * desc_overlap + 0.14 * file_overlap + severity_bonus)
    evidence_quality = min(1.0, 0.25 + 0.15 * len(observed.supporting_evidence))
    rationale = (
        f"title_overlap={title_overlap}, desc_overlap={desc_overlap}, "
        f"file_overlap={file_overlap}, severity_match={gold.severity == observed.severity}"
    )
    return score, evidence_quality, rationale


class BenchmarkJudge:
    def evaluate(self, gold: GoldFinding, observed: ObservedFinding) -> FindingMatchDecision:  # pragma: no cover - interface
        raise NotImplementedError


class DeterministicJudge(BenchmarkJudge):
    def evaluate(self, gold: GoldFinding, observed: ObservedFinding) -> FindingMatchDecision:
        score, evidence_quality, rationale = deterministic_similarity(gold, observed)
        strict_match = score >= 0.72
        semantic_match = score >= 0.45
        return FindingMatchDecision(
            gold_id=gold.finding_id,
            observed_id=observed.finding_id,
            strict_match=strict_match,
            semantic_match=semantic_match,
            score=score,
            rationale=rationale,
            evidence_quality=evidence_quality,
        )


class LLMJudge(BenchmarkJudge):
    def __init__(self, cfg: dict[str, Any], profile: str = "benchmark_judge"):
        self.cfg = cfg or {}
        self.profile = profile
        self.llm = UnifiedLLMClient(cfg=self.cfg, profile=profile)
        self.fallback = DeterministicJudge()

    def evaluate(self, gold: GoldFinding, observed: ObservedFinding) -> FindingMatchDecision:
        from pydantic import BaseModel, Field

        class JudgeResponse(BaseModel):
            strict_match: bool = Field(default=False)
            semantic_match: bool = Field(default=False)
            score: float = Field(default=0.0, ge=0.0, le=1.0)
            rationale: str = Field(default="")
            evidence_quality: float = Field(default=0.0, ge=0.0, le=1.0)

        try:
            payload = self.llm.generate_structured(
                system=(
                    "You are grading whether an observed security finding matches a gold vulnerability from an audit contest. "
                    "Be strict about root cause and affected path overlap."
                ),
                prompt=(
                    f"GOLD:\n{json.dumps(asdict(gold), ensure_ascii=False)}\n\n"
                    f"OBSERVED:\n{json.dumps(asdict(observed), ensure_ascii=False)}\n\n"
                    "Return JSON with strict_match, semantic_match, score, rationale, evidence_quality."
                ),
                schema=JudgeResponse,
            )
            return FindingMatchDecision(
                gold_id=gold.finding_id,
                observed_id=observed.finding_id,
                strict_match=bool(payload.strict_match),
                semantic_match=bool(payload.semantic_match),
                score=float(payload.score),
                rationale=str(payload.rationale),
                evidence_quality=float(payload.evidence_quality),
            )
        except Exception:
            return self.fallback.evaluate(gold, observed)


def match_findings(
    gold_findings: list[GoldFinding],
    observed_findings: list[ObservedFinding],
    *,
    judge: BenchmarkJudge | None = None,
) -> list[FindingMatchDecision]:
    judge = judge or DeterministicJudge()
    candidates: list[FindingMatchDecision] = []
    for gold in gold_findings:
        for observed in observed_findings:
            decision = judge.evaluate(gold, observed)
            if decision.semantic_match:
                candidates.append(decision)
    candidates.sort(key=lambda item: (item.strict_match, item.score, item.evidence_quality), reverse=True)

    matched_gold: set[str] = set()
    matched_observed: set[str] = set()
    accepted: list[FindingMatchDecision] = []
    for item in candidates:
        if item.gold_id in matched_gold or item.observed_id in matched_observed:
            continue
        matched_gold.add(item.gold_id)
        matched_observed.add(item.observed_id)
        accepted.append(item)
    return accepted


def compute_metrics(
    gold_findings: list[GoldFinding],
    observed_findings: list[ObservedFinding],
    matches: list[FindingMatchDecision],
) -> BenchmarkMetrics:
    strict_matches = sum(1 for item in matches if item.strict_match)
    semantic_matches = sum(1 for item in matches if item.semantic_match)
    gold_total = len(gold_findings)
    observed_total = len(observed_findings)
    false_positives = max(0, observed_total - semantic_matches)
    proof_backed = 0
    observed_map = {item.finding_id: item for item in observed_findings}
    for match in matches:
        if match.strict_match and observed_map.get(match.observed_id, ObservedFinding("", "", "", "", "", 0.0)).supporting_evidence:
            proof_backed += 1

    strict_recall = strict_matches / gold_total if gold_total else 0.0
    strict_precision = strict_matches / observed_total if observed_total else 0.0
    strict_f1 = (2 * strict_recall * strict_precision / (strict_recall + strict_precision)) if (strict_recall + strict_precision) else 0.0
    semantic_recall = semantic_matches / gold_total if gold_total else 0.0
    semantic_precision = semantic_matches / observed_total if observed_total else 0.0

    return BenchmarkMetrics(
        gold_total=gold_total,
        observed_total=observed_total,
        strict_matches=strict_matches,
        semantic_matches=semantic_matches,
        false_positives=false_positives,
        proof_backed_strict_matches=proof_backed,
        strict_recall=strict_recall,
        strict_precision=strict_precision,
        strict_f1=strict_f1,
        semantic_recall=semantic_recall,
        semantic_precision=semantic_precision,
    )


def baseline_checkout(repo_root: Path, workspace_root: Path, baseline_ref: str = DEFAULT_BASELINE_REF) -> Path:
    target = workspace_layout(workspace_root)["checkouts"] / f"baseline-{baseline_ref[:12]}"
    if target.exists():
        return target
    result = run_subprocess(["git", "worktree", "add", "--detach", str(target), baseline_ref], cwd=repo_root)
    if result.returncode != 0:
        raise RuntimeError(f"failed to create baseline checkout: {result.stderr.strip() or result.stdout.strip()}")
    return target


def arm_repo_path(repo_root: Path, workspace_root: Path, arm: str, baseline_ref: str = DEFAULT_BASELINE_REF) -> Path:
    if arm == "treatment":
        return repo_root
    if arm == "baseline":
        return baseline_checkout(repo_root, workspace_root, baseline_ref=baseline_ref)
    raise ValueError(f"Unknown arm: {arm}")


def project_name_for_task(task: BenchmarkTask, arm: str) -> str:
    return f"evmbench-{slugify(task.task_id)}-{arm}"


def arm_home_dir(workspace_root: Path, run_id: str, arm: str, task: BenchmarkTask) -> Path:
    return ensure_dir(workspace_root / "runs" / run_id / "homes" / arm / slugify(task.task_id))


def build_schedule(mode: str, *, budget_minutes: int) -> list[tuple[str, int]]:
    if mode == "cold":
        return [("sweep", budget_minutes)]
    if mode == "long":
        return [("sweep", budget_minutes), ("intuition", budget_minutes), ("intuition", budget_minutes)]
    raise ValueError(f"Unsupported mode: {mode}")


def default_budget(split: str, mode: str) -> int:
    if split == "debug":
        return 5
    if split == "detect":
        return 20
    return 10


def list_session_ids(project_dir: Path) -> set[str]:
    sessions_dir = project_dir / "sessions"
    if not sessions_dir.exists():
        return set()
    return {p.name for p in sessions_dir.iterdir() if p.is_dir()}


def latest_session_ids(project_dir: Path, previous: set[str]) -> list[str]:
    current = list_session_ids(project_dir)
    new_ids = sorted(current - previous)
    return new_ids


def build_submission_markdown(observed_findings: list[ObservedFinding]) -> str:
    if not observed_findings:
        return "# Hound Audit Submission\n\nNo findings.\n"
    lines = ["# Hound Audit Submission", ""]
    for idx, finding in enumerate(observed_findings, 1):
        lines.append(f"## {idx}. [{finding.severity.upper()}] {finding.title}")
        lines.append("")
        lines.append(f"- Type: {finding.vulnerability_type}")
        lines.append(f"- Confidence: {finding.confidence:.2f}")
        if finding.affected_code:
            lines.append(f"- Affected: {', '.join(finding.affected_code[:5])}")
        lines.append("")
        lines.append(finding.description or "(no description)")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def prepare_workspace(
    workspace_root: Path,
    *,
    clone_evmbench: bool = True,
    clone_frontier_evals: bool = True,
) -> dict[str, str]:
    paths = repo_paths(workspace_root)
    if clone_evmbench:
        clone_or_update_repo(EVMBENCH_REPO_URL, paths["evmbench"])
    if clone_frontier_evals:
        clone_or_update_repo(FRONTIER_EVALS_REPO_URL, paths["frontier_evals"])
    manifest = {
        "prepared_at": utc_now(),
        "workspace_root": str(workspace_root),
        "repos": {
            "evmbench": str(paths["evmbench"]),
            "frontier_evals": str(paths["frontier_evals"]),
        },
    }
    write_json(workspace_root / "manifests" / "workspace.json", manifest)
    return manifest


def manifest_tasks(workspace_root: Path, split: str) -> list[BenchmarkTask]:
    repos = repo_paths(workspace_root)
    tasks = load_tasks(repos["frontier_evals"], split=split, evmbench_root=repos["evmbench"])
    write_json(
        workspace_root / "manifests" / f"{split}_tasks.json",
        {"generated_at": utc_now(), "split": split, "tasks": [asdict(task) for task in tasks]},
    )
    return tasks


def _hound_env(home_dir: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["HOME"] = str(home_dir)
    env.setdefault("PYTHONUNBUFFERED", "1")
    return env


def _run_hound_command(
    repo_dir: Path,
    home_dir: Path,
    args: list[str],
    *,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    cmd = [sys.executable, "./hound.py", *args]
    result = run_subprocess(cmd, cwd=repo_dir, env=_hound_env(home_dir), timeout=timeout_seconds)
    return {
        "command": cmd,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def run_task_benchmark(
    *,
    repo_root: Path,
    workspace_root: Path,
    task: BenchmarkTask,
    arm: str,
    mode: str,
    config_path: Path | None,
    split: str,
    baseline_ref: str = DEFAULT_BASELINE_REF,
    judge: BenchmarkJudge | None = None,
) -> dict[str, Any]:
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    arm_repo = arm_repo_path(repo_root, workspace_root, arm, baseline_ref=baseline_ref)
    home_dir = arm_home_dir(workspace_root, run_id, arm, task)
    run_dir = ensure_dir(workspace_root / "runs" / run_id / arm / slugify(task.task_id))
    if not task.source_path:
        repo_url = str(task.metadata.get("source_repo_url") or "")
        base_commit = str(task.metadata.get("base_commit") or "") or None
        run_cmd_dir = str(task.metadata.get("run_cmd_dir") or "") or None
        if repo_url:
            try:
                resolved_source = ensure_source_checkout(
                    workspace_root,
                    repo_url=repo_url,
                    base_commit=base_commit,
                    run_cmd_dir=run_cmd_dir,
                )
                task.source_path = str(resolved_source)
            except Exception as exc:
                result = {
                    "run_id": run_id,
                    "arm": arm,
                    "mode": mode,
                    "split": split,
                    "task_id": task.task_id,
                    "status": "skipped",
                    "reason": f"source_checkout_failed: {exc}",
                }
                write_json(run_dir / "result.json", result)
                return result
        else:
            result = {
                "run_id": run_id,
                "arm": arm,
                "mode": mode,
                "split": split,
                "task_id": task.task_id,
                "status": "skipped",
                "reason": "source_path_unresolved",
            }
            write_json(run_dir / "result.json", result)
            return result

    project_name = project_name_for_task(task, arm)
    budget = default_budget(split, mode)
    commands: list[dict[str, Any]] = []

    create_res = _run_hound_command(
        arm_repo,
        home_dir,
        ["project", "create", project_name, task.source_path],
        timeout_seconds=300,
    )
    commands.append({"step": "project_create", **create_res})
    if create_res["returncode"] != 0:
        result = {
            "run_id": run_id,
            "arm": arm,
            "mode": mode,
            "split": split,
            "task_id": task.task_id,
            "status": "error",
            "failed_step": "project_create",
            "commands": commands,
        }
        write_json(run_dir / "result.json", result)
        return result

    graph_args = ["graph", "build", project_name, "--auto"]
    if config_path:
        graph_args.extend(["--config", str(config_path)])
    graph_res = _run_hound_command(
        arm_repo,
        home_dir,
        graph_args,
        timeout_seconds=60 * max(5, budget),
    )
    commands.append({"step": "graph_build", **graph_res})
    if graph_res["returncode"] != 0:
        result = {
            "run_id": run_id,
            "arm": arm,
            "mode": mode,
            "split": split,
            "task_id": task.task_id,
            "status": "error",
            "failed_step": "graph_build",
            "commands": commands,
        }
        write_json(run_dir / "result.json", result)
        return result

    project_dir = home_dir / ".hound" / "projects" / project_name
    seen_sessions = list_session_ids(project_dir)
    all_session_ids: list[str] = []
    for audit_mode, budget_minutes in build_schedule(mode, budget_minutes=budget):
        audit_args = ["agent", "audit", project_name, "--new-session", "--mode", audit_mode, "--time-limit", str(budget_minutes)]
        if config_path:
            audit_args.extend(["--config", str(config_path)])
        audit_res = _run_hound_command(
            arm_repo,
            home_dir,
            audit_args,
            timeout_seconds=(budget_minutes + 5) * 60,
        )
        commands.append({"step": f"audit_{audit_mode}", **audit_res})
        new_sessions = latest_session_ids(project_dir, seen_sessions)
        all_session_ids.extend(new_sessions)
        seen_sessions |= set(new_sessions)

    observed = extract_observed_findings(project_dir, session_ids=set(all_session_ids))
    matches = match_findings(task.gold_findings, observed, judge=judge)
    metrics = compute_metrics(task.gold_findings, observed, matches)

    submission_dir = ensure_dir(run_dir / "submission")
    submission_md = build_submission_markdown(observed)
    (submission_dir / "audit.md").write_text(submission_md, encoding="utf-8")
    (submission_dir / "audit.json").write_text(
        json.dumps({"findings": [asdict(item) for item in observed]}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    result = {
        "run_id": run_id,
        "arm": arm,
        "mode": mode,
        "split": split,
        "task_id": task.task_id,
        "contest_id": task.contest_id,
        "status": "completed",
        "project_name": project_name,
        "project_dir": str(project_dir),
        "task": asdict(task),
        "session_ids": all_session_ids,
        "metrics": asdict(metrics),
        "matches": [asdict(item) for item in matches],
        "observed_findings": [asdict(item) for item in observed],
        "commands": commands,
        "generated_at": utc_now(),
    }
    write_json(run_dir / "result.json", result)
    return result


def aggregate_results(result_payloads: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in result_payloads:
        if item.get("status") != "completed":
            continue
        key = (str(item.get("arm")), str(item.get("mode")))
        grouped.setdefault(key, []).append(item)

    summary: dict[str, Any] = {"groups": {}, "deltas": {}}
    for key, items in grouped.items():
        arm, mode = key
        total_gold = sum(int(item["metrics"]["gold_total"]) for item in items)
        total_observed = sum(int(item["metrics"]["observed_total"]) for item in items)
        strict_matches = sum(int(item["metrics"]["strict_matches"]) for item in items)
        semantic_matches = sum(int(item["metrics"]["semantic_matches"]) for item in items)
        false_positives = sum(int(item["metrics"]["false_positives"]) for item in items)
        strict_recall = strict_matches / total_gold if total_gold else 0.0
        strict_precision = strict_matches / total_observed if total_observed else 0.0
        semantic_recall = semantic_matches / total_gold if total_gold else 0.0
        semantic_precision = semantic_matches / total_observed if total_observed else 0.0
        strict_f1 = (2 * strict_recall * strict_precision / (strict_recall + strict_precision)) if (strict_recall + strict_precision) else 0.0
        summary["groups"][f"{arm}:{mode}"] = {
            "tasks": len(items),
            "gold_total": total_gold,
            "observed_total": total_observed,
            "strict_matches": strict_matches,
            "semantic_matches": semantic_matches,
            "false_positives": false_positives,
            "strict_recall": strict_recall,
            "strict_precision": strict_precision,
            "strict_f1": strict_f1,
            "semantic_recall": semantic_recall,
            "semantic_precision": semantic_precision,
        }

    for mode in {"cold", "long"}:
        base = summary["groups"].get(f"baseline:{mode}")
        treat = summary["groups"].get(f"treatment:{mode}")
        if not base or not treat:
            continue
        summary["deltas"][mode] = {
            "strict_recall_delta": treat["strict_recall"] - base["strict_recall"],
            "semantic_recall_delta": treat["semantic_recall"] - base["semantic_recall"],
            "strict_precision_delta": treat["strict_precision"] - base["strict_precision"],
            "false_positive_delta": treat["false_positives"] - base["false_positives"],
        }
    return summary


def render_report_markdown(aggregate: dict[str, Any], result_payloads: list[dict[str, Any]]) -> str:
    lines = ["# Hound EVMBench Benchmark Report", ""]
    groups = aggregate.get("groups") or {}
    for key in sorted(groups):
        item = groups[key]
        lines.append(f"## {key}")
        lines.append("")
        lines.append(f"- Tasks: {item['tasks']}")
        lines.append(f"- Strict recall: {item['strict_recall']:.3f}")
        lines.append(f"- Strict precision: {item['strict_precision']:.3f}")
        lines.append(f"- Strict F1: {item['strict_f1']:.3f}")
        lines.append(f"- Semantic recall: {item['semantic_recall']:.3f}")
        lines.append(f"- Semantic precision: {item['semantic_precision']:.3f}")
        lines.append(f"- False positives: {item['false_positives']}")
        lines.append("")
    deltas = aggregate.get("deltas") or {}
    if deltas:
        lines.append("## Treatment Delta")
        lines.append("")
        for mode, item in sorted(deltas.items()):
            lines.append(f"### {mode}")
            lines.append("")
            lines.append(f"- Strict recall delta: {item['strict_recall_delta']:+.3f}")
            lines.append(f"- Semantic recall delta: {item['semantic_recall_delta']:+.3f}")
            lines.append(f"- Strict precision delta: {item['strict_precision_delta']:+.3f}")
            lines.append(f"- False-positive delta: {item['false_positive_delta']:+d}")
            lines.append("")
    lines.append("## Task Results")
    lines.append("")
    for item in result_payloads:
        lines.append(f"- {item.get('task_id')}: {item.get('status')} ({item.get('arm')} / {item.get('mode')})")
    lines.append("")
    return "\n".join(lines)


def load_run_results(workspace_root: Path, run_id: str) -> list[dict[str, Any]]:
    run_root = workspace_root / "runs" / run_id
    if not run_root.exists():
        return []
    payloads: list[dict[str, Any]] = []
    for path in sorted(run_root.glob("**/result.json")):
        payloads.append(read_json(path))
    return payloads
