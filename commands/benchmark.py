"""Benchmark CLI helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from analysis.benchmarking import (
    DEFAULT_BASELINE_REF,
    DeterministicJudge,
    aggregate_results,
    default_workspace_root,
    load_run_results,
    manifest_tasks,
    prepare_workspace,
    render_report_markdown,
    repo_paths,
    run_task_benchmark,
    write_json,
)

console = Console()


def _workspace(path: Path | None) -> Path:
    return path or default_workspace_root()


def prepare_cmd(workspace_root: Path | None, split: str) -> dict[str, Any]:
    root = _workspace(workspace_root)
    manifest = prepare_workspace(root)
    tasks = []
    if split in {"debug", "detect"}:
        tasks = manifest_tasks(root, split)
    elif split == "all":
        tasks.extend(manifest_tasks(root, "debug"))
        tasks.extend(manifest_tasks(root, "detect"))
    console.print(f"[green]Prepared benchmark workspace:[/green] {root}")
    if tasks:
        console.print(f"[cyan]Manifested {len(tasks)} tasks[/cyan] for split '{split}'")
    return {"workspace_root": str(root), "manifest": manifest, "tasks": len(tasks)}


def run_cmd(
    *,
    workspace_root: Path | None,
    split: str,
    arm: str,
    mode: str,
    config_path: Path | None,
    limit: int | None,
    baseline_ref: str = DEFAULT_BASELINE_REF,
) -> dict[str, Any]:
    root = _workspace(workspace_root)
    repos = repo_paths(root)
    if not repos["frontier_evals"].exists():
        raise RuntimeError("Benchmark workspace is not prepared. Run 'hound benchmark evmbench prepare' first.")
    tasks = manifest_tasks(root, split)
    if limit:
        tasks = tasks[:limit]
    arms = ["baseline", "treatment"] if arm == "both" else [arm]
    modes = ["cold", "long"] if mode == "both" else [mode]
    judge = DeterministicJudge()
    results = []
    repo_root = Path(__file__).resolve().parent.parent
    run_id = None
    for selected_arm in arms:
        for selected_mode in modes:
            for task in tasks:
                payload = run_task_benchmark(
                    repo_root=repo_root,
                    workspace_root=root,
                    task=task,
                    arm=selected_arm,
                    mode=selected_mode,
                    config_path=config_path,
                    split=split,
                    baseline_ref=baseline_ref,
                    judge=judge,
                )
                run_id = payload.get("run_id") or run_id
                results.append(payload)
                console.print(
                    f"[cyan]{task.task_id}[/cyan] {selected_arm}/{selected_mode}: "
                    f"{payload.get('status')} strict="
                    f"{payload.get('metrics', {}).get('strict_matches', 0)}/"
                    f"{payload.get('metrics', {}).get('gold_total', 0)}"
                )

    aggregate = aggregate_results(results)
    if run_id is None:
        run_id = "unknown"
    out_dir = root / "runs" / run_id
    write_json(out_dir / "aggregate.json", aggregate)
    (out_dir / "report.md").write_text(render_report_markdown(aggregate, results), encoding="utf-8")
    console.print(f"[green]Benchmark run complete:[/green] {out_dir}")
    return {"run_id": run_id, "results": results, "aggregate": aggregate}


def report_cmd(workspace_root: Path | None, run_id: str) -> dict[str, Any]:
    root = _workspace(workspace_root)
    payloads = load_run_results(root, run_id)
    if not payloads:
        raise RuntimeError(f"No benchmark results found for run_id '{run_id}'")
    aggregate = aggregate_results(payloads)
    report_md = render_report_markdown(aggregate, payloads)
    out_dir = root / "runs" / run_id
    write_json(out_dir / "aggregate.json", aggregate)
    (out_dir / "report.md").write_text(report_md, encoding="utf-8")

    table = Table(title=f"EVMBench Benchmark {run_id}")
    table.add_column("Group")
    table.add_column("Tasks", justify="right")
    table.add_column("Strict Recall", justify="right")
    table.add_column("Semantic Recall", justify="right")
    table.add_column("FP", justify="right")
    for group, item in sorted((aggregate.get("groups") or {}).items()):
        table.add_row(
            group,
            str(item["tasks"]),
            f"{item['strict_recall']:.3f}",
            f"{item['semantic_recall']:.3f}",
            str(item["false_positives"]),
        )
    console.print(table)
    if aggregate.get("deltas"):
        console.print("[bold]Deltas[/bold]")
        console.print(json.dumps(aggregate["deltas"], indent=2))
    console.print(f"[green]Wrote report:[/green] {out_dir / 'report.md'}")
    return {"aggregate": aggregate, "report_path": str(out_dir / "report.md")}

