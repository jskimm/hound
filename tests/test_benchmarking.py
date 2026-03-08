import json
from pathlib import Path

from analysis.benchmarking import (
    BenchmarkTask,
    DeterministicJudge,
    GoldFinding,
    ObservedFinding,
    aggregate_results,
    build_schedule,
    cached_source_checkout_path,
    compute_metrics,
    extract_observed_findings,
    infer_source_repo_url,
    load_task,
    match_findings,
    parse_split_file,
    project_name_for_task,
    render_report_markdown,
)


def test_parse_split_file_ignores_comments_and_blank_lines(tmp_path):
    split = tmp_path / "debug.txt"
    split.write_text("\n# comment\ncontest-a\n\ncontest-b\n", encoding="utf-8")

    assert parse_split_file(split) == ["contest-a", "contest-b"]


def test_load_task_parses_config_and_findings(tmp_path):
    task_dir = tmp_path / "contest-a"
    findings_dir = task_dir / "findings"
    findings_dir.mkdir(parents=True)
    (task_dir / "src").mkdir()
    (task_dir / "config.yaml").write_text("name: Contest A\ncontest_id: contest-a\n", encoding="utf-8")
    (findings_dir / "H-01.md").write_text("# Critical auth bug\n\nUnauthorized drain.", encoding="utf-8")
    (findings_dir / "M-02.md").write_text("# Math issue\n\nRounding leak.", encoding="utf-8")

    task = load_task(task_dir, split="debug")

    assert task.task_id == "contest-a"
    assert task.contest_id == "contest-a"
    assert task.source_path.endswith("src")
    assert len(task.gold_findings) == 2
    assert task.gold_findings[0].severity == "high"
    assert task.gold_findings[1].severity == "medium"


def test_infer_source_repo_url_from_findings(tmp_path):
    task_dir = tmp_path / "contest-a"
    findings_dir = task_dir / "findings"
    findings_dir.mkdir(parents=True)
    (findings_dir / "H-01.md").write_text(
        "# Title\n\nSee https://github.com/acme/vault/blob/abcdef/src/Vault.sol#L1-L10",
        encoding="utf-8",
    )

    assert infer_source_repo_url(task_dir) == "https://github.com/acme/vault.git"


def test_extract_observed_findings_filters_by_session(tmp_path):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    payload = {
        "hypotheses": {
            "hyp_1": {
                "id": "hyp_1",
                "title": "Auth bypass",
                "description": "Unauthorized caller can drain",
                "vulnerability_type": "access_control",
                "severity": "high",
                "confidence": 0.91,
                "status": "proposed",
                "session_id": "sess_keep",
                "affected_code": ["src/Vault.sol:withdraw"],
                "evidence": [{"description": "trace"}],
            },
            "hyp_2": {
                "id": "hyp_2",
                "title": "Ignored",
                "description": "Other session",
                "vulnerability_type": "other",
                "severity": "low",
                "confidence": 0.2,
                "status": "proposed",
                "session_id": "sess_skip",
            },
        }
    }
    (project_dir / "hypotheses.json").write_text(json.dumps(payload), encoding="utf-8")

    findings = extract_observed_findings(project_dir, session_ids={"sess_keep"})

    assert len(findings) == 1
    assert findings[0].finding_id == "hyp_1"
    assert findings[0].supporting_evidence


def test_match_findings_and_metrics():
    gold = [
        GoldFinding(
            finding_id="H-01",
            title="Unauthorized withdraw",
            severity="high",
            description="Unauthorized caller can withdraw assets",
            affected_files=["src/Vault.sol:withdraw"],
        )
    ]
    observed = [
        ObservedFinding(
            finding_id="hyp_1",
            title="Unauthorized withdraw",
            description="Unauthorized caller can withdraw assets",
            vulnerability_type="access_control",
            severity="high",
            confidence=0.9,
            affected_code=["src/Vault.sol:withdraw"],
            supporting_evidence=[{"type": "trace"}],
        ),
        ObservedFinding(
            finding_id="hyp_2",
            title="Noise",
            description="Unrelated report",
            vulnerability_type="unknown",
            severity="low",
            confidence=0.1,
        ),
    ]

    matches = match_findings(gold, observed, judge=DeterministicJudge())
    metrics = compute_metrics(gold, observed, matches)

    assert len(matches) == 1
    assert matches[0].strict_match is True
    assert metrics.strict_matches == 1
    assert metrics.false_positives == 1
    assert metrics.proof_backed_strict_matches == 1


def test_build_schedule_shapes_modes():
    assert build_schedule("cold", budget_minutes=5) == [("sweep", 5)]
    assert build_schedule("long", budget_minutes=20) == [("sweep", 20), ("intuition", 20), ("intuition", 20)]


def test_aggregate_results_and_render_report():
    task = BenchmarkTask(task_id="contest-a", contest_id="contest-a", split="debug", task_dir="/tmp/contest-a", source_path="/tmp/contest-a/src")
    payloads = [
        {
            "task_id": task.task_id,
            "status": "completed",
            "arm": "baseline",
            "mode": "cold",
            "metrics": {
                "gold_total": 2,
                "observed_total": 2,
                "strict_matches": 1,
                "semantic_matches": 1,
                "false_positives": 1,
            },
        },
        {
            "task_id": task.task_id,
            "status": "completed",
            "arm": "treatment",
            "mode": "cold",
            "metrics": {
                "gold_total": 2,
                "observed_total": 2,
                "strict_matches": 2,
                "semantic_matches": 2,
                "false_positives": 0,
            },
        },
    ]

    aggregate = aggregate_results(payloads)
    report = render_report_markdown(aggregate, payloads)

    assert aggregate["groups"]["baseline:cold"]["strict_recall"] == 0.5
    assert aggregate["groups"]["treatment:cold"]["strict_recall"] == 1.0
    assert aggregate["deltas"]["cold"]["strict_recall_delta"] == 0.5
    assert "treatment:cold" in report


def test_project_name_for_task_is_stable():
    task = BenchmarkTask(task_id="Pool Together", contest_id="pool", split="debug", task_dir="/tmp/x", source_path="/tmp/y")
    assert project_name_for_task(task, "baseline") == "evmbench-pool-together-baseline"


def test_cached_source_checkout_path_uses_commit_and_run_dir(tmp_path):
    path = cached_source_checkout_path(
        tmp_path,
        repo_url="https://github.com/acme/vault.git",
        base_commit="abcdef1234567890",
        run_cmd_dir="vault",
    )
    assert str(path).endswith("acme-vault-abcdef123456/vault")
