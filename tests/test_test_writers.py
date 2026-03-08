import json
from unittest.mock import patch

from analysis.test_writers import FoundrySkeletonWriter, SkeletonWriterRegistry


def test_foundry_skeleton_writer_generates_manifest_and_test_file(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    src_dir = repo_dir / "src"
    src_dir.mkdir()
    (src_dir / "Counter.sol").write_text(
        """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Counter {
    bool public initialized;
    uint256 public number;

    function initialize() external {
        initialized = true;
    }

    function setNumber(uint256 newNumber) external {
        number = newNumber;
    }

    function increment() external {
        number += 1;
    }
}
""",
        encoding="utf-8",
    )
    session_dir = tmp_path / "session"
    session_dir.mkdir()

    invariants = [
        {
            "invariant_id": "inv_001",
            "statement": "State-changing operations must be gated until initialization is complete.",
            "forbidden_effect": "state write succeeds before initialization",
            "contrast_checks": ["Can any write path bypass initialization guards?"],
        }
    ]

    result = FoundrySkeletonWriter().write(invariants=invariants, project_dir=repo_dir, session_dir=session_dir)

    manifest = json.loads(result["test_skeletons"].read_text(encoding="utf-8"))
    content = result["test_skeleton_main"].read_text(encoding="utf-8")

    assert manifest["harness_type"] == "foundry"
    assert "HoundInvariantSkeleton.t.sol" in manifest["generated_files"][0]
    assert manifest["concrete_tests_generated"] >= 2
    assert "contract HoundInvariantSkeletonTest" in content
    assert 'Counter target = new Counter();' in content
    assert 'require(!ok, "Expected init gate to block Counter.setNumber before initialize");' in content


def test_writer_registry_returns_foundry_writer():
    registry = SkeletonWriterRegistry()

    writer = registry.get("foundry")

    assert writer is not None
    assert writer.harness_type == "foundry"


def test_foundry_writer_normalizes_prompt_style_args():
    writer = FoundrySkeletonWriter()

    assert writer._normalize_plan_args("setNumber(uint256)", "1") == ", 1"
    assert writer._normalize_plan_args("increment()", "()") == ""
    assert writer._normalize_plan_args("upgrade(address,bytes)", 'address(delegateTarget), abi.encodeWithSelector(DelegateTarget.smash.selector, 42)') == ", address(new DelegateTarget()), abi.encodeWithSelector(DelegateTarget.smash.selector, 42)"
    assert writer._normalize_plan_args("batchBump(address[])", "[address(0xBEEF)]") is None
    assert writer._normalize_plan_args("setNumber(uint256)", "uint256(1));") is None


def test_foundry_collect_feedback_parses_pass_and_fail(tmp_path):
    writer = FoundrySkeletonWriter()

    class _Completed:
        def __init__(self, code: int, stdout: str = "", stderr: str = ""):
            self.returncode = code
            self.stdout = stdout
            self.stderr = stderr

    with patch("analysis.test_writers.subprocess.run", side_effect=[
        _Completed(0, stdout="build ok"),
        _Completed(
            1,
            stdout="[PASS] test_case_001() (gas: 1)\n[FAIL: Expected proof case to fail] test_case_002() (gas: 1)\n",
        ),
    ]):
        feedback = writer.collect_feedback(
            project_dir=tmp_path,
            session_dir=tmp_path / "session",
            proof_plan={
                "loop_id": 4,
                "proof_cases": [
                    {"case_id": "case_001", "fingerprint": "fp1"},
                    {"case_id": "case_002", "fingerprint": "fp2"},
                ],
            },
        )

    assert feedback["results"][0]["status"] == "passed"
    assert feedback["results"][1]["status"] == "failed"
