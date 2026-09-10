import json
from pathlib import Path

import yaml

from threat_to_detection.cli import evaluate_scenarios_command

ROOT = Path(__file__).parents[1]


def test_canonical_multidomain_result_matches_scenario_catalog() -> None:
    index = yaml.safe_load(
        (ROOT / "evaluations/scenarios/index.yaml").read_text(encoding="utf-8")
    )
    result = yaml.safe_load(
        (ROOT / "evaluations/multidomain-results.json").read_text(encoding="utf-8")
    )
    expected_ids = [item["id"] for item in index["scenarios"]]
    actual_ids = [item["scenario_id"] for item in result["scenarios"]]

    assert index["evaluation_status"] == "measured_fixture_offline"
    assert actual_ids == expected_ids
    assert result["summary"]["scenario_count"] == len(expected_ids)
    assert result["summary"]["before_candidate_count"] == 6
    assert result["summary"]["applicable_count"] == 6
    assert result["summary"]["blocked_count"] == 0
    assert result["summary"]["unknown_count"] == 0
    assert result["summary"]["candidate_reduction_rate"] == 0.0
    by_id = {item["scenario_id"]: item for item in result["scenarios"]}
    assert all(item["expected_outcome"]["status"] == "not_declared" for item in by_id.values())
    evaluated = result["scenarios"][0]["candidate_evaluations"][0]
    assert evaluated["trace_id"]
    assert evaluated["technique_id"] == "T1059"
    assert evaluated["before_candidate"] is True
    assert evaluated["attack_applicability"]["status"] == "applicable"
    assert evaluated["detection_feasibility"]["status"] == "partial"
    assert "# 多分野シナリオ評価レポート" in (ROOT / "evaluations/report.md").read_text(
        encoding="utf-8"
    )


def test_catalog_evaluation_command_regenerates_all_scenarios(tmp_path: Path) -> None:
    output = tmp_path / "results.json"
    report = tmp_path / "report.md"
    assert evaluate_scenarios_command(
        [
            "--capec-fixture",
            str(ROOT / "tests/fixtures/capec/attack_patterns.xml"),
            "--attack-fixture",
            str(ROOT / "tests/fixtures/attack/enterprise-attack.json"),
            "--nvd-fixture",
            str(ROOT / "tests/fixtures/nvd/cves.json"),
            "--output",
            str(output),
            "--report",
            str(report),
        ]
    ) == 0
    regenerated = json.loads(output.read_text(encoding="utf-8"))
    canonical = json.loads(
        (ROOT / "evaluations/multidomain-results.json").read_text(encoding="utf-8")
    )
    assert regenerated["scenarios"] == canonical["scenarios"]
    assert regenerated["summary"] == canonical["summary"]


def test_condition_fixture_catalog_executes_declared_expected_outcomes(tmp_path: Path) -> None:
    output = tmp_path / "condition-results.json"
    report = tmp_path / "condition-report.md"
    assert evaluate_scenarios_command(
        [
            "--index",
            str(ROOT / "evaluations/scenarios/condition-fixtures.yaml"),
            "--capec-fixture",
            str(ROOT / "tests/fixtures/capec/attack_patterns.xml"),
            "--attack-fixture",
            str(ROOT / "tests/fixtures/attack/enterprise-attack.json"),
            "--nvd-fixture",
            str(ROOT / "tests/fixtures/nvd/cves.json"),
            "--output",
            str(output),
            "--report",
            str(report),
        ]
    ) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    assert all(item["expected_outcome"]["status"] == "passed" for item in result["scenarios"])
