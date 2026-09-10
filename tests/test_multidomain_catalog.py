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
