from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from threat_to_detection.cli import visualize_evaluations_command
from threat_to_detection.services.visualization import (
    aggregate_evaluation_a,
    aggregate_evaluation_b,
    generate_evaluation_visualizations,
)

SCENARIOS = (
    "scenario-01-cve-example-process",
    "scenario-03-malware-process-execution",
    "scenario-04-malware-ingress-transfer",
    "scenario-05-malware-staged-behavior",
)


def _evaluation_a() -> dict:
    return {
        "records": [
            {
                "cve_id": "CVE-1",
                "cwe_reached": True,
                "capec_reached": True,
                "attack_reached": True,
                "detection_reached": True,
            },
            {
                "cve_id": "CVE-2",
                "cwe_reached": True,
                "capec_reached": True,
                "attack_reached": True,
                "detection_reached": False,
            },
            {
                "cve_id": "CVE-3",
                "cwe_reached": True,
                "capec_reached": False,
                "attack_reached": False,
                "detection_reached": False,
            },
            {
                "cve_id": "CVE-4",
                "cwe_reached": False,
                "capec_reached": False,
                "attack_reached": False,
                "detection_reached": False,
            },
        ]
    }


def _evaluation_b() -> dict:
    return {
        "scenarios": [
            {
                "scenario_id": SCENARIOS[0],
                "candidate_evaluations": [
                    {"applicability_status": "applicable"},
                    {
                        "applicability_status": "blocked",
                        "blocked_reason": "communication_path",
                    },
                    {
                        "applicability_status": "unknown",
                        "unknown_reasons": ["trust_boundary", "authentication"],
                    },
                ],
            },
            {
                "scenario_id": SCENARIOS[1],
                "candidate_evaluations": [
                    {"attack_applicability": {"status": "applicable"}},
                    {
                        "attack_applicability": {
                            "status": "blocked",
                            "blocked_reasons": ["privilege"],
                        }
                    },
                ],
            },
            {
                "scenario_id": SCENARIOS[2],
                "before_candidate_count": 2,
                "applicable_count": 1,
                "blocked_count": 0,
                "unknown_count": 1,
                "unknown_reasons": {"authentication_information": 1},
            },
            {
                "scenario_id": SCENARIOS[3],
                "candidate_evaluations": [],
            },
        ]
    }


def test_evaluation_a_uses_stage_specific_denominators() -> None:
    result = aggregate_evaluation_a(_evaluation_a())

    assert [item["reached_count"] for item in result["cumulative"]] == [3, 2, 2, 1]
    assert [item["denominator"] for item in result["transitions"]] == [4, 3, 2, 2]
    assert [item["reached_count"] for item in result["transitions"]] == [3, 2, 2, 1]
    assert result["transitions"][1]["rate"] == pytest.approx(2 / 3)


def test_evaluation_b_keeps_unknown_separate_and_normalizes_reasons() -> None:
    result = aggregate_evaluation_b(_evaluation_b(), scenario_ids=SCENARIOS)

    first = result["scenarios"][0]
    assert first["before_candidate_count"] == 3
    assert first["blocked_count"] == 1
    assert first["unknown_count"] == 1
    assert result["totals"] == {
        "before_candidate_count": 7,
        "applicable_count": 3,
        "blocked_count": 2,
        "unknown_count": 2,
        "candidate_reduction_rate": pytest.approx(2 / 7),
    }
    reasons = {
        (row["reason"], row["blocked_count"], row["unknown_count"])
        for row in result["reasons"]
    }
    assert ("communication_path", 1, 0) in reasons
    assert ("authentication_information", 0, 1) in reasons


def test_visualization_command_writes_four_svg_figures_and_aggregates(tmp_path: Path) -> None:
    evaluation_a = tmp_path / "evaluation-a.json"
    evaluation_b = tmp_path / "evaluation-b.json"
    evaluation_a.write_text(json.dumps(_evaluation_a()), encoding="utf-8")
    evaluation_b.write_text(json.dumps(_evaluation_b()), encoding="utf-8")
    output = tmp_path / "results"

    assert visualize_evaluations_command(
        [
            "--evaluation-a",
            str(evaluation_a),
            "--evaluation-b",
            str(evaluation_b),
            "--output-dir",
            str(output),
        ]
    ) == 0

    figures = sorted((output / "figures").glob("*.svg"))
    assert [path.name for path in figures] == [
        "applicability_reasons.svg",
        "cumulative_reachability.svg",
        "stage_reachability.svg",
        "threat_model_applicability.svg",
    ]
    assert all(
        "<svg" in path.read_text(encoding="utf-8")
        and "{left}" not in path.read_text(encoding="utf-8")
        for path in figures
    )
    summary = json.loads((output / "aggregates/evaluation-summary.json").read_text())
    assert summary["evaluation_a"]["population"] == 4
    with (output / "aggregates/evaluation_a_summary.csv").open(
        newline="", encoding="utf-8"
    ) as stream:
        rows = list(csv.DictReader(stream))
    assert rows[0]["reached_count"] == "3"
    assert rows[4]["denominator"] == "4"


def test_empty_evaluations_still_generate_charts(tmp_path: Path) -> None:
    evaluation_a = tmp_path / "a.json"
    evaluation_b = tmp_path / "b.json"
    evaluation_a.write_text(json.dumps({"records": []}), encoding="utf-8")
    evaluation_b.write_text(json.dumps({"scenarios": []}), encoding="utf-8")

    paths = generate_evaluation_visualizations(evaluation_a, evaluation_b, tmp_path / "out")

    assert len(paths) == 7
    assert all(path.is_file() for path in paths.values())
    assert aggregate_evaluation_a({"records": []})["transitions"][0]["rate"] is None


def test_evaluation_b_rejects_inconsistent_summary_counts() -> None:
    document = {
        "scenarios": [
            {
                "scenario_id": SCENARIOS[0],
                "before_candidate_count": 2,
                "applicable_count": 1,
                "blocked_count": 0,
                "unknown_count": 0,
            }
        ]
    }

    with pytest.raises(ValueError, match="inconsistent applicability counts"):
        aggregate_evaluation_b(document, scenario_ids=(SCENARIOS[0],))


def test_evaluation_b_rejects_non_evaluation_scenario_output() -> None:
    document = {"scenarios": [{"scenario_id": SCENARIOS[0], "trace_paths": 1}]}

    with pytest.raises(ValueError, match="no threat-model candidate data"):
        aggregate_evaluation_b(document, scenario_ids=(SCENARIOS[0],))
