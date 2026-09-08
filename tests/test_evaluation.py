from __future__ import annotations

import json
from pathlib import Path

import yaml

from threat_to_detection.cli import analyze_scenario
from threat_to_detection.reporters.sigma import (
    detection_requirement_to_sigma,
    sigma_rule_matches_event,
)


def test_reproducible_evaluation_records_all_stage_counts(tmp_path: Path) -> None:
    fixtures = Path(__file__).parent / "fixtures"
    output_dir = tmp_path / "output"

    assert analyze_scenario(
        [
            str(Path(__file__).parents[1] / "evaluations/scenario.yaml"),
            "--nvd-fixture",
            str(fixtures / "nvd/cves.json"),
            "--capec-fixture",
            str(fixtures / "capec/attack_patterns.xml"),
            "--attack-fixture",
            str(fixtures / "attack/enterprise-attack.json"),
            "--offline",
            "--output-dir",
            str(output_dir),
        ]
    ) == 0

    document = json.loads((output_dir / "analysis.json").read_text(encoding="utf-8"))
    asset = document["assets"]["web-server"]
    assert document["status"] == "partial"
    assert len(asset["vulnerabilities"]) == 1
    assert asset["intermediate"] == {
        "cwe_ids": ["CWE-79"],
        "capec_ids": ["CAPEC-100", "CAPEC-101"],
        "technique_ids": ["T1059", "T1105"],
    }
    assert len(asset["detection_requirements"]) == 1
    assert len(asset["sigma_rules"]) == 1
    assert len(asset["trace_paths"]) == 1
    assert len(document["mapping_gaps"]) == 2


def test_evaluation_samples_satisfy_the_generated_candidate(tmp_path: Path) -> None:
    fixtures = Path(__file__).parent / "fixtures"
    output_dir = tmp_path / "output"
    assert analyze_scenario(
        [
            str(Path(__file__).parents[1] / "evaluations/scenario.yaml"),
            "--nvd-fixture",
            str(fixtures / "nvd/cves.json"),
            "--capec-fixture",
            str(fixtures / "capec/attack_patterns.xml"),
            "--attack-fixture",
            str(fixtures / "attack/enterprise-attack.json"),
            "--offline",
            "--output-dir",
            str(output_dir),
        ]
    ) == 0
    sigma = yaml.safe_load(
        next(output_dir.glob("sigma/*.yml")).read_text(encoding="utf-8")
    )
    selection = sigma["detection"]["selection"]
    assert selection == {"EventID": 1, "process.command_line|exists": True}

    # Reconstruct only the generated predicates to keep this test independent
    # of the current output directory's absolute location.
    from threat_to_detection.models.detection import (
        DataComponent,
        DetectionAnalytic,
        DetectionRequirement,
    )

    requirement = DetectionRequirement(
        technique_id="T1059",
        strategy_id="DET0001",
        strategy_name="Process execution monitoring",
        analytics=(DetectionAnalytic(
            analytic_id="AN0001",
            name="Process analytic",
            data_components=(DataComponent(component_id="DC0001", name="Process Creation"),),
            events=("Event ID 1",),
            fields=("process.command_line",),
        ),),
    )
    rule = detection_requirement_to_sigma(requirement)
    positive = json.loads(Path("evaluations/samples/positive.jsonl").read_text())
    negative = json.loads(Path("evaluations/samples/negative.jsonl").read_text())
    assert sigma_rule_matches_event(rule, positive)
    assert not sigma_rule_matches_event(rule, negative)
