import json
from pathlib import Path

from threat_to_detection.cli import evaluate_cves_command
from threat_to_detection.collectors.attack import AttackDataset
from threat_to_detection.collectors.capec import CapecDataset
from threat_to_detection.models.vulnerability import Vulnerability
from threat_to_detection.services.cve_evaluation import (
    ATTACK_TO_DETECTION,
    CAPEC_TO_ATTACK,
    CVE_TO_CWE,
    CWE_TO_CAPEC,
    evaluate_cves,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _datasets() -> tuple[CapecDataset, AttackDataset]:
    return (
        CapecDataset.from_xml(FIXTURES / "capec/attack_patterns.xml"),
        AttackDataset.from_json(FIXTURES / "attack/enterprise-attack.json"),
    )


def test_evaluation_records_reached_stage_counts_and_all_branch_gaps() -> None:
    capec, attack = _datasets()
    result = evaluate_cves(
        (
            Vulnerability(cve_id="CVE-DETECTION", product="fixture", cwes=("CWE-79",)),
            Vulnerability(cve_id="CVE-ATTACK", product="fixture", cwes=("CWE-79",)),
            Vulnerability(cve_id="CVE-CAPEC", product="fixture", cwes=("CWE-999",)),
            Vulnerability(cve_id="CVE-CWE", product="fixture", cwes=("CWE-89",)),
            Vulnerability(
                cve_id="CVE-NO-CWE",
                product="fixture",
                cwes=("NVD-CWE-noinfo", "NVD-CWE-Other"),
            ),
        ),
        categories={
            "CVE-DETECTION": "web_application_foundation",
            "CVE-ATTACK": "web_application_foundation",
            "CVE-CAPEC": "os_system_foundation",
            "CVE-CWE": "client_endpoint",
            "CVE-NO-CWE": "database_data_platform",
        },
        capec_dataset=capec,
        attack_dataset=attack,
    )

    by_id = {record.cve_id: record for record in result.records}
    assert by_id["CVE-DETECTION"].reached_stage == "detection"
    assert by_id["CVE-DETECTION"].cwe_count == 1
    assert by_id["CVE-DETECTION"].capec_count == 2
    assert by_id["CVE-DETECTION"].attack_count == 2
    assert by_id["CVE-DETECTION"].detection_count == 1
    assert {gap.stage for gap in by_id["CVE-DETECTION"].mapping_gaps} == {
        CAPEC_TO_ATTACK,
        ATTACK_TO_DETECTION,
    }
    assert by_id["CVE-ATTACK"].reached_stage == "detection"
    assert by_id["CVE-CAPEC"].reached_stage == "cwe"
    assert by_id["CVE-CWE"].reached_stage == "detection"
    assert by_id["CVE-NO-CWE"].reached_stage == "cve"
    assert [gap.stage for gap in by_id["CVE-NO-CWE"].mapping_gaps] == [CVE_TO_CWE]


def test_evaluation_uses_different_denominators_for_cumulative_and_transitional_rates() -> None:
    capec, attack = _datasets()
    result = evaluate_cves(
        (
            Vulnerability(cve_id="CVE-1", product="fixture", cwes=("CWE-79",)),
            Vulnerability(cve_id="CVE-2", product="fixture", cwes=("CWE-999",)),
            Vulnerability(cve_id="CVE-3", product="fixture", cwes=()),
        ),
        capec_dataset=capec,
        attack_dataset=attack,
    )

    metrics = result.to_mapping()["metrics"]
    assert metrics["cumulative"]["cve"] == {"reached_count": 3, "rate": 1.0}
    assert metrics["cumulative"]["cwe"] == {"reached_count": 2, "rate": 2 / 3}
    assert metrics["cumulative"]["capec"] == {"reached_count": 1, "rate": 1 / 3}
    assert metrics["transitions"][CWE_TO_CAPEC] == {
        "from_count": 2,
        "reached_count": 1,
        "rate": 0.5,
    }
    assert metrics["transitions"][CAPEC_TO_ATTACK] == {
        "from_count": 1,
        "reached_count": 1,
        "rate": 1.0,
    }

    empty_path = evaluate_cves(
        (Vulnerability(cve_id="CVE-EMPTY", product="fixture"),),
        capec_dataset=capec,
        attack_dataset=attack,
    )
    assert empty_path.to_mapping()["metrics"]["transitions"][ATTACK_TO_DETECTION]["rate"] is None


def test_evaluation_preserves_a_successful_branch_when_another_branch_gaps() -> None:
    capec, attack = _datasets()
    result = evaluate_cves(
        (Vulnerability(cve_id="CVE-BRANCHES", product="fixture", cwes=("CWE-79", "CWE-999")),),
        capec_dataset=capec,
        attack_dataset=attack,
    )

    record = result.records[0]
    assert record.reached_stage == "detection"
    assert any(gap.stage == CWE_TO_CAPEC and gap.source == "CWE-999" for gap in record.mapping_gaps)


def test_reached_stage_can_stop_at_attack_or_capec(tmp_path: Path) -> None:
    capec, attack = _datasets()
    vulnerability = Vulnerability(cve_id="CVE-STOP", product="fixture", cwes=("CWE-79",))

    attack_document = json.loads(
        (FIXTURES / "attack/enterprise-attack.json").read_text(encoding="utf-8")
    )
    for item in attack_document["objects"]:
        if item.get("type") == "relationship" and item.get("relationship_type") == "detects":
            item["revoked"] = True
    attack_path = tmp_path / "attack-without-detection.json"
    attack_path.write_text(json.dumps(attack_document), encoding="utf-8")
    attack_only = evaluate_cves(
        (vulnerability,),
        capec_dataset=capec,
        attack_dataset=AttackDataset.from_json(attack_path),
    )
    assert attack_only.records[0].reached_stage == "attack"

    capec_only_document = {
        "objects": [
            item
            for item in attack_document["objects"]
            if item.get("type") not in {"attack-pattern", "relationship"}
        ]
    }
    capec_only_path = tmp_path / "attack-without-techniques.json"
    capec_only_path.write_text(json.dumps(capec_only_document), encoding="utf-8")
    capec_only = evaluate_cves(
        (vulnerability,),
        capec_dataset=capec,
        attack_dataset=AttackDataset.from_json(capec_only_path),
    )
    assert capec_only.records[0].reached_stage == "capec"


def test_evaluate_command_writes_machine_readable_output(tmp_path: Path) -> None:
    selection = tmp_path / "selection.json"
    selection.write_text(
        json.dumps(
            {
                "selected": [
                    {
                        "cve_id": "CVE-TEST-0001",
                        "category": "web_application_foundation",
                        "vendor": "fixture-vendor",
                        "product": "fixture",
                        "cwes": ["CWE-79"],
                    },
                    {
                        "cve_id": "CVE-TEST-0002",
                        "category": "os_system_foundation",
                        "vendor": "fixture-vendor",
                        "product": "fixture",
                        "cwes": ["NVD-CWE-noinfo"],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "evaluation.json"

    assert (
        evaluate_cves_command(
            [
                "--selection",
                str(selection),
                "--capec-fixture",
                str(FIXTURES / "capec/attack_patterns.xml"),
                "--attack-fixture",
                str(FIXTURES / "attack/enterprise-attack.json"),
                "--output",
                str(output),
            ]
        )
        == 0
    )

    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["evaluation"]["population"] == 2
    assert document["source"]["capec"]["sha256"]
    assert document["source"]["attack"]["sha256"]
    assert document["metrics"]["final_stage_counts"] == {
        "cve": 1,
        "cwe": 0,
        "capec": 0,
        "attack": 0,
        "detection": 1,
    }
