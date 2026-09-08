from pathlib import Path

from threat_to_detection.collectors.attack import AttackDataset
from threat_to_detection.collectors.capec import CapecDataset
from threat_to_detection.models.system import Asset, Software, SystemModel
from threat_to_detection.models.vulnerability import Vulnerability
from threat_to_detection.services.pipeline import run_pipeline


def test_pipeline_matches_product_and_version() -> None:
    system = SystemModel(
        assets=(
            Asset(
                name="web-server",
                type="server",
                software=(Software(name="example-product", version="1.0"),),
            ),
        )
    )
    vulnerabilities = (
        Vulnerability(
            cve_id="CVE-TEST-0001",
            product="example-product",
            affected_versions=("1.0",),
        ),
        Vulnerability(
            cve_id="CVE-TEST-0002",
            product="example-product",
            affected_versions=("2.0",),
        ),
    )

    result = run_pipeline(system, vulnerabilities)

    assert [item.cve_id for item in result.relevant_vulnerabilities["web-server"]] == [
        "CVE-TEST-0001"
    ]


def test_pipeline_connects_cve_to_detection_requirement() -> None:
    fixtures = Path(__file__).parent / "fixtures"
    system = SystemModel(
        assets=(
            Asset(
                name="web-server",
                software=(Software(product="example-product", version="1.0"),),
            ),
        )
    )
    vulnerability = Vulnerability(
        cve_id="CVE-TEST-0001",
        product="example-product",
        affected_versions=("1.0",),
        cwes=("CWE-89",),
    )

    result = run_pipeline(
        system,
        (vulnerability,),
        capec_dataset=CapecDataset.from_xml(fixtures / "capec/attack_patterns.xml"),
        attack_dataset=AttackDataset.from_json(fixtures / "attack/enterprise-attack.json"),
    )

    assert result.detection_requirements["web-server"][0].technique_id == "T1059"
