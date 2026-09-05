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
