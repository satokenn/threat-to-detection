import json
from pathlib import Path
from urllib.request import Request

from threat_to_detection.collectors.nvd import NvdClient
from threat_to_detection.models.system import Asset, Software, SystemModel


FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures/nvd/cves.json").read_text(encoding="utf-8")
)


def test_nvd_response_is_normalized_and_cached(tmp_path: Path) -> None:
    calls: list[Request] = []

    def opener(request: Request, timeout: float) -> dict:
        calls.append(request)
        return FIXTURE

    client = NvdClient(cache_dir=tmp_path, opener=opener)
    first = client.search_cves(cpe_name="cpe:2.3:a:vendor:example-product:1.0:*:*:*:*:*:*:*")
    second = client.search_cves(cpe_name="cpe:2.3:a:vendor:example-product:1.0:*:*:*:*:*:*:*")

    assert first[0].cve_id == "CVE-TEST-0001"
    assert first[0].product == "example-product"
    assert first[0].affected_versions == ("1.0",)
    assert first[0].cwes == ("CWE-79",)
    assert first[0].cvss_score == 8.1
    assert second == first
    assert len(calls) == 1


def test_api_key_is_sent_in_header() -> None:
    captured: list[Request] = []

    def opener(request: Request, timeout: float) -> dict:
        captured.append(request)
        return {"vulnerabilities": []}

    NvdClient(api_key="secret", cache_dir=None, opener=opener).search_cves(cve_id="CVE-TEST-0001")

    assert captured[0].headers["Apikey"] == "secret"


def test_search_for_software_uses_generated_cpe() -> None:
    captured: list[Request] = []

    def opener(request: Request, timeout: float) -> dict:
        captured.append(request)
        return {"vulnerabilities": []}

    client = NvdClient(cache_dir=None, opener=opener)
    client.search_for_software(
        Software(vendor="apache", product="http_server", version="2.4.58")
    )

    assert "cpeName=cpe%3A2.3%3Aa%3Aapache%3Ahttp_server%3A2.4.58" in captured[0].full_url


def test_search_for_system_fetches_each_asset_and_deduplicates() -> None:
    calls: list[Request] = []

    def opener(request: Request, timeout: float) -> dict:
        calls.append(request)
        return FIXTURE

    system = SystemModel(
        assets=(
            Asset(
                name="web-server",
                software=(
                    Software(vendor="vendor", product="example-product", version="1.0"),
                    Software(vendor="vendor", product="example-product", version="1.0"),
                ),
            ),
        )
    )
    result = NvdClient(cache_dir=None, opener=opener).search_for_system(system)

    assert [item.cve_id for item in result["web-server"]] == ["CVE-TEST-0001"]
    assert len(calls) == 2
