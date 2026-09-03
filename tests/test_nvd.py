import json
from pathlib import Path
from urllib.request import Request

from threat_to_detection.collectors.nvd import NvdClient


FIXTURE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-TEST-0001",
                "descriptions": [{"lang": "en", "value": "Example issue."}],
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1}}]},
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": (
                                            "cpe:2.3:a:vendor:example-product:1.0:"
                                            "*:*:*:*:*:*:*"
                                        )
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        }
    ]
}


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
