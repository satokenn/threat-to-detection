"""Client and normalizer for the NVD CVE 2.0 API.

The client uses only the Python standard library so that the collector remains
easy to run in a small course project. HTTP access is injectable for tests.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from threat_to_detection.models.vulnerability import Vulnerability


NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
JsonLoader = Callable[[Request, float], Any]


class NvdApiError(RuntimeError):
    """Raised when the NVD API cannot return a valid response."""


class NvdRateLimitError(NvdApiError):
    """Raised when retries for an NVD rate limit are exhausted."""


class NvdClient:
    """Small NVD API 2.0 client with optional response caching."""

    def __init__(
        self,
        api_key: str | None = None,
        cache_dir: str | Path | None = "data/cache/nvd",
        timeout: float = 30.0,
        max_retries: int = 2,
        sleep: Callable[[float], None] = time.sleep,
        opener: JsonLoader | None = None,
    ) -> None:
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.timeout = timeout
        self.max_retries = max_retries
        self.sleep = sleep
        self._opener = opener or self._open_json

    def search_cves(
        self,
        *,
        cve_id: str | None = None,
        cpe_name: str | None = None,
        keyword: str | None = None,
        start_index: int = 0,
        results_per_page: int = 100,
    ) -> tuple[Vulnerability, ...]:
        """Search CVEs and return normalized vulnerability models.

        NVD allows one primary search selector per request. Supplying multiple
        selectors is rejected to avoid silently changing the search semantics.
        """
        selectors = [value for value in (cve_id, cpe_name, keyword) if value]
        if len(selectors) > 1:
            raise ValueError("Provide only one of cve_id, cpe_name, or keyword")
        if start_index < 0 or results_per_page <= 0:
            raise ValueError("start_index must be >= 0 and results_per_page must be > 0")
        if results_per_page > 2_000:
            raise ValueError("results_per_page must be <= 2000")

        params = {
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
        }
        if cve_id:
            params["cveId"] = cve_id
        elif cpe_name:
            params["cpeName"] = cpe_name
        elif keyword:
            params["keywordSearch"] = keyword

        payload = self._request(params)
        vulnerabilities = payload.get("vulnerabilities", [])
        return tuple(_normalize(item["cve"]) for item in vulnerabilities if "cve" in item)

    def fetch_all(self, **search: str) -> tuple[Vulnerability, ...]:
        """Fetch all pages for a search selector."""
        start_index = 0
        page_size = 2_000
        results: list[Vulnerability] = []
        while True:
            page = self.search_cves(
                **search, start_index=start_index, results_per_page=page_size
            )
            results.extend(page)
            if len(page) < page_size:
                return tuple(results)
            start_index += page_size

    def _request(self, params: dict[str, Any]) -> dict[str, Any]:
        query = urlencode(params)
        cache_path = self._cache_path(query)
        if cache_path and cache_path.exists():
            return json.loads(cache_path.read_text(encoding="utf-8"))

        request = Request(f"{NVD_CVE_URL}?{query}", headers=self._headers())
        for attempt in range(self.max_retries + 1):
            try:
                payload = self._opener(request, self.timeout)
                if not isinstance(payload, dict) or "vulnerabilities" not in payload:
                    raise NvdApiError("NVD response did not contain vulnerabilities")
                if cache_path:
                    cache_path.parent.mkdir(parents=True, exist_ok=True)
                    cache_path.write_text(json.dumps(payload), encoding="utf-8")
                return payload
            except HTTPError as error:
                if error.code != 429:
                    raise NvdApiError(f"NVD API returned HTTP {error.code}") from error
                if attempt >= self.max_retries:
                    raise NvdRateLimitError("NVD rate limit retries exhausted") from error
                retry_after = error.headers.get("Retry-After") if error.headers else None
                self.sleep(float(retry_after) if retry_after else 1.0 * (attempt + 1))
            except (URLError, TimeoutError) as error:
                raise NvdApiError("Could not connect to the NVD API") from error
        raise AssertionError("unreachable")

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": "threat-to-detection/0.1"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _cache_path(self, query: str) -> Path | None:
        if not self.cache_dir:
            return None
        digest = hashlib.sha256(query.encode("utf-8")).hexdigest()[:20]
        return self.cache_dir / f"{digest}.json"

    @staticmethod
    def _open_json(request: Request, timeout: float) -> dict[str, Any]:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed NVD URL
            return json.load(response)


def _normalize(cve: dict[str, Any]) -> Vulnerability:
    descriptions = cve.get("descriptions", [])
    description = next(
        (item.get("value", "") for item in descriptions if item.get("lang") == "en"),
        "",
    )
    cwes = tuple(
        description_item["value"]
        for weakness in cve.get("weaknesses", [])
        for description_item in weakness.get("description", [])
        if description_item.get("lang") == "en" and description_item.get("value")
    )
    score = _cvss_score(cve.get("metrics", {}))
    product, versions = _affected_software(cve.get("configurations", []))
    return Vulnerability(
        cve_id=cve["id"],
        product=product,
        affected_versions=versions,
        description=description,
        cwes=cwes,
        cvss_score=score,
    )


def _cvss_score(metrics: dict[str, Any]) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            return entries[0].get("cvssData", {}).get("baseScore")
    return None


def _affected_software(configurations: list[dict[str, Any]]) -> tuple[str, tuple[str, ...]]:
    """Extract one representative product/version from NVD CPE matches.

    The full CPE applicability tree is intentionally preserved for a later
    matcher; this MVP exposes the first concrete product and version only.
    """
    for configuration in configurations:
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) > 5:
                    product = parts[4]
                    version = parts[5]
                    return product, (() if version in {"*", "-"} else (version,))
    return "unknown", ()
