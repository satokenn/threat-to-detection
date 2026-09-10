"""Reproducible, stratified CVE candidate selection for evaluation runs."""

from __future__ import annotations

import csv
import hashlib
import json
import random
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Mapping

from threat_to_detection.models.vulnerability import Vulnerability

CVE_PERIOD_START = date(2021, 1, 1)
CVE_PERIOD_END = date(2025, 12, 31)
DEFAULT_SELECTION_SEED = 23
DEFAULT_SAMPLE_SIZE = 6
SELECTION_RULE = (
    "Within each category, sort eligible CVE IDs lexicographically and use a "
    "category-specific pseudo-random sample without replacement from the fixed seed."
)

CATEGORIES: tuple[str, ...] = (
    "os_system_foundation",
    "web_application_foundation",
    "network_security_appliance",
    "client_endpoint",
    "database_data_platform",
    "cloud_virtualization_container",
    "iot_embedded_ot_ics",
)

# Classification is deliberately based only on the NVD product metadata and
# description.  Mapping coverage is not consulted, so the selection cannot
# prefer CVEs that happen to reach CWE/CAPEC/ATT&CK.
_CATEGORY_TERMS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "iot_embedded_ot_ics",
        (
            "industrial",
            "scada",
            "plc",
            "hmi",
            "ics",
            "ot/",
            "iot",
            "firmware",
            "embedded",
        ),
    ),
    (
        "cloud_virtualization_container",
        (
            "amazon web services",
            "aws",
            "azure",
            "google cloud",
            "gcp",
            "kubernetes",
            "docker",
            "containerd",
            "vmware",
            "virtualbox",
            "openstack",
            "proxmox",
            "terraform",
        ),
    ),
    (
        "database_data_platform",
        (
            "mysql",
            "mariadb",
            "postgresql",
            "postgres",
            "mongodb",
            "redis",
            "oracle_database",
            "oracle_db",
            "sql_server",
            "sqlite",
            "elasticsearch",
            "kibana",
            "cassandra",
            "hadoop",
        ),
    ),
    (
        "network_security_appliance",
        (
            "cisco",
            "fortinet",
            "fortigate",
            "palo_alto",
            "juniper",
            "checkpoint",
            "sonicwall",
            "f5_networks",
            "firewall",
            "router",
            "switch",
            "vpn",
            "load_balancer",
        ),
    ),
    (
        "client_endpoint",
        (
            "chrome",
            "chromium",
            "firefox",
            "mozilla",
            "edge",
            "safari",
            "internet_explorer",
            "office",
            "adobe_reader",
            "acrobat",
            "endpoint",
            "antivirus",
            "zoom",
            "slack",
        ),
    ),
    (
        "web_application_foundation",
        (
            "apache",
            "nginx",
            "http_server",
            "tomcat",
            "wordpress",
            "drupal",
            "jenkins",
            "spring",
            "express",
            "node.js",
            "nodejs",
            "php",
            "django",
            "rails",
            "web_app",
            "web_application",
        ),
    ),
    (
        "os_system_foundation",
        (
            "microsoft_windows",
            "windows",
            "linux",
            "kernel",
            "ubuntu",
            "debian",
            "red_hat",
            "redhat",
            "fedora",
            "suse",
            "unix",
            "freebsd",
            "android",
            "macos",
            "openssh",
        ),
    ),
)


class CveSelectionError(ValueError):
    """Raised when a reproducible selection cannot be completed."""


class InsufficientCandidatesError(CveSelectionError):
    """Raised when a category has fewer candidates than requested."""

    def __init__(self, counts: Mapping[str, int], sample_size: int) -> None:
        self.counts = dict(counts)
        self.sample_size = sample_size
        missing = ", ".join(
            f"{category}={count}" for category, count in self.counts.items() if count < sample_size
        )
        super().__init__(f"not enough candidates for {sample_size} per category: {missing}")


@dataclass(frozen=True)
class SelectionResult:
    """Machine-readable output of candidate filtering and final selection."""

    start_date: date
    end_date: date
    seed: int
    sample_size: int
    candidates: tuple[dict[str, object], ...]
    selected: tuple[dict[str, object], ...]
    exclusions: Mapping[str, int]

    def to_mapping(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "selection": {
                "period": {
                    "published_start": self.start_date.isoformat(),
                    "published_end": self.end_date.isoformat(),
                },
                "categories": list(CATEGORIES),
                "sample_size_per_category": self.sample_size,
                "seed": self.seed,
                "rule": SELECTION_RULE,
                "mapping_independence": (
                    "CWE, CAPEC, ATT&CK, and detection reachability are not selection criteria."
                ),
            },
            "counts": {
                "candidate_records": len(self.candidates),
                "selected_records": len(self.selected),
                "selected_per_category": self.sample_size,
                "excluded": dict(self.exclusions),
            },
            "candidate_sets": {
                category: [
                    item for item in self.candidates if item["category"] == category
                ]
                for category in CATEGORIES
            },
            "selected": list(self.selected),
        }


def replay_selection(path: str | Path) -> dict[str, object]:
    """Validate and return a committed selection without contacting NVD.

    The selection JSON contains the complete candidate and selected sets, so
    it is a portable replay input.  This deliberately validates consistency
    rather than trying to reconstruct candidates from an unavailable raw NVD
    response.
    """
    source = Path(path)
    document = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise CveSelectionError("selection replay input must be a JSON object")
    selection = document.get("selection")
    selected = document.get("selected")
    candidate_sets = document.get("candidate_sets")
    if not isinstance(selection, dict) or not isinstance(selected, list):
        raise CveSelectionError("selection replay input is missing selection/selected")
    if not isinstance(candidate_sets, dict):
        raise CveSelectionError("selection replay input is missing candidate_sets")
    configured_categories = tuple(selection.get("categories", ()))
    if configured_categories != CATEGORIES:
        raise CveSelectionError("selection replay categories do not match the current schema")
    selected_ids = [item.get("cve_id") for item in selected if isinstance(item, dict)]
    if len(selected_ids) != len(selected) or any(
        not isinstance(item, str) for item in selected_ids
    ):
        raise CveSelectionError("selection replay contains an invalid selected CVE record")
    if len(set(selected_ids)) != len(selected_ids):
        raise CveSelectionError("selection replay contains duplicate selected CVE IDs")
    candidate_by_id: dict[str, dict[str, object]] = {}
    for category in CATEGORIES:
        records = candidate_sets.get(category)
        if not isinstance(records, list):
            raise CveSelectionError(f"selection replay is missing category: {category}")
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("cve_id"), str):
                raise CveSelectionError(
                    f"selection replay contains an invalid candidate: {category}"
                )
            cve_id = record["cve_id"]
            if cve_id in candidate_by_id:
                raise CveSelectionError(f"selection replay contains duplicate CVE ID: {cve_id}")
            candidate_by_id[cve_id] = record
    if set(selected_ids) != {
        cve_id for cve_id, record in candidate_by_id.items() if record.get("selected") is True
    }:
        raise CveSelectionError("selected and candidate_sets selected flags disagree")
    expected_size = selection.get("sample_size_per_category")
    if not isinstance(expected_size, int) or expected_size <= 0:
        raise CveSelectionError("selection replay has an invalid sample size")
    for category in CATEGORIES:
        count = sum(
            1
            for cve_id in selected_ids
            if candidate_by_id[cve_id].get("category") == category
        )
        if count != expected_size:
            raise CveSelectionError(
                f"selection replay category {category} has {count} selected records, "
                f"expected {expected_size}"
            )
    return document


def classify_cve(vulnerability: Vulnerability) -> str | None:
    """Return one explicit evaluation category from NVD product metadata."""

    haystack = _normalized_text(
        " ".join((vulnerability.vendor, vulnerability.product, vulnerability.description))
    )
    for category, terms in _CATEGORY_TERMS:
        if any(_term_matches(haystack, term) for term in terms):
            return category
    return None


def select_cves(
    vulnerabilities: Iterable[Vulnerability],
    *,
    start_date: date = CVE_PERIOD_START,
    end_date: date = CVE_PERIOD_END,
    seed: int = DEFAULT_SELECTION_SEED,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
    classifier=classify_cve,
    kev_ids: frozenset[str] = frozenset(),
) -> SelectionResult:
    """Filter and sample CVEs without using downstream mapping results."""

    if start_date > end_date:
        raise CveSelectionError("start_date must not be after end_date")
    if sample_size <= 0:
        raise CveSelectionError("sample_size must be positive")

    exclusions: dict[str, int] = {
        "outside_publication_period": 0,
        "rejected": 0,
        "unknown_category": 0,
        "duplicate_cve_id": 0,
    }
    unique: dict[str, Vulnerability] = {}
    for vulnerability in vulnerabilities:
        if vulnerability.cve_id in unique:
            exclusions["duplicate_cve_id"] += 1
            continue
        if vulnerability.vuln_status and vulnerability.vuln_status.casefold() == "rejected":
            exclusions["rejected"] += 1
            continue
        published = _published_date(vulnerability.published)
        if published is None or not start_date <= published <= end_date:
            exclusions["outside_publication_period"] += 1
            continue
        category = classifier(vulnerability)
        if category not in CATEGORIES:
            exclusions["unknown_category"] += 1
            continue
        unique[vulnerability.cve_id] = vulnerability

    category_records: dict[str, list[dict[str, object]]] = {category: [] for category in CATEGORIES}
    for vulnerability in sorted(unique.values(), key=lambda item: item.cve_id):
        category = classifier(vulnerability)
        assert category is not None
        category_records[category].append(_candidate_mapping(vulnerability, category, kev_ids))

    counts = {category: len(items) for category, items in category_records.items()}
    if any(count < sample_size for count in counts.values()):
        raise InsufficientCandidatesError(counts, sample_size)

    selected: list[dict[str, object]] = []
    candidates: list[dict[str, object]] = []
    for category in CATEGORIES:
        records = category_records[category]
        category_seed = _category_seed(seed, category)
        selected_records = random.Random(category_seed).sample(records, sample_size)
        selected_ids = {item["cve_id"] for item in selected_records}
        selection_order = {
            item["cve_id"]: index for index, item in enumerate(selected_records, start=1)
        }
        for record in records:
            enriched = {
                **record,
                "selected": record["cve_id"] in selected_ids,
                "selection_order": selection_order.get(record["cve_id"]),
            }
            candidates.append(enriched)
        selected.extend(
            {
                **record,
                "cwes": list(unique[str(record["cve_id"])].cwes),
                "selected": True,
                "selection_order": selection_order[record["cve_id"]],
            }
            for record in selected_records
        )

    selected.sort(key=lambda item: (str(item["category"]), int(item["selection_order"])))
    return SelectionResult(
        start_date=start_date,
        end_date=end_date,
        seed=seed,
        sample_size=sample_size,
        candidates=tuple(candidates),
        selected=tuple(selected),
        exclusions=exclusions,
    )


def load_kev_ids(path: str | Path) -> frozenset[str]:
    """Load CVE IDs from a CISA KEV JSON or CSV export when supplied."""

    source = Path(path)
    if source.suffix.casefold() == ".csv":
        with source.open(newline="", encoding="utf-8") as stream:
            return frozenset(
                row["cveID"].strip()
                for row in csv.DictReader(stream)
                if row.get("cveID", "").strip()
            )
    document = json.loads(source.read_text(encoding="utf-8"))
    vulnerabilities = document.get("vulnerabilities", []) if isinstance(document, dict) else []
    return frozenset(
        item["cveID"].strip()
        for item in vulnerabilities
        if isinstance(item, dict) and item.get("cveID", "").strip()
    )


def _candidate_mapping(
    vulnerability: Vulnerability,
    category: str,
    kev_ids: frozenset[str],
) -> dict[str, object]:
    return {
        "cve_id": vulnerability.cve_id,
        "published": vulnerability.published,
        "vendor": vulnerability.vendor,
        "product": vulnerability.product,
        "category": category,
        "cvss": vulnerability.cvss_score,
        "kev": vulnerability.cve_id in kev_ids or vulnerability.in_kev,
        "vuln_status": vulnerability.vuln_status,
        "selected": False,
        "selection_order": None,
    }


def _published_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).date()


def _category_seed(seed: int, category: str) -> int:
    digest = hashlib.sha256(f"{seed}:{category}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def _normalized_text(value: str) -> str:
    return re.sub(r"[^a-z0-9/]+", "_", value.casefold()).strip("_")


def _term_matches(haystack: str, term: str) -> bool:
    normalized_term = _normalized_text(term)
    return normalized_term in haystack


def iter_date_windows(
    start_date: date,
    end_date: date,
    *,
    window_days: int = 90,
) -> tuple[tuple[str, str], ...]:
    """Split a long NVD period into API-safe windows."""

    if start_date > end_date or window_days <= 0:
        raise ValueError("invalid date window")
    windows: list[tuple[str, str]] = []
    cursor = start_date
    while cursor <= end_date:
        window_end = min(cursor + timedelta(days=window_days - 1), end_date)
        windows.append(
            (
                f"{cursor.isoformat()}T00:00:00.000",
                f"{window_end.isoformat()}T23:59:59.999",
            )
        )
        cursor = window_end + timedelta(days=1)
    return tuple(windows)
