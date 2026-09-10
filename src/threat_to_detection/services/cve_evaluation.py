"""Batch CVE mapping coverage evaluation.

This module evaluates the public-knowledge mapping path without applying a
target-system relevance filter.  The mapping functions remain the single
source of truth for CWE → CAPEC → ATT&CK → Detection Requirement edges.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from threat_to_detection.collectors.attack import AttackDataset
from threat_to_detection.collectors.capec import CapecDataset
from threat_to_detection.mappers.capec_to_attack import (
    map_attack_to_detection,
    map_capec_to_attack,
)
from threat_to_detection.mappers.cwe_to_capec import map_cwe_to_capec
from threat_to_detection.models.vulnerability import Vulnerability

CVE_TO_CWE = "CVE→CWE"
CWE_TO_CAPEC = "CWE→CAPEC"
CAPEC_TO_ATTACK = "CAPEC→ATT&CK"
ATTACK_TO_DETECTION = "ATT&CK→Detection Requirement"
MAPPING_STAGES = (CVE_TO_CWE, CWE_TO_CAPEC, CAPEC_TO_ATTACK, ATTACK_TO_DETECTION)
REACHED_STAGES = ("cve", "cwe", "capec", "attack", "detection")
_CONCRETE_CWE = re.compile(r"^CWE-\d+$")


@dataclass(frozen=True)
class EvaluationGap:
    """One unresolved mapping edge for one CVE branch."""

    cve_id: str
    category: str
    source: str
    path: str
    stage: str
    reason: str

    def to_mapping(self) -> dict[str, str]:
        return {
            "cve_id": self.cve_id,
            "category": self.category,
            "source": self.source,
            "path": self.path,
            "stage": self.stage,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CveEvaluationRecord:
    """Coverage and candidate counts for one CVE."""

    cve_id: str
    category: str
    cwe_reached: bool
    capec_reached: bool
    attack_reached: bool
    detection_reached: bool
    reached_stage: str
    cwe_count: int
    capec_count: int
    attack_count: int
    detection_count: int
    mapping_gaps: tuple[EvaluationGap, ...] = ()

    def to_mapping(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "category": self.category,
            "cwe_reached": self.cwe_reached,
            "capec_reached": self.capec_reached,
            "attack_reached": self.attack_reached,
            "detection_reached": self.detection_reached,
            "reached_stage": self.reached_stage,
            "cwe_count": self.cwe_count,
            "capec_count": self.capec_count,
            "attack_count": self.attack_count,
            "detection_count": self.detection_count,
            "mapping_gaps": [gap.to_mapping() for gap in self.mapping_gaps],
        }


@dataclass(frozen=True)
class CveEvaluationResult:
    """Machine-readable result for a batch of CVEs."""

    records: tuple[CveEvaluationRecord, ...]
    selection_path: str | None = None

    @property
    def mapping_gaps(self) -> tuple[EvaluationGap, ...]:
        return tuple(gap for record in self.records for gap in record.mapping_gaps)

    def to_mapping(self) -> dict[str, Any]:
        grouped = _group_by_category(self.records)
        return {
            "schema_version": "1.0",
            "evaluation": {
                "population": len(self.records),
                "selection": self.selection_path,
                "mapping": "CVE → CWE → CAPEC → ATT&CK Technique → Detection Requirement",
                "cwe_rule": (
                    "Only concrete CWE-N IDs count; NVD-CWE-noinfo and "
                    "NVD-CWE-Other are excluded."
                ),
            },
            "records": [record.to_mapping() for record in self.records],
            "metrics": _aggregate_metrics(self.records),
            "by_category": {
                category: _aggregate_metrics(records)
                for category, records in grouped.items()
            },
            "mapping_gaps": [gap.to_mapping() for gap in self.mapping_gaps],
        }


def evaluate_cves(
    vulnerabilities: Iterable[Vulnerability],
    *,
    capec_dataset: CapecDataset,
    attack_dataset: AttackDataset,
    categories: Mapping[str, str] | None = None,
    selection_path: str | None = None,
) -> CveEvaluationResult:
    """Evaluate every supplied CVE through the existing mapping functions.

    The input is intentionally a sequence of normalized vulnerabilities rather
    than a target system.  This measures knowledge-base reachability and keeps
    system relevance and threat-model filtering out of the baseline.
    """

    category_by_cve = categories or {}
    records: list[CveEvaluationRecord] = []
    seen: set[str] = set()
    for vulnerability in vulnerabilities:
        if vulnerability.cve_id in seen:
            raise ValueError(f"duplicate CVE ID in evaluation input: {vulnerability.cve_id}")
        seen.add(vulnerability.cve_id)
        category = category_by_cve.get(vulnerability.cve_id, "uncategorized")
        cwes = concrete_cwes(vulnerability.cwes)
        gaps: list[EvaluationGap] = []
        if not cwes:
            gaps.append(
                EvaluationGap(
                    cve_id=vulnerability.cve_id,
                    category=category,
                    source=vulnerability.cve_id,
                    path=vulnerability.cve_id,
                    stage=CVE_TO_CWE,
                    reason="No concrete CWE ID is mapped",
                )
            )

        capecs: list[str] = []
        attacks: list[str] = []
        detections: list[tuple[str, str]] = []
        for cwe_id in cwes:
            patterns = map_cwe_to_capec(cwe_id, capec_dataset)
            if not patterns:
                gaps.append(
                    EvaluationGap(
                        cve_id=vulnerability.cve_id,
                        category=category,
                        source=cwe_id,
                        path=f"{vulnerability.cve_id}:{cwe_id}",
                        stage=CWE_TO_CAPEC,
                        reason="No CAPEC pattern is mapped",
                    )
                )
            for pattern in patterns:
                if pattern.capec_id not in capecs:
                    capecs.append(pattern.capec_id)
                techniques = map_capec_to_attack(pattern.capec_id, attack_dataset)
                if not techniques:
                    gaps.append(
                        EvaluationGap(
                            cve_id=vulnerability.cve_id,
                            category=category,
                            source=pattern.capec_id,
                            path=f"{vulnerability.cve_id}:{cwe_id}:{pattern.capec_id}",
                            stage=CAPEC_TO_ATTACK,
                            reason="No ATT&CK technique is mapped",
                        )
                    )
                for technique in techniques:
                    if technique.technique_id not in attacks:
                        attacks.append(technique.technique_id)
                    requirements = map_attack_to_detection(
                        technique.technique_id, attack_dataset
                    )
                    if not requirements:
                        gaps.append(
                            EvaluationGap(
                                cve_id=vulnerability.cve_id,
                                category=category,
                                source=technique.technique_id,
                                path=(
                                    f"{vulnerability.cve_id}:{cwe_id}:{pattern.capec_id}:"
                                    f"{technique.technique_id}"
                                ),
                                stage=ATTACK_TO_DETECTION,
                                reason="No detection requirement is mapped",
                            )
                        )
                    for requirement in requirements:
                        candidate = (requirement.technique_id, requirement.strategy_id)
                        if candidate not in detections:
                            detections.append(candidate)

        attack_reached = bool(attacks)
        record = CveEvaluationRecord(
            cve_id=vulnerability.cve_id,
            category=category,
            cwe_reached=bool(cwes),
            capec_reached=bool(capecs),
            attack_reached=attack_reached,
            detection_reached=bool(detections),
            reached_stage=_reached_stage(
                cwe_reached=bool(cwes),
                capec_reached=bool(capecs),
                attack_reached=attack_reached,
                detection_reached=bool(detections),
            ),
            cwe_count=len(cwes),
            capec_count=len(capecs),
            attack_count=len(attacks),
            detection_count=len(detections),
            mapping_gaps=tuple(gaps),
        )
        records.append(record)
    return CveEvaluationResult(tuple(records), selection_path=selection_path)


def concrete_cwes(cwes: Iterable[str]) -> tuple[str, ...]:
    """Return normalized numeric CWE IDs, excluding NVD sentinel values."""

    result: list[str] = []
    for cwe_id in cwes:
        if not isinstance(cwe_id, str):
            continue
        normalized = cwe_id.strip().upper()
        if _CONCRETE_CWE.fullmatch(normalized) and normalized not in result:
            result.append(normalized)
    return tuple(result)


def load_selection(path: str | Path) -> tuple[tuple[Vulnerability, ...], dict[str, str]]:
    """Load selected normalized CVEs and categories from Issue #23 output."""

    source = Path(path)
    document = json.loads(source.read_text(encoding="utf-8"))
    selected = document.get("selected") if isinstance(document, dict) else None
    if not isinstance(selected, list):
        raise ValueError(f"selection file must contain a selected list: {source}")
    vulnerabilities: list[Vulnerability] = []
    categories: dict[str, str] = {}
    for item in selected:
        if not isinstance(item, dict) or not isinstance(item.get("cve_id"), str):
            raise ValueError(f"selection contains an invalid CVE record: {source}")
        cve_id = item["cve_id"]
        vulnerabilities.append(
            Vulnerability(
                cve_id=cve_id,
                vendor=str(item.get("vendor") or "unknown"),
                product=str(item.get("product") or "unknown"),
                cwes=tuple(item.get("cwes") or ()),
                cvss_score=item.get("cvss"),
                in_kev=bool(item.get("kev", False)),
                published=item.get("published"),
                vuln_status=item.get("vuln_status"),
            )
        )
        category = item.get("category")
        if isinstance(category, str) and category:
            categories[cve_id] = category
    return tuple(vulnerabilities), categories


def _reached_stage(
    *, cwe_reached: bool, capec_reached: bool, attack_reached: bool, detection_reached: bool
) -> str:
    if detection_reached:
        return "detection"
    if attack_reached:
        return "attack"
    if capec_reached:
        return "capec"
    if cwe_reached:
        return "cwe"
    return "cve"


def _group_by_category(
    records: Iterable[CveEvaluationRecord],
) -> dict[str, tuple[CveEvaluationRecord, ...]]:
    grouped: dict[str, list[CveEvaluationRecord]] = defaultdict(list)
    for record in records:
        grouped[record.category].append(record)
    return {category: tuple(values) for category, values in sorted(grouped.items())}


def _aggregate_metrics(records: Iterable[CveEvaluationRecord]) -> dict[str, Any]:
    values = tuple(records)
    population = len(values)
    reached = {
        "cve": population,
        "cwe": sum(record.cwe_reached for record in values),
        "capec": sum(record.capec_reached for record in values),
        "attack": sum(record.attack_reached for record in values),
        "detection": sum(record.detection_reached for record in values),
    }
    cumulative = {
        stage: {
            "reached_count": count,
            "rate": _rate(count, population),
        }
        for stage, count in reached.items()
    }
    transitions = {
        CVE_TO_CWE: {
            "from_count": population,
            "reached_count": reached["cwe"],
            "rate": _rate(reached["cwe"], population),
        },
        CWE_TO_CAPEC: {
            "from_count": reached["cwe"],
            "reached_count": reached["capec"],
            "rate": _rate(reached["capec"], reached["cwe"]),
        },
        CAPEC_TO_ATTACK: {
            "from_count": reached["capec"],
            "reached_count": reached["attack"],
            "rate": _rate(reached["attack"], reached["capec"]),
        },
        ATTACK_TO_DETECTION: {
            "from_count": reached["attack"],
            "reached_count": reached["detection"],
            "rate": _rate(reached["detection"], reached["attack"]),
        },
    }
    final_stage_counts = dict.fromkeys(REACHED_STAGES, 0)
    for record in values:
        final_stage_counts[record.reached_stage] += 1
    gap_counts = Counter(gap.stage for record in values for gap in record.mapping_gaps)
    return {
        "population": population,
        "cumulative": cumulative,
        "transitions": transitions,
        "final_stage_counts": final_stage_counts,
        "mapping_gaps": {
            "total": sum(gap_counts.values()),
            "by_stage": {stage: gap_counts.get(stage, 0) for stage in MAPPING_STAGES},
        },
    }


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None
