"""Reproducible evaluation of the checked-in multi-domain scenario catalog."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

from threat_to_detection.collectors.attack import AttackDataset
from threat_to_detection.collectors.capec import CapecDataset
from threat_to_detection.models.system import load_system
from threat_to_detection.services.pipeline import run_analysis


def evaluate_catalog(
    index_path: str | Path,
    *,
    capec_dataset: CapecDataset | None = None,
    attack_dataset: AttackDataset | None = None,
    nvd_client: Any | None = None,
) -> dict[str, Any]:
    """Run every catalog entry and return a deterministic machine report."""
    index = Path(index_path)
    document = yaml.safe_load(index.read_text(encoding="utf-8")) or {}
    entries = document.get("scenarios")
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"scenario index has no scenarios: {index}")

    results: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
            raise ValueError(f"invalid scenario entry in {index}")
        scenario_path = index.parent / entry["file"]
        system = load_system(scenario_path)
        result = run_analysis(
            system,
            vulnerabilities=None if system.scenario_type == "vulnerability" else (),
            nvd_client=nvd_client if system.scenario_type == "vulnerability" else None,
            capec_dataset=capec_dataset,
            attack_dataset=attack_dataset,
            scenario_id=entry.get("id"),
        )
        analysis = result.to_mapping(system)
        coverage = _coverage_summary(analysis.get("threat_analysis", ()))
        threat_evaluation = analysis.get("threat_evaluation", _empty_threat_evaluation())
        expected_outcome = _scenario_expected_outcome(system, threat_evaluation)
        results.append(
            {
                "scenario_id": entry.get("id", scenario_path.stem),
                "title": analysis.get("system", {}).get("metadata", {}).get("description", ""),
                "domain": entry.get("domain", system.scenario_type),
                "catalog_status": entry.get("status"),
                "pipeline_status": result.status,
                "analysis_outcome": analysis.get("analysis_outcome", "no_match"),
                "trace_paths": len(result.traces),
                "before_candidate_count": threat_evaluation["before_candidate_count"],
                "applicable_count": threat_evaluation["applicable_count"],
                "blocked_count": threat_evaluation["blocked_count"],
                "unknown_count": threat_evaluation["unknown_count"],
                "candidate_reduction_rate": threat_evaluation["candidate_reduction_rate"],
                "blocked_reasons": threat_evaluation["blocked_reasons"],
                "unknown_reasons": threat_evaluation["unknown_reasons"],
                "detection_feasibility": threat_evaluation["detection_feasibility"],
                "candidate_evaluations": threat_evaluation["paths"],
                "mapping_gaps": len(result.mapping_gaps),
                "sigma_rules": sum(len(rules) for rules in result.sigma_rules.values()),
                "coverage": coverage,
                "expected_outcome": expected_outcome,
                "errors": analysis.get("errors", []),
            }
        )
    return _catalog_mapping(index, results, capec_dataset, attack_dataset)


def render_report(result: dict[str, Any]) -> str:
    """Render the catalog result as a concise human-readable report."""
    summary = result["summary"]
    lines = [
        "# 多分野シナリオ評価レポート",
        "",
        "> 固定fixtureと安全な合成JSONLを使い、"
        "カタログの全シナリオを同じ処理で再評価した結果です。",
        "> 実マルウェア、攻撃ペイロード、外部ネットワークは使用していません。",
        "",
        "## 集計",
        "",
        f"- シナリオ: **{summary['scenario_count']}件**",
        f"- trace paths: **{summary['trace_paths']}**",
        f"- mapping gaps: **{summary['mapping_gaps']}**",
        f"- generated Sigma candidates: **{summary['sigma_rules']}**",
        f"- ATT&CK candidates before threat model: **{summary['before_candidate_count']}**",
        f"- applicable / blocked / unknown: **{summary['applicable_count']} / "
        f"{summary['blocked_count']} / {summary['unknown_count']}**",
        f"- candidate reduction rate: **{summary['candidate_reduction_rate']:.3f}**",
        "",
        "## シナリオ別結果",
        "",
        (
            "| ID | 分野 | pipeline | outcome | before | applicable | blocked | "
            "unknown | coverage |"
        ),
        "|---|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for item in result["scenarios"]:
        lines.append(
            f"| {item['scenario_id']} | {item['domain']} | {item['pipeline_status']} | "
            f"{item['analysis_outcome']} | {item['before_candidate_count']} | "
            f"{item['applicable_count']} | {item['blocked_count']} | {item['unknown_count']} | "
            f"{item['coverage']['coverage_ratio']:.3f} |"
        )
    lines.extend(
        [
            "",
            "## 解釈上の注意",
            "",
            "この評価は、公開知識から検知候補を生成できるかと、宣言したテレメトリの充足状況を測定します。",
            "`attack_applicability`（攻撃適用可否）と`detection_feasibility`（検知可能性）は別の判定であり、",
            "本レポートのcoverageは後者だけを表します。実環境ログや実攻撃への有効性は未評価です。",
            "候補削減率は `blocked / before_candidate_count` とし、`unknown` は削減に含めません。",
            (
                "脅威モデル条件の境界値fixtureは、実脅威カタログとは分離して"
                "`scenarios/condition-fixtures.yaml`で評価します。"
            ),
            "本カタログの6候補はすべてapplicableであり、ここでは候補削減効果は観測されません。",
            "複数の公開脅威候補から対象システムに適用可能なものを選別する評価は、"
            "`threat-universe-results.json`で別途実施します。",
            (
                "blocked / unknown の理由は、通信経路、信頼境界、認証、認可、"
                "権限、権限遷移を区別して集計します。"
            ),
            "",
            "## 理由別集計",
            "",
            f"- blocked: `{summary['blocked_reasons']}`",
            f"- unknown: `{summary['unknown_reasons']}`",
            f"- detection feasibility: `{summary['detection_feasibility']}`",
            "",
        ]
    )
    return "\n".join(lines)


def _catalog_mapping(
    index: Path,
    scenarios: list[dict[str, Any]],
    capec_dataset: Any,
    attack_dataset: Any,
) -> dict[str, Any]:
    by_domain: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in scenarios:
        by_domain[item["domain"]].append(item)
    return {
        "schema_version": "1.1",
        "evaluation_id": "multidomain-fixture-evaluation",
        "mode": "fixture_offline_safe_synthetic",
        "inputs": {"scenario_index": str(index)},
        "summary": _summary(scenarios),
        "scenarios": scenarios,
    }


def _summary(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "scenario_count": len(scenarios),
        "by_pipeline_status": dict(Counter(item["pipeline_status"] for item in scenarios)),
        "by_analysis_outcome": dict(Counter(item["analysis_outcome"] for item in scenarios)),
        "trace_paths": sum(item["trace_paths"] for item in scenarios),
        "mapping_gaps": sum(item["mapping_gaps"] for item in scenarios),
        "sigma_rules": sum(item["sigma_rules"] for item in scenarios),
        "coverage_ratio": _weighted_coverage(scenarios),
        "before_candidate_count": sum(item["before_candidate_count"] for item in scenarios),
        "applicable_count": sum(item["applicable_count"] for item in scenarios),
        "blocked_count": sum(item["blocked_count"] for item in scenarios),
        "unknown_count": sum(item["unknown_count"] for item in scenarios),
        "candidate_reduction_rate": _candidate_reduction_rate(scenarios),
        "blocked_reasons": _reason_summary(scenarios, "blocked_reasons"),
        "unknown_reasons": _reason_summary(scenarios, "unknown_reasons"),
        "detection_feasibility": _detection_summary(scenarios),
    }


def _empty_threat_evaluation() -> dict[str, Any]:
    return {
        "before_candidate_count": 0,
        "applicable_count": 0,
        "blocked_count": 0,
        "unknown_count": 0,
        "candidate_reduction_rate": 0.0,
        "blocked_reasons": {},
        "unknown_reasons": {},
        "detection_feasibility": {
            status: 0 for status in ("detectable", "partial", "unavailable", "unknown")
        },
        "paths": [],
    }


def _scenario_expected_outcome(
    system: Any,
    threat_evaluation: dict[str, Any],
) -> dict[str, Any]:
    """Compare a scenario's declared expectation with measured candidates."""

    declared_model = system.expected_outcome
    if declared_model is None:
        return {"status": "not_declared", "declared": None, "actual": None, "mismatches": []}

    paths = threat_evaluation.get("paths", ())
    applicability = [
        path.get("attack_applicability", {}) for path in paths if isinstance(path, dict)
    ]
    statuses = tuple(item.get("status") for item in applicability)
    actual = {
        "attack_applicability": statuses[0] if len(set(statuses)) == 1 and statuses else "mixed",
        "blocked_reason": (
            applicability[0].get("blocked_reason") if len(applicability) == 1 else None
        ),
        "unknown_reasons": sorted(
            {
                reason
                for item in applicability
                for reason in item.get("unknown_reasons", ())
            }
        ),
    }
    declared = declared_model.model_dump(mode="json")
    mismatches: list[str] = []
    if declared["attack_applicability"] != actual["attack_applicability"]:
        mismatches.append("attack_applicability")
    if declared.get("blocked_reason") != actual["blocked_reason"]:
        mismatches.append("blocked_reason")
    if sorted(declared.get("unknown_reasons", ())) != actual["unknown_reasons"]:
        mismatches.append("unknown_reasons")
    return {
        "status": "passed" if not mismatches else "failed",
        "declared": declared,
        "actual": actual,
        "mismatches": mismatches,
    }


def _candidate_reduction_rate(scenarios: list[dict[str, Any]]) -> float:
    before = sum(item["before_candidate_count"] for item in scenarios)
    blocked = sum(item["blocked_count"] for item in scenarios)
    return round(blocked / before, 6) if before else 0.0


def _reason_summary(scenarios: list[dict[str, Any]], key: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for scenario in scenarios:
        for reason, count in scenario[key].items():
            result[reason] = result.get(reason, 0) + count
    return dict(sorted(result.items()))


def _detection_summary(scenarios: list[dict[str, Any]]) -> dict[str, int]:
    statuses = ("detectable", "partial", "unavailable", "unknown")
    return {
        status: sum(item["detection_feasibility"].get(status, 0) for item in scenarios)
        for status in statuses
    }


def _coverage_summary(records: Any) -> dict[str, Any]:
    coverages = [item.get("coverage", {}) for item in records if isinstance(item, dict)]
    if not coverages:
        return {"coverage_ratio": 1.0, "status": "unknown", "required": 0, "missing": 0}
    required = sum(
        len(item.get("required_events", item.get("required", ())))
        + len(item.get("required_fields", ()))
        for item in coverages
    )
    missing = sum(
        len(item.get("missing_events", ())) + len(item.get("missing_fields", ()))
        for item in coverages
    )
    ratio = sum(float(item.get("coverage_ratio", 0.0)) for item in coverages) / len(coverages)
    return {
        "coverage_ratio": round(ratio, 6),
        "status": "complete"
        if missing == 0
        else ("partial" if required > missing else "unavailable"),
        "required": required,
        "missing": missing,
    }


def _weighted_coverage(scenarios: list[dict[str, Any]]) -> float:
    values = [item["coverage"]["coverage_ratio"] for item in scenarios]
    return round(sum(values) / len(values), 6) if values else 1.0
