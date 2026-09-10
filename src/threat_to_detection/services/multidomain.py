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
        results.append(
            {
                "scenario_id": entry.get("id", scenario_path.stem),
                "title": analysis.get("system", {}).get("metadata", {}).get("description", ""),
                "domain": entry.get("domain", system.scenario_type),
                "catalog_status": entry.get("status"),
                "pipeline_status": result.status,
                "analysis_outcome": analysis.get("analysis_outcome", "no_match"),
                "trace_paths": len(result.traces),
                "mapping_gaps": len(result.mapping_gaps),
                "sigma_rules": sum(len(rules) for rules in result.sigma_rules.values()),
                "coverage": coverage,
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
        "",
        "## シナリオ別結果",
        "",
        "| ID | 分野 | pipeline | outcome | paths | gaps | Sigma | coverage |",
        "|---|---|---|---|---:|---:|---:|---:|",
    ]
    for item in result["scenarios"]:
        lines.append(
            f"| {item['scenario_id']} | {item['domain']} | {item['pipeline_status']} | "
            f"{item['analysis_outcome']} | {item['trace_paths']} | {item['mapping_gaps']} | "
            f"{item['sigma_rules']} | {item['coverage']['coverage_ratio']:.3f} |"
        )
    lines.extend(
        [
            "",
            "## 解釈上の注意",
            "",
            "この評価は、公開知識から検知候補を生成できるかと、宣言したテレメトリの充足状況を測定します。",
            "`attack_applicability`（攻撃適用可否）と`detection_feasibility`（検知可能性）は別の判定であり、",
            "本レポートのcoverageは後者だけを表します。実環境ログや実攻撃への有効性は未評価です。",
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
