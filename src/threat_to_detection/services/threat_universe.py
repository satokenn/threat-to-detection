"""Evaluate a reproducibly sampled population of threat hypotheses."""

from __future__ import annotations

import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

from threat_to_detection.models.system import load_system
from threat_to_detection.models.threat import ThreatUniverse, ThreatUniverseCandidate
from threat_to_detection.services.applicability import evaluate_attack_applicability


def evaluate_threat_universe(
    universe_path: str | Path,
    *,
    system_path: str | Path | None = None,
) -> dict[str, Any]:
    """Sample and evaluate a threat universe against one target system.

    Sampling is stratified by the candidate's declared domain and uses a
    fixed seed from the universe document.  The full population remains in
    the input file, while the selected population is the denominator for the
    applicability result.
    """

    universe_file = Path(universe_path)
    document = yaml.safe_load(universe_file.read_text(encoding="utf-8")) or {}
    universe = ThreatUniverse.model_validate(document)
    target_file = (
        Path(system_path)
        if system_path
        else universe_file.parent / universe.target_system
    )
    system = load_system(target_file)

    selected = _sample_candidates(universe)
    records: list[dict[str, Any]] = []
    for candidate in selected:
        asset = next((item for item in system.assets if item.name == candidate.target_asset), None)
        if asset is None:
            raise ValueError(
                f"threat candidate {candidate.threat_id} targets unknown asset "
                f"{candidate.target_asset!r}"
            )
        applicability = evaluate_attack_applicability(
            system,
            asset=asset,
            trace_id=candidate.threat_id,
            profile=candidate.applicability,
        )
        applicability["provenance"].append(
            {
                "source_type": candidate.source.source_type,
                "source_id": candidate.source.source_id,
                "field": "applicability_profile",
                "rationale": candidate.applicability.rationale,
                "url": candidate.source.url,
            }
        )
        records.append(
            {
                "threat_id": candidate.threat_id,
                "name": candidate.name,
                "domain": candidate.domain,
                "target_asset": candidate.target_asset,
                "attack_technique_ids": list(candidate.attack_technique_ids),
                "source": candidate.source.model_dump(mode="json"),
                "applicability_profile": candidate.applicability.model_dump(mode="json"),
                "before_candidate": True,
                "attack_applicability": applicability,
            }
        )

    summary = _summary(universe, selected, records)
    expected_outcome = _expected_outcome(universe, summary, selected)
    return {
        "schema_version": "1.0",
        "evaluation_id": "threat-universe-applicability-001",
        "mode": "fixture_offline_safe_synthetic",
        "inputs": {"threat_universe": str(universe_file), "target_system": str(target_file)},
        "sampling": {
            "method": universe.sampling.method,
            "seed": universe.sampling.seed,
            "strata_field": universe.sampling.strata_field,
            "sample_per_stratum": universe.sampling.sample_per_stratum,
            "population_count": len(universe.threats),
            "sampled_candidate_count": len(selected),
            "selected_threat_ids": [item.threat_id for item in selected],
        },
        "summary": summary,
        "expected_outcome": expected_outcome,
        "candidates": records,
    }


def render_threat_universe_report(result: dict[str, Any]) -> str:
    """Render the sampled threat-universe result for reviewers."""

    summary = result["summary"]
    sampling = result["sampling"]
    expectation = result["expected_outcome"]
    lines = [
        "# 脅威候補母集団の適用可否評価",
        "",
        "> 公開ATT&CK Technique IDを参照した脅威候補母集団から、固定seedで層別抽出し、",
        "> 対象システムの明示条件に照合したオフライン評価です。",
        "> 実マルウェア、攻撃ペイロード、外部ネットワークは使用していません。",
        "",
        "## 集計",
        "",
        f"- 母集団: **{sampling['population_count']}件**",
        f"- 抽出候補: **{sampling['sampled_candidate_count']}件**",
        f"- seed: **{sampling['seed']}**（domainごとに{sampling['sample_per_stratum']}件）",
        f"- applicable / blocked / unknown: **{summary['applicable_count']} / "
        f"{summary['blocked_count']} / {summary['unknown_count']}**",
        f"- 候補削減率: **{summary['candidate_reduction_rate']:.3f}**",
        f"- expected_outcome: **{expectation['status']}**",
        "",
        "## 候補別結果",
        "",
        "| Threat ID | domain | technique | target | status | reasons |",
        "|---|---|---|---|---|---|",
    ]
    for candidate in result["candidates"]:
        applicability = candidate["attack_applicability"]
        reasons = ", ".join(
            applicability.get("blocked_reasons", ())
            or applicability.get("unknown_reasons", ())
            or ("none",)
        )
        lines.append(
            f"| {candidate['threat_id']} | {candidate['domain']} | "
            f"{', '.join(candidate['attack_technique_ids'])} | {candidate['target_asset']} | "
            f"{applicability['status']} | {reasons} |"
        )
    lines.extend(
        [
            "",
            "## 解釈上の注意",
            "",
            "母集団は、公開ATT&CKページで識別できるTechniqueを出発点にした評価用の脅威仮説です。",
            "各候補の通信経路・境界・認証・認可・権限・前提条件は、対象システムへ照合するための"
            "明示的な評価プロファイルであり、ATT&CKページが特定環境の成立条件を保証するものではありません。",
            "その解釈根拠は候補ごとの`source`と`applicability_profile.rationale`に保存しています。",
            "候補を生成したこと自体は攻撃可能性を意味しません。条件が未確定の候補は`unknown`として残し、"
            "`blocked`だけを候補削減として集計します。",
            "",
            "## expected_outcome 契約",
            "",
            f"- 判定: **{expectation['status']}**",
            f"- 不一致: `{expectation['mismatches']}`",
            "",
        ]
    )
    return "\n".join(lines)


def _sample_candidates(universe: ThreatUniverse) -> tuple[ThreatUniverseCandidate, ...]:
    strata: dict[str, list[ThreatUniverseCandidate]] = defaultdict(list)
    for candidate in universe.threats:
        strata[candidate.domain].append(candidate)
    rng = random.Random(universe.sampling.seed)
    selected: list[ThreatUniverseCandidate] = []
    for domain in sorted(strata):
        candidates = sorted(strata[domain], key=lambda item: item.threat_id)
        if len(candidates) < universe.sampling.sample_per_stratum:
            raise ValueError(
                f"stratum {domain!r} has only {len(candidates)} candidates; "
                f"requires {universe.sampling.sample_per_stratum}"
            )
        selected.extend(rng.sample(candidates, universe.sampling.sample_per_stratum))
    return tuple(sorted(selected, key=lambda item: item.threat_id))


def _summary(
    universe: ThreatUniverse,
    selected: tuple[ThreatUniverseCandidate, ...],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    statuses = Counter(item["attack_applicability"]["status"] for item in records)
    before = len(records)
    return {
        "population_count": len(universe.threats),
        "sampled_candidate_count": len(selected),
        "before_candidate_count": before,
        "applicable_count": statuses["applicable"],
        "blocked_count": statuses["blocked"],
        "unknown_count": statuses["unknown"],
        "candidate_reduction_rate": round(statuses["blocked"] / before, 6) if before else 0.0,
        "blocked_reasons": _reason_counts(records, "blocked_reasons"),
        "unknown_reasons": _reason_counts(records, "unknown_reasons"),
    }


def _reason_counts(records: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for record in records:
        for reason in record["attack_applicability"].get(key, ()):
            counts[reason] += 1
    return dict(sorted(counts.items()))


def _expected_outcome(
    universe: ThreatUniverse,
    summary: dict[str, Any],
    selected: tuple[ThreatUniverseCandidate, ...],
) -> dict[str, Any]:
    declared = universe.expected_outcome.model_dump(mode="json")
    actual = {
        "sampled_candidate_count": summary["sampled_candidate_count"],
        "status_counts": {
            "applicable": summary["applicable_count"],
            "blocked": summary["blocked_count"],
            "unknown": summary["unknown_count"],
        },
        "selected_threat_ids": [item.threat_id for item in selected],
    }
    mismatches: list[str] = []
    if declared["sampled_candidate_count"] != actual["sampled_candidate_count"]:
        mismatches.append("sampled_candidate_count")
    if declared["status_counts"] != actual["status_counts"]:
        mismatches.append("status_counts")
    if declared["selected_threat_ids"] != actual["selected_threat_ids"]:
        mismatches.append("selected_threat_ids")
    return {
        "status": "passed" if not mismatches else "failed",
        "declared": declared,
        "actual": actual,
        "mismatches": mismatches,
    }
