"""Reproducible charts for the Issue #26 and #27 evaluation outputs.

The evaluator and the chart generator deliberately communicate through JSON
documents.  This keeps the plotting step usable with archived results and
prevents chart code from changing evaluation semantics.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from html import escape
from pathlib import Path
from typing import Any, Iterable, Mapping

DEFAULT_SCENARIO_IDS = (
    "scenario-01-cve-example-process",
    "scenario-03-malware-process-execution",
    "scenario-04-malware-ingress-transfer",
    "scenario-05-malware-staged-behavior",
)

_STAGES = ("cve", "cwe", "capec", "attack", "detection")
_STAGE_LABELS = {
    "cve": "CVE",
    "cwe": "CWE",
    "capec": "CAPEC",
    "attack": "ATT&CK",
    "detection": "Detection Requirement",
}
_TRANSITIONS = (
    ("cve", "cwe", "CVE → CWE"),
    ("cwe", "capec", "CWE → CAPEC"),
    ("capec", "attack", "CAPEC → ATT&CK"),
    ("attack", "detection", "ATT&CK → Detection Requirement"),
)
_STATUSES = ("applicable", "blocked", "unknown")
_STATUS_LABELS = {
    "applicable": "applicable",
    "blocked": "blocked",
    "unknown": "unknown",
}
_REASON_ORDER = (
    "communication_path",
    "trust_boundary",
    "authentication",
    "authorization",
    "privilege",
    "privilege_transition",
    "communication_path_information",
    "trust_boundary_information",
    "authentication_information",
    "authorization_information",
    "privilege_information",
)
_REASON_LABELS = {
    "communication_path": "通信経路不成立",
    "trust_boundary": "信頼境界条件不成立",
    "authentication": "認証条件不成立",
    "authorization": "認可条件不成立",
    "privilege": "権限不足",
    "privilege_transition": "権限遷移不成立",
    "communication_path_information": "通信経路情報不足",
    "trust_boundary_information": "信頼境界情報不足",
    "authentication_information": "認証情報不足",
    "authorization_information": "認可情報不足",
    "privilege_information": "権限情報不足",
}
_COLORS = {
    "cumulative": "#2563eb",
    "transition": "#0f766e",
    "applicable": "#15803d",
    "blocked": "#dc2626",
    "unknown": "#d97706",
}


def load_evaluation(path: str | Path) -> dict[str, Any]:
    """Load and validate a JSON evaluation document."""

    source = Path(path)
    document = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"evaluation must contain a JSON object: {source}")
    return document


def aggregate_evaluation_a(document: Mapping[str, Any]) -> dict[str, Any]:
    """Calculate cumulative and transitional reachability from CVE records."""

    records = document.get("records")
    if not isinstance(records, list):
        raise ValueError("evaluation A must contain a records list")

    reached = {stage: 0 for stage in _STAGES}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("evaluation A records must be objects")
        reached["cve"] += 1
        for stage in _STAGES[1:]:
            if _record_reached(record, stage):
                reached[stage] += 1

    population = len(records)
    cumulative = [
        {
            "stage": stage,
            "label": _STAGE_LABELS[stage],
            "reached_count": reached[stage],
            "denominator": population,
            "rate": _rate(reached[stage], population),
        }
        for stage in _STAGES[1:]
    ]
    transitions = [
        {
            "from_stage": source,
            "to_stage": target,
            "label": label,
            "from_count": reached[source],
            "reached_count": reached[target],
            "denominator": reached[source],
            "rate": _rate(reached[target], reached[source]),
        }
        for source, target, label in _TRANSITIONS
    ]
    return {
        "population": population,
        "cumulative": cumulative,
        "transitions": transitions,
    }


def aggregate_evaluation_b(
    document: Mapping[str, Any],
    *,
    scenario_ids: Iterable[str] = DEFAULT_SCENARIO_IDS,
) -> dict[str, Any]:
    """Normalize threat-model candidate statuses and reasons for charting.

    Issue #27 emits nested ``attack_applicability`` records.  The flat fields
    listed in Issue #30 are accepted as well so archived or hand-exported
    results remain usable.
    """

    scenarios = document.get("scenarios")
    if not isinstance(scenarios, list):
        raise ValueError("evaluation B must contain a scenarios list")
    scenario_ids = tuple(scenario_ids)
    by_id = {
        item.get("scenario_id"): item
        for item in scenarios
        if isinstance(item, dict) and isinstance(item.get("scenario_id"), str)
    }

    scenario_rows: list[dict[str, Any]] = []
    reason_counts: Counter[tuple[str, str]] = Counter()
    for scenario_id in scenario_ids:
        scenario = by_id.get(scenario_id)
        if scenario is None:
            counts = {status: 0 for status in _STATUSES}
            reasons: Counter[str] = Counter()
        else:
            candidate_records = scenario.get("candidate_evaluations")
            if isinstance(candidate_records, list):
                counts, reasons = _candidate_counts(candidate_records, scenario_id)
                _validate_candidate_summary(scenario, counts, scenario_id)
            elif _has_summary_counts(scenario):
                counts, reasons = _summary_counts(scenario, scenario_id)
            else:
                counts = {status: 0 for status in _STATUSES}
                reasons = Counter()

        before = sum(counts.values())
        scenario_rows.append(
            {
                "scenario_id": scenario_id,
                "before_candidate_count": before,
                **{f"{status}_count": counts[status] for status in _STATUSES},
                "candidate_reduction_rate": _rate(counts["blocked"], before) or 0.0,
            }
        )
        for reason_key, count in reasons.items():
            status, reason = reason_key.split(":", 1)
            reason_counts[(status, reason)] += count

    selected_present = [by_id.get(scenario_id) for scenario_id in scenario_ids]
    if any(item is not None for item in selected_present) and not any(
        isinstance(item, dict)
        and (
            isinstance(item.get("candidate_evaluations"), list)
            or _has_summary_counts(item)
        )
        for item in selected_present
    ):
        raise ValueError("evaluation B has no threat-model candidate data")

    applicability = [
        {
            "scenario_id": row["scenario_id"],
            "status": status,
            "count": row[f"{status}_count"],
        }
        for row in scenario_rows
        for status in _STATUSES
    ]
    reasons = _reason_rows(reason_counts)
    before = sum(row["before_candidate_count"] for row in scenario_rows)
    totals = {
        "before_candidate_count": before,
        **{
            f"{status}_count": sum(row[f"{status}_count"] for row in scenario_rows)
            for status in _STATUSES
        },
    }
    totals["candidate_reduction_rate"] = _rate(totals["blocked_count"], before) or 0.0
    return {
        "scenario_ids": list(scenario_ids),
        "scenarios": scenario_rows,
        "applicability": applicability,
        "reasons": reasons,
        "totals": totals,
    }


def generate_evaluation_visualizations(
    evaluation_a_path: str | Path,
    evaluation_b_path: str | Path,
    output_dir: str | Path,
    *,
    scenario_ids: Iterable[str] = DEFAULT_SCENARIO_IDS,
) -> dict[str, Path]:
    """Write aggregate CSV/JSON and four deterministic SVG figures."""

    aggregate_a = aggregate_evaluation_a(load_evaluation(evaluation_a_path))
    aggregate_b = aggregate_evaluation_b(
        load_evaluation(evaluation_b_path), scenario_ids=scenario_ids
    )
    root = Path(output_dir)
    aggregates_dir = root / "aggregates"
    figures_dir = root / "figures"
    aggregates_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    _write_json(
        aggregates_dir / "evaluation-summary.json",
        {"evaluation_a": aggregate_a, "evaluation_b": aggregate_b},
    )
    _write_evaluation_a_csv(aggregates_dir / "evaluation_a_summary.csv", aggregate_a)
    _write_evaluation_b_csv(aggregates_dir / "evaluation_b_summary.csv", aggregate_b)

    paths = {
        "evaluation_a_summary": aggregates_dir / "evaluation_a_summary.csv",
        "evaluation_b_summary": aggregates_dir / "evaluation_b_summary.csv",
        "evaluation_summary": aggregates_dir / "evaluation-summary.json",
        "cumulative_reachability": figures_dir / "cumulative_reachability.svg",
        "stage_reachability": figures_dir / "stage_reachability.svg",
        "threat_model_applicability": figures_dir / "threat_model_applicability.svg",
        "applicability_reasons": figures_dir / "applicability_reasons.svg",
    }
    paths["cumulative_reachability"].write_text(
        _render_rate_chart(
            "Evaluation A: cumulative reachability",
            aggregate_a["cumulative"],
            description="CVE population reaching each mapping stage.",
        ),
        encoding="utf-8",
    )
    paths["stage_reachability"].write_text(
        _render_rate_chart(
            "Evaluation A: stage-to-stage reachability",
            aggregate_a["transitions"],
            description="Reachability from the immediately preceding stage.",
        ),
        encoding="utf-8",
    )
    paths["threat_model_applicability"].write_text(
        _render_stacked_chart(
            "Evaluation B: threat-model applicability",
            aggregate_b["scenarios"],
            description="ATT&CK candidates classified after threat-model evaluation.",
        ),
        encoding="utf-8",
    )
    paths["applicability_reasons"].write_text(
        _render_reason_chart(
            "Evaluation B: blocked and unknown reasons",
            aggregate_b["reasons"],
            description="Normalized reasons from threat-model applicability only.",
        ),
        encoding="utf-8",
    )
    return paths


def _record_reached(record: Mapping[str, Any], stage: str) -> bool:
    field = f"{stage}_reached"
    if field in record:
        value = record[field]
        if not isinstance(value, bool):
            raise ValueError(f"evaluation A field {field} must be boolean")
        return value
    return _as_nonnegative_int(record.get(f"{stage}_count"), field) > 0


def _candidate_counts(
    records: list[Any], scenario_id: str
) -> tuple[dict[str, int], Counter[str]]:
    counts = {status: 0 for status in _STATUSES}
    reasons: Counter[str] = Counter()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError(f"candidate evaluation in {scenario_id} must be an object")
        if record.get("before_candidate", True) is False:
            continue
        status = _candidate_status(record)
        counts[status] += 1
        for reason in _candidate_reasons(record, status):
            reasons[f"{status}:{reason}"] += 1
    return counts, reasons


def _summary_counts(
    scenario: Mapping[str, Any], scenario_id: str
) -> tuple[dict[str, int], Counter[str]]:
    counts = {
        status: _as_nonnegative_int(scenario.get(f"{status}_count"), f"{scenario_id}.{status}")
        for status in _STATUSES
    }
    before = _as_nonnegative_int(
        scenario.get("before_candidate_count"), f"{scenario_id}.before_candidate_count"
    )
    if sum(counts.values()) != before:
        raise ValueError(
            f"evaluation B scenario {scenario_id} has inconsistent applicability counts"
        )
    reasons: Counter[str] = Counter()
    for status, key in (("blocked", "blocked_reasons"), ("unknown", "unknown_reasons")):
        values = scenario.get(key, {})
        if not isinstance(values, dict):
            raise ValueError(f"evaluation B field {scenario_id}.{key} must be an object")
        for reason, count in values.items():
            reasons[f"{status}:{_normalize_reason(reason)}"] += _as_nonnegative_int(
                count, f"{scenario_id}.{key}.{reason}"
            )
    return counts, reasons


def _validate_candidate_summary(
    scenario: Mapping[str, Any], counts: Mapping[str, int], scenario_id: str
) -> None:
    """Reject a report whose per-path records disagree with its summary."""

    before = sum(counts.values())
    if "before_candidate_count" in scenario and scenario["before_candidate_count"] != before:
        raise ValueError(
            f"evaluation B scenario {scenario_id} has inconsistent applicability counts"
        )
    for status in _STATUSES:
        key = f"{status}_count"
        if key in scenario and scenario[key] != counts[status]:
            raise ValueError(
                f"evaluation B scenario {scenario_id} has inconsistent applicability counts"
            )


def _candidate_status(record: Mapping[str, Any]) -> str:
    nested = record.get("attack_applicability")
    status = nested.get("status") if isinstance(nested, dict) else None
    flat_status = record.get("applicability_status")
    if flat_status is not None:
        status = flat_status
    if status not in _STATUSES:
        raise ValueError(f"invalid applicability status: {status!r}")
    return status


def _candidate_reasons(record: Mapping[str, Any], status: str) -> tuple[str, ...]:
    nested = record.get("attack_applicability")
    sources = [nested, record] if isinstance(nested, dict) else [record]
    plural = next(
        (source.get(f"{status}_reasons") for source in sources if isinstance(source, dict)
         and isinstance(source.get(f"{status}_reasons"), list)),
        None,
    )
    singular = next(
        (source.get(f"{status}_reason") for source in sources if isinstance(source, dict)
         and source.get(f"{status}_reason")),
        None,
    )
    values: list[Any]
    if isinstance(plural, list):
        values = plural
    elif singular:
        values = [singular]
    else:
        conditions = next(
            (
                source.get("evaluated_conditions")
                for source in sources
                if isinstance(source, dict) and isinstance(source.get("evaluated_conditions"), list)
            ),
            None,
        )
        values = [
            item.get("condition")
            for item in conditions
            if isinstance(item, dict)
            and _condition_matches_status(item.get("status"), status)
        ] if isinstance(conditions, list) else []
    return tuple(_normalize_reason(value) for value in values if isinstance(value, str) and value)


def _normalize_reason(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "communication": "communication_path",
        "path": "communication_path",
        "communication_path_not_established": "communication_path",
        "trust_boundary_not_established": "trust_boundary",
        "auth": "authentication",
        "authn": "authentication",
        "authz": "authorization",
        "privilege_level": "privilege",
        "reachability": "communication_path",
        "authentication_logs": "authentication_information",
        "authorization_logs": "authorization_information",
    }
    return aliases.get(normalized, normalized)


def _condition_matches_status(condition_status: Any, status: str) -> bool:
    if status == "blocked":
        return condition_status in {"blocked", "unsatisfied", "not_satisfied"}
    return condition_status in {"unknown", "undetermined"}


def _reason_rows(reason_counts: Counter[tuple[str, str]]) -> list[dict[str, Any]]:
    reasons = sorted(
        {reason for _, reason in reason_counts},
        key=lambda reason: (
            _REASON_ORDER.index(reason) if reason in _REASON_ORDER else len(_REASON_ORDER),
            reason,
        ),
    )
    return [
        {
            "reason": reason,
            "label": _REASON_LABELS.get(reason, reason),
            "blocked_count": reason_counts[("blocked", reason)],
            "unknown_count": reason_counts[("unknown", reason)],
        }
        for reason in reasons
    ]


def _has_summary_counts(scenario: Mapping[str, Any]) -> bool:
    return all(f"{status}_count" in scenario for status in _STATUSES) and (
        "before_candidate_count" in scenario
    )


def _as_nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"evaluation field {field} must be a non-negative integer")
    return value


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: Iterable[Mapping[str, Any]], fieldnames: tuple[str, ...]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_evaluation_a_csv(path: Path, aggregate: Mapping[str, Any]) -> None:
    rows = [
        {
            "chart": "cumulative_reachability",
            "label": item["label"],
            "from_stage": "",
            "to_stage": item["stage"],
            "reached_count": item["reached_count"],
            "denominator": item["denominator"],
            "rate": "" if item["rate"] is None else item["rate"],
        }
        for item in aggregate["cumulative"]
    ]
    rows.extend(
        {
            "chart": "stage_reachability",
            "label": item["label"],
            "from_stage": item["from_stage"],
            "to_stage": item["to_stage"],
            "reached_count": item["reached_count"],
            "denominator": item["denominator"],
            "rate": "" if item["rate"] is None else item["rate"],
        }
        for item in aggregate["transitions"]
    )
    _write_csv(
        path,
        rows,
        ("chart", "label", "from_stage", "to_stage", "reached_count", "denominator", "rate"),
    )


def _write_evaluation_b_csv(path: Path, aggregate: Mapping[str, Any]) -> None:
    rows = [
        {
            "chart": "threat_model_applicability",
            "scenario_id": item["scenario_id"],
            "status": item["status"],
            "reason": "",
            "count": item["count"],
        }
        for item in aggregate["applicability"]
    ]
    rows.extend(
        {
            "chart": "applicability_reasons",
            "scenario_id": "",
            "status": status,
            "reason": item["reason"],
            "count": item[f"{status}_count"],
        }
        for item in aggregate["reasons"]
        for status in ("blocked", "unknown")
    )
    _write_csv(path, rows, ("chart", "scenario_id", "status", "reason", "count"))


def _svg_header(title: str, description: str, width: int, height: int) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" viewBox="0 0 {width} {height}">'
        f"<title>{escape(title)}</title><desc>{escape(description)}</desc>"
        f'<rect width="{width}" height="{height}" fill="white"/>'
        f'<text x="{width / 2:.1f}" y="34" text-anchor="middle" '
        'font-family="sans-serif" font-size="20" font-weight="bold">'
        f"{escape(title)}</text>"
    )


def _render_rate_chart(title: str, rows: list[Mapping[str, Any]], *, description: str) -> str:
    width, height = 1100, 560
    left, right, top, bottom = 100, 40, 70, 135
    plot_width, plot_height = width - left - right, height - top - bottom
    parts = [_svg_header(title, description, width, height)]
    parts.append(_grid(left, top, plot_width, plot_height, 100, "Rate (%)"))
    count = max(len(rows), 1)
    bar_width = min(150, plot_width / count * 0.62)
    for index, row in enumerate(rows):
        value = float(row["rate"] or 0.0) * 100
        x = left + (index + 0.5) * plot_width / count - bar_width / 2
        y = top + plot_height - plot_height * value / 100
        bar_height = top + plot_height - y
        parts.append(
            f'<rect x="{x:.2f}" y="{y:.2f}" width="{bar_width:.2f}" height="{bar_height:.2f}" '
            f'fill="{_COLORS["cumulative" if "stage" in row else "transition"]}">'
            f"<title>{escape(str(row['label']))}: {value:.1f}% "
            f"({row['reached_count']}/{row['denominator']})</title></rect>"
        )
        label = str(row["label"])
        parts.append(
            f'<text x="{x + bar_width / 2:.2f}" y="{height - bottom + 28}" '
            'text-anchor="middle" font-family="sans-serif" font-size="13">'
            f"{escape(label)}</text>"
        )
        parts.append(
            f'<text x="{x + bar_width / 2:.2f}" y="{max(y - 8, top + 14):.2f}" '
            'text-anchor="middle" font-family="sans-serif" font-size="13">'
            f"{value:.1f}%</text>"
        )
    parts.append("</svg>")
    return "".join(parts)


def _render_stacked_chart(
    title: str, rows: list[Mapping[str, Any]], *, description: str
) -> str:
    width, height = 1200, 600
    left, right, top, bottom = 100, 40, 70, 180
    plot_width, plot_height = width - left - right, height - top - bottom
    maximum = max((row["before_candidate_count"] for row in rows), default=0)
    maximum = max(maximum, 1)
    parts = [_svg_header(title, description, width, height)]
    parts.append(_grid(left, top, plot_width, plot_height, maximum, "Candidates"))
    count = max(len(rows), 1)
    bar_width = min(150, plot_width / count * 0.58)
    for index, row in enumerate(rows):
        x = left + (index + 0.5) * plot_width / count - bar_width / 2
        current_y = top + plot_height
        for status in _STATUSES:
            value = row[f"{status}_count"]
            bar_height = plot_height * value / maximum
            current_y -= bar_height
            parts.append(
                f'<rect x="{x:.2f}" y="{current_y:.2f}" width="{bar_width:.2f}" '
                f'height="{bar_height:.2f}" fill="{_COLORS[status]}">'
                f"<title>{escape(row['scenario_id'])} {status}: {value}</title></rect>"
            )
        parts.append(
            f'<text x="{x + bar_width / 2:.2f}" y="{height - bottom + 28}" '
            'text-anchor="middle" font-family="sans-serif" font-size="12" '
            f'transform="rotate(-38 {x + bar_width / 2:.2f} {height - bottom + 28})">'
            f"{escape(row['scenario_id'])}</text>"
        )
    parts.append(_legend(left, height - 62, _STATUSES))
    parts.append("</svg>")
    return "".join(parts)


def _render_reason_chart(
    title: str, rows: list[Mapping[str, Any]], *, description: str
) -> str:
    width, height = 1200, 600
    left, right, top, bottom = 100, 40, 70, 180
    plot_width, plot_height = width - left - right, height - top - bottom
    maximum = max(
        (max(row["blocked_count"], row["unknown_count"]) for row in rows), default=0
    )
    maximum = max(maximum, 1)
    parts = [_svg_header(title, description, width, height)]
    parts.append(_grid(left, top, plot_width, plot_height, maximum, "Occurrences"))
    chart_rows = rows or [
        {"reason": "", "label": "No reasons", "blocked_count": 0, "unknown_count": 0}
    ]
    group_width = plot_width / max(len(chart_rows), 1)
    bar_width = min(46, group_width * 0.26)
    for index, row in enumerate(chart_rows):
        center = left + (index + 0.5) * group_width
        for series_index, status in enumerate(("blocked", "unknown")):
            value = row[f"{status}_count"]
            x = center + (series_index - 0.5) * bar_width
            y = top + plot_height - plot_height * value / maximum
            parts.append(
                f'<rect x="{x:.2f}" y="{y:.2f}" width="{bar_width:.2f}" '
                f'height="{top + plot_height - y:.2f}" fill="{_COLORS[status]}">'
                f"<title>{escape(str(row['label']))} {status}: {value}</title></rect>"
            )
        parts.append(
            f'<text x="{center:.2f}" y="{height - bottom + 28}" text-anchor="middle" '
            'font-family="sans-serif" font-size="12" '
            f'transform="rotate(-38 {center:.2f} {height - bottom + 28})">'
            f"{escape(str(row['label']))}</text>"
        )
    parts.append(_legend(left, height - 62, ("blocked", "unknown")))
    parts.append("</svg>")
    return "".join(parts)


def _grid(left: int, top: int, width: int, height: int, maximum: int, axis_title: str) -> str:
    parts = [
        f'<line x1="{left}" y1="{top + height}" x2="{left + width}" y2="{top + height}" '
        f'stroke="#374151"/><line x1="{left}" y1="{top}" x2="{left}" y2="{top + height}" '
        'stroke="#374151"/>'
    ]
    tick_values = list(range(maximum + 1)) if maximum <= 4 else [
        maximum * tick / 4 for tick in range(5)
    ]
    for value in tick_values:
        y = top + height - height * value / maximum
        parts.append(
            f'<line x1="{left}" y1="{y:.2f}" x2="{left + width}" y2="{y:.2f}" '
            'stroke="#e5e7eb"/>'
            f'<text x="{left - 12}" y="{y + 4:.2f}" text-anchor="end" '
            'font-family="sans-serif" font-size="12">'
            f"{value:.0f}</text>"
        )
    parts.append(
        f'<text x="24" y="{top + height / 2:.2f}" text-anchor="middle" '
        'font-family="sans-serif" font-size="13" transform="rotate(-90 24 '
        f'{top + height / 2:.2f})">{escape(axis_title)}</text>'
    )
    return "".join(parts)


def _legend(x: int, y: int, series: Iterable[str]) -> str:
    parts: list[str] = []
    current_x = x
    for item in series:
        label = _STATUS_LABELS.get(item, item)
        parts.append(
            f'<rect x="{current_x}" y="{y - 12}" width="14" height="14" fill="{_COLORS[item]}"/>'
            f'<text x="{current_x + 22}" y="{y}" font-family="sans-serif" font-size="13">'
            f"{escape(label)}</text>"
        )
        current_x += 130
    return "".join(parts)
