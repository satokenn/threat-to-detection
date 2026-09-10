"""Command-line entry point for system inspection and end-to-end analysis."""

import argparse
import hashlib
import json
import logging
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from threat_to_detection.collectors.attack import ATTACK_STIX_URL, AttackCollector, AttackDataError
from threat_to_detection.collectors.capec import CAPEC_XML_URL, CapecCollector, CapecDataError
from threat_to_detection.collectors.nvd import NVD_CVE_URL, NvdApiError, NvdClient
from threat_to_detection.models.provenance import DataSnapshot, display_path, file_sha256
from threat_to_detection.models.system import load_system
from threat_to_detection.reporters.sigma import sigma_rule_matches_event
from threat_to_detection.services.cve_evaluation import evaluate_cves, load_selection
from threat_to_detection.services.cve_selection import (
    CVE_PERIOD_END,
    CVE_PERIOD_START,
    DEFAULT_SAMPLE_SIZE,
    DEFAULT_SELECTION_SEED,
    CveSelectionError,
    iter_date_windows,
    load_kev_ids,
    replay_selection,
    select_cves,
)
from threat_to_detection.services.multidomain import evaluate_catalog, render_report
from threat_to_detection.services.pipeline import run_analysis

LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect a threat model YAML file")
    parser.add_argument("system", help="Path to the system model YAML")
    return parser


def build_fetch_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fetch CVEs from the NVD API 2.0")
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--cve-id")
    selector.add_argument("--cpe-name")
    selector.add_argument("--keyword")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--no-cache", action="store_true")
    return parser


def build_select_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threat-to-detection select-cves",
        description="Build and sample a reproducible stratified CVE evaluation set",
    )
    parser.add_argument("--start-date", type=_iso_date, default=CVE_PERIOD_START)
    parser.add_argument("--end-date", type=_iso_date, default=CVE_PERIOD_END)
    parser.add_argument("--seed", type=int, default=DEFAULT_SELECTION_SEED)
    parser.add_argument("--per-category", type=int, default=DEFAULT_SAMPLE_SIZE)
    parser.add_argument("--output", default="evaluations/cve-selection.json")
    parser.add_argument("--nvd-cache", default="data/cache/nvd-selection")
    parser.add_argument("--nvd-fixture")
    parser.add_argument(
        "--replay",
        help=(
            "Validate and replay a committed selection JSON without NVD access; "
            "can be used with --offline"
        ),
    )
    parser.add_argument("--kev-file", help="Optional CISA KEV JSON or CSV export")
    network = parser.add_mutually_exclusive_group()
    network.add_argument(
        "--offline",
        action="store_true",
        help="Disable NVD network access; use --nvd-fixture or an existing cache",
    )
    network.add_argument(
        "--online",
        action="store_true",
        help="Allow NVD downloads for missing date-window responses",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Force refresh of NVD date-window responses; implies --online",
    )
    return parser


def build_evaluate_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threat-to-detection evaluate-cves",
        description="Evaluate mapping reachability for a selected CVE set",
    )
    parser.add_argument(
        "--selection",
        default="evaluations/cve-selection.json",
        help="Issue #23 selection output (default: evaluations/cve-selection.json)",
    )
    parser.add_argument(
        "--capec-path",
        "--capec-fixture",
        dest="capec_path",
        help="CAPEC XML snapshot or fixture",
    )
    parser.add_argument(
        "--attack-path",
        "--attack-fixture",
        dest="attack_path",
        help="Enterprise ATT&CK STIX snapshot or fixture",
    )
    parser.add_argument(
        "--output",
        default="evaluations/cve-evaluation.json",
        help="Machine-readable evaluation output",
    )
    network = parser.add_mutually_exclusive_group()
    network.add_argument(
        "--offline",
        action="store_true",
        help="Disable downloads; use existing snapshots or fixtures",
    )
    network.add_argument(
        "--online",
        action="store_true",
        help="Download missing CAPEC and ATT&CK snapshots",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Refresh CAPEC and ATT&CK snapshots; implies --online",
    )
    return parser


def build_analyze_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threat-to-detection analyze",
        description="Run the CVE-to-Sigma analysis pipeline for a system YAML",
    )
    parser.add_argument("scenario", help="Path to the system model YAML")
    parser.add_argument(
        "--output-dir",
        "--output",
        default="output",
        help="Artifact root for analysis.json and sigma/ (default: output)",
    )
    parser.add_argument(
        "--nvd-cache",
        "--cache-dir",
        dest="nvd_cache",
        default="data/cache/nvd",
        help="NVD response cache directory; use an empty value to disable cache",
    )
    parser.add_argument(
        "--nvd-fixture",
        "--vulnerability-fixture",
        dest="nvd_fixture",
        help="Offline NVD JSON response fixture",
    )
    parser.add_argument(
        "--capec-path",
        "--capec-fixture",
        "--capec-xml",
        "--capec",
        dest="capec_path",
        help="CAPEC XML path (also used as an offline fixture)",
    )
    parser.add_argument(
        "--attack-path",
        "--attack-fixture",
        "--attack-json",
        "--attack",
        dest="attack_path",
        help="Enterprise ATT&CK STIX JSON path (also used as an offline fixture)",
    )
    network = parser.add_mutually_exclusive_group()
    network.add_argument(
        "--offline",
        action="store_true",
        help="Disable all network access; provide --nvd-fixture for offline CVE data",
    )
    network.add_argument(
        "--online",
        action="store_true",
        help="Allow downloads for missing CAPEC/ATT&CK datasets",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Force refresh of local datasets; implies --online",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return exit code 3 when the analysis is partial",
    )
    parser.add_argument("--logsource-category")
    parser.add_argument("--logsource-product")
    parser.add_argument("--logsource-service")
    parser.add_argument("--positive-samples", help="JSONL file containing positive events")
    parser.add_argument("--negative-samples", help="JSONL file containing negative events")
    parser.add_argument("--verbose", action="store_true", help="Enable diagnostic logging")
    return parser


def build_evaluate_scenarios_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threat-to-detection evaluate-scenarios",
        description="Evaluate every checked-in multi-domain scenario offline",
    )
    parser.add_argument("--index", default="evaluations/scenarios/index.yaml")
    parser.add_argument("--capec-fixture", required=True)
    parser.add_argument("--attack-fixture", required=True)
    parser.add_argument("--nvd-fixture")
    parser.add_argument("--output", default="evaluations/multidomain-results.json")
    parser.add_argument("--report", default="evaluations/report.md")
    return parser


def fetch_cves(argv: list[str]) -> int:
    args = build_fetch_parser().parse_args(argv)
    try:
        vulnerabilities = NvdClient(
            cache_dir=None if args.no_cache else "data/cache/nvd"
        ).search_cves(
            cve_id=args.cve_id,
            cpe_name=args.cpe_name,
            keyword=args.keyword,
            results_per_page=args.limit,
        )
    except (NvdApiError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for vulnerability in vulnerabilities:
        score = f" CVSS={vulnerability.cvss_score}" if vulnerability.cvss_score else ""
        print(f"{vulnerability.cve_id}{score} {vulnerability.description}")
    return 0


def select_cves_command(argv: list[str]) -> int:
    args = build_select_parser().parse_args(argv)
    if args.offline and (args.online or args.refresh):
        build_select_parser().error("--offline cannot be combined with --online or --refresh")
    try:
        if args.replay:
            if args.nvd_fixture or args.online or args.refresh or args.kev_file:
                build_select_parser().error(
                    "--replay cannot be combined with NVD, network, refresh, or KEV options"
                )
            document = replay_selection(args.replay)
            document["source"] = {
                "mode": "replay",
                "replay_of": {
                    "path": display_path(Path(args.replay)),
                    "sha256": file_sha256(Path(args.replay)),
                },
            }
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            selected = document.get("selected", [])
            print(f"selection: {output}")
            print(f"selected: {len(selected) if isinstance(selected, list) else 0}")
            print("mode: replay")
            return 0
        vulnerabilities, request_metadata = _fetch_selection_vulnerabilities(args)
        kev_ids = load_kev_ids(args.kev_file) if args.kev_file else frozenset()
        result = select_cves(
            vulnerabilities,
            start_date=args.start_date,
            end_date=args.end_date,
            seed=args.seed,
            sample_size=args.per_category,
            kev_ids=kev_ids,
        )
    except (CveSelectionError, OSError, ValueError, NvdApiError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    document = result.to_mapping()
    document["source"] = {
        "nvd_api": NVD_CVE_URL,
        "nvd_request_windows": len(request_metadata),
        "nvd_requests": [
            {
                "url": record.get("url"),
                "mode": record.get("mode"),
                "path": record.get("path"),
                "release": record.get("release"),
                "retrieved_at": record.get("retrieved_at"),
                "raw_sha256": record.get("raw_sha256"),
            }
            for record in request_metadata
        ],
        "kev": {
            "path": str(args.kev_file) if args.kev_file else None,
            "loaded": bool(args.kev_file),
            "record_count": len(kev_ids),
        },
    }
    output = Path(args.output)
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    except OSError as error:
        print(f"error: could not write {output}: {error}", file=sys.stderr)
        return 2

    print(f"selection: {output}")
    print(f"candidates: {len(result.candidates)}")
    print(f"selected: {len(result.selected)}")
    print(f"seed: {result.seed}")
    return 0


def evaluate_cves_command(argv: list[str]) -> int:
    args = build_evaluate_parser().parse_args(argv)
    if args.offline and (args.online or args.refresh):
        build_evaluate_parser().error("--offline cannot be combined with --online or --refresh")
    try:
        vulnerabilities, categories = load_selection(args.selection)
        errors: list[str] = []
        allow_online = args.online or args.refresh
        capec_input = (
            args.capec_path
            if args.capec_path
            else None
            if allow_online
            else "tests/fixtures/evaluation/capec-selected.xml"
        )
        attack_input = (
            args.attack_path
            if args.attack_path
            else None
            if allow_online
            else "tests/fixtures/evaluation/attack-selected.json"
        )
        capec_dataset = _load_capec(
            capec_input,
            args.offline,
            errors,
            online=allow_online,
            refresh=args.refresh,
        )
        attack_dataset = _load_attack(
            attack_input,
            args.offline,
            errors,
            online=allow_online,
            refresh=args.refresh,
        )
        if errors or capec_dataset is None or attack_dataset is None:
            raise ValueError("; ".join(errors) or "CAPEC and ATT&CK datasets are required")
        capec_path = (
            Path(capec_input)
            if capec_input
            else Path("data/cache/capec_latest.xml")
        )
        attack_path = (
            Path(attack_input)
            if attack_input
            else Path("data/cache/enterprise-attack.json")
        )
        capec_mode = "fixture" if capec_input else "refresh" if args.refresh else "online"
        attack_mode = "fixture" if attack_input else "refresh" if args.refresh else "online"
        result = evaluate_cves(
            vulnerabilities,
            categories=categories,
            capec_dataset=capec_dataset,
            attack_dataset=attack_dataset,
            selection_path=str(args.selection),
        )
        document = result.to_mapping()
        document["source"] = {
            "selection": {
                "path": display_path(Path(args.selection)),
                "sha256": file_sha256(Path(args.selection)),
            },
            "capec": {
                "url": CAPEC_XML_URL,
                "mode": capec_mode,
                "path": display_path(capec_path),
                "sha256": file_sha256(capec_path),
            },
            "attack": {
                "url": ATTACK_STIX_URL,
                "mode": attack_mode,
                "path": display_path(attack_path),
                "sha256": file_sha256(attack_path),
            },
        }
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    except (OSError, ValueError, CapecDataError, AttackDataError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    metrics = document["metrics"]
    print(f"evaluation: {output}")
    print(f"cves: {metrics['population']}")
    print(f"detection reached: {metrics['cumulative']['detection']['reached_count']}")
    print(f"mapping gaps: {metrics['mapping_gaps']['total']}")
    return 0


def evaluate_scenarios_command(argv: list[str]) -> int:
    args = build_evaluate_scenarios_parser().parse_args(argv)
    errors: list[str] = []
    try:
        capec_dataset = _load_capec(args.capec_fixture, True, errors)
        attack_dataset = _load_attack(args.attack_fixture, True, errors)
        nvd_client = _build_nvd_client(
            args.nvd_fixture,
            None,
            errors,
            offline=True,
        )
        if errors or capec_dataset is None or attack_dataset is None:
            raise ValueError("; ".join(errors) or "evaluation fixtures are required")
        result = evaluate_catalog(
            args.index,
            capec_dataset=capec_dataset,
            attack_dataset=attack_dataset,
            nvd_client=nvd_client,
        )
        output = Path(args.output)
        report = Path(args.report)
        output.parent.mkdir(parents=True, exist_ok=True)
        report.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        report.write_text(render_report(result), encoding="utf-8")
    except (OSError, ValueError, CapecDataError, AttackDataError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"evaluation: {output}")
    print(f"report: {report}")
    print(f"scenarios: {result['summary']['scenario_count']}")
    return 0


def _fetch_selection_vulnerabilities(
    args: argparse.Namespace,
) -> tuple[tuple[Any, ...], tuple[dict[str, Any], ...]]:
    payload: dict[str, Any] | None = None
    if args.nvd_fixture:
        payload = json.loads(Path(args.nvd_fixture).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("NVD fixture must contain a JSON object")

    def opener(_request: Any, _timeout: float) -> dict[str, Any]:
        assert payload is not None
        return payload

    client = NvdClient(
        api_key=None,
        cache_dir=None if payload is not None else args.nvd_cache,
        opener=opener if payload is not None else None,
        allow_network=bool(args.online or args.refresh or payload is not None),
        refresh=args.refresh,
    )
    vulnerabilities: dict[str, Any] = {}
    for pub_start, pub_end in iter_date_windows(args.start_date, args.end_date):
        for vulnerability in client.fetch_all(
            pub_start_date=pub_start,
            pub_end_date=pub_end,
        ):
            vulnerabilities.setdefault(vulnerability.cve_id, vulnerability)
    return tuple(vulnerabilities.values()), client.request_metadata


def _iso_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("date must be YYYY-MM-DD") from error


def analyze_scenario(argv: list[str]) -> int:
    args = build_analyze_parser().parse_args(argv)
    if args.offline and (args.online or args.refresh):
        build_analyze_parser().error("--offline cannot be combined with --online or --refresh")
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    try:
        system = load_system(args.scenario)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    output_dir = Path(args.output_dir)
    errors: list[str] = []
    capec_destination = (
        Path(args.capec_path) if args.capec_path else Path("data/cache/capec_latest.xml")
    )
    attack_destination = (
        Path(args.attack_path) if args.attack_path else Path("data/cache/enterprise-attack.json")
    )
    capec_was_present = capec_destination.exists()
    attack_was_present = attack_destination.exists()
    online = args.online or args.refresh
    nvd_client = _build_nvd_client(
        args.nvd_fixture,
        args.nvd_cache,
        errors,
        offline=args.offline,
        online=online,
        refresh=args.refresh,
    )
    capec_dataset = _load_capec(
        args.capec_path,
        args.offline,
        errors,
        online=online,
        refresh=args.refresh,
    )
    attack_dataset = _load_attack(
        args.attack_path,
        args.offline,
        errors,
        online=online,
        refresh=args.refresh,
    )
    result = run_analysis(
        system,
        nvd_client=nvd_client,
        capec_dataset=capec_dataset,
        attack_dataset=attack_dataset,
        output_dir=output_dir,
        logsource_resolver=_logsource_override(args),
    )
    document = result.to_mapping(system)
    snapshots = _build_snapshots(
        args,
        nvd_client=nvd_client,
        capec_path=capec_destination,
        attack_path=attack_destination,
        capec_was_present=capec_was_present,
        attack_was_present=attack_was_present,
        errors=errors,
    )
    document["execution"] = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "mode": _execution_mode(args, snapshots),
        "network_allowed": online,
        "input": display_path(args.scenario),
    }
    document["mode"] = document["execution"]["mode"]
    document["snapshots"] = {name: snapshot.to_mapping() for name, snapshot in snapshots.items()}
    document["metrics"] = _analysis_metrics(document)
    document["evaluation"] = _evaluate_samples(
        result.sigma_rules,
        args.positive_samples,
        args.negative_samples,
        scenario_path=Path(args.scenario),
        errors=errors,
    )
    document["metrics"].update(_evaluation_metrics(document["evaluation"]))
    all_errors = [*errors, *(error.message for error in result.errors)]
    if all_errors:
        # Keep loader errors visible in the machine-readable report too.
        document["errors"] = [
            *document.get("errors", []),
        ] + [
            {
                "stage": (
                    "nvd"
                    if message.startswith(("Offline mode", "Could not load NVD"))
                    else "dataset"
                ),
                "message": message,
            }
            for message in errors
        ]
        document["status"] = "partial"
    document["metrics"]["errors"] = len(document.get("errors", []))
    document["counts"] = dict(document["metrics"])
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "analysis.json").write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    except OSError as error:
        print(f"error: could not write analysis.json: {error}", file=sys.stderr)
        return 2
    try:
        _write_manifest(output_dir, document, result, snapshots)
    except OSError as error:
        print(f"error: could not write manifest.json: {error}", file=sys.stderr)
        return 2

    for message in all_errors:
        LOGGER.warning(message)
    print(f"analysis: {output_dir / 'analysis.json'}")
    print(f"assets: {len(system.assets)}")
    print(f"trace paths: {len(result.traces)}")
    print(f"sigma rules: {sum(len(rules) for rules in result.sigma_rules.values())}")
    return 3 if args.strict and document.get("status") != "success" else 0


def _write_manifest(
    output_dir: Path,
    document: dict[str, Any],
    result: Any,
    snapshots: dict[str, DataSnapshot],
) -> None:
    """Write a manifest for files owned by this analysis run."""
    files: list[dict[str, Any]] = [{
        "path": "analysis.json",
        "kind": "analysis",
        "status": "written",
        "title": None,
        "sha256": hashlib.sha256((output_dir / "analysis.json").read_bytes()).hexdigest(),
        "depends_on": ["scenario", *snapshots],
    }]
    for artifacts in result.sigma_artifacts.values():
        for artifact in artifacts:
            relative_path = Path(artifact.file) if artifact.file else None
            absolute_path = output_dir / relative_path if relative_path else None
            files.append(
                {
                    "path": relative_path.as_posix() if relative_path else None,
                    "kind": "sigma",
                    "status": artifact.status,
                    "title": artifact.title or None,
                    "sha256": (
                        hashlib.sha256(absolute_path.read_bytes()).hexdigest()
                        if absolute_path and absolute_path.is_file()
                        else None
                    ),
                    "depends_on": ["scenario", "nvd", "capec", "attack"],
                }
            )
    input_path = Path(str(document.get("execution", {}).get("input", "")))
    scenario_input = {
        "path": input_path.as_posix(),
        "sha256": file_sha256(input_path) if input_path.is_file() else None,
    }
    manifest = {
        "schema_version": "1.0",
        "scenario_id": document.get("scenario_id"),
        "status": document.get("status"),
        "mode": document.get("mode"),
        "inputs": {
            "scenario": scenario_input,
            "snapshots": {name: snapshot.to_mapping() for name, snapshot in snapshots.items()},
        },
        "files": files,
        "relationships": [
            {"artifact": item["path"], "inputs": item["depends_on"]} for item in files
        ],
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _build_snapshots(
    args: argparse.Namespace,
    *,
    nvd_client: NvdClient | None,
    capec_path: Path,
    attack_path: Path,
    capec_was_present: bool,
    attack_was_present: bool,
    errors: list[str],
) -> dict[str, DataSnapshot]:
    snapshots: dict[str, DataSnapshot] = {}
    snapshots["nvd"] = _nvd_snapshot(args, nvd_client, errors)
    snapshots["capec"] = _file_snapshot(
        source="capec",
        path=capec_path,
        url=CAPEC_XML_URL,
        mode=_dataset_mode(
            args.capec_path,
            args.refresh,
            args.online,
            capec_was_present,
        ),
        release=_capec_release(capec_path),
        retrieved_at=_capec_date(capec_path),
        normalization=("Parse active Attack_Pattern records", "Normalize CWE IDs to CWE-N"),
        exclusions=("Reject records without CAPEC ID or name",),
    )
    snapshots["attack"] = _file_snapshot(
        source="attack",
        path=attack_path,
        url=ATTACK_STIX_URL,
        mode=_dataset_mode(
            args.attack_path,
            args.refresh,
            args.online,
            attack_was_present,
        ),
        release=_attack_release(attack_path),
        retrieved_at=_attack_date(attack_path),
        normalization=(
            "Parse Enterprise ATT&CK STIX attack-patterns",
            "Normalize external IDs to uppercase",
            "Normalize CAPEC IDs to CAPEC-N",
        ),
        exclusions=("Exclude revoked or deprecated STIX objects",),
    )
    return snapshots


def _file_snapshot(
    *,
    source: str,
    path: Path,
    url: str,
    mode: str,
    release: str | None,
    retrieved_at: str | None,
    normalization: tuple[str, ...],
    exclusions: tuple[str, ...],
) -> DataSnapshot:
    raw_sha256 = file_sha256(path) if path.is_file() else None
    return DataSnapshot(
        source=source,
        mode=mode,
        url=url,
        path=display_path(path),
        release=release or (f"file:{raw_sha256[:16]}" if raw_sha256 else None),
        retrieved_at=retrieved_at,
        sha=release or raw_sha256,
        raw_sha256=raw_sha256,
        normalization=normalization,
        exclusions=exclusions,
    )


def _nvd_snapshot(
    args: argparse.Namespace,
    client: NvdClient | None,
    errors: list[str],
) -> DataSnapshot:
    normalization = (
        "Select English descriptions and CWE references",
        "Extract CVSS base score",
        "Extract the first concrete CPE product and version",
    )
    exclusions = ("Ignore malformed vulnerability entries without a cve object",)
    if args.nvd_fixture:
        path = Path(args.nvd_fixture)
        payload: dict[str, Any] = {}
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, dict):
                payload = value
        except (OSError, json.JSONDecodeError):
            pass
        return _file_snapshot(
            source="nvd",
            path=path,
            url=NVD_CVE_URL,
            mode="fixture",
            release=payload.get("dataVersion") or payload.get("version"),
            retrieved_at=payload.get("timestamp"),
            normalization=normalization,
            exclusions=exclusions,
        )

    records = tuple(getattr(client, "request_metadata", ())) if client else ()
    if records:
        raw_hashes = sorted(
            str(record["raw_sha256"])
            for record in records
            if record.get("raw_sha256")
        )
        combined_hash = hashlib.sha256("\n".join(raw_hashes).encode("utf-8")).hexdigest()
        modes = {record.get("mode") for record in records}
        mode = "refresh" if "refresh" in modes else "online" if "online" in modes else "cache"
        paths = sorted({str(record["path"]) for record in records if record.get("path")})
        public_records = tuple(
            {
                **record,
                "path": display_path(record["path"]) if record.get("path") else None,
            }
            for record in records
        )
        return DataSnapshot(
            source="nvd",
            mode=mode,
            url=NVD_CVE_URL,
            path=(
                display_path(paths[0])
                if len(paths) == 1
                else display_path(args.nvd_cache) if args.nvd_cache else None
            ),
            release=next(
                (record.get("release") for record in records if record.get("release")),
                None,
            ) or f"responses:{len(records)}",
            retrieved_at=next(
                (record.get("retrieved_at") for record in records if record.get("retrieved_at")),
                None,
            ),
            sha=next((record.get("sha") for record in records if record.get("sha")), None)
            or combined_hash,
            raw_sha256=combined_hash,
            normalization=normalization,
            exclusions=exclusions,
            records=public_records,
        )

    cache_path = Path(args.nvd_cache) if args.nvd_cache else None
    return DataSnapshot(
        source="nvd",
        mode="refresh" if args.refresh else "cache",
        url=NVD_CVE_URL,
        path=display_path(cache_path) if cache_path else None,
        normalization=normalization,
        exclusions=exclusions,
    )


def _dataset_mode(
    explicit_path: str | None,
    refresh: bool,
    online: bool,
    was_present: bool,
) -> str:
    if explicit_path:
        return "fixture"
    if refresh:
        return "refresh"
    if was_present:
        return "cache"
    if online:
        return "online"
    return "cache"


def _execution_mode(args: argparse.Namespace, snapshots: dict[str, DataSnapshot]) -> str:
    modes = {snapshot.mode for snapshot in snapshots.values()}
    if args.refresh:
        return "refresh"
    if args.online and "online" in modes:
        return "online"
    if "fixture" in modes:
        return "fixture"
    return "cache"


def _capec_release(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        root = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError):
        return None
    return next(
        (value for key, value in root.attrib.items() if key.lower() in {"version", "release"}),
        None,
    )


def _capec_date(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        root = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError):
        return None
    return next(
        (value for key, value in root.attrib.items() if key.lower() in {"date", "last_modified"}),
        None,
    )


def _attack_document(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _attack_release(path: Path) -> str | None:
    document = _attack_document(path)
    if document.get("version"):
        return str(document["version"])
    objects = document.get("objects", [])
    versions = sorted(
        str(item["x_mitre_version"])
        for item in objects
        if isinstance(item, dict) and item.get("x_mitre_version")
    )
    return versions[-1] if versions else document.get("id")


def _attack_date(path: Path) -> str | None:
    objects = _attack_document(path).get("objects", [])
    dates = sorted(
        str(item["modified"])
        for item in objects
        if isinstance(item, dict) and item.get("modified")
    )
    return dates[-1] if dates else None


def _analysis_metrics(document: dict[str, Any]) -> dict[str, int]:
    assets = document.get("assets", {})
    cves: set[str] = set()
    cwes: set[str] = set()
    capecs: set[str] = set()
    techniques: set[str] = set()
    requirements = 0
    sigma_rules = 0
    for asset in assets.values():
        for vulnerability in asset.get("vulnerabilities", []):
            cves.add(vulnerability["cve_id"])
            cwes.update(vulnerability.get("cwes", []))
        intermediate = asset.get("intermediate", {})
        capecs.update(intermediate.get("capec_ids", []))
        techniques.update(intermediate.get("technique_ids", []))
        requirements += len(asset.get("detection_requirements", []))
        sigma_rules += len(asset.get("sigma_rules", []))
    return {
        "assets": len(assets),
        "cves": len(cves),
        "cwes": len(cwes),
        "capecs": len(capecs),
        "techniques": len(techniques),
        "detection_requirements": requirements,
        "sigma_rules": sigma_rules,
        "complete_paths": len(document.get("trace_paths", [])),
        "candidate_paths": len(document.get("trace_paths", [])),
        "mapping_gaps": len(document.get("mapping_gaps", [])),
    }


def _sample_path(explicit: str | None, scenario_path: Path, name: str) -> Path | None:
    if explicit:
        return Path(explicit)
    candidate = scenario_path.parent / "samples" / name
    return candidate if candidate.is_file() else None


def _read_jsonl(path: Path, errors: list[str]) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        errors.append(f"Could not load sample file {path}: {error}")
        return []
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            errors.append(f"Could not parse sample file {path}:{line_number}: {error}")
            continue
        if not isinstance(value, dict):
            errors.append(f"Sample event must be a JSON object: {path}:{line_number}")
            continue
        events.append(value)
    return events


def _evaluate_samples(
    sigma_rules: dict[str, tuple[Any, ...]],
    positive_path: str | None,
    negative_path: str | None,
    *,
    scenario_path: Path,
    errors: list[str],
) -> dict[str, Any]:
    paths = {
        "positive": _sample_path(positive_path, scenario_path, "positive.jsonl"),
        "negative": _sample_path(negative_path, scenario_path, "negative.jsonl"),
    }
    if not any(paths.values()):
        return {"status": "not_run", "positive": None, "negative": None}

    rules = tuple(rule for values in sigma_rules.values() for rule in values)
    evaluation: dict[str, Any] = {"status": "pass"}
    for label, path in paths.items():
        if path is None:
            evaluation[label] = None
            continue
        events = _read_jsonl(path, errors)
        matched = sum(
            any(sigma_rule_matches_event(rule, event) for rule in rules) for event in events
        )
        passed = matched == len(events) if label == "positive" else matched == 0
        evaluation[label] = {
            "path": display_path(path),
            "count": len(events),
            "matched": matched,
            "unmatched": len(events) - matched,
            "expected": "all_match" if label == "positive" else "none_match",
            "result": "pass" if passed else "fail",
        }
        if not passed:
            evaluation["status"] = "fail"
    return evaluation


def _evaluation_metrics(evaluation: dict[str, Any]) -> dict[str, int]:
    result: dict[str, int] = {}
    for label in ("positive", "negative"):
        sample = evaluation.get(label)
        if sample:
            result[f"{label}_samples"] = sample["count"]
            result[f"{label}_matched"] = sample["matched"]
    return result


def _build_nvd_client(
    fixture: str | None,
    cache_dir: str | None,
    errors: list[str],
    *,
    offline: bool = False,
    online: bool = False,
    refresh: bool = False,
) -> NvdClient | None:
    cache_available = bool(
        cache_dir
        and Path(cache_dir).is_dir()
        and any(Path(cache_dir).glob("*.json"))
    )
    if offline and not fixture and not cache_available:
        errors.append("Offline mode requires --nvd-fixture; NVD network access is disabled")
        return None
    if not fixture:
        return NvdClient(
            cache_dir=cache_dir or None,
            allow_network=online or refresh,
            refresh=refresh,
        )
    try:
        payload = json.loads(Path(fixture).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("NVD fixture must contain a JSON object")
    except (OSError, json.JSONDecodeError, ValueError) as error:
        errors.append(f"Could not load NVD fixture {fixture}: {error}")
        payload = {"vulnerabilities": []}

    def opener(_request: Any, _timeout: float) -> dict[str, Any]:
        return payload

    # The injected opener reads a local fixture; it is not a network boundary.
    return NvdClient(cache_dir=None, opener=opener, allow_network=True)


def _logsource_override(args: argparse.Namespace) -> dict[str, str] | None:
    values = {
        key: value
        for key, value in (
            ("category", args.logsource_category),
            ("product", args.logsource_product),
            ("service", args.logsource_service),
        )
        if value
    }
    return values or None


def _load_capec(
    path: str | None,
    offline: bool,
    errors: list[str],
    *,
    online: bool = False,
    refresh: bool = False,
):
    destination = Path(path) if path else Path("data/cache/capec_latest.xml")
    collector = CapecCollector()
    if (not destination.exists() or refresh) and not offline and not path and online:
        try:
            collector.download(destination)
        except CapecDataError as error:
            errors.append(str(error))
            return None
    if not destination.exists():
        errors.append(f"CAPEC dataset not found: {destination}")
        return None
    try:
        return collector.load(destination)
    except CapecDataError as error:
        errors.append(str(error))
        return None


def _load_attack(
    path: str | None,
    offline: bool,
    errors: list[str],
    *,
    online: bool = False,
    refresh: bool = False,
):
    destination = Path(path) if path else Path("data/cache/enterprise-attack.json")
    collector = AttackCollector()
    if (not destination.exists() or refresh) and not offline and not path and online:
        try:
            collector.download(destination)
        except AttackDataError as error:
            errors.append(str(error))
            return None
    if not destination.exists():
        errors.append(f"ATT&CK dataset not found: {destination}")
        return None
    try:
        return collector.load(destination)
    except AttackDataError as error:
        errors.append(str(error))
        return None


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "fetch-cves":
        return fetch_cves(argv[1:])
    if argv and argv[0] in {"select-cves", "collect-cves"}:
        return select_cves_command(argv[1:])
    if argv and argv[0] == "evaluate-cves":
        return evaluate_cves_command(argv[1:])
    if argv and argv[0] == "evaluate-scenarios":
        return evaluate_scenarios_command(argv[1:])
    if argv and argv[0] == "analyze":
        return analyze_scenario(argv[1:])
    args = build_parser().parse_args(argv)
    try:
        system = load_system(args.system)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print(f"assets: {len(system.assets)}")
    print(f"flows: {len(system.flows)}")
    for asset in system.assets:
        software = ", ".join(f"{item.name} {item.version}" for item in asset.software)
        print(f"- {asset.name} ({asset.type}): {software or 'no software listed'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
