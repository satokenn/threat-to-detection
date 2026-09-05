"""MITRE ATT&CK STIX data acquisition and parsing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from threat_to_detection.models.attack import AttackTechnique


ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)


class AttackDataError(RuntimeError):
    """Raised when ATT&CK STIX data cannot be downloaded or parsed."""


class AttackDataset:
    """Parsed ATT&CK techniques and a CAPEC reverse index."""

    def __init__(self, techniques: tuple[AttackTechnique, ...]) -> None:
        self.techniques = techniques
        self._by_capec: dict[str, tuple[AttackTechnique, ...]] = {}
        for technique in techniques:
            for capec_id in technique.related_capec_ids:
                self._by_capec.setdefault(capec_id, ())
                self._by_capec[capec_id] += (technique,)

    @classmethod
    def from_json(cls, path: str | Path) -> "AttackDataset":
        try:
            document = json.loads(Path(path).read_text(encoding="utf-8"))
            objects = document["objects"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
            raise AttackDataError(f"Could not parse ATT&CK STIX JSON: {path}") from error
        try:
            techniques = tuple(
                _parse_technique(item)
                for item in objects
                if item.get("type") == "attack-pattern"
                and not item.get("revoked", False)
                and not item.get("x_mitre_deprecated", False)
            )
        except (TypeError, ValueError) as error:
            raise AttackDataError("Invalid ATT&CK attack-pattern object") from error
        return cls(techniques)

    def for_capec(self, capec_id: str) -> tuple[AttackTechnique, ...]:
        """Return all techniques externally mapped to a CAPEC ID."""
        return self._by_capec.get(_normalize_capec(capec_id), ())


class AttackCollector:
    """Download the Enterprise ATT&CK STIX bundle and load it."""

    def __init__(self, url: str = ATTACK_STIX_URL, timeout: float = 30.0) -> None:
        self.url = url
        self.timeout = timeout

    def download(self, destination: str | Path) -> Path:
        destination = Path(destination)
        try:
            with urlopen(self.url, timeout=self.timeout) as response:  # noqa: S310 - configured URL
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(response.read())
        except (HTTPError, URLError, OSError) as error:
            raise AttackDataError(f"Could not download ATT&CK STIX data from {self.url}") from error
        return destination

    def load(self, path: str | Path) -> AttackDataset:
        return AttackDataset.from_json(path)


def _parse_technique(item: dict[str, Any]) -> AttackTechnique:
    technique_id, related_capec_ids = _external_references(item.get("external_references", []))
    if not technique_id or not item.get("name"):
        raise ValueError("ATT&CK technique is missing an external ID or name")
    return AttackTechnique(
        technique_id=technique_id,
        name=item["name"],
        description=item.get("description", ""),
        tactics=tuple(
            phase["phase_name"]
            for phase in item.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
            and phase.get("phase_name")
        ),
        related_capec_ids=tuple(related_capec_ids),
    )


def _external_references(references: list[dict[str, Any]]) -> tuple[str | None, list[str]]:
    technique_id = None
    capec_ids: list[str] = []
    for reference in references:
        source_name = str(reference.get("source_name", "")).lower()
        external_id = reference.get("external_id", "")
        if source_name == "mitre-attack" and str(external_id).startswith("T"):
            technique_id = str(external_id)
        if source_name == "capec" and external_id:
            capec_ids.append(_normalize_capec(str(external_id)))
    return technique_id, list(dict.fromkeys(capec_ids))


def _normalize_capec(capec_id: str) -> str:
    value = capec_id.strip().upper()
    return value if value.startswith("CAPEC-") else f"CAPEC-{value}"
