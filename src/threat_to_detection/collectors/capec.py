"""CAPEC XML acquisition and parsing."""

from __future__ import annotations

from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
from xml.etree import ElementTree

from threat_to_detection.models.capec import CapecAttackPattern


CAPEC_XML_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"


class CapecDataError(RuntimeError):
    """Raised when CAPEC data cannot be downloaded or parsed."""


class CapecDataset:
    """A parsed CAPEC dataset and its CWE reverse index."""

    def __init__(self, patterns: tuple[CapecAttackPattern, ...]) -> None:
        self.patterns = patterns
        self._by_cwe: dict[str, tuple[CapecAttackPattern, ...]] = {}
        for pattern in patterns:
            for cwe_id in pattern.related_weaknesses:
                self._by_cwe.setdefault(cwe_id, ())
                self._by_cwe[cwe_id] += (pattern,)

    @classmethod
    def from_xml(cls, path: str | Path) -> "CapecDataset":
        try:
            root = ElementTree.parse(path).getroot()
        except (OSError, ElementTree.ParseError) as error:
            raise CapecDataError(f"Could not parse CAPEC XML: {path}") from error
        return cls(tuple(_parse_pattern(element) for element in _attack_patterns(root)))

    def for_cwe(self, cwe_id: str) -> tuple[CapecAttackPattern, ...]:
        """Return all CAPEC patterns related to a CWE, or an empty tuple."""
        return self._by_cwe.get(_normalize_cwe(cwe_id), ())


class CapecCollector:
    """Download CAPEC XML and load it as a :class:`CapecDataset`."""

    def __init__(self, url: str = CAPEC_XML_URL, timeout: float = 30.0) -> None:
        self.url = url
        self.timeout = timeout

    def download(self, destination: str | Path) -> Path:
        destination = Path(destination)
        try:
            with urlopen(self.url, timeout=self.timeout) as response:  # noqa: S310 - configured URL
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(response.read())
        except (HTTPError, URLError, OSError) as error:
            raise CapecDataError(f"Could not download CAPEC XML from {self.url}") from error
        return destination

    def load(self, path: str | Path) -> CapecDataset:
        return CapecDataset.from_xml(path)


def _attack_patterns(root: ElementTree.Element) -> list[ElementTree.Element]:
    return [element for element in root.iter() if _local_name(element.tag) == "Attack_Pattern"]


def _parse_pattern(element: ElementTree.Element) -> CapecAttackPattern:
    capec_id = element.attrib.get("ID") or element.attrib.get("id")
    name = element.attrib.get("Name") or element.attrib.get("name")
    if not capec_id or not name:
        raise CapecDataError("CAPEC Attack_Pattern is missing ID or Name")
    description = _child_text(element, "Description")
    weaknesses = []
    for child in element.iter():
        if _local_name(child.tag) != "Related_Weakness":
            continue
        cwe_id = child.attrib.get("CWE_ID") or child.attrib.get("cwe_id")
        if cwe_id:
            weaknesses.append(_normalize_cwe(cwe_id))
    return CapecAttackPattern(
        capec_id=f"CAPEC-{capec_id.removeprefix('CAPEC-')}",
        name=name,
        description=description,
        related_weaknesses=tuple(dict.fromkeys(weaknesses)),
    )


def _child_text(element: ElementTree.Element, child_name: str) -> str:
    for child in element:
        if _local_name(child.tag) == child_name:
            return " ".join("".join(child.itertext()).split())
    return ""


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _normalize_cwe(cwe_id: str) -> str:
    value = cwe_id.strip().upper()
    return value if value.startswith("CWE-") else f"CWE-{value}"
