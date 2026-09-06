"""Normalized MITRE ATT&CK technique models."""

from pydantic import BaseModel, ConfigDict


class AttackTechnique(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    technique_id: str
    name: str
    description: str = ""
    tactics: tuple[str, ...] = ()
    related_capec_ids: tuple[str, ...] = ()
