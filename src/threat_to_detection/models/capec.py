"""Normalized CAPEC attack-pattern models."""

from pydantic import BaseModel, ConfigDict


class CapecAttackPattern(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    capec_id: str
    name: str
    description: str = ""
    related_weaknesses: tuple[str, ...] = ()
