"""Detection planning models."""

from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionGuidance:
    behavior: str
    required_logs: tuple[str, ...] = ()
    rationale: str = ""


@dataclass(frozen=True)
class DetectionGap:
    asset: str
    required_logs: tuple[str, ...]
    available_logs: tuple[str, ...]

    @property
    def missing_logs(self) -> tuple[str, ...]:
        available = set(self.available_logs)
        return tuple(log for log in self.required_logs if log not in available)
