"""Detection planning models."""

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class DataComponent:
    """ATT&CK telemetry concept used by an analytic."""

    component_id: str
    name: str
    data_source_id: str | None = None
    data_source_name: str | None = None
    log_sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class DetectionAnalytic:
    """A platform-specific ATT&CK analytic."""

    analytic_id: str
    name: str
    description: str = ""
    data_components: tuple[DataComponent, ...] = ()
    events: tuple[str, ...] = ()
    fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class DetectionRequirement:
    """Normalized detection information for one ATT&CK technique."""

    technique_id: str
    strategy_id: str
    strategy_name: str
    analytics: tuple[DetectionAnalytic, ...] = ()

    @property
    def data_components(self) -> tuple[DataComponent, ...]:
        return merge_data_components(
            component
            for analytic in self.analytics
            for component in analytic.data_components
        )

    @property
    def required_logs(self) -> tuple[str, ...]:
        return tuple(component.name for component in self.data_components)

    @property
    def events(self) -> tuple[str, ...]:
        return _unique(value for analytic in self.analytics for value in analytic.events)

    @property
    def fields(self) -> tuple[str, ...]:
        return _unique(value for analytic in self.analytics for value in analytic.fields)


def _unique(values):
    return tuple(dict.fromkeys(values))


def merge_data_components(values: Iterable[DataComponent]) -> tuple[DataComponent, ...]:
    """Merge repeated components without losing their telemetry references."""
    merged: dict[str, DataComponent] = {}
    for component in values:
        previous = merged.get(component.component_id)
        if previous is None:
            merged[component.component_id] = component
            continue
        merged[component.component_id] = DataComponent(
            component_id=previous.component_id,
            name=previous.name or component.name,
            data_source_id=previous.data_source_id or component.data_source_id,
            data_source_name=previous.data_source_name or component.data_source_name,
            log_sources=_unique((*previous.log_sources, *component.log_sources)),
        )
    return tuple(merged.values())


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
