"""Helper utilities to build asset-oriented ticket histories."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable, List, Optional

from django.utils import timezone

from ..models import Ticket


__all__ = ["AssetHistory", "build_asset_history"]


@dataclass
class AssetHistory:
    asset_id: str
    tickets: List[Ticket]
    period_start: Optional[timezone.datetime]
    period_end: timezone.datetime
    threshold_count: Optional[int]
    threshold_months: Optional[int]

    @property
    def total(self) -> int:
        return len(self.tickets)

    @property
    def within_threshold_period(self) -> List[Ticket]:
        if not self.period_start:
            return self.tickets
        start = self.period_start
        return [t for t in self.tickets if t.created_at >= start]

    @property
    def rule_triggered(self) -> bool:
        if not self.threshold_count:
            return False
        return len(self.within_threshold_period) >= self.threshold_count


def _coerce_int(value: Optional[str]) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        value_int = int(value)
    except (TypeError, ValueError):
        return None
    return value_int if value_int > 0 else None


def _compute_period_end(reference: Optional[timezone.datetime] = None) -> timezone.datetime:
    return reference or timezone.now()


def _compute_period_start(months: Optional[int], *, reference: Optional[timezone.datetime] = None) -> Optional[timezone.datetime]:
    if not months:
        return None
    # Use 30-day blocks to avoid depending on dateutil.
    return _compute_period_end(reference) - timedelta(days=30 * months)


def build_asset_history(
    *,
    asset_id: str,
    queryset: Iterable[Ticket],
    rule_n: Optional[str],
    rule_m: Optional[str],
    reference: Optional[timezone.datetime] = None,
) -> AssetHistory:
    threshold_count = _coerce_int(rule_n)
    threshold_months = _coerce_int(rule_m)

    tickets = [t for t in queryset if t.asset_id == asset_id]
    period_end = _compute_period_end(reference)
    period_start = _compute_period_start(threshold_months, reference=period_end)

    if period_start:
        tickets.sort(key=lambda t: t.created_at, reverse=True)
    else:
        tickets.sort(key=lambda t: (t.created_at, t.id), reverse=True)

    return AssetHistory(
        asset_id=asset_id,
        tickets=tickets,
        period_start=period_start,
        period_end=period_end,
        threshold_count=threshold_count,
        threshold_months=threshold_months,
    )

