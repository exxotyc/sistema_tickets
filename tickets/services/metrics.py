"""Utilities for computing ticket KPIs based on real activity logs."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from django.db.models import Count, QuerySet

from ..models import Comment, Ticket, TicketLog

__all__ = [
    "TicketMetricsService",
]


class TicketMetricsService:
    """Provides KPI helpers for a filtered queryset of tickets.

    The service loads TicketLog and Comment instances once and exposes
    helpers to compute first-response / first-resolution metrics in
    minutes. Only activity logged while the ticket was priority 1
    ("high" or "critical") is considered for aggregated KPIs, matching
    how operators measure these indicators.
    """

    STATE_CHOICES = ("open", "in_progress", "resolved", "closed")
    P1_PRIORITIES = {"high", "critical"}
    RESOLUTION_TARGET_STATES = {"resolved", "closed"}

    def __init__(self, queryset: QuerySet[Ticket]):
        self.queryset = queryset
        self._tickets: Optional[List[Ticket]] = None
        self._logs_by_ticket: Optional[Dict[int, List[TicketLog]]] = None
        self._comments_by_ticket: Optional[Dict[int, List[Comment]]] = None

    # ------------------------------
    # Public API
    # ------------------------------
    @property
    def tickets(self) -> List[Ticket]:
        if self._tickets is None:
            self._tickets = list(self.queryset)
        return self._tickets

    @property
    def ticket_ids(self) -> List[int]:
        return [ticket.id for ticket in self.tickets]

    def summarize(self) -> Dict[str, object]:
        """Return counts and KPI averages (in minutes) for the queryset."""
        state_counts = {state: 0 for state in self.STATE_CHOICES}
        for row in self.queryset.values("state").annotate(total=Count("id")):
            state_counts[row["state"]] = row["total"]

        total = sum(state_counts.values())
        p1_count = self.queryset.filter(priority__in=self.P1_PRIORITIES).count()

        mttr_minutes = self._average_minutes(self._iter_resolution_minutes())
        frt_minutes = self._average_minutes(self._iter_response_minutes())

        return {
            "total": total,
            "by_state": state_counts,
            "critical": p1_count,
            "mttr_minutes": mttr_minutes,
            "frt_minutes": frt_minutes,
        }

    def first_resolution_at(self, ticket: Ticket) -> Optional[TicketLog]:
        for log in self._logs_for_ticket(ticket.id):
            if log.action in self.RESOLUTION_TARGET_STATES:
                return log
            if log.action == "state_change":
                target = (log.meta_json or {}).get("to")
                if target in self.RESOLUTION_TARGET_STATES:
                    return log
        return None

    def first_response_at(self, ticket: Ticket) -> Optional[Tuple[str, object]]:
        """Return the first non-requester response as (kind, instance)."""
        requester_id = ticket.requester_id
        for comment in self._comments_for_ticket(ticket.id):
            if comment.user_id and comment.user_id != requester_id:
                return ("comment", comment)
        for log in self._logs_for_ticket(ticket.id):
            if log.user_id and log.user_id != requester_id:
                return ("log", log)
        return None

    def per_ticket_metrics(self) -> Iterator[Tuple[Ticket, Optional[TicketLog], Optional[Tuple[str, object]]]]:
        for ticket in self.tickets:
            yield ticket, self.first_resolution_at(ticket), self.first_response_at(ticket)

    def minutes_between(self, start, end) -> Optional[float]:
        if not start or not end:
            return None
        delta = end - start
        return round(delta.total_seconds() / 60.0, 2)

    # ------------------------------
    # Internals
    # ------------------------------
    def _iter_resolution_minutes(self) -> Iterator[float]:
        for ticket, resolution_log, _ in self.per_ticket_metrics():
            if ticket.priority not in self.P1_PRIORITIES:
                continue
            if resolution_log:
                minutes = self.minutes_between(ticket.created_at, resolution_log.created_at)
                if minutes is not None:
                    yield minutes

    def _iter_response_minutes(self) -> Iterator[float]:
        for ticket, _, response in self.per_ticket_metrics():
            if ticket.priority not in self.P1_PRIORITIES:
                continue
            if response:
                kind, payload = response
                response_dt = payload.created_at
                minutes = self.minutes_between(ticket.created_at, response_dt)
                if minutes is not None:
                    yield minutes

    @staticmethod
    def _average_minutes(samples: Iterable[float]) -> Optional[float]:
        total = 0.0
        count = 0
        for value in samples:
            total += value
            count += 1
        if not count:
            return None
        return round(total / count, 2)

    def _logs_for_ticket(self, ticket_id: int) -> Sequence[TicketLog]:
        if self._logs_by_ticket is None:
            self._load_activity()
        return self._logs_by_ticket.get(ticket_id, [])

    def _comments_for_ticket(self, ticket_id: int) -> Sequence[Comment]:
        if self._comments_by_ticket is None:
            self._load_activity()
        return self._comments_by_ticket.get(ticket_id, [])

    def _load_activity(self) -> None:
        logs_by_ticket: Dict[int, List[TicketLog]] = defaultdict(list)
        comments_by_ticket: Dict[int, List[Comment]] = defaultdict(list)
        ids = self.ticket_ids
        if ids:
            for log in TicketLog.objects.filter(ticket_id__in=ids).order_by("created_at"):
                logs_by_ticket[log.ticket_id].append(log)
            for comment in Comment.objects.filter(ticket_id__in=ids).order_by("created_at"):
                comments_by_ticket[comment.ticket_id].append(comment)
        self._logs_by_ticket = logs_by_ticket
        self._comments_by_ticket = comments_by_ticket
