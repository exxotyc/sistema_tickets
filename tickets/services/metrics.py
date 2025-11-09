"""Utilities for computing ticket KPIs based on real activity logs and SLA."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple
from datetime import timedelta

from django.db.models import Count, QuerySet, F, ExpressionWrapper, DurationField, Avg
from django.utils.timezone import now

from ..models import Comment, Ticket, TicketLog
from ..services.sla import calculate_sla_status  # 👈 para usar la lógica de SLA real

__all__ = [
    "TicketMetricsService",
]


class TicketMetricsService:
    """Calcula KPIs de tickets: conteos, MTTR, FRT y cumplimiento de SLA."""

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
        """Devuelve KPIs resumidos del queryset, incluyendo SLA, MTTR y FRT."""

        # --- Conteo por estado
        state_counts = {state: 0 for state in self.STATE_CHOICES}
        for row in self.queryset.values("state").annotate(total=Count("id")):
            state_counts[row["state"]] = row["total"]

        total = sum(state_counts.values())
        p1_count = self.queryset.filter(priority__in=self.P1_PRIORITIES).count()

        # --- MTTR (Mean Time To Resolve)
        qs_resolved = self.queryset.filter(
            state__in=self.RESOLUTION_TARGET_STATES,
            created_at__isnull=False,
            updated_at__isnull=False,
        )
        mttr_duration = qs_resolved.annotate(
            dur=ExpressionWrapper(F("updated_at") - F("created_at"), output_field=DurationField())
        ).aggregate(avg=Avg("dur"))["avg"]
        mttr_hours = round(mttr_duration.total_seconds() / 3600, 2) if mttr_duration else 0

        # --- FRT (First Response Time)
        qs_frt = self.queryset.filter(frt_due_at__isnull=False)
        frt_duration = qs_frt.annotate(
            frt_dur=ExpressionWrapper(F("frt_due_at") - F("created_at"), output_field=DurationField())
        ).aggregate(avg=Avg("frt_dur"))["avg"]
        frt_hours = round(frt_duration.total_seconds() / 3600, 2) if frt_duration else 0

        # --- SLA detallado (basado en calculate_sla_status)
        sla_ok = sla_risk = sla_breached = 0
        for ticket in self.tickets:
            try:
                data = calculate_sla_status(ticket)
                if data["breached"]:
                    sla_breached += 1
                elif data["nearing_breach"]:
                    sla_risk += 1
                else:
                    sla_ok += 1
            except Exception:
                # En caso de error en un ticket, lo omitimos
                continue

        sla_compliance = round((sla_ok / total) * 100, 2) if total else 0

        return {
            "total": total,
            "by_state": state_counts,
            "critical": p1_count,
            "mttr_hours": mttr_hours,
            "frt_hours": frt_hours,
            "sla_compliance": sla_compliance,
            "sla_in_time": sla_ok,
            "sla_risk": sla_risk,
            "sla_breached": sla_breached,
        }

    # ------------------------------
    # Métricas individuales
    # ------------------------------
    def first_resolution_at(self, ticket: Ticket) -> Optional[TicketLog]:
        """Retorna el primer log que marcó el ticket como resuelto o cerrado."""
        for log in self._logs_for_ticket(ticket.id):
            if log.action in self.RESOLUTION_TARGET_STATES:
                return log
            if log.action == "state_change":
                target = (log.meta_json or {}).get("to")
                if target in self.RESOLUTION_TARGET_STATES:
                    return log
        return None

    def first_response_at(self, ticket: Ticket) -> Optional[Tuple[str, object]]:
        """Devuelve la primera respuesta no solicitante (comentario o log)."""
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
        """Calcula minutos entre dos timestamps."""
        if not start or not end:
            return None
        delta = end - start
        return round(delta.total_seconds() / 60.0, 2)

    # ------------------------------
    # Internals
    # ------------------------------
    def _iter_resolution_minutes(self) -> Iterator[float]:
        """Itera tiempos de resolución (solo P1)."""
        for ticket, resolution_log, _ in self.per_ticket_metrics():
            if ticket.priority not in self.P1_PRIORITIES:
                continue
            if resolution_log:
                minutes = self.minutes_between(ticket.created_at, resolution_log.created_at)
                if minutes is not None:
                    yield minutes

    def _iter_response_minutes(self) -> Iterator[float]:
        """Itera tiempos de primera respuesta (solo P1)."""
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
        """Calcula el promedio de minutos de una lista."""
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
        """Carga logs y comentarios de todos los tickets de una sola vez."""
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
