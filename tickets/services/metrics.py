"""Utilities for computing ticket KPIs based on real activity logs and SLA."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple
from datetime import timedelta

from django.db.models import Count, QuerySet, F, ExpressionWrapper, DurationField, Avg
from django.utils.timezone import now

from ..models import Comment, Ticket, TicketLog, Priority
from ..services.sla import calculate_sla_status  # SLA real

__all__ = [
    "TicketMetricsService",
]


class TicketMetricsService:
    """Calcula KPIs de tickets: conteos, MTTR, FRT y cumplimiento de SLA."""

    STATE_CHOICES = ("open", "in_progress", "resolved", "closed")
    RESOLUTION_TARGET_STATES = {"resolved", "closed"}

    def __init__(self, queryset: QuerySet[Ticket]):
        self.queryset = queryset
        self._tickets: Optional[List[Ticket]] = None
        self._logs_by_ticket: Optional[Dict[int, List[TicketLog]]] = None
        self._comments_by_ticket: Optional[Dict[int, List[Comment]]] = None

        # ===========================================================
        # PRIORIDAD CRÍTICA (P1)
        # Detecta correctamente:
        #   code = "critical"
        #   name = "Crítica"
        # ===========================================================
        posibles_codes = ["critical"]
        posibles_names = ["Crítica"]

        ids_por_code = list(
            Priority.objects.filter(code__in=posibles_codes).values_list("id", flat=True)
        )

        ids_por_name = list(
            Priority.objects.filter(name__in=posibles_names).values_list("id", flat=True)
        )

        # IDs que representan prioridades críticas
        self.P1_PRIORITIES = list(set(ids_por_code + ids_por_name))

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

    # ------------------------------
    # MÉTRICAS PRINCIPALES
    # ------------------------------
    def summarize(self) -> Dict[str, object]:
        """Devuelve KPIs resumidos del queryset, incluyendo SLA, MTTR y FRT."""

        # --- Conteo por estado
        state_counts = {state: 0 for state in self.STATE_CHOICES}
        for row in self.queryset.values("state").annotate(total=Count("id")):
            state_counts[row["state"]] = row["total"]

        total = sum(state_counts.values())

        # --- Conteo de tickets críticos (P1)
        p1_count = (
            self.queryset.filter(priority_id__in=self.P1_PRIORITIES).count()
            if self.P1_PRIORITIES else 0
        )

        # --- MTTR (Mean Time To Resolve)
        qs_resolved = self.queryset.filter(
            state__in=self.RESOLUTION_TARGET_STATES,
            created_at__isnull=False,
            updated_at__isnull=False,
        )
        mttr_duration = qs_resolved.annotate(
            dur=ExpressionWrapper(
                F("updated_at") - F("created_at"),
                output_field=DurationField()
            )
        ).aggregate(avg=Avg("dur"))["avg"]
        mttr_hours = round(mttr_duration.total_seconds() / 3600, 2) if mttr_duration else 0

        # --- FRT (First Response Time)
        qs_frt = self.queryset.filter(frt_due_at__isnull=False)
        frt_duration = qs_frt.annotate(
            frt_dur=ExpressionWrapper(
                F("frt_due_at") - F("created_at"),
                output_field=DurationField()
            )
        ).aggregate(avg=Avg("frt_dur"))["avg"]
        frt_hours = round(frt_duration.total_seconds() / 3600, 2) if frt_duration else 0

        # --- SLA detallado
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
                continue

        sla_compliance = round((sla_ok / total) * 100, 2) if total else 0

        return {
            "total": total,
            "by_state": state_counts,
            "critical": p1_count,               # cantidad P1 (Crítica)
            "mttr_hours": mttr_hours,          # tiempo de resolución promedio
            "frt_hours": frt_hours,            # tiempo de primera respuesta
            "sla_compliance": sla_compliance,  # % SLA cumplido
            "sla_in_time": sla_ok,
            "sla_risk": sla_risk,
            "sla_breached": sla_breached,
        }

    # ------------------------------
    # Métricas individuales
    # ------------------------------
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
        requester_id = ticket.requester_id

        # Primer comentario de alguien que no sea el solicitante
        for comment in self._comments_for_ticket(ticket.id):
            if comment.user_id and comment.user_id != requester_id:
                return ("comment", comment)

        # Primer log de alguien que no sea el solicitante
        for log in self._logs_for_ticket(ticket.id):
            if log.user_id and log.user_id != requester_id:
                return ("log", log)

        return None

    # Generador de métricas por ticket
    def per_ticket_metrics(self) -> Iterator[Tuple[Ticket, Optional[TicketLog], Optional[Tuple[str, object]]]]:
        for ticket in self.tickets:
            yield ticket, self.first_resolution_at(ticket), self.first_response_at(ticket)

    # Diferencia en minutos
    def minutes_between(self, start, end) -> Optional[float]:
        if not start or not end:
            return None
        delta = end - start
        return round(delta.total_seconds() / 60.0, 2)

    # ------------------------------
    # Internos
    # ------------------------------
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
