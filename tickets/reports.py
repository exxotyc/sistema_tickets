"""Helpers to generate ticket reports reusing KPI computations."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

from django.utils import timezone

from .models import Ticket
from .services.metrics import TicketMetricsService


@dataclass
class TicketReportRow:
    ticket: Ticket
    resolution_minutes: Optional[float]
    response_minutes: Optional[float]
    resolution_dt: Optional[datetime]

    def as_list(self) -> List[object]:
        tz = timezone.get_current_timezone()
        created_at = self.ticket.created_at.astimezone(tz).strftime("%Y-%m-%d %H:%M")
        resolution = f"{self.resolution_minutes:.2f}" if self.resolution_minutes is not None else ""
        response = f"{self.response_minutes:.2f}" if self.response_minutes is not None else ""

        resolved_dt = ""
        if self.resolution_dt:
            resolved_dt = self.resolution_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M")

        return [
            self.ticket.id,
            self.ticket.title or "",
            self.ticket.state,
            self.ticket.priority,
            getattr(self.ticket.category, "name", "") if self.ticket.category_id else "",
            getattr(self.ticket.assigned_to, "username", "") if self.ticket.assigned_to_id else "",
            created_at,
            resolved_dt,
            resolution,
            response,
        ]


def build_report_rows(service: TicketMetricsService) -> List[List[object]]:
    rows: List[List[object]] = []
    for ticket, resolution_log, response in service.per_ticket_metrics():
        resolution_minutes = None
        resolution_dt = None
        if resolution_log:
            resolution_dt = resolution_log.created_at
            resolution_minutes = service.minutes_between(ticket.created_at, resolution_dt)
        response_minutes = None
        if response:
            response_minutes = service.minutes_between(ticket.created_at, response[1].created_at)

        rows.append(
            TicketReportRow(
                ticket=ticket,
                resolution_minutes=resolution_minutes,
                response_minutes=response_minutes,
                resolution_dt=resolution_dt,
            ).as_list()
        )
    return rows


def filters_footer(params: Dict[str, str]) -> Dict[str, str]:
    keys = ("from", "to", "category", "assignee", "priority")
    return {key: params.get(key, "") or "" for key in keys}
