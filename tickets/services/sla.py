"""Rutinas relacionadas con SLA."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Dict, Tuple

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from ..models import Ticket, TicketLog
from ..notifications import notify_sla_risk

logger = logging.getLogger("tickets.sla")

_DEFAULT_MATRIX: Dict[str, Dict[str, int]] = {
    "low": {"res_h": 72},
    "medium": {"res_h": 48},
    "high": {"res_h": 24},
}


def _get_matrix() -> Dict[str, Dict[str, int]]:
    return getattr(settings, "SLA_MATRIX", _DEFAULT_MATRIX)


def _to_minutes(config: Dict[str, int]) -> int:
    if not config:
        return 24 * 60
    if "res_min" in config:
        return int(config["res_min"])
    if "res_h" in config:
        return int(config["res_h"]) * 60
    if "sla_min" in config:
        return int(config["sla_min"])
    return 24 * 60


def compute_sla_minutes(ticket: Ticket) -> int:
    if getattr(ticket, "sla_minutes", None):
        return int(ticket.sla_minutes)
    matrix = _get_matrix()
    priority = (ticket.priority or "medium").lower()
    config = matrix.get(priority) or matrix.get("medium") or {}
    return _to_minutes(config)


def compute_due_at(ticket: Ticket, *, reference=None) -> Tuple[int, timezone.datetime]:
    reference = reference or timezone.now()
    created = getattr(ticket, "created_at", None) or reference
    if timezone.is_naive(created):
        created = timezone.make_aware(created, timezone.get_current_timezone())
    minutes = compute_sla_minutes(ticket)
    due_at = created + timedelta(minutes=minutes)
    return minutes, due_at


def _is_at_risk(*, due_at, minutes: int, reference=None) -> bool:
    if due_at is None:
        return False
    reference = reference or timezone.now()
    if reference >= due_at:
        return True
    margin_ratio = float(getattr(settings, "SLA_AT_RISK_MARGIN", 0.2) or 0)
    if margin_ratio <= 0:
        return False
    remaining = (due_at - reference).total_seconds() / 60
    margin_minutes = max(1, minutes * margin_ratio)
    return remaining <= margin_minutes


@transaction.atomic
def refresh_ticket_sla(ticket: Ticket, *, reference=None, persist: bool = True) -> Dict[str, object]:
    """Recalcula campos SLA en un ticket.

    Retorna un diccionario con los campos modificados.
    """

    reference = reference or timezone.now()
    previous_minutes = getattr(ticket, "sla_minutes", None)
    previous_due = getattr(ticket, "due_at", None)
    previous_risk = getattr(ticket, "breach_risk", False)

    minutes, due_at = compute_due_at(ticket, reference=reference)
    risk = _is_at_risk(due_at=due_at, minutes=minutes, reference=reference)

    updates: Dict[str, object] = {}
    if previous_minutes != minutes:
        updates["sla_minutes"] = minutes
    if previous_due != due_at:
        updates["due_at"] = due_at
    if previous_risk != risk:
        updates["breach_risk"] = risk

    if persist and updates:
        Ticket.objects.filter(pk=ticket.pk).update(**updates)
        for name, value in updates.items():
            setattr(ticket, name, value)

    if not previous_risk and risk:
        TicketLog.objects.create(
            ticket=ticket,
            user=None,
            action="sla_at_risk",
            meta_json={"due_at": due_at.isoformat() if due_at else None},
        )
        try:
            notify_sla_risk(ticket, due_at)
        except Exception:
            logger.exception("No se pudo enviar la notificación de riesgo SLA para el ticket %s", ticket.pk)

    if updates:
        logger.info("Ticket %s actualizado con SLA %s", ticket.pk, updates)

    return updates

*** End
