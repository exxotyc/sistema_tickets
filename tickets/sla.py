# tickets/sla.py
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from django.utils.timezone import now
from .models import Ticket, TicketLog

# Config SLA opcional (puedes definir SLA_MATRIX en settings)
# Ejemplo por defecto si no existe en settings:
#   {"low": {"frt_min":480, "res_h":72},
#    "medium": {"frt_min":240, "res_h":48},
#    "high": {"frt_min":60, "res_h":8}}
MATRIX = getattr(settings, "SLA_MATRIX", {
    "low":    {"frt_min": 480, "res_h": 72},
    "medium": {"frt_min": 240, "res_h": 48},
    "high":   {"frt_min":  60, "res_h":  8},
})

AT_RISK_HOURS = getattr(settings, "SLA_AT_RISK_HOURS", 6)  # heurística simple


def _tz(dt):
    """Asegura datetime aware en tz local."""
    if dt is None:
        return now()
    return timezone.localtime(dt) if timezone.is_aware(dt) else timezone.make_aware(dt, timezone.get_current_timezone())


def _has_fields(obj, names):
    return all(hasattr(obj, n) for n in names)


def compute_deadlines(ticket):
    """Calcula FRT y resolución según prioridad."""
    pr = (ticket.priority or "medium").lower()
    cfg = MATRIX.get(pr, MATRIX.get("medium", {"frt_min": 120, "res_h": 48}))
    created = _tz(ticket.created_at or now())
    frt_due = created + timedelta(minutes=cfg["frt_min"])
    res_due = created + timedelta(hours=cfg["res_h"])
    return frt_due, res_due


def ensure_deadlines(ticket):
    """
    Escribe frt_due_at / resolve_due_at vía UPDATE directo.
    No genera señales ni requiere que el instance tenga esos attrs en memoria.
    Si el modelo no tiene esos campos, sale silenciosamente.
    """
    if not _has_fields(ticket, ["frt_due_at", "resolve_due_at"]):
        return
    frt_due, res_due = compute_deadlines(ticket)
    Ticket.objects.filter(pk=ticket.pk).update(frt_due_at=frt_due, resolve_due_at=res_due)


def mark_first_response(ticket, when=None):
    """
    Marca cumplimiento de FRT. No falla si campos no existen.
    Crea TicketLog 'sla_frt_breached' al primer incumplimiento.
    """
    if not _has_fields(ticket, ["frt_due_at", "frt_met", "frt_breached_at"]):
        return
    ensure_deadlines(ticket)
    when = _tz(when or now())

    # refresca para leer due_at actual si recién calculado
    ticket.refresh_from_db(fields=["frt_due_at", "frt_met", "frt_breached_at"])

    if ticket.frt_met is not None:
        return  # ya evaluado

    met = when <= ticket.frt_due_at if ticket.frt_due_at else False
    updates = {"frt_met": met}

    if not met and ticket.frt_breached_at is None:
        updates["frt_breached_at"] = when
        TicketLog.objects.create(ticket=ticket, user=None, action="sla_frt_breached", meta_json={})

    Ticket.objects.filter(pk=ticket.pk).update(**updates)


def mark_resolution(ticket, when=None):
    """
    Marca cumplimiento de SLA de resolución. No falla si campos no existen.
    Crea TicketLog 'sla_res_breached' al primer incumplimiento.
    """
    if not _has_fields(ticket, ["resolve_due_at", "resolve_met", "resolve_breached_at"]):
        return
    ensure_deadlines(ticket)
    when = _tz(when or now())

    ticket.refresh_from_db(fields=["resolve_due_at", "resolve_met", "resolve_breached_at"])

    if ticket.resolve_met is not None:
        return

    met = when <= ticket.resolve_due_at if ticket.resolve_due_at else False
    updates = {"resolve_met": met}

    if not met and ticket.resolve_breached_at is None:
        updates["resolve_breached_at"] = when
        TicketLog.objects.create(ticket=ticket, user=None, action="sla_res_breached", meta_json={})

    Ticket.objects.filter(pk=ticket.pk).update(**updates)


def at_risk_qs(qs):
    """
    Heurística simple: tickets abiertos/en progreso con vencimiento de resolución
    en las próximas N horas y aún no incumplidos.
    Si no existen campos due/breached, usa fallback por antigüedad (>48h).
    """
    if _has_fields(Ticket, ["resolve_due_at", "resolve_breached_at"]):
        return qs.filter(
            state__in=["open", "in_progress"],
            resolve_due_at__isnull=False,
            resolve_breached_at__isnull=True,
            resolve_due_at__lte=now() + timedelta(hours=AT_RISK_HOURS),
        )
    # Fallback
    cutoff = now() - timedelta(hours=48)
    return qs.filter(state__in=["open", "in_progress"], created_at__lte=cutoff)
