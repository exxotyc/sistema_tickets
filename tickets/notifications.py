import json
import logging
from typing import Optional

from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail
from django.utils import timezone

try:  # pragma: no cover - optional import
    from urllib import request as urllib_request
except ImportError:  # pragma: no cover
    urllib_request = None


logger = logging.getLogger("tickets.notifications")


def _get_config() -> dict:
    return getattr(settings, "TICKET_NOTIFICATIONS", {}) or {}


def _dedup_key(event: str, ticket_id: int, suffix: Optional[str] = None) -> str:
    suffix = suffix or ""
    return f"ticket_notify:{event}:{ticket_id}:{suffix}"


def _should_send(event: str, ticket_id: int, suffix: Optional[str] = None) -> bool:
    cfg = _get_config()
    dedup_seconds = int(cfg.get("dedup_seconds", 300) or 0)
    if dedup_seconds <= 0:
        return True
    key = _dedup_key(event, ticket_id, suffix)
    if cache.get(key):
        logger.debug("Notificación %s para ticket %s suprimida por deduplicación", event, ticket_id)
        return False
    cache.set(key, True, dedup_seconds)
    return True


def _dispatch(event: str, ticket, context: dict) -> None:
    logger.info(
        "Enviando notificación %s para ticket %s", event, getattr(ticket, "pk", None),
    )
    _send_email(event, ticket, context)
    _send_webhook(event, ticket, context)


# ------------------------
#   IN-APP NOTIFICATIONS
# ------------------------
def create_inapp_notification(user, ticket, type, title, message):
    """
    Crea una notificación interna básica.
    """
    from tickets.models import Notification
    Notification.objects.create(
        user=user,
        ticket=ticket,
        type=type,
        title=title,
        message=message,
    )


def _send_email(event: str, ticket, context: dict) -> None:
    cfg = _get_config()
    recipients = [addr for addr in cfg.get("emails", []) if addr]
    subject = context.get("subject")
    message = context.get("message")
    if not recipients or not subject or not message:
        return
    send_mail(
        subject,
        message,
        getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@localhost"),
        recipients,
        fail_silently=True,
    )


def _send_webhook(event: str, ticket, context: dict) -> None:
    cfg = _get_config()
    url = cfg.get("webhook_url")
    if not url or not urllib_request:
        return
    payload = {
        "event": event,
        "ticket_id": getattr(ticket, "pk", None),
        "timestamp": timezone.now().isoformat(),
        **{k: v for k, v in context.items() if k not in {"subject", "message"}},
    }
    data = json.dumps(payload).encode("utf-8")
    request = urllib_request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib_request.urlopen(request, timeout=5):  # nosec: B310 - URL controlado por configuración
            pass
    except Exception:  # pragma: no cover - la excepción se registra pero no rompe el flujo
        logger.exception("Error enviando webhook para ticket %s", getattr(ticket, "pk", None))


def _notify(event: str, ticket, context: dict, *, key_suffix: Optional[str] = None) -> bool:
    if not getattr(ticket, "pk", None):
        return False
    if not _should_send(event, ticket.pk, key_suffix):
        return False
    _dispatch(event, ticket, context)
    return True


def notify_ticket_created(ticket) -> bool:
    # notificación interna
    create_inapp_notification(
        ticket.requester,
        ticket,
        "created",
        f"Ticket #{ticket.pk} creado",
        f"Se ha creado el ticket #{ticket.pk}: {ticket.title}",
    )
    return _notify(
        "ticket_created",
        ticket,
        {
            "subject": f"Ticket #{ticket.pk} creado",
            "message": f"Se ha creado el ticket #{ticket.pk}: {ticket.title}",
            "state": ticket.state,
        },
    )


def notify_ticket_state_change(ticket, previous: str, new: str, user=None) -> bool:
    username = getattr(user, "username", None)

    # Notificación interna al solicitante
    create_inapp_notification(
        ticket.requester,
        ticket,
        "state_changed",
        f"Ticket #{ticket.pk} cambió a {new}",
        f"Estado: {previous} → {new}",
    )
    # Y al técnico asignado (si existe)
    if ticket.assigned_to:
        create_inapp_notification(
            ticket.assigned_to,
            ticket,
            "state_changed",
            f"Ticket #{ticket.pk} cambió a {new}",
            f"Estado: {previous} → {new}",
        )

    return _notify(
        "ticket_state_changed",
        ticket,
        {
            "subject": f"Ticket #{ticket.pk} cambió a {new}",
            "message": f"El ticket #{ticket.pk} cambió de {previous} → {new}.",
            "from": previous,
            "to": new,
            "username": username,
        },
        key_suffix=f"{previous}->{new}",
    )


def notify_sla_risk(ticket, due_at) -> bool:
    # 🔔 Notificación interna para el técnico asignado
    if ticket.assigned_to:
        create_inapp_notification(
            ticket.assigned_to,
            ticket,
            "sla_risk",
            f"SLA en riesgo · Ticket #{ticket.pk}",
            f"El ticket vence pronto ({due_at}).",
        )

    suffix = due_at.isoformat() if due_at else None

    return _notify(
        "ticket_sla_risk",
        ticket,
        {
            "subject": f"Ticket #{ticket.pk} en riesgo de SLA",
            "message": (
                f"El ticket #{ticket.pk} se acerca a su vencimiento ({due_at})."
            ),
            "due_at": due_at.isoformat() if due_at else None,
        },
        key_suffix=suffix,
    )


# =====================================================
# NOTIFICACIÓN: Ticket asignado
# =====================================================
def notify_ticket_assigned(ticket, technician, by_user=None):
    """
    Notificación cuando un ticket es asignado a un técnico.
    """
    # Notificación interna al técnico
    create_inapp_notification(
        technician,
        ticket,
        "assigned",
        f"Nuevo ticket asignado #{ticket.pk}",
        f"Se te ha asignado el ticket #{ticket.pk}: {ticket.title}",
    )

    # Opcional: también al solicitante si quieres
    create_inapp_notification(
        ticket.requester,
        ticket,
        "assigned",
        f"Ticket #{ticket.pk} asignado",
        f"Tu ticket #{ticket.pk} fue asignado a {technician.username}.",
    )

    # Opcional: correo / webhook de asignación
    return _notify(
        "ticket_assigned",
        ticket,
        {
            "subject": f"Ticket #{ticket.pk} asignado",
            "message": (
                f"El ticket #{ticket.pk} fue asignado a {technician.username}."
            ),
            "assigned_to": technician.username,
            "by": getattr(by_user, "username", None),
        },
        key_suffix=str(technician.pk),
    )
