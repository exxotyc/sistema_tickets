import logging

from django.contrib.auth.signals import user_login_failed
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import Ticket, TicketLog
from .notifications import notify_ticket_created
from .services.sla import refresh_ticket_sla

logger = logging.getLogger("tickets.signals")
security_logger = logging.getLogger("tickets.security")


@receiver(post_save, sender=Ticket)
def ticket_created_or_updated(sender, instance: Ticket, created, **kwargs):
    refresh_ticket_sla(instance)
    if created:
        try:
            notify_ticket_created(instance)
        except Exception:
            logger.exception("No se pudo notificar la creación del ticket %s", instance.pk)

                # Autoasignación por área (round robin)
        try:
            from tickets.services.autoassign import auto_assign_ticket
            assigned = auto_assign_ticket(instance)
            if assigned:
                TicketLog.objects.create(
                    ticket=instance,
                    user=None,
                    action="autoassigned",
                    meta_json={"assigned_to": assigned.username},
                    is_critical=False
                )
        except Exception:
            logger.exception("Autoasignación falló en ticket %s", instance.pk)


@receiver(user_login_failed)
def audit_failed_login(sender, credentials, request, **kwargs):
    username = credentials.get("username") if isinstance(credentials, dict) else None
    ip = request.META.get("REMOTE_ADDR") if request is not None else None
    TicketLog.objects.create(
        ticket=None,
        user=None,
        action="auth.login_failed",
        is_critical=True,
        meta_json={"username": username, "ip": ip},
    )
    security_logger.warning("login_failed username=%s ip=%s", username, ip)

