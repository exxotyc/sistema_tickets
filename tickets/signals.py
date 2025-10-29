import logging

from django.contrib.auth.signals import user_login_failed
from django.db.models.signals import post_save
from django.dispatch import receiver

from django.utils import timezone

from .models import Ticket, TicketLog
from .notifications import notify_ticket_created
from .services.sla import refresh_ticket_sla

logger = logging.getLogger("tickets.signals")


@receiver(post_save, sender=Ticket)
def ticket_created_or_updated(sender, instance: Ticket, created, **kwargs):
    refresh_ticket_sla(instance)
    if created:
        try:
            notify_ticket_created(instance)
        except Exception:
            logger.exception("No se pudo notificar la creación del ticket %s", instance.pk)


@receiver(user_login_failed)
def login_failed(sender, credentials, request, **kwargs):
    username = credentials.get("username") if isinstance(credentials, dict) else None
    ip = None
    if request is not None:
        ip = request.META.get("REMOTE_ADDR")
    TicketLog.objects.create(
        ticket=None,
        user=None,
        action="auth.login_failed",
        meta_json={"username": username, "ip": ip, "timestamp": timezone.now().isoformat()},
        is_critical=True,
    )

