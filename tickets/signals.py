import logging

from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import Ticket
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

