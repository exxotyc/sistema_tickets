from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from .models import Ticket, Comment
from .sla import ensure_deadlines, mark_first_response, mark_resolution
from .models import TicketLog


@receiver(post_save, sender=Ticket)
def ticket_created_or_updated(sender, instance, created, **kwargs):
    ensure_deadlines(instance) 

@receiver(post_save, sender=Comment)
def first_response_from_staff(sender, instance: Comment, created, **kwargs):
    if not created:
        return
    t = instance.ticket
    # primera respuesta de alguien distinto del solicitante
    if instance.user_id and instance.user_id != getattr(t, "requester_id", None) and t.frt_met is None:
        mark_first_response(t, when=instance.created_at)

