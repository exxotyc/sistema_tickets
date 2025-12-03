import logging

from django.contrib.auth.signals import user_login_failed
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import Ticket, TicketLog
from .notifications import notify_ticket_created
from .services.sla import refresh_ticket_sla
from django.db.models import Count, Q
from django.utils import timezone

from .models import (
    Ticket,
    AutoAssignConfig,
    UserProfile,
    AreaRoundRobin,
    TicketLog,
    Area,
)

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


# ======================================================
#   Round Robin Helper
# ======================================================
def get_next_round_robin_user(area):
    """
    Devuelve el próximo técnico del área usando Round Robin.
    """

    techs = UserProfile.objects.filter(
        area=area,
        auto_assign_enabled=True,
        user__is_active=True,
        user__groups__name="tecnico"
    ).select_related("user").order_by("user__id")

    if not techs.exists():
        return None

    rr, _ = AreaRoundRobin.objects.get_or_create(area=area)

    if not rr.last_user:
        next_user = techs.first().user
        rr.last_user = next_user
        rr.save()
        return next_user

    users = [t.user for t in techs]

    try:
        idx = users.index(rr.last_user)
        next_user = users[(idx + 1) % len(users)]
    except ValueError:
        next_user = users[0]

    rr.last_user = next_user
    rr.save()

    return next_user


# ======================================================
#   FALLBACK: Técnico con menor carga
# ======================================================
from django.db.models import Count, Q

def get_least_loaded_technician():
    """
    Devuelve el técnico con menos tickets activos (open o in_progress).
    """

    techs = (
        UserProfile.objects.filter(
            auto_assign_enabled=True,
            user__is_active=True,
            user__groups__name="tecnico"
        )
        .select_related("user")
        .annotate(
            active_tickets=Count(
                "user__assigned_tickets",
                filter=Q(user__assigned_tickets__state__in=["open", "in_progress"])
            )
        )
        .order_by("active_tickets", "user__id")
    )

    if not techs.exists():
        return None

    return techs.first().user



# ======================================================
#   AUTOASIGNACIÓN DE TICKETS
# ======================================================
@receiver(post_save, sender=Ticket)
def autoassign_ticket(sender, instance, created, **kwargs):
    """
    - Si hay técnicos del área → Round Robin
    - Si NO hay técnicos del área → técnico con menor carga
    """

    if not created:
        return

    cfg = AutoAssignConfig.objects.first()
    if not cfg or not cfg.enabled:
        return

    ticket = instance

    # Ticket debe tener área
    if not ticket.area:
        return

    # 1. Intentar RR por área
    technician = get_next_round_robin_user(ticket.area)

    # 2. Si no hay técnicos del área → fallback por carga
    if not technician:
        technician = get_least_loaded_technician()

    # Si no hay ningún técnico, devolver (no error)
    if not technician:
        return

    # Asignar ticket
    ticket.assigned_to = technician
    ticket.save(update_fields=["assigned_to"])

    # Registrar log
    TicketLog.objects.create(
        ticket=ticket,
        action="autoassigned",
        created_at=timezone.now(),
        meta_json={
            "assigned_to": technician.username,
            "area": ticket.area.name,
            "mode": "fallback" if not get_next_round_robin_user(ticket.area) else "rr"
        }
    )