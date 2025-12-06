from django.contrib.auth import get_user_model
from tickets.models import AutoAssignConfig, AreaRoundRobin, UserProfile, Ticket

User = get_user_model()

def auto_assign_ticket(ticket: Ticket):
    """
    Autoasigna un ticket según su área.
    Round-robin dentro del área.
    """
    from tickets.notifications import create_inapp_notification

    # Configuración general
    cfg = AutoAssignConfig.objects.first()
    if not cfg or not cfg.enabled:
        return None

    # Si ya tiene técnico, no hacer nada
    if ticket.assigned_to:
        return None

    area = ticket.area
    if not area:
        return None

    # Buscar técnicos del área con flag activo
    techs = (
        User.objects.filter(
            groups__name="tecnico",
            is_active=True,
            profile__area=area,
            profile__auto_assign_enabled=True
        )
        .distinct()
        .order_by("id")
    )

    if not techs.exists():
        return None

    # ROUND ROBIN
    rr, _ = AreaRoundRobin.objects.get_or_create(area=area)
    tech_list = list(techs)

    # Determinar siguiente técnico
    if rr.last_user and rr.last_user in tech_list:
        idx = tech_list.index(rr.last_user)
        next_user = tech_list[(idx + 1) % len(tech_list)]
    else:
        next_user = tech_list[0]

    # Guardar asignación
    rr.last_user = next_user
    rr.save()

    ticket.assigned_to = next_user
    ticket.save(update_fields=["assigned_to"])

    # ============================================================
    # 🔔 NOTIFICACIÓN INTERNA AL TÉCNICO AUTOASIGNADO
    # ============================================================
    create_inapp_notification(
        next_user,
        ticket,
        "autoassigned",
        f"Se te asignó automáticamente el ticket #{ticket.pk}",
        f"El sistema te asignó este ticket basado en tu área ({area.name})."
    )

    return next_user
