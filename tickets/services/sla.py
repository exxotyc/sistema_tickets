from datetime import timedelta
from django.db import transaction
from django.utils.timezone import now


def calculate_sla_status(ticket):
    """
    Determina el estado SLA del ticket (en tiempo, en riesgo, vencido).
    Retorna un dict con flags booleanos y riesgo global.
    """
    if not ticket.created_at:
        return {"breached": False, "nearing_breach": False, "breach_risk": False}

    elapsed = (now() - ticket.created_at).total_seconds() / 60  # minutos transcurridos

    SLA_RULES = {
        "high": 240,    # 4 horas
        "medium": 1440, # 24 horas
        "low": 4320,    # 72 horas
    }

    limit = SLA_RULES.get(ticket.priority or "medium", 1440)
    nearing = limit * 0.8  # 80% del tiempo = riesgo

    breached = elapsed >= limit
    nearing_breach = not breached and elapsed >= nearing
    breach_risk = breached or nearing_breach

    return {
        "elapsed": elapsed,
        "limit": limit,
        "breached": breached,
        "nearing_breach": nearing_breach,
        "breach_risk": breach_risk,
    }


def refresh_ticket_sla(ticket):
    """
    Actualiza el estado SLA del ticket sin provocar recursión infinita.
    Evalúa el SLA actual con calculate_sla_status() y actualiza directamente en la DB.
    """
    result = calculate_sla_status(ticket)
    breach = result["breach_risk"]

    # Evita recursión: actualización directa
    with transaction.atomic():
        type(ticket).objects.filter(pk=ticket.pk).update(breach_risk=breach)

    return result


def compute_due_at(ticket):
    """
    Devuelve la fecha estimada de resolución (por prioridad).
    """
    SLA_RULES = {
        "high": 4,     # horas
        "medium": 24,
        "low": 72,
    }
    hours = SLA_RULES.get(ticket.priority or "medium", 24)
    return now() + timedelta(hours=hours)


def compute_sla_minutes(ticket):
    """
    Devuelve el tiempo total de SLA en minutos según la prioridad.
    """
    SLA_RULES = {
        "high": 240,    # 4 horas
        "medium": 1440, # 24 horas
        "low": 4320,    # 72 horas
    }
    return SLA_RULES.get(ticket.priority or "medium", 1440)
