from datetime import timedelta
from django.db import transaction
from django.utils.timezone import now


# ============================================================
#  USAR EL SLA REAL DESDE PRIORITY.sla_minutes
# ============================================================
def get_sla_limit(ticket):
    """
    Obtiene el SLA (en minutos) desde la base de datos.
    """
    pr = ticket.priority
    if pr and hasattr(pr, "sla_minutes") and pr.sla_minutes:
        return pr.sla_minutes  # YA VIENE EN MINUTOS

    return 1440  # fallback universal (24h)


# ============================================================
#  CALCULAR SLA STATUS
# ============================================================
def calculate_sla_status(ticket):
    if not ticket.created_at:
        return {
            "elapsed": 0,
            "limit": get_sla_limit(ticket),
            "breached": False,
            "nearing_breach": False,
            "breach_risk": False,
        }

    elapsed = (now() - ticket.created_at).total_seconds() / 60
    limit = get_sla_limit(ticket)

    nearing = limit * 0.8
    breached = elapsed >= limit
    nearing_breach = (not breached) and (elapsed >= nearing)
    breach_risk = breached or nearing_breach

    return {
        "elapsed": elapsed,
        "limit": limit,
        "breached": breached,
        "nearing_breach": nearing_breach,
        "breach_risk": breach_risk,
    }


# ============================================================
#  GUARDAR FLAG SLA
# ============================================================
def refresh_ticket_sla(ticket):
    result = calculate_sla_status(ticket)
    breach = result["breach_risk"]

    with transaction.atomic():
        type(ticket).objects.filter(pk=ticket.pk).update(breach_risk=breach)

    return result


# ============================================================
#  FECHA DE VENCIMIENTO (due_at)
# ============================================================
def compute_due_at(created_at, priority):
    """
    Usa el SLA real (sla_minutes) para calcular la fecha de vencimiento.
    """
    if priority and priority.sla_minutes:
        return created_at + timedelta(minutes=priority.sla_minutes)

    return created_at + timedelta(minutes=1440)
