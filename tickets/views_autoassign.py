import json
from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.contrib.auth import get_user_model

from tickets.models import (
    AutoAssignConfig,
    UserProfile,
    AreaRoundRobin,
    Ticket,
    TicketLog,
    Area
)

User = get_user_model()


# ======================================================
#     VISTA PRINCIPAL (PRO)
# ======================================================
@login_required
def maint_autoassign_page(request):
    if not request.user.groups.filter(name="admin").exists():
        return render(request, "tickets/403.html", status=403)

    # Configuración global
    cfg = AutoAssignConfig.objects.first()
    if cfg:
        cfg.refresh_from_db()
    else:
        cfg = AutoAssignConfig.objects.create(enabled=True)

    # Lista de técnicos
    techs_qs = (
        User.objects.filter(groups__name="tecnico")
        .select_related("profile")
        .order_by("profile__area__name", "username")
    )

    # Métricas globales
    total_techs = techs_qs.count()
    techs_enabled = techs_qs.filter(profile__auto_assign_enabled=True).count()
    techs_no_area = techs_qs.filter(profile__area__isnull=True).count()

    # Lista PRO final
    techs = []
    for t in techs_qs:

        # Tickets activos del técnico
        active_tickets = Ticket.objects.filter(
            assigned_to=t,
            state__in=["open", "in_progress"]
        ).count()

        # Nivel de carga
        if active_tickets <= 3:
            load_level = "low"
        elif active_tickets <= 7:
            load_level = "medium"
        else:
            load_level = "high"

        # Última asignación RR para esa área
        last_rr = "-"
        if t.profile.area:
            rr = AreaRoundRobin.objects.filter(area=t.profile.area).first()
            if rr and rr.last_user:
                last_rr = rr.last_user.username

        techs.append({
            "obj": t,
            "id": t.id,
            "username": t.username,
            "fullname": t.get_full_name(),
            "area": t.profile.area.name if t.profile.area else None,
            "active": t.is_active,
            "auto_assign": t.profile.auto_assign_enabled,
            "active_tickets": active_tickets,
            "load_level": load_level,
            "last_rr": last_rr,
        })

    # Historial de autoasignaciones
    history = (
        TicketLog.objects
        .filter(action="autoassigned")
        .select_related("ticket")
        .order_by("-created_at")[:15]
    )

    # Lista de áreas para RR
    areas = Area.objects.all().order_by("name")

    return render(
        request,
        "tickets/maint_autoasignacion.html",
        {
            "cfg": cfg,
            "techs": techs,
            "total_techs": total_techs,
            "techs_enabled": techs_enabled,
            "techs_no_area": techs_no_area,
            "history": history,
            "areas": areas,
        }
    )



# ======================================================
#     GUARDAR CONFIG (ON/OFF + FLAGS)
# ======================================================
@require_POST
@login_required
def autoassign_save(request):
    if not request.user.groups.filter(name="admin").exists():
        return JsonResponse({"ok": False, "error": "No autorizado"}, status=403)

    try:
        data = json.loads(request.body.decode("utf-8"))
    except:
        return JsonResponse({"ok": False, "error": "JSON inválido"}, status=400)

    # Leer valores seguros
    enabled = data.get("enabled", False)
    flags = data.get("tech_flags", {})

    # Obtener configuración
    cfg = AutoAssignConfig.objects.first()
    if not cfg:
        cfg = AutoAssignConfig.objects.create(enabled=True)

    # Guardar ON/OFF autoasignación
    cfg.enabled = True if str(enabled).lower() == "true" else False
    cfg.save()

    # Guardar flags de técnicos
    for user_id, flag in flags.items():
        try:
            p = UserProfile.objects.get(user_id=user_id)
            p.auto_assign_enabled = True if str(flag).lower() == "true" else False
            p.save()
        except UserProfile.DoesNotExist:
            continue

    return JsonResponse({"ok": True})



# ======================================================
#     RESET ROUND ROBIN POR ÁREA
# ======================================================
@login_required
@require_POST
def reset_rr(request):
    if not request.user.groups.filter(name="admin").exists():
        return JsonResponse({"ok": False, "error": "No autorizado"}, status=403)

    try:
        data = json.loads(request.body.decode("utf-8"))
        area_id = data.get("area_id")
    except:
        return JsonResponse({"ok": False, "error": "Datos inválidos"}, status=400)

    # Validación si es vacío ("")
    if not area_id:
        return JsonResponse({"ok": False, "error": "Debe seleccionar un área."}, status=400)

    try:
        area = Area.objects.get(id=int(area_id))
    except:
        return JsonResponse({"ok": False, "error": "Área no encontrada."}, status=404)

    rr, _ = AreaRoundRobin.objects.get_or_create(area=area)
    rr.last_user = None
    rr.save()

    return JsonResponse({"ok": True, "msg": f"Round-robin reiniciado para {area.name}."})
