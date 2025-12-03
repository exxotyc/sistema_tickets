# tickets/views_users.py
from __future__ import annotations

import json
from typing import List, Iterable

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import JsonResponse, HttpResponseBadRequest
from django.shortcuts import render, get_object_or_404
from django.views.decorators.http import require_GET, require_POST

from .rbac import (
    ROLE_LABELS,
    MANAGED_ROLE_NAMES,
    ensure_groups_exist,
    user_managed_roles,
    actor_allowed_roles,
    assert_actor_can_manage,
    apply_roles,
    RolePermissionError,
    LastAdminRemovalError,
)

from tickets.models import UserProfile, Area  # ← NECESARIO

User = get_user_model()


# ==========================================================
#   PERMISOS
# ==========================================================
def _actor_can_use_user_maint(actor) -> bool:
    if not actor or not actor.is_authenticated:
        return False
    return actor.is_superuser or actor.is_staff or bool(actor_allowed_roles(actor))


# ==========================================================
#   PAGE — MANTENEDOR DE USUARIOS
# ==========================================================
@login_required
def users_page(request):
    if not _actor_can_use_user_maint(request.user):
        return render(request, "tickets/403.html", status=403)

    ensure_groups_exist()

    from .models import Section
    maint_sections = Section.objects.filter(is_active=True).order_by("title", "id")

    # ============================
    #   ROLES SEGÚN TIPO DE USUARIO
    # ============================
    actor = request.user
    allowed = actor_allowed_roles(actor)

    # 🧩 FIX CRÍTICO: si es admin/staff pero no tiene grupos, debe poder manejar todos los roles
    if (actor.is_staff or actor.is_superuser) and not allowed:
        allowed = MANAGED_ROLE_NAMES

    role_options = [
        {"code": r, "label": ROLE_LABELS.get(r, r)}
        for r in MANAGED_ROLE_NAMES
    ]

    ctx = {
        "maint_sections": maint_sections,
        "allowed_roles_json": json.dumps(list(allowed)),
        "role_options_json": json.dumps(role_options),
        "can_manage_staff": actor.is_staff or actor.is_superuser,
    }

    return render(request, "tickets/maint_usuarios.html", ctx)




# ==========================================================
#   API — LISTA DE USUARIOS
# ==========================================================
@login_required
@require_GET
def users_data(request):
    if not _actor_can_use_user_maint(request.user):
        return JsonResponse({"error": "No autorizado."}, status=403)

    q = (request.GET.get("q") or "").strip().lower()

    qs = (
        User.objects.all()
        .only("id", "username", "email", "first_name", "last_name", "is_staff", "is_active")
        .order_by("id")
    )

    users: List[dict] = []
    for u in qs:
        roles = user_managed_roles(u)

        # === PERFIL ===
        profile, _ = UserProfile.objects.get_or_create(user=u)

        row = {
            "id": u.id,
            "username": u.username or "",
            "full_name": (u.get_full_name() or "").strip(),
            "email": u.email or "",
            "is_staff": bool(u.is_staff),
            "is_active": bool(u.is_active),
            "roles": sorted(set(roles)),
            "area_id": profile.area_id,
            "area_name": profile.area.name if profile.area else "",
        }

        if q:
            text = " ".join([
                row["username"].lower(),
                row["full_name"].lower(),
                row["email"].lower(),
                " ".join(row["roles"]).lower(),
                (row["area_name"] or "").lower(),
            ])
            if q not in text:
                continue

        users.append(row)

    return JsonResponse({"users": users})


# ==========================================================
#   API — CREAR / EDITAR USUARIO  (VALIDACIÓN DE ÁREA CORREGIDA)
# ==========================================================
@login_required
@require_POST
@transaction.atomic
def users_save(request):

    if not _actor_can_use_user_maint(request.user):
        return JsonResponse({"ok": False, "error": "No autorizado."}, status=403)

    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return HttpResponseBadRequest("JSON inválido")

    uid = data.get("id")
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    first_name = (data.get("first_name") or "").strip()
    last_name = (data.get("last_name") or "").strip()
    is_staff = bool(data.get("is_staff", False))
    is_active = bool(data.get("is_active", True))

    desired_roles = [(r or "").strip().lower() for r in (data.get("roles") or []) if r]
    desired_roles = sorted(set(desired_roles))

    raw_password = data.get("password")
    area_id = data.get("area")

    # ================================
    # VALIDACIONES IMPORTANTES (BACKEND)
    # ================================
    is_admin = "admin" in desired_roles
    is_tec = "tecnico" in desired_roles
    is_solic = "usuario" in desired_roles

    # 🔥 ADMIN puede tener área o NO tenerla, NO requiere validación adicional
    # 🔥 TÉCNICO y SOLICITANTE → DEBEN tener área obligatoria
    if (is_tec or is_solic) and not area_id:
        return JsonResponse({
            "ok": False,
            "error": "Los roles técnico y solicitante requieren un área asignada."
        }, status=400)

    if is_admin and is_tec:
        return JsonResponse({
            "ok": False,
            "error": "El rol admin NO puede coexistir con técnico."
        }, status=400)

    # =========================
    # CREAR USUARIO
    # =========================
    if uid is None:
        if User.objects.filter(username=username).exists():
            return JsonResponse({"ok": False, "error": "Username ya existe."}, status=400)

        user = User(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            is_staff=is_staff,
            is_active=is_active
        )

        if raw_password:
            user.set_password(raw_password)
        else:
            user.set_unusable_password()

        user.save()

    # =========================
    # EDITAR USUARIO
    # =========================
    else:
        user = get_object_or_404(User, pk=uid)

        try:
            _ = assert_actor_can_manage(request.user, user, desired_roles)
        except (LastAdminRemovalError, RolePermissionError) as e:
            return JsonResponse({"ok": False, "error": str(e)}, status=403)

        user.username = username
        user.email = email
        user.first_name = first_name
        user.last_name = last_name
        user.is_staff = is_staff
        user.is_active = is_active
        user.save()

        if raw_password:
            user.set_password(raw_password)
            user.save()

    # ================================
    # GUARDAR ÁREA EN EL PERFIL
    # ================================
    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile.area_id = area_id if area_id else None
    profile.save()

    # ================================
    # APLICAR ROLES
    # ================================
    try:
        desired_set = assert_actor_can_manage(request.user, user, desired_roles)
        final_roles = apply_roles(user, sorted(desired_set))
    except LastAdminRemovalError as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=409)
    except RolePermissionError as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=403)

    return JsonResponse({
        "ok": True,
        "user": {
            "id": user.id,
            "username": user.username,
            "full_name": (user.get_full_name() or "").strip(),
            "email": user.email or "",
            "is_staff": bool(user.is_staff),
            "is_active": bool(user.is_active),
            "roles": list(final_roles),
            "area_id": profile.area_id,
            "area_name": profile.area.name if profile.area else "",
        }
    })




# ==========================================================
#   API — ACTIVAR / DESACTIVAR
# ==========================================================
@login_required
@require_POST
@transaction.atomic
def users_toggle_active(request):

    if not _actor_can_use_user_maint(request.user):
        return JsonResponse({"ok": False, "error": "No autorizado."}, status=403)

    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return HttpResponseBadRequest("JSON inválido")

    uid = data.get("id")
    active = bool(data.get("active", True))
    user = get_object_or_404(User, pk=uid)

    try:
        assert_actor_can_manage(request.user, user, user_managed_roles(user))
    except (LastAdminRemovalError, RolePermissionError) as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=403)

    if not active:
        try:
            assert_actor_can_manage(request.user, user, user_managed_roles(user))
        except LastAdminRemovalError as e:
            return JsonResponse({"ok": False, "error": str(e)}, status=409)

    user.is_active = active
    user.save()

    return JsonResponse({"ok": True, "id": user.id, "is_active": user.is_active})
