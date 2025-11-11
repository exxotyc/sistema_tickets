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

User = get_user_model()


def _actor_can_use_user_maint(actor) -> bool:
    # Mismo criterio que roles: superuser/staff o con capacidad de gestión
    if not actor or not actor.is_authenticated:
        return False
    return actor.is_superuser or actor.is_staff or bool(actor_allowed_roles(actor))


@login_required
def users_page(request):
    if not _actor_can_use_user_maint(request.user):
        return render(request, "403.html", status=403)

    ensure_groups_exist()

    ctx = {
        "role_labels_json": json.dumps(ROLE_LABELS, ensure_ascii=False),
        "managed_roles_json": json.dumps(sorted(MANAGED_ROLE_NAMES)),
    }
    return render(request, "tickets/maint_usuarios.html", ctx)


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
        row = {
            "id": u.id,
            "username": u.username or "",
            "full_name": (u.get_full_name() or "").strip(),
            "email": u.email or "",
            "is_staff": bool(u.is_staff),
            "is_active": bool(u.is_active),
            "roles": sorted(set(roles)),
        }
        if q:
            text = " ".join([
                row["username"].lower(),
                row["full_name"].lower(),
                row["email"].lower(),
                " ".join(row["roles"]).lower(),
            ])
            if q not in text:
                continue
        users.append(row)

    return JsonResponse({"users": users})


@login_required
@require_POST
@transaction.atomic
def users_save(request):
    """
    Crea o edita un usuario.
    Payload esperado:
      {
        "id": null|int,            # null -> crear; int -> editar
        "username": "foo",
        "email": "a@b.c",
        "first_name": "A",
        "last_name": "B",
        "is_staff": bool,
        "is_active": bool,
        "roles": ["admin"|"tecnico"|"usuario", ...],   # reemplazo total de roles administrables
        "password": "opcional_en_creacion"             # si viene y es crear, set_password
      }
    Reglas:
      - valida matriz de RBAC (assert_actor_can_manage)
      - protege Último Admin (LastAdminRemovalError)
      - admin y tecnico no simultáneos (en tu RBAC)
    """
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
    desired_roles = [ (r or "").strip().lower() for r in (data.get("roles") or []) if r ]
    desired_roles = sorted(set(desired_roles))
    raw_password = data.get("password")

    if not username:
        return HttpResponseBadRequest("username requerido")

    # Crear
    if uid is None:
        if User.objects.filter(username=username).exists():
            return JsonResponse({"ok": False, "error": "Username ya existe."}, status=400)
        user = User(username=username, email=email, first_name=first_name, last_name=last_name)
        user.is_staff = is_staff
        user.is_active = is_active
        if raw_password:
            user.set_password(raw_password)
        else:
            # establece algo aleatorio; luego podrás forzar cambio si quieres
            user.set_unusable_password()
        user.save()
    else:
        user = get_object_or_404(User, pk=uid)
        # antes de modificar roles o estado, valida RBAC
        try:
            _ = assert_actor_can_manage(request.user, user, desired_roles)
        except (LastAdminRemovalError, RolePermissionError) as e:
            return JsonResponse({"ok": False, "error": str(e)}, status=403)

        # edita campos
        user.username = username
        user.email = email
        user.first_name = first_name
        user.last_name = last_name
        user.is_staff = is_staff
        user.is_active = is_active
        user.save()

        # si te interesa permitir cambio de password en edición:
        if raw_password:
            user.set_password(raw_password)
            user.save()

    # aplica roles (tanto para crear como para editar)
    try:
        desired_set = assert_actor_can_manage(request.user, user, desired_roles)
        final_roles: Iterable[str] = apply_roles(user, sorted(desired_set))
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
        }
    })


@login_required
@require_POST
@transaction.atomic
def users_toggle_active(request):
    """
    Activa/Desactiva un usuario.
    Protege el último admin si la operación dejaría 0.
    Payload: { "id": 123, "active": true|false }
    """
    if not _actor_can_use_user_maint(request.user):
        return JsonResponse({"ok": False, "error": "No autorizado."}, status=403)

    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return HttpResponseBadRequest("JSON inválido")

    uid = data.get("id")
    active = bool(data.get("active", True))
    user = get_object_or_404(User, pk=uid)

    # Validación de matriz: no puedas desactivar a alguien que no puedes gestionar
    try:
        # Mantén sus roles actuales; solo validamos actor/target
        assert_actor_can_manage(request.user, user, user_managed_roles(user))
    except (LastAdminRemovalError, RolePermissionError) as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=403)

    # Si vamos a desactivar y este usuario es (el) último admin, bloquear
    if not active:
        try:
            # Pasando roles actuales; la helper debería chequear la condición de último admin
            assert_actor_can_manage(request.user, user, user_managed_roles(user))
        except LastAdminRemovalError as e:
            return JsonResponse({"ok": False, "error": str(e)}, status=409)

    user.is_active = active
    user.save()

    return JsonResponse({"ok": True, "id": user.id, "is_active": user.is_active})
