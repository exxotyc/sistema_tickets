# tickets/views_roles.py
from __future__ import annotations

import json
from typing import List, Iterable
from django.contrib.auth import get_user_model

from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.http import (
    JsonResponse,
    HttpRequest,
    HttpResponse,
    HttpResponseBadRequest,
)
from django.shortcuts import render, get_object_or_404
from django.views.decorators.http import require_GET, require_POST

# ⚙️ Importa tu núcleo RBAC existente
from .rbac import (
    ROLE_LABELS,            # dict: codigo->etiqueta legible
    MANAGED_ROLE_NAMES,     # set/list: {"admin","tecnico","usuario"}
    ensure_groups_exist,    # crea grupos si no existen
    user_managed_roles,     # obtiene solo los roles administrables del usuario
    actor_allowed_roles,    # qué roles puede asignar este actor
    assert_actor_can_manage,# valida matriz y “último admin” (raise si no)
    apply_roles,            # aplica (reemplaza) roles administrables
    RolePermissionError,    # error de permisos (matriz)
    LastAdminRemovalError,  # error por dejar al sistema sin admin
)

User = get_user_model()


def _actor_can_use_maint(actor) -> bool:
    """
    Política mínima para entrar al mantenedor:
    - autenticado Y
    - es superuser/staff O tiene alguna capacidad de gestión según matriz
    """
    if not actor or not actor.is_authenticated:
        return False
    return actor.is_superuser or actor.is_staff or bool(actor_allowed_roles(actor))


@login_required
def roles_page(request: HttpRequest) -> HttpResponse:
    """
    Renderiza el template del mantenedor e inyecta:
      - role_labels_json      (mapa código->etiqueta)
      - managed_roles_json    (lista de roles administrables)
    """
    if not _actor_can_use_maint(request.user):
        # Puedes usar tu propio 403 si lo prefieres
        return render(request, "403.html", status=403)

    # Asegura que existan los grupos “admin/tecnico/usuario”
    ensure_groups_exist()

    ctx = {
        "role_labels_json": json.dumps(ROLE_LABELS, ensure_ascii=False),
        "managed_roles_json": json.dumps(sorted(MANAGED_ROLE_NAMES)),
    }
    return render(request, "tickets/maint_roles.html", ctx)


@login_required
@require_GET
def roles_data(request: HttpRequest) -> JsonResponse:
    """
    Devuelve listado de usuarios con sus roles administrables actuales.
    Soporta ?q= para filtrar en backend (por username/email/roles).
    """
    if not _actor_can_use_maint(request.user):
        return JsonResponse({"error": "No autorizado."}, status=403)

    q = (request.GET.get("q") or "").strip().lower()
    # Ajusta campos según tus necesidades; evitamos traer todo para performance
    qs = User.objects.all().order_by("id").only("id", "username", "email", "is_staff")

    users: List[dict] = []
    for u in qs:
        roles = user_managed_roles(u)  # p.ej. ["admin"] / ["tecnico"] / ["usuario"]
        row = {
            "id": u.id,
            "username": u.username or "",
            "email": u.email or "",
            "is_staff": bool(u.is_staff),
            "roles": roles,
        }
        if q:
            hay = (
                (row["username"] and q in row["username"].lower())
                or (row["email"] and q in row["email"].lower())
                or any(q in r for r in roles)
            )
            if not hay:
                continue
        users.append(row)

    return JsonResponse({"users": users})


@login_required
@require_POST
def maint_roles_set(request: HttpRequest) -> JsonResponse:
    """
    Recibe JSON: { "user_id": <int>, "roles": ["admin"|"tecnico"|"usuario", ...] }
    Aplica REEMPLAZO de todos los roles administrables del usuario por los “roles” recibidos.

    Protecciones clave vía núcleo RBAC:
      - Valida si el actor puede gestionar al target (matriz).
      - Evita admin+tecnico simultáneos (si lo implementaste ahí).
      - Impide dejar al sistema sin al menos 1 admin (LastAdminRemovalError).
    """
    if not _actor_can_use_maint(request.user):
        return JsonResponse({"ok": False, "error": "No autorizado."}, status=403)

    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return HttpResponseBadRequest("JSON inválido")

    target_id = data.get("user_id", None)
    desired = data.get("roles", None)

    if target_id is None or not isinstance(desired, list):
        return HttpResponseBadRequest("Payload incompleto")

    # Normaliza codigos y elimina duplicados, ignora vacíos
    desired_codes: List[str] = []
    seen = set()
    for r in desired:
        if not isinstance(r, str):
            continue
        c = r.strip().lower()
        if not c or c in seen:
            continue
        seen.add(c)
        desired_codes.append(c)

    target = get_object_or_404(User, pk=target_id)

    try:
        # Valida matriz y sistema (puede lanzar RolePermissionError / LastAdminRemovalError)
        desired_set = assert_actor_can_manage(request.user, target, desired_codes)

        # Aplica roles (reemplazo total de roles administrables) en transacción
        # apply_roles debe devolver la lista final de roles administrables p. ej. ["usuario"]
        new_roles: Iterable[str] = apply_roles(target, sorted(desired_set))

    except LastAdminRemovalError as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=409)

    except RolePermissionError as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=403)

    except Exception:
        # Loguea el error si quieres: logger.exception("...")
        return JsonResponse({"ok": False, "error": "Error interno."}, status=500)

    return JsonResponse({"ok": True, "roles": list(new_roles)})
