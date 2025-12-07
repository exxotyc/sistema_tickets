# tickets/views_perfil.py
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_POST
from .models import UserProfile

import magic   # ← reemplaza imghdr


@login_required
def perfil_usuario(request):
    return render(request, "tickets/perfil_usuario.html")


# ============================================================
#  SUBIR FOTO (CON VALIDACIÓN REAL)
# ============================================================
@login_required
@require_POST
def perfil_actualizar_foto(request):

    file = request.FILES.get("profile_picture")

    if not file:
        return JsonResponse({"ok": False, "error": "No se recibió ninguna imagen."})

    # ---------------------------------------------------------
    # VALIDAR TAMAÑO (máx. 2 MB)
    # ---------------------------------------------------------
    if file.size > 2 * 1024 * 1024:
        return JsonResponse({
            "ok": False,
            "error": "La imagen no puede superar los 2 MB."
        })

    # ---------------------------------------------------------
    # VALIDAR TIPO MIME REAL
    # ---------------------------------------------------------
    mime = magic.from_buffer(file.read(2048), mime=True)
    file.seek(0)  # ← imprescindible!

    allowed_mimes = ["image/jpeg", "image/png", "image/gif", "image/webp"]

    if mime not in allowed_mimes:
        return JsonResponse({
            "ok": False,
            "error": "Solo se permiten imágenes JPEG, PNG, GIF o WEBP."
        })

    # ---------------------------------------------------------
    # GUARDAR FOTO
    # ---------------------------------------------------------
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    profile.profile_picture = file
    profile.save()

    return JsonResponse({
        "ok": True,
        "url": profile.profile_picture.url
    })


# ============================================================
#  ELIMINAR FOTO
# ============================================================
@login_required
@require_POST
def perfil_eliminar_foto(request):

    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    profile.profile_picture = None
    profile.save()

    return JsonResponse({"ok": True})


# ============================================================
#  ACTUALIZAR NOMBRE Y APELLIDO
# ============================================================
@login_required
@require_POST
def perfil_actualizar_datos(request):

    first = request.POST.get("first_name", "").strip()
    last = request.POST.get("last_name", "").strip()

    u = request.user
    u.first_name = first
    u.last_name = last
    u.save()

    return JsonResponse({
        "ok": True,
        "first_name": first,
        "last_name": last
    })
