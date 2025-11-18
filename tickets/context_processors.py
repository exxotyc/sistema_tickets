def role_flags(request):
    """Entrega variables globales para mostrar/ocultar menús según rol."""

    if not request.user.is_authenticated:
        return {
            "is_admin": False,
            "is_tecnico": False,
            "is_solicitante": False,
        }

    groups = {g.name.lower() for g in request.user.groups.all()}

    return {
        "is_admin": "admin" in groups,
        "is_tecnico": "tecnico" in groups,
        "is_solicitante": "solicitante" in groups or len(groups) == 0,
    }
