# tickets/role_flags.py
from .rbac import user_managed_roles

def role_flags(request):
    user = getattr(request, "user", None)
    roles = set(user_managed_roles(user)) if user and user.is_authenticated else set()

    return {
        "is_admin": "admin" in roles,
        "is_tecnico": "tecnico" in roles,
        "is_usuario": "usuario" in roles,
    }
