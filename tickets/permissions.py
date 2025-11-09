# tickets/permissions.py
from rest_framework.permissions import BasePermission, SAFE_METHODS

def _extract_ticket(obj):
    """Obtiene el ticket asociado desde el objeto recibido."""
    if hasattr(obj, "ticket") and obj.ticket is not None:
        return obj.ticket
    return obj


class IsTicketActorOrAdmin(BasePermission):
    """Permite acceso a requester, asignado y usuarios admin/tecnico."""

    admin_like_groups = {"admin", "tecnico"}

    def has_permission(self, request, view):
        user = request.user
        # Solo usuarios autenticados pueden acceder
        if not user or not user.is_authenticated:
            return False

        # Si está listando, verificar que su rol sea válido
        if view.action == "list":
            return True  # permitimos listar, pero el filtrado lo hará get_queryset
        return True

    def has_object_permission(self, request, view, obj):
        user = request.user
        if not user or not user.is_authenticated:
            return False

        ticket = _extract_ticket(obj)
        requester_id = getattr(ticket, "requester_id", None)
        assigned_to_id = getattr(ticket, "assigned_to_id", None)
        is_admin_like = (
            user.is_superuser
            or user.is_staff
            or user.groups.filter(name__in=self.admin_like_groups).exists()
        )

        # Métodos de solo lectura (GET, HEAD, OPTIONS)
        if request.method in SAFE_METHODS:
            return (
                is_admin_like
                or requester_id == user.id
                or assigned_to_id == user.id
            )

        # Escritura o modificación
        if is_admin_like:
            return True

        return requester_id == user.id or assigned_to_id == user.id
