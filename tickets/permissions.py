# tickets/permissions.py
from rest_framework import permissions
from rest_framework.permissions import BasePermission, SAFE_METHODS


def in_group(user, name):
    return user.is_authenticated and user.groups.filter(name=name).exists()

class IsRequesterOrAssignedOrAdmin(permissions.BasePermission):
    """
    admin: todo (is_staff o grupo admin)
    tecnico: puede modificar cualquier ticket
    usuario: puede modificar solo los propios
    GET siempre permitido autenticado
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        u = request.user
        if request.method in permissions.SAFE_METHODS:
            return True
        if u.is_staff or in_group(u, "admin") or in_group(u, "tecnico"):
            return True
        if getattr(obj, "requester_id", None) == u.id:
            return True
        return False
    
class IsAdminTechOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        u = request.user
        if not u.is_authenticated:
            return False
        if u.is_superuser:
            return True
        # Lectura
        if request.method in SAFE_METHODS:
            return obj.requester_id == u.id or getattr(obj, "assigned_to_id", None) == u.id
        # Escritura: dueño o técnico asignado
        return obj.requester_id == u.id or getattr(obj, "assigned_to_id", None) == u.id
    
def in_group(user, name):
    return user.is_authenticated and user.groups.filter(name=name).exists()

class IsRequesterOrAssignedOrAdmin(BasePermission):
    """
    Lectura: requester, asignado, staff, admin/tecnico.
    Escritura: requester o asignado; además staff o admin/tecnico pueden editar cualquiera.
    """
    def has_object_permission(self, request, view, obj):
        u = request.user
        if not u.is_authenticated:
            return False

        is_admin_like = u.is_staff or in_group(u, "admin") or in_group(u, "tecnico")

        if request.method in SAFE_METHODS:
            return is_admin_like or obj.requester_id == u.id or (obj.assigned_to_id == u.id if obj.assigned_to_id else False)

        # Escritura
        if is_admin_like:
            return True
        return obj.requester_id == u.id or (obj.assigned_to_id == u.id if obj.assigned_to_id else False)
