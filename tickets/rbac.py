"""Utilities for role-based access control in the maintenance area."""
from __future__ import annotations

from typing import Iterable, List, Sequence, Set, Collection

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import transaction



# Ajusta este set según nomenclatura real.
MANAGED_ROLE_NAMES: Set[str] = {"admin", "tecnico", "usuario"}

ROLE_LABELS = {
    "admin": "Admin",
    "tecnico": "Técnico",
    "usuario": "Usuario",      # ← corregido
    # "solicitante": "Usuario",  # ← elimina o añade "solicitante" a MANAGED_ROLE_NAMES
}

# Roles que pueden gestionar otros roles
ROLE_MANAGEMENT_MATRIX = {
    "admin": set(MANAGED_ROLE_NAMES),
    "tecnico": {"tecnico", "usuario"},
}

User = get_user_model()


class RolePermissionError(Exception):
    """Raised when the actor is not allowed to perform a role operation."""


class LastAdminRemovalError(RolePermissionError):
    """Raised when an operation would leave the system without admins."""


def ensure_groups_exist() -> None:
    """Ensure that the managed groups are present in the database."""
    for name in MANAGED_ROLE_NAMES:
        Group.objects.get_or_create(name=name)


def clean_roles(raw_roles: Iterable[str] | None) -> List[str]:
    """Normalise a list of roles, keeping only managed names (lowercased)."""
    roles = {str(role).strip().lower() for role in (raw_roles or [])}
    return sorted(role for role in roles if role in MANAGED_ROLE_NAMES)


def user_managed_roles(user: User | None) -> List[str]:
    """Return the list of managed roles currently assigned to the user."""
    if not user or not getattr(user, "pk", None):
        return []
    return sorted(
        user.groups.filter(name__in=MANAGED_ROLE_NAMES).values_list("name", flat=True)
    )


def actor_allowed_roles(actor: User | None) -> Set[str]:
    """Roles that the actor is allowed to grant or revoke."""
    if not actor or not actor.is_authenticated:
        return set()
    if actor.is_superuser or actor.is_staff:
        return set(MANAGED_ROLE_NAMES)

    allowed: Set[str] = set()
    actor_roles = set(
        actor.groups.filter(name__in=MANAGED_ROLE_NAMES).values_list("name", flat=True)
    )
    for name in actor_roles:
        allowed |= ROLE_MANAGEMENT_MATRIX.get(name, set())
    return allowed


def has_other_admins(exclude_user: User | int | None = None) -> bool:
    """Check whether there is at least one admin besides the excluded user."""
    qs = User.objects.filter(groups__name="admin")
    if exclude_user is not None:
        exclude_id = exclude_user.pk if hasattr(exclude_user, "pk") else exclude_user
        qs = qs.exclude(pk=exclude_id)
    return qs.exists()


def assert_actor_can_manage(actor: User | None, target_user: User, new_roles: Sequence[str]) -> Set[str]:
    """Validate that the actor can set the target user's roles to ``new_roles``."""
    desired = set(clean_roles(new_roles))
    current = set(user_managed_roles(target_user))

    allowed = actor_allowed_roles(actor)
    if not allowed:
        raise RolePermissionError("No tienes permisos para administrar roles.")

    to_add = desired - current
    to_remove = current - desired

    disallowed_add = to_add - allowed
    disallowed_remove = to_remove - allowed
    if disallowed_add:
        raise RolePermissionError(
            "No puedes asignar los roles: " + ", ".join(sorted(disallowed_add))
        )
    if disallowed_remove:
        raise RolePermissionError(
            "No puedes revocar los roles: " + ", ".join(sorted(disallowed_remove))
        )

    # Proteger último admin
    if "admin" in current and "admin" not in desired and not has_other_admins(target_user):
        raise LastAdminRemovalError("Debe quedar al menos un admin en el sistema.")

    return desired


@transaction.atomic
def apply_roles(user: User, roles: Sequence[str], *, protect_last_admin: bool = True) -> List[str]:
    """
    Assign the provided managed roles to the user, replacing the current ones.

    If protect_last_admin is True, it will ensure we don't remove the last admin,
    incluso si no se llamó a `assert_actor_can_manage` previamente.
    """
    ensure_groups_exist()

    new_roles = set(clean_roles(roles))
    current_roles = set(user_managed_roles(user))

    # Protección adicional opcional ante carreras o uso directo:
    if protect_last_admin and "admin" in current_roles and "admin" not in new_roles:
        # Re-verificar bajo la misma transacción para minimizar condiciones de carrera
        if not has_other_admins(user):
            raise LastAdminRemovalError("Debe quedar al menos un admin en el sistema.")

    to_remove = current_roles - new_roles
    if to_remove:
        user.groups.remove(*Group.objects.filter(name__in=to_remove))

    to_add = new_roles - current_roles
    if to_add:
        user.groups.add(*Group.objects.filter(name__in=to_add))

    return sorted(new_roles)
