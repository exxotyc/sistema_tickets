"""Utilities for role-based access control in the maintenance area."""
from __future__ import annotations

from typing import Iterable, List, Sequence, Set

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group


MANAGED_ROLE_NAMES: Set[str] = {"admin", "tecnico", "usuario"}
ROLE_LABELS = {
    "admin": "Admin",
    "tecnico": "Técnico",
    "solicitante": "Usuario",
}

# Roles that allow managing other roles.
ROLE_MANAGEMENT_MATRIX = {
    "admin": MANAGED_ROLE_NAMES.copy(),
    "tecnico": {"tecnico", "usuario"},
}


class RolePermissionError(Exception):
    """Raised when the actor is not allowed to perform a role operation."""


class LastAdminRemovalError(RolePermissionError):
    """Raised when an operation would leave the system without admins."""


def ensure_groups_exist() -> None:
    """Ensure that the managed groups are present in the database."""

    for name in MANAGED_ROLE_NAMES:
        Group.objects.get_or_create(name=name)


def clean_roles(raw_roles: Iterable[str] | None) -> List[str]:
    """Normalise a list of roles, keeping only managed names."""

    roles = {str(role).strip() for role in raw_roles or []}
    return sorted(role for role in roles if role in MANAGED_ROLE_NAMES)


def user_managed_roles(user) -> List[str]:
    """Return the list of managed roles currently assigned to the user."""

    if not user or not getattr(user, "pk", None):
        return []
    return list(
        user.groups.filter(name__in=MANAGED_ROLE_NAMES).values_list("name", flat=True)
    )


def actor_allowed_roles(actor) -> Set[str]:
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


def has_other_admins(exclude_user=None) -> bool:
    """Check whether there is at least one admin besides the excluded user."""

    qs = get_user_model().objects.filter(groups__name="admin")
    if exclude_user is not None:
        exclude_id = exclude_user.pk if hasattr(exclude_user, "pk") else exclude_user
        qs = qs.exclude(pk=exclude_id)
    return qs.exists()


def assert_actor_can_manage(actor, target_user, new_roles: Sequence[str]) -> Set[str]:
    """Validate that the actor can set the target user's roles to ``new_roles``."""

    desired = set(clean_roles(new_roles))
    current = set(user_managed_roles(target_user))

    allowed = actor_allowed_roles(actor)
    if not allowed and not (actor and (actor.is_superuser or actor.is_staff)):
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

    if "admin" in current and "admin" not in desired and not has_other_admins(target_user):
        raise LastAdminRemovalError("Debe quedar al menos un admin en el sistema.")

    return desired


def apply_roles(user, roles: Sequence[str]) -> List[str]:
    """Assign the provided managed roles to the user, replacing the current ones."""

    ensure_groups_exist()
    new_roles = set(clean_roles(roles))
    current_roles = set(user_managed_roles(user))

    to_remove = current_roles - new_roles
    if to_remove:
        user.groups.remove(*Group.objects.filter(name__in=to_remove))

    to_add = new_roles - current_roles
    if to_add:
        user.groups.add(*Group.objects.filter(name__in=to_add))

    return sorted(new_roles)
