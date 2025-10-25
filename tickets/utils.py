# tickets/utils.py
def user_sections(user):
    if not user.is_authenticated:
        return []
    if user.is_staff or user.groups.filter(name__in=["admin"]).exists():
        # Admin ve todas
        from .models import Section
        return list(Section.objects.filter(is_active=True))
    from .models import Section
    return list(Section.objects.filter(is_active=True, groups__in=user.groups.all()).distinct())
