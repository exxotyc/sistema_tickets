# tickets/context.py
from .models import Section

def maint_sections(request):
    if not getattr(request, "user", None) or not request.user.is_authenticated:
        return {}
    u = request.user
    is_adminlike = u.is_superuser or u.is_staff or u.groups.filter(name__in=["admin","tecnico"]).exists()
    qs = Section.objects.filter(is_active=True).order_by("title")
    if is_adminlike:
        items = list(qs.values("code", "title"))
    else:
        items = list(qs.filter(groups__in=u.groups.all()).distinct().values("code", "title"))
    return {"maint_sections": items}
