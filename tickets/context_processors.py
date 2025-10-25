from .utils import user_sections
def maint_sections(request):
    return {"maint_sections": user_sections(request.user)}