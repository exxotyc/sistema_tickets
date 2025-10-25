from django.contrib import admin
from .models import Ticket, Category, Comment, Attachment, TicketLog, Section

@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ("id","title","state","priority","requester","assigned_to","updated_at")
    list_filter = ("state","priority","category","assigned_to")
    search_fields = ("title","description")

admin.site.register([Category, Comment, Attachment, TicketLog])

@admin.register(Section)
class SectionAdmin(admin.ModelAdmin):
    list_display = ("title","code","url_name","is_active")
    list_filter = ("is_active",)
    search_fields = ("title","code","url_name")
    filter_horizontal = ("groups",)