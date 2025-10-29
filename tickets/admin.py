from django.contrib import admin
from .models import (
    Ticket,
    Category,
    Comment,
    Attachment,
    TicketLog,
    Section,
    FAQ,
    FAQFeedback,
)


class CommentInline(admin.TabularInline):
    model = Comment
    extra = 0
    readonly_fields = ("user", "body", "created_at")


class AttachmentInline(admin.TabularInline):
    model = Attachment
    extra = 0
    readonly_fields = ("user", "file", "mime", "size_bytes", "sha256", "created_at")


@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ("id", "title", "state", "priority", "requester", "assigned_to", "updated_at")
    list_filter = ("state", "priority", "assigned_to", "category")
    search_fields = ("title", "description", "asset_id")
    inlines = [CommentInline, AttachmentInline]


admin.site.register([Category, Comment, Attachment, TicketLog, FAQ, FAQFeedback])

@admin.register(Section)
class SectionAdmin(admin.ModelAdmin):
    list_display = ("title","code","url_name","is_active")
    list_filter = ("is_active",)
    search_fields = ("title","code","url_name")
    filter_horizontal = ("groups",)