from django.db import models
from django.contrib.auth.models import User, Group


PRIORITY_CHOICES = [
    ("low","Baja"),
    ("medium","Media"),
    ("high","Alta"),
    ("critical","Crítica"),
]

STATE_CHOICES = [
    ("open","Abierto"),
    ("in_progress","En progreso"),
    ("resolved","Resuelto"),
    ("closed","Cerrado"),
]

class Category(models.Model):
    name = models.CharField(max_length=50, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

class Ticket(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    requester = models.ForeignKey(User, related_name="tickets", on_delete=models.CASCADE)
    assigned_to = models.ForeignKey(User, related_name="assigned_tickets", null=True, blank=True, on_delete=models.SET_NULL)
    category = models.ForeignKey(Category, null=True, blank=True, on_delete=models.SET_NULL)
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default="medium")
    state = models.CharField(max_length=20, choices=STATE_CHOICES, default="open")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    attachment = models.FileField(upload_to="attachments/%Y/%m/", null=True, blank=True)  # <- así
    frt_due_at = models.DateTimeField(null=True, blank=True)       # vencimiento 1ª respuesta
    resolve_due_at = models.DateTimeField(null=True, blank=True)   # vencimiento resolución


    def __str__(self):
        return f"#{self.id} {self.title}"

class TicketLog(models.Model):
    ticket = models.ForeignKey(Ticket, related_name="logs", on_delete=models.CASCADE)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    action = models.CharField(max_length=200)
    meta_json = models.JSONField(default=dict, blank=True)   # <- DEBE existir
    created_at = models.DateTimeField(auto_now_add=True)

class Comment(models.Model):
    ticket = models.ForeignKey(Ticket, related_name="comments", on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.PROTECT)
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self): return f"Comment {self.id} on Ticket {self.ticket_id}"

class Attachment(models.Model):
    ticket = models.ForeignKey(Ticket, related_name="attachments", on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.PROTECT)
    file = models.FileField(upload_to="attachments/%Y/%m/")
    mime = models.CharField(max_length=100, blank=True)
    size_bytes = models.BigIntegerField(null=True, blank=True)
    sha256 = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self): return f"Attachment {self.id} for Ticket {self.ticket_id}"


class Section(models.Model):
    code = models.SlugField(unique=True)                 # p.ej. "categorias", "usuarios"
    title = models.CharField(max_length=80)              # Título visible
    url_name = models.CharField(max_length=80)           # nombre de URL a resolver
    groups = models.ManyToManyField(Group, blank=True)   # quiénes la ven
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["title"]

    def __str__(self):
        return self.title
    

    # añade estos campos (luego makemigrations/migrate)
frt_due_at = models.DateTimeField(null=True, blank=True)
resolve_due_at = models.DateTimeField(null=True, blank=True)
frt_met = models.BooleanField(null=True, blank=True)       # True, False, o None si aún no aplica
resolve_met = models.BooleanField(null=True, blank=True)
frt_breached_at = models.DateTimeField(null=True, blank=True)
resolve_breached_at = models.DateTimeField(null=True, blank=True)