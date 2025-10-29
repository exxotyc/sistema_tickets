import logging

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
    asset_id = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default="medium")
    state = models.CharField(max_length=20, choices=STATE_CHOICES, default="open")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    attachment = models.FileField(upload_to="attachments/%Y/%m/", null=True, blank=True)  # <- así
    frt_due_at = models.DateTimeField(null=True, blank=True)       # vencimiento 1ª respuesta
    resolve_due_at = models.DateTimeField(null=True, blank=True)   # vencimiento resolución
    sla_minutes = models.PositiveIntegerField(null=True, blank=True)
    due_at = models.DateTimeField(null=True, blank=True)
    breach_risk = models.BooleanField(default=False)

    STATE_TRANSITIONS = {
        "open": {"in_progress"},
        "in_progress": {"open", "resolved"},
        "resolved": {"in_progress", "closed", "open"},
        "closed": {"in_progress", "open"},
    }

    class InvalidStateTransition(Exception):
        def __init__(self, current_state, new_state):
            self.current_state = current_state
            self.new_state = new_state
            super().__init__(
                f"Transición inválida {current_state} → {new_state}."
            )

    def can_transition_to(self, new_state):
        if new_state == self.state:
            return True
        return new_state in self.STATE_TRANSITIONS.get(self.state, set())

    def change_state(self, new_state, *, by=None, force=False):
        """Modifica el estado validando la transición y agendando el log."""

        if new_state == self.state:
            return False

        if not force and not self.can_transition_to(new_state):
            raise self.InvalidStateTransition(self.state, new_state)

        previous_state = self.state
        self.state = new_state
        self._state_change_context = {
            "from": previous_state,
            "to": new_state,
            "user": by,
        }
        return True

    def save(self, *args, **kwargs):
        previous_state = None
        has_context = hasattr(self, "_state_change_context") and self._state_change_context
        if self.pk and not has_context:
            previous_state = (
                Ticket.objects.filter(pk=self.pk)
                .values_list("state", flat=True)
                .first()
            )

        super().save(*args, **kwargs)

        context = getattr(self, "_state_change_context", None)
        state_from = state_to = None
        if context:
            state_from = context.get("from")
            state_to = context.get("to")
        elif previous_state is not None and previous_state != self.state:
            state_from = previous_state
            state_to = self.state

        if state_from is not None and state_from != state_to:
            TicketLog.objects.create(
                ticket=self,
                user=context.get("user") if context else None,
                action="state_change",
                meta_json={"from": state_from, "to": state_to},
            )
            try:
                from .notifications import notify_ticket_state_change

                notify_ticket_state_change(
                    self,
                    state_from,
                    state_to,
                    context.get("user") if context else None,
                )
            except Exception:
                # Las notificaciones no deben impedir el guardado del ticket.
                logging.getLogger("tickets.notifications").exception(
                    "Fallo al enviar notificación de cambio de estado"
                )

        if hasattr(self, "_state_change_context"):
            self._state_change_context = None


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