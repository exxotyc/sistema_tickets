import logging
from datetime import timedelta
from django.db import models
from django.contrib.auth.models import User, Group
from django.utils.timezone import now
from django.db.models.signals import post_save
from django.dispatch import receiver

from .services.sla import calculate_sla_status


# ==========================
#   CATEGORY
# ==========================
class Category(models.Model):
    name = models.CharField(max_length=50, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


# ==========================
#   PRIORITY  (NUEVA)
# ==========================
class Priority(models.Model):
    code = models.SlugField(max_length=20, unique=True)   # low, medium, high, critical
    name = models.CharField(max_length=50, unique=True)
    sla_minutes = models.PositiveIntegerField(default=60)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["sla_minutes"]

    def __str__(self):
        return f"{self.name} ({self.code})"


# ==========================
#   TICKET
# ==========================
class Ticket(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()

    requester = models.ForeignKey(
        User, related_name="tickets", on_delete=models.CASCADE
    )
    assigned_to = models.ForeignKey(
        User, related_name="assigned_tickets",
        null=True, blank=True, on_delete=models.SET_NULL
    )
    category = models.ForeignKey(
        Category, null=True, blank=True, on_delete=models.SET_NULL
    )

    asset_id = models.CharField(max_length=120, null=True, blank=True, db_index=True)

    # ================================
    #     PRIORIDAD — FOREIGN KEY
    # ================================
    priority = models.ForeignKey(
        "Priority",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="tickets"
    )

    # (el resto de tus campos va debajo si existen)

    state = models.CharField(
        max_length=20,
        choices=[
            ("open", "Abierto"),
            ("in_progress", "En progreso"),
            ("resolved", "Resuelto"),
            ("closed", "Cerrado"),
        ],
        default="open"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # adjuntos
    attachment = models.FileField(
        upload_to="attachments/%Y/%m/", null=True, blank=True
    )

    # SLA
    frt_due_at = models.DateTimeField(null=True, blank=True)
    resolve_due_at = models.DateTimeField(null=True, blank=True)
    sla_minutes = models.PositiveIntegerField(null=True, blank=True)
    due_at = models.DateTimeField(null=True, blank=True)
    breach_risk = models.BooleanField(default=False)

    # ---- Control transición de estados ----
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
            super().__init__(f"Transición inválida {current_state} → {new_state}.")

    def can_transition_to(self, new_state):
        if new_state == self.state:
            return True
        return new_state in self.STATE_TRANSITIONS.get(self.state, set())

    def change_state(self, new_state, *, by=None, force=False):
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
        has_context = (
            hasattr(self, "_state_change_context")
            and self._state_change_context
        )

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
            from .models import TicketLog  # evita import circular

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
                logging.getLogger("tickets.notifications").exception(
                    "Fallo al enviar notificación de cambio de estado"
                )

        # SLA update
        try:
            self.update_sla_status()
        except Exception:
            logging.getLogger("tickets.sla").exception(
                f"Error al evaluar SLA para ticket {self.id}"
            )

        if hasattr(self, "_state_change_context"):
            self._state_change_context = None

    # --- SLA ---
    def update_sla_status(self):
        sla = calculate_sla_status(self)
        type(self).objects.filter(pk=self.pk).update(breach_risk=sla["breach_risk"])
        self.breach_risk = sla["breach_risk"]
        return sla

    def get_sla_label(self):
        data = calculate_sla_status(self)
        if data["breached"]:
            return ("Vencido", "danger", "🔴")
        elif data["nearing_breach"]:
            return ("En riesgo", "warning", "🟡")
        return ("En tiempo", "success", "🟢")

    def __str__(self):
        return f"#{self.id} {self.title}"
    
    area = models.ForeignKey(
    "Area",
    null=True,
    blank=True,
    on_delete=models.SET_NULL,
    related_name="tickets"
)



# ==========================
#   TICKET LOG
# ==========================
class TicketLog(models.Model):
    ticket = models.ForeignKey(
        Ticket, related_name="logs",
        null=True, blank=True, on_delete=models.CASCADE
    )
    user = models.ForeignKey(
        User, null=True, blank=True,
        on_delete=models.SET_NULL
    )
    action = models.CharField(max_length=200)
    meta_json = models.JSONField(default=dict, blank=True)
    is_critical = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    ACTION_LABELS = {
        "state_change": "Cambio de estado",
        "reassigned": "Reasignado",
        "auth.login_failed": "Inicio de sesión fallido",
        "permissions.updated": "Actualización de permisos",
        "faq.unresolved": "FAQ no resolvió",
    }

    def get_action_display(self):
        return self.ACTION_LABELS.get(self.action, self.action)


# ==========================
#   FAQ
# ==========================
class FAQ(models.Model):
    category = models.ForeignKey(
        Category, related_name="faqs", on_delete=models.CASCADE
    )
    question = models.CharField(max_length=255)
    answer = models.TextField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("category", "question")]
        ordering = ["question"]

    def __str__(self):
        return self.question


class FAQFeedback(models.Model):
    faq = models.ForeignKey(FAQ, related_name="feedback", on_delete=models.CASCADE)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    comment = models.TextField(blank=True)
    is_useful = models.BooleanField(default=False)
    resolved = models.BooleanField(default=False)  # IMPORTANTE
    created_at = models.DateTimeField(auto_now_add=True)


# ==========================
#   COMMENT
# ==========================
class Comment(models.Model):
    ticket = models.ForeignKey(
        Ticket, related_name="comments", on_delete=models.CASCADE
    )
    user = models.ForeignKey(User, on_delete=models.PROTECT)
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Comment {self.id} on Ticket {self.ticket_id}"


# ==========================
#   ATTACHMENT
# ==========================
class Attachment(models.Model):
    ticket = models.ForeignKey(
        Ticket, related_name="attachments", on_delete=models.CASCADE
    )
    user = models.ForeignKey(User, on_delete=models.PROTECT)
    file = models.FileField(upload_to="attachments/%Y/%m/")
    mime = models.CharField(max_length=100, blank=True)
    size_bytes = models.BigIntegerField(null=True, blank=True)
    sha256 = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Attachment {self.id} for Ticket {self.ticket_id}"


# ==========================
#   SECTION
# ==========================
class Section(models.Model):
    code = models.SlugField(unique=True)
    title = models.CharField(max_length=80)
    url_name = models.CharField(max_length=80)
    groups = models.ManyToManyField(Group, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["title"]

    def __str__(self):
        return self.title


# ==========================
#   AREA (NUEVA)
# ==========================
class Area(models.Model):
    name = models.CharField(max_length=80, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name




# ==========================
#   UserProfile (NUEVA)
# ==========================
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    area = models.ForeignKey(
        Area,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="users"
    )

    def __str__(self):
        return f"Perfil de {self.user.username}"




@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

