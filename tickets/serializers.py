# tickets/serializers.py
import hashlib
import mimetypes

from rest_framework import serializers
from django.contrib.auth.models import User

from .models import (
    Ticket,
    Comment,
    Attachment,
    TicketLog,
    Category,
    FAQ,
)

# ---------- Users ----------
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name"]


# ---------- Categories ----------
class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ["id", "name", "created_at"]
        read_only_fields = ["created_at"]


# ---------- Attachments ----------
class TicketAttachmentSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    filename = serializers.CharField(source="file.name", read_only=True)

    class Meta:
        model = Attachment
        fields = [
            "id", "ticket", "user", "file", "filename", 
            "mime", "size_bytes", "sha256", "created_at"
        ]
        read_only_fields = [
            "user", "mime", "size_bytes", "sha256", "created_at", "filename"
        ]

    def _guess_mime(self, uploaded_file):
        if hasattr(uploaded_file, "content_type") and uploaded_file.content_type:
            return uploaded_file.content_type
        guessed, _ = mimetypes.guess_type(uploaded_file.name)
        return guessed or ""

    def _compute_sha256(self, uploaded_file):
        hasher = hashlib.sha256()
        position = None
        if hasattr(uploaded_file, "tell") and hasattr(uploaded_file, "seek"):
            try:
                position = uploaded_file.tell()
            except (OSError, AttributeError):
                position = None
        for chunk in uploaded_file.chunks():
            hasher.update(chunk)
        if hasattr(uploaded_file, "seek"):
            uploaded_file.seek(position or 0)
        return hasher.hexdigest()

    def create(self, validated_data):
        uploaded_file = validated_data.get("file")
        if uploaded_file is not None:
            validated_data["size_bytes"] = getattr(uploaded_file, "size", None)
            validated_data["mime"] = self._guess_mime(uploaded_file)
            validated_data["sha256"] = self._compute_sha256(uploaded_file)
        request = self.context.get("request")
        user = getattr(request, "user", None) if request else None
        if user and user.is_authenticated:
            validated_data.setdefault("user", user)
        attachment = Attachment.objects.create(**validated_data)
        return attachment


# ---------- Comments ----------

class CommentSerializer(serializers.ModelSerializer):
    user_username = serializers.CharField(source="user.username", read_only=True)
    # El frontend envía "content". Lo aceptamos como write_only.
    content = serializers.CharField(write_only=True)

    class Meta:
        model = Comment
        fields = ["id", "ticket", "user", "user_username", "created_at", "content"]
        read_only_fields = ["id", "user", "user_username", "created_at"]

    def _model_content_field_name(self):
        # Detecta el nombre real del campo de texto en el modelo
        for name in ("content", "text", "body", "message", "comment"):
            if hasattr(self.instance or self.Meta.model, name):
                # hasattr(model) funciona porque Django pone descriptores en la clase
                return name
        # Si no encuentra, por lo menos intenta "content"
        return "content"

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # Inyecta "content" para lectura desde el campo real
        for name in ("content", "text", "body", "message", "comment"):
            if hasattr(instance, name):
                data["content"] = getattr(instance, name)
                break
        return data

    def create(self, validated_data):
        # Sacamos el "content" que viene del frontend y lo colocamos en el campo real del modelo
        raw = validated_data.pop("content")
        # Construye el objeto con el resto (ticket, user)
        obj = Comment(**validated_data)
        target = None
        for name in ("content", "text", "body", "message", "comment"):
            if hasattr(obj, name):
                target = name
                break
        if target is None:
            # Como última opción, crea atributo "content"
            target = "content"
        setattr(obj, target, raw)
        obj.save()
        return obj


class TicketSerializer(serializers.ModelSerializer):
    # Campos relacionadas escribibles (PKs)
    assigned_to = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        required=False,
        allow_null=True
    )
    assignment_reason = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True,
        allow_null=True,
    )
    category = serializers.PrimaryKeyRelatedField(
        queryset=Category.objects.all()
    )

    # Campos de solo lectura para información relacionada
    requester_username = serializers.CharField(
        source="requester.username", 
        read_only=True
    )
    assigned_to_username = serializers.CharField(
        source="assigned_to.username", 
        read_only=True
    )
    category_name = serializers.CharField(
        source="category.name", 
        read_only=True
    )

    class Meta:
        model = Ticket
        fields = [
            "id",
            "title",
            "description",
            "asset_id",
            "priority",
            "state",
            "requester",              # RO - se establece en la vista
            "requester_username",     # RO
            "assigned_to",            # RW (admin/técnico puede cambiar)
            "assignment_reason",
            "assigned_to_username",   # RO
            "category",               # RW
            "category_name",          # RO
            "created_at",
            "updated_at",
            "frt_due_at",
            "resolve_due_at",
            "sla_minutes",
            "due_at",
            "breach_risk",
        ]
        read_only_fields = [
            "id",
            "requester",
            "requester_username",
            "assigned_to_username",
            "category_name",
            "created_at",
            "updated_at",
            "sla_minutes",
            "due_at",
            "breach_risk",
        ]

    def validate(self, attrs):
        """Valida las transiciones de estado según los permisos del usuario"""
        instance = getattr(self, "instance", None)
        new_state = attrs.get("state")

        if not instance or new_state is None or new_state == instance.state:
            return attrs

        request = self.context.get("request")
        user = getattr(request, "user", None) if request else None

        if self._is_admin_like_user(user):
            return attrs

        if not instance.can_transition_to(new_state):
            allowed = instance.STATE_TRANSITIONS.get(instance.state, set())
            allowed_display = ", ".join(sorted(allowed)) or "ninguna"
            raise serializers.ValidationError({
                "state": (
                    f"Transición inválida {instance.state} → {new_state}. "
                    f"Transiciones permitidas: {allowed_display}"
                )
            })

        return attrs

    def _is_admin_like_user(self, user):
        """Verifica si el usuario tiene permisos de administrador/técnico"""
        if not user or not user.is_authenticated:
            return False
        
        return user.is_staff or user.groups.filter(
            name__in=["admin", "tecnico"]
        ).exists()

    def create(self, validated_data):
        """Crea un nuevo ticket (requester se establece en perform_create de la vista)"""
        return Ticket.objects.create(**validated_data)

    def update(self, instance, validated_data):
        """Actualiza el ticket"""
        request = self.context.get("request")
        user = getattr(request, "user", None) if request else None

        new_state = validated_data.pop("state", None)
        if new_state is not None:
            force = self._is_admin_like_user(user)
            try:
                instance.change_state(new_state, by=user, force=force)
            except Ticket.InvalidStateTransition as exc:
                allowed = instance.STATE_TRANSITIONS.get(exc.current_state, set())
                allowed_display = ", ".join(sorted(allowed)) or "ninguna"
                raise serializers.ValidationError({
                    "state": (
                        f"Transición inválida {exc.current_state} → {exc.new_state}. "
                        f"Transiciones permitidas: {allowed_display}"
                    )
                })

        assignment_reason = validated_data.pop("assignment_reason", None)
        new_assignee = validated_data.pop("assigned_to", serializers.empty)
        previous_assignee = instance.assigned_to
        assignment_changed = False

        if new_assignee is not serializers.empty:
            instance.assigned_to = new_assignee
            assignment_changed = new_assignee != previous_assignee

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if assignment_changed:
            meta = {
                "from": previous_assignee.id if previous_assignee else None,
                "to": instance.assigned_to.id if instance.assigned_to else None,
                "username": instance.assigned_to.username if instance.assigned_to else None,
            }
            if assignment_reason is not None:
                meta["reason"] = assignment_reason
            TicketLog.objects.create(
                ticket=instance,
                user=user if user and user.is_authenticated else None,
                action="reassigned",
                meta_json=meta,
            )

        return instance


# ---------- Logs ----------
class TicketLogSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    # Campo legible para la acción
    action_display = serializers.CharField(
        source="get_action_display", 
        read_only=True
    )

    class Meta:
        model = TicketLog
        fields = [
            "id", "ticket", "user", "action", "action_display",
            "meta_json", "is_critical", "created_at"
        ]
        read_only_fields = [
            "created_at", "user", "meta_json", "action_display", "is_critical"
        ]


class FAQSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source="category.name", read_only=True)
    unresolved = serializers.IntegerField(source="feedback.count", read_only=True)

    class Meta:
        model = FAQ
        fields = [
            "id",
            "category",
            "category_name",
            "question",
            "answer",
            "is_active",
            "created_at",
            "updated_at",
            "unresolved",
        ]
        read_only_fields = ["created_at", "updated_at", "unresolved", "category_name"]