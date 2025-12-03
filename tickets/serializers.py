# tickets/serializers.py
import hashlib
import mimetypes

from django.contrib.auth import get_user_model, password_validation
from rest_framework import serializers

from . import rbac
from .models import (
    Area,
    Ticket,
    Comment,
    Attachment,
    TicketLog,
    Category,
    FAQ,
    Priority,
)

UserModel = get_user_model()


# ==========================================================
#   USER SUMMARY (NECESARIO ANTES DE UserAdminSerializer)
# ==========================================================
# ==========================================================
#   USERS
# ==========================================================
class UserSummarySerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField()

    # Área solo lectura (para listar / ver)
    area = serializers.PrimaryKeyRelatedField(
        source="profile.area",
        read_only=True
    )
    area_name = serializers.CharField(
        source="profile.area.name",
        read_only=True
    )

    class Meta:
        model = UserModel
        fields = [
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "is_active",
            "is_staff",
            "roles",
            "area",
            "area_name",
        ]

    def get_roles(self, obj):
        return rbac.user_managed_roles(obj)


class UserAdminSerializer(UserSummarySerializer):
    password = serializers.CharField(write_only=True, required=False, allow_blank=True)
    roles = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True,
    )

    # Área editable (perfil)
    area = serializers.PrimaryKeyRelatedField(
        source="profile.area",
        queryset=Area.objects.all(),
        required=False,
        allow_null=True,
    )

    class Meta(UserSummarySerializer.Meta):
        fields = UserSummarySerializer.Meta.fields + [
            "password",
            "area",
        ]

    # ------------------------
    # VALIDACIONES
    # ------------------------
    def validate_password(self, value):
        if value:
            password_validation.validate_password(value, self.instance or None)
        return value

    def validate_roles(self, value):
        return rbac.clean_roles(value)

    # ------------------------
    # CREATE
    # ------------------------
    def create(self, validated_data):
        roles = validated_data.pop("roles", [])
        password = validated_data.pop("password", "")
        profile_data = validated_data.pop("profile", {})
        area = profile_data.get("area")

        if not password:
            password = UserModel.objects.make_random_password()

        user = UserModel(**validated_data)
        user.set_password(password)
        user.save()

        # Aseguramos profile + área
        profile = getattr(user, "profile", None)
        if profile is not None and area:
            profile.area = area
            profile.save()

        rbac.apply_roles(user, roles)
        return user

    # ------------------------
    # UPDATE
    # ------------------------
    def update(self, instance, validated_data):
        roles = validated_data.pop("roles", None)
        password = validated_data.pop("password", "")
        profile_data = validated_data.pop("profile", {})
        new_area = profile_data.get("area", None)

        # Campos normales
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            instance.set_password(password)

        instance.save()

        # Actualizar área en profile
        profile = getattr(instance, "profile", None)
        if profile is not None and new_area is not None:
            profile.area = new_area
            profile.save()

        if roles is not None:
            rbac.apply_roles(instance, roles)

        return instance



# ==========================================================
#   USER ADMIN (CON AREA)
# ==========================================================
class UserAdminSerializer(UserSummarySerializer):
    password = serializers.CharField(write_only=True, required=False, allow_blank=True)
    roles = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True
    )

    # ➕ NUEVO CAMPO: Área del usuario (profile.area)
    area = serializers.PrimaryKeyRelatedField(
        source="profile.area",
        queryset=Area.objects.all(),
        required=False,
        allow_null=True
    )

    class Meta(UserSummarySerializer.Meta):
        fields = UserSummarySerializer.Meta.fields + [
            "password",
            "area",
        ]

    # ------------------------
    # VALIDACIONES
    # ------------------------
    def validate_password(self, value):
        if value:
            password_validation.validate_password(value, self.instance or None)
        return value

    def validate_roles(self, value):
        return rbac.clean_roles(value)

    # ------------------------
    # CREATE
    # ------------------------
    def create(self, validated_data):
        roles = validated_data.pop("roles", [])
        password = validated_data.pop("password", "")

        # Extraemos el área desde profile.area
        profile_data = validated_data.pop("profile", {})
        area = profile_data.get("area")

        if not password:
            password = UserModel.objects.make_random_password()

        # Crear usuario
        user = UserModel(**validated_data)
        user.set_password(password)
        user.save()

        # Guardar área en profile
        if area:
            user.profile.area = area
            user.profile.save()

        # Aplicar roles
        rbac.apply_roles(user, roles)

        return user

    # ------------------------
    # UPDATE
    # ------------------------
    def update(self, instance, validated_data):
        roles = validated_data.pop("roles", None)
        password = validated_data.pop("password", "")

        # Área desde el profile
        profile_data = validated_data.pop("profile", {})
        new_area = profile_data.get("area")

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            instance.set_password(password)

        instance.save()

        # Actualizar área
        if new_area is not None:
            instance.profile.area = new_area
            instance.profile.save()

        # Aplicar roles
        if roles is not None:
            rbac.apply_roles(instance, roles)

        return instance


# ==========================================================
#   CATEGORY
# ==========================================================
class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ["id", "name", "created_at"]
        read_only_fields = ["created_at"]


# ==========================================================
#   PRIORITY
# ==========================================================
class PrioritySerializer(serializers.ModelSerializer):
    class Meta:
        model = Priority
        fields = ["id", "code", "name", "sla_minutes", "is_active", "created_at"]
        read_only_fields = ["created_at"]


# ==========================================================
#   ATTACHMENTS
# ==========================================================
class TicketAttachmentSerializer(serializers.ModelSerializer):
    user = UserSummarySerializer(read_only=True)
    filename = serializers.CharField(source="file.name", read_only=True)

    class Meta:
        model = Attachment
        fields = [
            "id",
            "ticket",
            "user",
            "file",
            "filename",
            "mime",
            "size_bytes",
            "sha256",
            "created_at",
        ]
        read_only_fields = [
            "user",
            "mime",
            "size_bytes",
            "sha256",
            "created_at",
            "filename",
        ]

    def _guess_mime(self, uploaded_file):
        if hasattr(uploaded_file, "content_type") and uploaded_file.content_type:
            return uploaded_file.content_type
        guessed, _ = mimetypes.guess_type(uploaded_file.name)
        return guessed or ""

    def _compute_sha256(self, uploaded_file):
        hasher = hashlib.sha256()
        position = getattr(uploaded_file, "tell", lambda: None)()
        for chunk in uploaded_file.chunks():
            hasher.update(chunk)
        if hasattr(uploaded_file, "seek") and position is not None:
            uploaded_file.seek(position)
        return hasher.hexdigest()

    def create(self, validated_data):
        uploaded_file = validated_data.get("file")
        if uploaded_file:
            validated_data["size_bytes"] = getattr(uploaded_file, "size", None)
            validated_data["mime"] = self._guess_mime(uploaded_file)
            validated_data["sha256"] = self._compute_sha256(uploaded_file)

        request = self.context.get("request")
        user = getattr(request, "user", None)

        if user and user.is_authenticated:
            validated_data.setdefault("user", user)

        return Attachment.objects.create(**validated_data)


# ==========================================================
#   COMMENTS
# ==========================================================
class CommentSerializer(serializers.ModelSerializer):
    user_username = serializers.CharField(source="user.username", read_only=True)
    content = serializers.CharField(write_only=True)

    class Meta:
        model = Comment
        fields = ["id", "ticket", "user", "user_username", "created_at", "content"]
        read_only_fields = ["id", "user", "user_username", "created_at"]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["content"] = instance.body
        return data

    def create(self, validated_data):
        body = validated_data.pop("content", "")
        comment = Comment(**validated_data)
        comment.body = body
        comment.save()
        return comment


# ==========================================================
#   FAQ
# ==========================================================
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
        read_only_fields = ["category_name", "created_at", "updated_at", "unresolved"]


# ==========================================================
#   TICKET SERIALIZER (CON ÁREAS Y STATE_DISPLAY)
# ==========================================================
class TicketSerializer(serializers.ModelSerializer):

    # PRIORIDAD
    priority = serializers.PrimaryKeyRelatedField(
        queryset=Priority.objects.all(), required=False, allow_null=True
    )
    priority_name = serializers.CharField(source="priority.name", read_only=True)

    # ÁREA DEL TICKET
    area = serializers.PrimaryKeyRelatedField(
        queryset=Area.objects.all(), required=False, allow_null=True
    )
    area_name = serializers.CharField(source="area.name", read_only=True)

    # ÁREA DEL SOLICITANTE
    requester_area_name = serializers.CharField(
        source="requester.profile.area.name",
        read_only=True
    )

    # ÁREA DEL TÉCNICO ASIGNADO
    assigned_to_area_name = serializers.CharField(
        source="assigned_to.profile.area.name",
        read_only=True
    )

    # ASIGNACIÓN
    assigned_to = serializers.PrimaryKeyRelatedField(
        queryset=UserModel.objects.all(), required=False, allow_null=True
    )
    assignment_reason = serializers.CharField(
        write_only=True, required=False, allow_blank=True, allow_null=True
    )

    # CATEGORÍA
    category = serializers.PrimaryKeyRelatedField(
        queryset=Category.objects.all(), required=False, allow_null=True
    )
    category_name = serializers.CharField(source="category.name", read_only=True)

    # USUARIOS
    requester_username = serializers.CharField(source="requester.username", read_only=True)
    assigned_to_username = serializers.CharField(source="assigned_to.username", read_only=True)

    # ESTADO LEGIBLE
    state_display = serializers.SerializerMethodField()

    class Meta:
        model = Ticket
        fields = [
            "id",
            "title",
            "description",
            "asset_id",

            # Estado
            "state",
            "state_display",

            # Prioridad
            "priority",
            "priority_name",

            # Área del ticket
            "area",
            "area_name",

            # Áreas de usuarios
            "requester_area_name",
            "assigned_to_area_name",

            # Usuarios
            "requester",
            "requester_username",
            "assigned_to",
            "assigned_to_username",

            "assignment_reason",

            # Categoría
            "category",
            "category_name",

            # Fechas
            "created_at",
            "updated_at",
            "frt_due_at",
            "resolve_due_at",
            "due_at",

            "breach_risk",
        ]

        read_only_fields = [
            "id",
            "requester",
            "requester_username",
            "assigned_to_username",
            "category_name",
            "priority_name",
            "area_name",
            "requester_area_name",
            "assigned_to_area_name",
            "created_at",
            "updated_at",
            "due_at",
            "breach_risk",
            "state_display",
        ]

    # ------------------------------------------------------
    #   STATE DISPLAY — Traducción del estado
    # ------------------------------------------------------
    def get_state_display(self, obj):
        MAP = {
            "open": "Abierto",
            "in_progress": "En progreso",
            "resolved": "Resuelto",
            "closed": "Cerrado",
        }
        return MAP.get(obj.state, obj.state)

    # ------------------------------------------------------
    #   UPDATE — REASIGNACIÓN & PROTECCIÓN
    # ------------------------------------------------------
    def update(self, instance, validated_data):
        request = self.context.get("request")
        user = getattr(request, "user", None)

        new_assignee = validated_data.get("assigned_to", serializers.empty)
        assignment_reason = validated_data.get("assignment_reason")

        # Log de reasignación
        if new_assignee is not serializers.empty and new_assignee != instance.assigned_to:
            if not user or not user.groups.filter(name__in=["admin", "tecnico"]).exists():
                raise serializers.ValidationError({
                    "assigned_to": "Solo técnicos o administradores pueden reasignar tickets."
                })

            TicketLog.objects.create(
                ticket=instance,
                action="reassigned",
                meta_json={
                    "from": instance.assigned_to.id if instance.assigned_to else None,
                    "to": new_assignee.id if new_assignee else None,
                    "by": user.id if user else None,
                    "reason": assignment_reason or "No especificado",
                },
            )

        # Bloquear campos a solicitantes
        if user and user.groups.filter(name="solicitante").exists():
            restricted = {"priority", "category", "assigned_to", "area"}
            for f in restricted:
                validated_data.pop(f, None)

        return super().update(instance, validated_data)



# ==========================================================
#   TICKET LOG
# ==========================================================
class TicketLogSerializer(serializers.ModelSerializer):
    user = UserSummarySerializer(read_only=True)
    action_display = serializers.CharField(source="get_action_display", read_only=True)

    class Meta:
        model = TicketLog
        fields = [
            "id",
            "ticket",
            "user",
            "action",
            "action_display",
            "meta_json",
            "is_critical",
            "created_at",
        ]
        read_only_fields = [
            "created_at",
            "user",
            "meta_json",
            "action_display",
            "is_critical",
        ]



# ==========================================================
#   AREA (NUEVO)
# ==========================================================
class AreaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Area
        fields = ["id", "name", "created_at"]
        read_only_fields = ["created_at"]
