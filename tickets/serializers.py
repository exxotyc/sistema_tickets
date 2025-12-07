# tickets/serializers.py
# tickets/serializers.py
import hashlib
import mimetypes
import uuid
import magic   # requiere libmagic instalado en el sistema

from django.contrib.auth import get_user_model, password_validation
from django.core.exceptions import ValidationError
from rest_framework import serializers

# Imports correctos desde el propio módulo
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
    FAQFeedback,
    UserExtension,   # ← agregado correctamente
)

UserModel = get_user_model()



# ==========================================================
#   USER SUMMARY (LISTADO / VISTAS GENERALES)
# ==========================================================
class UserSummarySerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField()

    area = serializers.PrimaryKeyRelatedField(
        source="profile.area",
        read_only=True
    )
    area_name = serializers.CharField(
        source="profile.area.name",
        read_only=True
    )

    # ➕ NUEVO: Avatar URL para navbar y mantenedor
    profile_picture_url = serializers.SerializerMethodField()

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
            "profile_picture_url",
        ]

    # Roles limpios
    def get_roles(self, obj):
        return rbac.user_managed_roles(obj)

    # Avatar URL
    def get_profile_picture_url(self, obj):
        try:
            ext = obj.userextension
            if ext.profile_picture:
                request = self.context.get("request")
                return request.build_absolute_uri(ext.profile_picture.url) if request else ext.profile_picture.url
        except UserExtension.DoesNotExist:
            pass
        return None


# ==========================================================
#   USER ADMIN (CREAR / EDITAR USUARIOS)
# ==========================================================
class UserAdminSerializer(UserSummarySerializer):
    password = serializers.CharField(write_only=True, required=False, allow_blank=True)
    roles = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True,
    )

    # Área editable
    area = serializers.PrimaryKeyRelatedField(
        source="profile.area",
        queryset=Area.objects.all(),
        required=False,
        allow_null=True
    )

    # ➕ NUEVO: permitir subir avatar
    profile_picture = serializers.ImageField(
        source="userextension.profile_picture",
        required=False,
        allow_null=True
    )

    class Meta(UserSummarySerializer.Meta):
        fields = UserSummarySerializer.Meta.fields + [
            "password",
            "area",
            "profile_picture",
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

        # Avatar
        extension_data = validated_data.pop("userextension", {})
        avatar = extension_data.get("profile_picture")

        if not password:
            password = UserModel.objects.make_random_password()

        # Crear usuario base
        user = UserModel(**validated_data)
        user.set_password(password)
        user.save()

        # Crear y asignar área
        if area:
            user.profile.area = area
            user.profile.save()

        # Crear extensión
        UserExtension.objects.update_or_create(
            user=user,
            defaults={"profile_picture": avatar}
        )

        # Aplicar roles
        rbac.apply_roles(user, roles)

        return user

    # ------------------------
    # UPDATE
    # ------------------------
    def update(self, instance, validated_data):
        roles = validated_data.pop("roles", None)
        password = validated_data.pop("password", "")

        profile_data = validated_data.pop("profile", {})
        new_area = profile_data.get("area")

        extension_data = validated_data.pop("userextension", {})
        new_avatar = extension_data.get("profile_picture")

        # Actualizar campos normales del usuario
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            instance.set_password(password)

        instance.save()

        # Actualizar área
        if new_area is not None:
            instance.profile.area = new_area
            instance.profile.save()

        # Actualizar o eliminar avatar
        ext, _ = UserExtension.objects.get_or_create(user=instance)
        if new_avatar is None:
            pass  # no cambio
        else:
            ext.profile_picture = new_avatar
            ext.save()

        # Actualizar roles
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
#   ATTACHMENT
# ==========================================================
# -----------------------------
# CONFIGURACIÓN DE SEGURIDAD
# -----------------------------
SAFE_EXTENSIONS = {
    ".pdf",
    ".png",
    ".jpg", ".jpeg",
    ".webp",
    ".txt", ".log",
    ".csv",
    ".xlsx",
    ".docx",
    ".pptx",
}

ALLOWED_MIME = {
    "application/pdf",
    "image/png", "image/jpeg", "image/webp",
    "text/plain",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


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

    # ---------------------------------------------
    # FUNCIÓN CENTRAL DE CHEQUEO DE SEGURIDAD
    # ---------------------------------------------
    def _run_security_checks(self, f):
        # 1) Extensión
        ext = "." + f.name.lower().rsplit(".", 1)[-1]
        if ext not in SAFE_EXTENSIONS:
            raise ValidationError(f"Extensión no permitida: {ext}")

        # 2) Tamaño máximo
        if getattr(f, "size", 0) > MAX_FILE_SIZE:
            raise ValidationError("El archivo supera el límite de 10 MB.")

        # 3) MIME real (no el que dice el navegador)
        #    Leemos un pequeño trozo y luego devolvemos el puntero
        pos = f.tell() if hasattr(f, "tell") else None
        head = f.read(2048)
        mime_real = magic.from_buffer(head, mime=True)
        if pos is not None and hasattr(f, "seek"):
            f.seek(pos)

        if mime_real not in ALLOWED_MIME:
            raise ValidationError(f"Tipo MIME no permitido: {mime_real}")

        # 4) Nombre sospechoso (doble extensión tipo foto.jpg.php)
        if f.name.count(".") > 1:
            raise ValidationError("El nombre del archivo es sospechoso (doble extensión).")

    # ---------------------------------------------
    # VALIDACIÓN DE CAMPO (DRF LA LLAMA SI TODO OK)
    # ---------------------------------------------
    def validate_file(self, f):
        self._run_security_checks(f)
        return f

    # ---------------------------------------------
    # UTILITARIOS PARA META
    # ---------------------------------------------
    def _guess_mime(self, uploaded_file):
        if hasattr(uploaded_file, "content_type") and uploaded_file.content_type:
            return uploaded_file.content_type
        guessed, _ = mimetypes.guess_type(uploaded_file.name)
        return guessed or ""

    def _compute_sha256(self, uploaded_file):
        hasher = hashlib.sha256()
        pos = uploaded_file.tell() if hasattr(uploaded_file, "tell") else None
        for chunk in uploaded_file.chunks():
            hasher.update(chunk)
        if pos is not None and hasattr(uploaded_file, "seek"):
            uploaded_file.seek(pos)
        return hasher.hexdigest()

    # ---------------------------------------------
    # CREATE — SIEMPRE VUELVE A CHEQUEAR
    # ---------------------------------------------
    def create(self, validated_data):
        uploaded_file = validated_data.get("file")

        if uploaded_file:
            # ⚠️ Chequeos de seguridad SIEMPRE aquí
            self._run_security_checks(uploaded_file)

            # Tamaño, MIME, hash
            validated_data["size_bytes"] = getattr(uploaded_file, "size", None)
            validated_data["mime"] = self._guess_mime(uploaded_file)
            validated_data["sha256"] = self._compute_sha256(uploaded_file)

            # Nombre seguro
            ext = uploaded_file.name.lower().rsplit(".", 1)[-1]
            safe_name = f"{uuid.uuid4().hex}.{ext}"
            uploaded_file.name = safe_name

        # Asignar usuario
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            validated_data["user"] = request.user

        return Attachment.objects.create(**validated_data)

# ==========================================================
#   COMMENTS
# ==========================================================
class CommentSerializer(serializers.ModelSerializer):
    user_username = serializers.CharField(source="user.username", read_only=True)

    # Aceptamos ambas variantes
    content = serializers.CharField(write_only=True, required=False)
    body = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = Comment
        fields = ["id", "ticket", "user", "user_username", "created_at", "content", "body"]
        read_only_fields = ["id", "user", "user_username", "created_at"]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["content"] = instance.body  # respuesta estándar
        data.pop("body", None)
        return data

    def create(self, validated_data):
        # Soporte para content o body
        body = validated_data.pop("content", "") or validated_data.pop("body", "")

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

    has_voted = serializers.SerializerMethodField()
    user_vote = serializers.SerializerMethodField()  # ← LO QUE FALTABA

    def get_has_voted(self, obj):
        user = self.context["request"].user
        if not user or not user.is_authenticated:
            return False
        return FAQFeedback.objects.filter(faq=obj, user=user).exists()

    def get_user_vote(self, obj):
        user = self.context["request"].user
        if not user or not user.is_authenticated:
            return None

        fb = FAQFeedback.objects.filter(faq=obj, user=user).first()
        if not fb:
            return None

        return "useful" if fb.is_useful else "unresolved"

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
            "has_voted",
            "user_vote",   # ← ESTO YA ES VÁLIDO
        ]
        read_only_fields = [
            "category_name",
            "created_at",
            "updated_at",
            "unresolved",
            "has_voted",
            "user_vote",
        ]





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
