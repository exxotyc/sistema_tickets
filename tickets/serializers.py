# tickets/serializers.py
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Ticket, Comment, Attachment, TicketLog, Category

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
class AttachmentSerializer(serializers.ModelSerializer):
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


# ---------- Tickets ----------
# Matriz de transiciones de estado permitidas
ALLOWED_TRANSITIONS = {
    "open": {"in_progress"},
    "in_progress": {"open", "resolved"},
    "resolved": {"in_progress", "closed"},
    "closed": set(),
}

class TicketSerializer(serializers.ModelSerializer):
    # Campos relacionadas escribibles (PKs)
    assigned_to = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), 
        required=False, 
        allow_null=True
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
            "priority",
            "state",
            "requester",              # RO - se establece en la vista
            "requester_username",     # RO
            "assigned_to",            # RW (admin/técnico puede cambiar)
            "assigned_to_username",   # RO
            "category",               # RW
            "category_name",          # RO
            "created_at",
            "updated_at",
             "frt_due_at", 
             "resolve_due_at",
        ]
        read_only_fields = [
            "id",
            "requester",
            "requester_username",
            "assigned_to_username",
            "category_name",
            "created_at",
            "updated_at",
        ]

    def validate(self, attrs):
        """
        Valida las transiciones de estado según los permisos del usuario
        """
        instance = getattr(self, "instance", None)
        new_state = attrs.get("state")
        
        # Si no hay instancia, nuevo estado, o el estado no cambia, no validar
        if not instance or not new_state or new_state == instance.state:
            return attrs

        # Obtener usuario del contexto
        request = self.context.get("request")
        user = getattr(request, "user", None) if request else None
        
        # Usuarios admin-like pueden saltarse las restricciones
        is_admin_like = self._is_admin_like_user(user)
        if is_admin_like:
            return attrs

        # Validar transición para usuarios normales
        self._validate_state_transition(instance.state, new_state)
        return attrs

    def _is_admin_like_user(self, user):
        """Verifica si el usuario tiene permisos de administrador/técnico"""
        if not user or not user.is_authenticated:
            return False
        
        return user.is_staff or user.groups.filter(
            name__in=["admin", "tecnico"]
        ).exists()

    def _validate_state_transition(self, current_state, new_state):
        """Valida si la transición de estado está permitida"""
        allowed_next_states = ALLOWED_TRANSITIONS.get(current_state, set())
        
        if new_state not in allowed_next_states:
            raise serializers.ValidationError({
                "state": f"Transición inválida {current_state} → {new_state}. "
                        f"Transiciones permitidas: {', '.join(allowed_next_states) or 'ninguna'}"
            })

    def create(self, validated_data):
        """Crea un nuevo ticket (requester se establece en perform_create de la vista)"""
        return Ticket.objects.create(**validated_data)

    def update(self, instance, validated_data):
        """Actualiza el ticket"""
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
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
            "meta_json", "created_at"
        ]
        read_only_fields = [
            "created_at", "user", "meta_json", "action_display"
        ]