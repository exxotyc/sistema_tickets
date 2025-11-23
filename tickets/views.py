# tickets/views.py
from datetime import timedelta
from time import perf_counter
import re
import json
import io, csv
from django.contrib.auth import get_user_model
from collections import Counter, defaultdict
import sys
import django
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Q, Count
from django.utils.timezone import now
from django.shortcuts import render, redirect, get_object_or_404
from django.http import Http404, HttpResponseForbidden, JsonResponse, HttpResponse
from django.urls import reverse
from django.template.response import TemplateResponse
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.csrf import csrf_exempt
from django.middleware.csrf import get_token
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime
from django.db.models import Min
from datetime import datetime, time
from django.utils.timezone import make_aware, get_current_timezone
from urllib.parse import urlencode
from django.utils import timezone
import io, csv, json
from django.contrib.auth.models import User
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, permissions, filters, status, mixins
from rest_framework import serializers as drf_serializers
from rest_framework.decorators import (
    action,
    api_view,
    permission_classes,
    authentication_classes,
)
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.response import Response
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated

try:
    import openpyxl
except Exception:
    openpyxl = None

try:
    from reportlab.pdfgen import canvas
except Exception:
    canvas = None

from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken

from . import rbac
from .models import (
    Ticket,
    Category,
    TicketLog,
    Comment,
    Attachment,
    Section,
    FAQ,
    FAQFeedback,
    Priority,
)
from .permissions import IsTicketActorOrAdmin
from .serializers import (
    TicketSerializer,
    CategorySerializer,
    TicketLogSerializer,
    CommentSerializer,
    TicketAttachmentSerializer,
    FAQSerializer,
    UserAdminSerializer,
    UserSummarySerializer,
    PrioritySerializer,
)
from .reports import build_report_rows, filters_footer
from .services.assets import build_asset_history
from .services.metrics import TicketMetricsService


# ---------- Parámetros comunes de filtros ----------
FILTER_QUERY_PARAMS = [
    openapi.Parameter("from", openapi.IN_QUERY, description="Fecha inicial (YYYY-MM-DD)", type=openapi.TYPE_STRING),
    openapi.Parameter("to", openapi.IN_QUERY, description="Fecha final (YYYY-MM-DD)", type=openapi.TYPE_STRING),
    openapi.Parameter("category", openapi.IN_QUERY, description="ID de categoría", type=openapi.TYPE_INTEGER),
    openapi.Parameter("assignee", openapi.IN_QUERY, description="ID de técnico asignado", type=openapi.TYPE_INTEGER),
    openapi.Parameter("priority", openapi.IN_QUERY, description="Prioridad (low, medium, high)", type=openapi.TYPE_STRING),
]

REPORT_STATE_CHOICES = [
    ("", "Todos"),
    ("open", "Abiertos"),
    ("in_progress", "En progreso"),
    ("resolved", "Resueltos"),
    ("closed", "Cerrados"),
]


#==================== Helpers ====================

def index(request):
    return render(request, "tickets/index.html")


def in_group(user, name: str) -> bool:
    return user.is_authenticated and user.groups.filter(name=name).exists()

def _is_adminlike(u) -> bool:
    return (
        u.is_authenticated and (
            u.is_superuser or
            u.is_staff or
            u.groups.filter(name__in=["admin", "tecnico"]).exists()
        )
    )

def _navbar_sections(user):
    if not user.is_authenticated:
        return []
    qs = Section.objects.filter(is_active=True)
    if not _is_adminlike(user):
        qs = qs.filter(groups__in=user.groups.all())
    qs = qs.distinct().order_by("title")
    return [{"code": s.code, "name": s.title, "title": s.title} for s in qs]

def _render(request, template_name, ctx=None):
    ctx = ctx or {}
    ctx.setdefault("maint_sections", _navbar_sections(request.user))
    return render(request, template_name, ctx)

# ==================== JWT ====================

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["username"] = user.username
        token["is_staff"] = user.is_staff
        token["roles"] = list(user.groups.values_list("name", flat=True))
        return token

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

# ==================== API (DRF) ====================

class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all().order_by("name")
    serializer_class = CategorySerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

# tickets/views.py

class FAQViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    queryset = FAQ.objects.filter(is_active=True).select_related("category").order_by("question")
    serializer_class = FAQSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ["category"]
    search_fields = ["question", "answer"]

    # ========================================
    #   Registrar voto "Útil"
    # ========================================
    @action(detail=True, methods=["post"], permission_classes=[permissions.AllowAny])
    def useful(self, request, pk=None):
        faq = self.get_object()
        user = request.user if request.user.is_authenticated else None

        fb = FAQFeedback.objects.create(
            faq=faq,
            user=user,
            is_useful=True,
            resolved=True,
            comment="",
        )

        return Response({"status": "ok", "feedback_id": fb.id})

    # ========================================
    #   Registrar voto "No útil"
    # ========================================
    @action(detail=True, methods=["post"], permission_classes=[permissions.AllowAny])
    def unresolved(self, request, pk=None):
        faq = self.get_object()
        comment = (request.data.get("comment") or "").strip()
        user = request.user if request.user.is_authenticated else None

        fb = FAQFeedback.objects.create(
            faq=faq,
            user=user,
            is_useful=False,
            resolved=False,
            comment=comment,
        )

        return Response({"status": "ok", "feedback_id": fb.id})


# ================================
#   TICKET VIEWSET CORREGIDO
# ================================
class TicketViewSet(viewsets.ModelViewSet):
    """
    ViewSet para gestionar Tickets:
    - admin: ve y edita todos
    - técnico: ve sus propios asignados
    - usuario: solo sus propios tickets
    """
    serializer_class = TicketSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    filter_backends = [filters.SearchFilter, filters.OrderingFilter, DjangoFilterBackend]
    search_fields = ["title", "description"]
    ordering_fields = ["created_at", "updated_at", "priority"]
    filterset_fields = ["state", "priority", "category", "asset_id"]

    # ------------------------------------------------------
    # QUERYSET según rol
    # ------------------------------------------------------
    def get_queryset(self):
        user = self.request.user

        qs = Ticket.objects.select_related(
        "requester",
        "assigned_to",
        "category",
        "priority"
        ).order_by("-created_at")

    # Admin ve todo
        if user.groups.filter(name="admin").exists():
            return qs

    # Técnico ve todo (pero las acciones se controlan en el frontend y en perform_update)
        if user.groups.filter(name="tecnico").exists():
            return qs

    # Usuario normal: solo sus tickets
        return qs.filter(requester=user)

    # ------------------------------------------------------
    # CREAR TICKET
    # ------------------------------------------------------
    def perform_create(self, serializer):
        user = self.request.user
        if not user.is_authenticated:
            raise PermissionDenied("Debes iniciar sesión para crear tickets.")
        return serializer.save(requester=user)

    # ------------------------------------------------------
    # ACTUALIZAR TICKET (corregido prioridad FK)
    # ------------------------------------------------------
    def perform_update(self, serializer):
        instance = self.get_object()
        user = self.request.user

        is_admin = user.groups.filter(name="admin").exists()
        is_tech = user.groups.filter(name="tecnico").exists()

        # Solicitantes NO editan
        if not (is_admin or is_tech):
            raise PermissionDenied("No tienes permiso para editar este ticket.")

        # Técnicos solo editan si están asignados
        if is_tech and instance.assigned_to != user:
            raise PermissionDenied("No puedes modificar tickets que no te fueron asignados.")

        validated = serializer.validated_data

        # PRIORIDAD — siempre FK correcta
        if "priority" in validated:
            instance.priority = validated["priority"]

        # CATEGORY — también FK
        if "category" in validated:
            instance.category = validated["category"]

        serializer.save()

    # ------------------------------------------------------
    # ASIGNAR TICKET
    # ------------------------------------------------------
    @action(detail=True, methods=["post"], permission_classes=[permissions.IsAuthenticated])
    def assign(self, request, pk=None):
        """
        Lógica corregida:
        - ADMIN → puede asignar a cualquiera.
        - TÉCNICO →
            ✔ puede tomarse un ticket sin asignar
            ✘ NO puede reasignar un ticket asignado a él
            ✘ NO puede reasignar un ticket asignado a otros
        """
        user = request.user
        ticket = self.get_object()

        is_admin = user.groups.filter(name="admin").exists()
        is_tech = user.groups.filter(name="tecnico").exists()

        # --- validar parámetro ---
        user_id = request.data.get("user_id")
        if not user_id:
            return Response({"error": "user_id requerido"}, status=400)

        try:
            target = get_user_model().objects.get(pk=user_id)
        except:
            return Response({"error": "Usuario no encontrado"}, status=404)

        # =====================================================
        # ADMIN: acceso total
        # =====================================================
        if is_admin:
            previous = ticket.assigned_to
            ticket.assigned_to = target
            ticket.save(update_fields=["assigned_to"])

            TicketLog.objects.create(
                ticket=ticket,
                user=user,
                action="reassigned",
                meta_json={
                    "from": previous.id if previous else None,
                    "to": target.id,
                    "username": target.username,
                }
            )

            return Response({
                "status": "assigned",
                "assigned_to": target.username,
                "by": user.username
            })

        # =====================================================
        # TÉCNICO: LÓGICA ESTRICTA DE PERMISOS
        # =====================================================
        if is_tech:

            # 1) Ticket SIN asignar → puede tomarlo, pero solo a sí mismo
            if ticket.assigned_to is None:
                if target != user:
                    return Response(
                        {"error": "Solo puedes asignarte a ti mismo"},
                        status=403
                    )

                ticket.assigned_to = user
                ticket.save(update_fields=["assigned_to"])

                TicketLog.objects.create(
                    ticket=ticket,
                    user=user,
                    action="assigned",
                    meta_json={"to": user.id, "username": user.username}
                )

                return Response({
                    "status": "assigned",
                    "assigned_to": user.username
                })

            # 2) Ticket asignado a él → no puede reasignarlo
            if ticket.assigned_to == user:
                return Response(
                    {"error": "No puedes reasignar un ticket que ya está asignado a ti"},
                    status=403
                )

            # 3) Ticket asignado a otro técnico → prohibido
            return Response(
                {"error": "No puedes reasignar tickets asignados a otros técnicos"},
                status=403
            )

        # =====================================================
        # Rol no autorizado
        # =====================================================
        return Response({"detail": "No autorizado"}, status=403)


class CommentViewSet(mixins.CreateModelMixin, mixins.ListModelMixin, viewsets.GenericViewSet):
    queryset = Comment.objects.select_related("ticket", "user").order_by("created_at")
    serializer_class = CommentSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ["ticket"]
    ordering_fields = ["created_at"]

    def get_queryset(self):
        qs = super().get_queryset()
        u = self.request.user
        if _is_admin_or_tech(u):
            return qs
        return qs.filter(Q(ticket__requester=u) | Q(ticket__assigned_to=u)).distinct()

    def perform_create(self, serializer):
        t = get_object_or_404(Ticket, pk=self.request.data.get("ticket"))
        u = self.request.user
        if not (_is_admin_or_tech(u) or t.requester_id == u.id or t.assigned_to_id == u.id):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("No autorizado para comentar este ticket")
        serializer.save(user=u, ticket=t)


class AttachmentViewSet(mixins.CreateModelMixin, mixins.ListModelMixin, viewsets.GenericViewSet):
    queryset = Attachment.objects.select_related("ticket", "user").all().order_by("-created_at")
    serializer_class = TicketAttachmentSerializer
    permission_classes = [IsTicketActorOrAdmin]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ["ticket"]
    ordering_fields = ["created_at"]

    def get_queryset(self):
        qs = super().get_queryset()
        u = self.request.user
        return qs if _is_admin_or_tech(u) else qs.filter(Q(ticket__requester=u) | Q(ticket__assigned_to=u)).distinct()


class TicketLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = TicketLog.objects.select_related("user", "ticket").all().order_by("-created_at")
    serializer_class = TicketLogSerializer
    permission_classes = [permissions.IsAuthenticated]


class UserViewSet(viewsets.ModelViewSet):
    """
    ViewSet para gestión y consulta de usuarios.
    - Admins pueden listar, crear y editar usuarios.
    - Técnicos pueden ver otros técnicos y administradores.
    - Los solicitantes solo pueden verse a sí mismos.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserAdminSerializer  # Por defecto
    queryset = get_user_model().objects.all().order_by("username").prefetch_related("groups")

    def get_serializer_class(self):
        # 🔹 Para listados o lectura, usamos el serializer liviano
        if self.action in ["list", "retrieve"]:
            return UserSummarySerializer
        # 🔹 Para crear/editar, el administrativo
        return UserAdminSerializer

    def get_queryset(self):
        user = self.request.user
        username_field = getattr(get_user_model(), "USERNAME_FIELD", "username")
        qs = get_user_model().objects.all().order_by(username_field).prefetch_related("groups")

        # Admin → ve todos
        if user.groups.filter(name="admin").exists() or user.is_staff or user.is_superuser:
            pass
        # Técnico → ve técnicos y admins
        elif user.groups.filter(name="tecnico").exists():
            qs = qs.filter(groups__name__in=["tecnico", "admin"]).distinct()
        # usuario → solo él mismo
        else:
            qs = qs.filter(pk=user.pk)

        # 🔍 Filtro de búsqueda opcional
        search = (self.request.query_params.get("search") or self.request.query_params.get("q") or "").strip()
        if search:
            qs = qs.filter(
                Q(username__icontains=search)
                | Q(email__icontains=search)
                | Q(first_name__icontains=search)
                | Q(last_name__icontains=search)
            )
        return qs

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        ctx["actor"] = self.request.user
        return ctx

    def perform_create(self, serializer):
        actor = self.request.user
        allowed = rbac.actor_allowed_roles(actor)
        if not allowed and not (actor.is_staff or actor.is_superuser):
            raise PermissionDenied("No autorizado para crear usuarios.")

        roles = list(serializer.validated_data.get("roles") or [])
        disallowed = set(roles) - allowed
        if disallowed:
            raise PermissionDenied("No puedes asignar los roles: " + ", ".join(sorted(disallowed)))

        if serializer.validated_data.get("is_staff") and not (actor.is_staff or actor.is_superuser):
            raise PermissionDenied("No puedes asignar el estado de staff.")

        serializer.save()

    def perform_update(self, serializer):
        actor = self.request.user
        target = serializer.instance

        if "is_staff" in serializer.validated_data:
            desired_staff = bool(serializer.validated_data["is_staff"])
            if desired_staff != target.is_staff and not (actor.is_staff or actor.is_superuser):
                raise PermissionDenied("No puedes modificar el estado de staff.")

        roles = serializer.validated_data.get("roles", None)
        if roles is not None:
            try:
                rbac.assert_actor_can_manage(actor, target, roles)
            except rbac.LastAdminRemovalError as exc:
                raise PermissionDenied(str(exc))
            except rbac.RolePermissionError as exc:
                raise PermissionDenied(str(exc))

        serializer.save()

    def perform_destroy(self, instance):
        actor = self.request.user
        if actor.pk == instance.pk:
            raise PermissionDenied("No puedes eliminar tu propio usuario.")

        allowed = rbac.actor_allowed_roles(actor)
        if not (actor.is_staff or actor.is_superuser):
            current_roles = set(rbac.user_managed_roles(instance))
            if current_roles - allowed:
                raise PermissionDenied("No puedes eliminar usuarios con roles que no administras.")

        if "admin" in rbac.user_managed_roles(instance) and not rbac.has_other_admins(instance):
            raise PermissionDenied("Debe quedar al menos un admin en el sistema.")

        super().perform_destroy(instance)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def stats(request):
    """
    Devuelve información general del sistema + roles del usuario autenticado.
    Utilizada por el frontend para mostrar permisos dinámicamente.
    """
    user = request.user
    groups = list(user.groups.values_list("name", flat=True))

    data = {
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "roles": groups,
        },
        "ok": True,
    }
    return Response(data)

@api_view(["POST"])
@permission_classes([permissions.IsAuthenticated])
@authentication_classes([SessionAuthentication])
def session_token(request):
    refresh = RefreshToken.for_user(request.user)
    return Response({"access": str(refresh.access_token), "refresh": str(refresh)})

# ==================== Vistas HTML ====================

@login_required
def ticket_new(request):

    # ====================================================
    # 1) Capturar texto proveniente de FAQ (?fromfaq=...)
    # ====================================================
    from_faq = request.GET.get("fromfaq", "").strip()

    # ====================================================
    # 0) PERMISOS: permitir crear tickets a:
    #    - admin
    #    - tecnico
    #    - usuario (cualquiera autenticado)
    # ====================================================
    roles = set(request.user.groups.values_list("name", flat=True))
    if not roles & {"admin", "tecnico", "usuario"}:
        messages.error(request, "No tienes permiso para crear tickets.")
        return redirect("ticket_list")

    # ====================================================
    # 2) Procesar POST (crear ticket)
    # ====================================================
    if request.method == "POST":
        title = request.POST.get("title", "").strip()
        description = request.POST.get("description", "").strip()
        category_id = request.POST.get("category")
        priority = request.POST.get("priority", "medium")

        if not title or not description:
            messages.error(request, "Título y descripción son obligatorios.")
            categories = Category.objects.order_by("name")
            return render(
                request,
                "tickets/ticket_new.html",
                {
                    "categories": categories,
                    "is_admin_or_tecnico": request.user.groups.filter(
                        name__in=["admin", "tecnico"]
                    ).exists(),
                    "from_faq": from_faq,
                },
            )

        # 🔒 Forzar prioridad fija para solicitantes simples
        # Admin y técnico pueden elegir prioridad
        if "admin" not in roles and "tecnico" not in roles:
            priority = "medium"

        Ticket.objects.create(
            title=title,
            description=description,
            category_id=category_id or None,
            priority=priority,
            requester=request.user,
            state="open",
        )

        messages.success(request, "Ticket creado correctamente.")
        return redirect("ticket_list")

    # ====================================================
    # 3) GET — Renderizar formulario
    # ====================================================
    categories = Category.objects.order_by("name")

    return render(
        request,
        "tickets/ticket_new.html",
        {
            "categories": categories,
            "is_admin_or_tecnico": request.user.groups.filter(
                name__in=["admin", "tecnico"]
            ).exists(),
            "from_faq": from_faq,
        },
    )



@login_required
def dashboard(request):
    user = request.user

    # --- Base queryset (visibilidad según rol)
    if user.groups.filter(name="admin").exists():
        base_qs = Ticket.objects.all()
    elif user.groups.filter(name="tecnico").exists():
        base_qs = Ticket.objects.filter(assigned_to=user)
    else:
        base_qs = Ticket.objects.filter(requester=user)

    # --- Totales globales del usuario
    total = base_qs.count()
    abiertos = base_qs.filter(state="open").count()
    en_progreso = base_qs.filter(state="in_progress").count()
    resueltos = base_qs.filter(state="resolved").count()
    mios = Ticket.objects.filter(requester=user).count()

    # --- Porcentajes para la barra de estado
    if total:
        pa = round(abiertos * 100 / total)
        pp = round(en_progreso * 100 / total)
        pr = round(resueltos * 100 / total)
    else:
        pa = pp = pr = 0

    # --- Top categorías (solo tickets visibles para el usuario)
    por_categoria = (
        base_qs.values("category__name")
        .annotate(c=Count("id"))
        .order_by("-c")[:6]
    )

    # --- Últimos 7 días
    ultimos_7d = now() - timedelta(days=7)
    recientes = (
        base_qs.select_related("requester", "category")
        .filter(created_at__gte=ultimos_7d)
        .order_by("-created_at")[:8]
    )

    # --- Contexto final
    ctx = {
        "total": total,
        "abiertos": abiertos,
        "en_progreso": en_progreso,
        "resueltos": resueltos,
        "mios": mios,
        "por_categoria": por_categoria,
        "recientes": recientes,
        "pa": pa,
        "pp": pp,
        "pr": pr,
    }

    return render(request, "tickets/dashboard.html", ctx)


@login_required
def ticket_list(request):
    user = request.user
    roles = set(user.groups.values_list("name", flat=True))

    qs = (
        Ticket.objects.select_related("requester", "assigned_to", "category", "priority")
        .order_by("-created_at")
    )

    # --- RBAC
    if "admin" in roles:
        pass  # Admin ve todo
    elif "tecnico" in roles:
        qs = qs.filter(assigned_to=user)
    else:
        qs = qs.filter(requester=user)

    # ================================
    #   Filtros GET avanzados
    # ================================
    state = request.GET.get("state") or ""
    category = request.GET.get("category") or ""
    priority = request.GET.get("priority") or ""
    assignee = request.GET.get("assignee") or ""
    from_date = request.GET.get("from") or ""
    to_date = request.GET.get("to") or ""
    q = request.GET.get("q") or ""

    # --- FILTRO ESTADO
    if state:
        qs = qs.filter(state=state)

    # --- FILTRO CATEGORÍA
    if category.isdigit():
        qs = qs.filter(category_id=int(category))

    # --- FILTRO PRIORIDAD
    if priority:
        qs = qs.filter(priority__code=priority)

    # --- FILTRO ASIGNADO
    if assignee.isdigit():
        qs = qs.filter(assigned_to_id=int(assignee))

    # --- FILTRO DE FECHAS
    try:
        if from_date:
            from_dt = make_aware(datetime.strptime(from_date, "%Y-%m-%d"))
            qs = qs.filter(created_at__gte=from_dt)

        if to_date:
            to_dt = make_aware(datetime.strptime(to_date, "%Y-%m-%d")) + timedelta(days=1)
            qs = qs.filter(created_at__lt=to_dt)
    except Exception:
        pass

    # --- FILTRO TEXTO (ID / título / descripción)
    if q.strip():
        raw = q.strip()
        m = re.fullmatch(r"#?\s*(\d+)", raw)
        if m:
            tid = int(m.group(1))
            qs = qs.filter(
                Q(id=tid)
                | Q(title__icontains=raw)
                | Q(description__icontains=raw)
            )
        else:
            qs = qs.filter(
                Q(title__icontains=raw) |
                Q(description__icontains=raw)
            )

    # ================================
    #   Evaluación final
    # ================================
    tickets = list(qs)

    is_tecnico = "tecnico" in roles

    # ================================
    #   Para filtros del template
    # ================================
    categories = Category.objects.all().order_by("name")
    priorities = Priority.objects.all().order_by("sla_minutes")
    assignees = User.objects.filter(groups__name="tecnico").order_by("username")


    return render(
        request,
        "tickets/tickets_list.html",
        {
            "tickets": tickets,
            "tickets_count": len(tickets),

            # Filtros actuales
            "state": state,
            "priority": priority,
            "category": category,
            "assignee": assignee,
            "from": from_date,
            "to": to_date,
            "q": q,

            # Datos para selects
            "categories": categories,
            "priorities": priorities,
            "assignees": assignees,

            "is_tecnico": is_tecnico,
        },
    )

@login_required
def ticket_list_all(request):
    user = request.user

    if not user.groups.filter(name="tecnico").exists() and not user.groups.filter(name="admin").exists():
        messages.error(request, "No tienes permiso para ver todos los tickets.")
        return redirect("ticket_list")

    qs = Ticket.objects.select_related(
        "requester", "assigned_to", "category", "priority"
    ).order_by("-created_at")

    # Filtros generales
    state = request.GET.get("state", "")
    priority = request.GET.get("priority", "")
    category = request.GET.get("category", "")
    q = request.GET.get("q", "")

    if state:
        qs = qs.filter(state=state)

    if priority:
        qs = qs.filter(priority=priority)

    if category:
        qs = qs.filter(category_id=category)

    if q:
        qs = qs.filter(Q(title__icontains=q) | Q(description__icontains=q))

    categories = Category.objects.order_by("name")
    priorities = Priority.objects.order_by("name")

    return render(request, "tickets/tickets_list_table.html", {
        "tickets": qs,
        "show_assignments": True,  # muestra columna asignado
        "title": "Todos los tickets",
        "categories": categories,
        "priorities": priorities,
        "filters": request.GET,
    })
@login_required
def ticket_list_assigned(request):
    user = request.user

    if not user.groups.filter(name="tecnico").exists():
        messages.error(request, "Solo los técnicos pueden ver esta sección.")
        return redirect("ticket_list")

    qs = Ticket.objects.select_related(
        "requester", "assigned_to", "category", "priority"
    ).filter(assigned_to=user).order_by("-created_at")

    # Filtros iguales a la vista anterior
    state = request.GET.get("state", "")
    priority = request.GET.get("priority", "")
    category = request.GET.get("category", "")
    q = request.GET.get("q", "")

    if state:
        qs = qs.filter(state=state)
    if priority:
        qs = qs.filter(priority=priority)
    if category:
        qs = qs.filter(category_id=category)
    if q:
        qs = qs.filter(Q(title__icontains=q) | Q(description__icontains=q))

    categories = Category.objects.order_by("name")
    priorities = Priority.objects.order_by("name")

    return render(request, "tickets/tickets_list_table.html", {
        "tickets": qs,
        "show_assignments": False,  # el técnico no necesita verse a sí mismo
        "title": "Mis tickets asignados",
        "categories": categories,
        "priorities": priorities,
        "filters": request.GET,
    })



@login_required
def ticket_detail(request, pk: int):
    t = get_object_or_404(
        Ticket.objects.select_related("requester", "assigned_to", "category"), pk=pk
    )
    is_admin = _is_adminlike(request.user)
    return _render(request, "tickets/ticket_detail.html", {
        "ticket": t, "ticket_id": t.id, "is_admin": is_admin
    })

def tickets_alias(request):
    return redirect("ticket_list") if request.user.is_authenticated else redirect("index")

def logout_view(request):
    logout(request)
    return redirect("index")

# ==================== Mantenedor ====================
@login_required
def maint_index(request):
    # Solo admin estricto (superuser, staff o grupo "admin") 
    # o quien tenga el permiso explícito "tickets.access_maint"
    if not (_is_admin_strict(request.user) or request.user.has_perm("tickets.access_maint")):
        return HttpResponseForbidden("No autorizado")

    sections = Section.objects.filter(is_active=True).order_by("title")
    allowed = []
    for s in sections:
        if _is_admin_strict(request.user) or s.groups.filter(
            id__in=request.user.groups.values_list("id", flat=True)
        ).exists():
            allowed.append(s)

    return _render(
        request,
        "tickets/maint_index.html",
        {
            "sections": allowed,
            "maint_sections": [
                {"code": s.code, "name": s.title, "title": s.title}
                for s in allowed
            ],
        },
    )


@login_required
def maint_section(request, code: str):
    # Busca la sección activa
    sec = get_object_or_404(Section, code=code, is_active=True)

    # Solo admin estricto o usuarios que tengan la sección asignada por grupo
    if not (_is_admin_strict(request.user) or sec.groups.filter(
        id__in=request.user.groups.values_list("id", flat=True)
    ).exists()):
        return HttpResponseForbidden("No autorizado")

    tpl_specific = f"tickets/maint_{code}.html"
    tpl_fallback = "tickets/maint_section.html"

    ctx = {
        "section": sec,
        "code": sec.code,
        "maint_sections": _navbar_sections(request.user),
    }

    # ======================================
    # 🔥 AQUI SE AGREGAN LOS DATOS NUEVOS
    # ======================================

    # --- Prioridades ---
    if code == "prioridades":
        from .models import Priority
        ctx["priorities"] = Priority.objects.order_by("sla_minutes")

    # --- Categorías (opcional si las manejas igual) ---
    if code == "categorias":
        from .models import Category
        ctx["categories"] = Category.objects.order_by("name")

    # ======================================

    return TemplateResponse(
        request,
        template=[tpl_specific, tpl_fallback],
        context=ctx,
    )



# ---------- Roles (UI) ----------
def _is_admin_strict(u):
    return (
        u.is_authenticated
        and (
            u.is_superuser
            or u.is_staff
            or u.groups.filter(name="admin").exists()
        )
    )


def _is_admin_or_tech(u):
    return u.is_superuser or u.groups.filter(name__in=["admin", "tecnico"]).exists()


@login_required
@user_passes_test(_is_admin_or_tech)
def maint_roles(request):
    rbac.ensure_groups_exist()

    username_field = getattr(get_user_model(), "USERNAME_FIELD", "username")
    users_qs = get_user_model().objects.order_by(username_field).prefetch_related("groups")
    users_list = list(users_qs)

    def _display_name(user):
        base = getattr(user, username_field) or user.get_username()
        full = (user.get_full_name() or "").strip()
        if full:
            return f"{full} ({user.get_username()})"
        return base

    users = [
        {
            "id": u.id,
            "username": _display_name(u),
            "email": u.email,
        }
        for u in users_list
    ]

    # 🔥 Cargar correctamente los roles desde RBAC
    roles_map = {str(u.id): rbac.user_managed_roles(u) for u in users_list}
    allowed_roles = sorted(rbac.actor_allowed_roles(request.user))
    managed_roles = sorted(rbac.MANAGED_ROLE_NAMES)
    role_labels = rbac.ROLE_LABELS

    ctx = {
        "users": users,
        "roles_map": roles_map,
        "roles_map_json": json.dumps(roles_map),
        "allowed_roles": allowed_roles,
        "managed_roles": managed_roles,
        "allowed_roles_json": json.dumps(allowed_roles),
        "managed_roles_json": json.dumps(managed_roles),
        "role_labels_json": json.dumps(role_labels),
        "role_labels": role_labels,
        "can_manage_staff": request.user.is_staff or request.user.is_superuser,
    }

    return render(request, "tickets/maint_roles.html", ctx)

# ---------- Roles (API simple para búsquedas opcionales) ----------

@login_required
@require_GET
def roles_data(request):
    if not _is_adminlike(request.user):
        return HttpResponseForbidden("No autorizado")

    q = (request.GET.get("q") or "").strip().lower()

    # ✅ Usa el modelo de usuario correcto
    User = get_user_model()
    username_field = getattr(User, "USERNAME_FIELD", "username")

    users = (
        User.objects.order_by(username_field)
        .only("id", "username", "email", "first_name", "last_name", "is_staff")
        .prefetch_related("groups")
    )

    if q:
        users = users.filter(
            Q(username__icontains=q)
            | Q(email__icontains=q)
            | Q(first_name__icontains=q)
            | Q(last_name__icontains=q)
        )

    data = []
    for u in users:
        full_name = (u.get_full_name() or "").strip()
        base_name = getattr(u, username_field) or u.get_username()
        display = f"{full_name} ({u.get_username()})" if full_name else base_name

        # ✅ Usa tus helpers RBAC para roles administrables (consistente con el resto)
        from .rbac import user_managed_roles
        roles = user_managed_roles(u)
        if not roles:
            roles = ["usuario"]

        data.append({
            "id": u.id,
            "username": display,
            "email": u.email,
            "roles": roles,
            "is_staff": u.is_staff,
        })

    return JsonResponse({"users": data})


# ---------- Roles (mutación) ----------
@login_required
@user_passes_test(_is_admin_or_tech)
@require_POST
def roles_update(request):
    if not _is_adminlike(request.user):
        return HttpResponseForbidden("No autorizado")

    try:
        payload = json.loads(request.body.decode("utf-8"))
        user_id = int(payload.get("user_id"))
        roles = payload.get("roles", [])
    except Exception:
        return JsonResponse({"ok": False, "error": "JSON inválido"}, status=400)

    try:
        target = get_user_model().objects.get(pk=user_id)
    except get_user_model().DoesNotExist:
        return JsonResponse({"ok": False, "error": "Usuario no existe"}, status=404)

    # Normaliza roles válidos
    MANAGED_ROLE_NAMES = {"admin", "tecnico", "usuario"}
    roles = [r for r in roles if r in MANAGED_ROLE_NAMES]

    # Exclusión mutua admin/tecnico
    if "admin" in roles and "tecnico" in roles:
        return JsonResponse({"ok": False, "error": "admin y técnico son excluyentes"}, status=400)

    # 🚫 Validar último admin
    from django.contrib.auth.models import Group
    admin_group, _ = Group.objects.get_or_create(name="admin")
    current_admins = get_user_model().objects.filter(groups=admin_group).exclude(pk=target.pk)
    if not current_admins.exists() and "admin" not in roles:
        return JsonResponse({
            "ok": False,
            "error": "No puedes eliminar el rol admin del único administrador activo."
        }, status=400)

    # Asegura todos los grupos base
    for name in MANAGED_ROLE_NAMES:
        Group.objects.get_or_create(name=name)

    # Limpia roles previos y asigna nuevos
    target.groups.remove(*Group.objects.filter(name__in=MANAGED_ROLE_NAMES))
    if roles:
        target.groups.add(*Group.objects.filter(name__in=roles))
    else:
        usuario = Group.objects.get(name="usuario")
        target.groups.add(usuario)
        roles = ["usuario"]

    # Guarda y devuelve datos actualizados
    target.save()

    return JsonResponse({
        "ok": True,
        "user": {
            "id": target.id,
            "username": target.get_username(),
            "email": target.email,
            "roles": roles,
            "is_staff": target.is_staff,
        },
        "roles": roles,
    })


@login_required
@user_passes_test(_is_admin_or_tech)
def maint_roles_set(request):
    try:
        payload = json.loads(request.body or "{}")
        user_id = int(payload.get("user_id"))
        roles = payload.get("roles", [])
    except Exception:
        return JsonResponse({"error":"JSON inválido"}, status=400)

    if not user_id:
        return JsonResponse({"error":"user_id requerido"}, status=400)

    sanitized_roles = rbac.clean_roles(roles)
    if "admin" in sanitized_roles and "tecnico" in sanitized_roles:
        return JsonResponse({"error":"admin y técnico son excluyentes"}, status=400)

    rbac.ensure_groups_exist()
    user = get_user_model().objects.filter(pk=user_id).first()
    if not user:
        return JsonResponse({"error":"Usuario no existe"}, status=404)
    try:
        desired = rbac.assert_actor_can_manage(request.user, user, sanitized_roles)
    except rbac.LastAdminRemovalError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    except rbac.RolePermissionError as exc:
        return JsonResponse({"error": str(exc)}, status=403)

    applied = rbac.apply_roles(user, desired)

    TicketLog.objects.create(
        ticket=None,
        user=request.user if request.user.is_authenticated else None,
        action="permissions.updated",
        meta_json={
            "target_user": user.get_username(),
            "roles": applied,
        },
        is_critical=True,
    )

    return JsonResponse({"ok": True, "roles": applied})


# --- HELPERS MÉTRICAS ---
def parse_ticket_range(request):
    """from,to pueden venir como 'YYYY-MM-DD' o ISO datetime."""
    f = request.GET.get("from") or request.GET.get("date_from")
    t = request.GET.get("to") or request.GET.get("date_to")
    tz = timezone.get_current_timezone()

    def _to_dt(x, start=True):
        if not x:
            return None
        dt = parse_datetime(x)
        if dt is None:
            d = parse_date(x)
            if not d:
                return None
            if start:
                dt = timezone.datetime(d.year, d.month, d.day, 0, 0, 0)
            else:
                dt = timezone.datetime(d.year, d.month, d.day, 23, 59, 59)
        if timezone.is_naive(dt):
            dt = timezone.make_aware(dt, tz)
        return dt

    return _to_dt(f, True), _to_dt(t, False)

def apply_ticket_filters(qs, request):
    fdt, tdt = parse_ticket_range(request)
    category = request.GET.get("category")
    assignee = request.GET.get("assignee")
    priority = request.GET.get("priority")
    asset = request.GET.get("asset_id") or request.GET.get("asset")

    if fdt:
        qs = qs.filter(created_at__gte=fdt)
    if tdt:
        qs = qs.filter(created_at__lte=tdt)
    if category:
        # acepta id numérico o nombre
        if category.isdigit():
            qs = qs.filter(category_id=int(category))
        else:
            qs = qs.filter(category__name__iexact=category)
    if assignee:
        # acepta id o username
        if assignee.isdigit():
            qs = qs.filter(assigned_to_id=int(assignee))
        else:
            qs = qs.filter(assigned_to__username__iexact=assignee)
    if priority:
        qs = qs.filter(priority=priority)
    if asset:
        qs = qs.filter(asset_id=asset)
    return qs



def _reports_base_queryset(request):
    """
    QS base para los reportes HTML, respetando visibilidad y filtros.
    Usa apply_ticket_filters para rango de fechas, categoría, prioridad, assignee, asset.
    Además aplica filtros de estado y texto (q).
    """
    qs = Ticket.objects.select_related("category", "assigned_to", "requester")

    # Visibilidad según rol (igual que otros endpoints)
    if not _is_admin_or_tech(request.user):
        qs = qs.filter(Q(requester=request.user) | Q(assigned_to=request.user))

    # Filtros comunes (from/to, category, assignee, priority, asset)
    qs = apply_ticket_filters(qs, request)

    # Filtro de estado (state)
    state = (request.GET.get("state") or "").strip()
    if state:
        qs = qs.filter(state=state)

    # Búsqueda por texto en título / descripción
    q = (request.GET.get("q") or "").strip()
    if q:
        qs = qs.filter(Q(title__icontains=q) | Q(description__icontains=q))

    return qs

# --- ENDPOINT: /api/metrics/summary ---
def _visible_qs(u):
    return Ticket.objects.all() if _is_admin_or_tech(u) else Ticket.objects.filter(Q(requester=u)|Q(assigned_to=u))

FILTER_QUERY_PARAMS = [
    openapi.Parameter(
        "from",
        openapi.IN_QUERY,
        description="Fecha mínima de creación (YYYY-MM-DD).",
        type=openapi.TYPE_STRING,
        required=False,
    ),
    openapi.Parameter(
        "to",
        openapi.IN_QUERY,
        description="Fecha máxima de creación (YYYY-MM-DD).",
        type=openapi.TYPE_STRING,
        required=False,
    ),
    openapi.Parameter(
        "category",
        openapi.IN_QUERY,
        description="Categoría por ID numérico o nombre exacto.",
        type=openapi.TYPE_STRING,
        required=False,
    ),
    openapi.Parameter(
        "assignee",
        openapi.IN_QUERY,
        description="Asignado por ID numérico o username.",
        type=openapi.TYPE_STRING,
        required=False,
    ),
    openapi.Parameter(
        "priority",
        openapi.IN_QUERY,
        description="Prioridad exacta (low, medium, high, critical).",
        type=openapi.TYPE_STRING,
        required=False,
    ),
]

# --- ENDPOINT: /api/reports/export ---
EXPORT_FORMAT_PARAM = openapi.Parameter(
    "format",
    openapi.IN_QUERY,
    description="Formato de exportación (csv, xlsx o pdf).",
    type=openapi.TYPE_STRING,
    required=False,
)


@swagger_auto_schema(method="get", manual_parameters=FILTER_QUERY_PARAMS + [EXPORT_FORMAT_PARAM])
@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def reports_export(request):
    fmt = (request.GET.get("format") or "csv").lower()
    qs = Ticket.objects.select_related("category", "assigned_to", "requester")
    if not _is_admin_or_tech(request.user):
        qs = qs.filter(Q(requester=request.user) | Q(assigned_to=request.user))
    qs = apply_ticket_filters(qs, request).order_by("-created_at")

    start_time = perf_counter()
    service = TicketMetricsService(qs)
    rows = build_report_rows(service)
    footer = filters_footer(request.GET)

    headers = [
        "ID",
        "Título",
        "Estado",
        "Prioridad",
        "Categoría",
        "Asignado a",
        "Creado",
        "Resuelto",
        "MTTR(min)",
        "FRT(min)",
    ]

    content_type = None
    filename = None
    payload = None

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(headers)
        for row in rows:
            writer.writerow(row)
        writer.writerow([])
        writer.writerow([f"Parámetros: {footer}"])
        payload = buf.getvalue().encode("utf-8-sig")
        content_type = "text/csv; charset=utf-8"
        filename = "tickets_report.csv"
    elif fmt == "xlsx":
        if not openpyxl:
            return Response({"error": "openpyxl no instalado"}, status=501)
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Reporte"
        ws.append(headers)
        for row in rows:
            ws.append(row)
        ws.append([])
        ws.append([f"Parámetros: {footer}"])
        buffer = io.BytesIO()
        wb.save(buffer)
        payload = buffer.getvalue()
        content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        filename = "tickets_report.xlsx"
    elif fmt == "pdf":
        if not canvas:
            return Response({"error": "reportlab no instalado"}, status=501)
        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer)
        pdf.setFont("Helvetica", 10)
        y = 800
        pdf.drawString(40, y, "Reporte de Tickets"); y -= 20
        pdf.drawString(40, y, f"Parámetros: {footer}"); y -= 30
        pdf.drawString(
            40,
            y,
            "ID  Título  Estado  Prioridad  Categoría  Asignado  Creado  Resuelto  MTTR  FRT",
        )
        y -= 15
        for row in rows[:600]:
            line = "  ".join(str(x) for x in row[:10])
            pdf.drawString(40, y, line[:180])
            y -= 12
            if y < 60:
                pdf.showPage()
                pdf.setFont("Helvetica", 10)
                y = 800
        pdf.showPage()
        pdf.save()
        payload = buffer.getvalue()
        content_type = "application/pdf"
        filename = "tickets_report.pdf"
    else:
        return Response({"error": "format inválido (csv|xlsx|pdf)"}, status=400)

    elapsed = perf_counter() - start_time
    response = Response(payload)
    response["Content-Type"] = content_type
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    response["X-Export-Generation"] = f"{elapsed:.6f}"
    return response


# --- ENDPOINT: /api/assets/{asset_id}/tickets ---
ASSET_RULE_PARAMS = [
    openapi.Parameter(
        "n",
        openapi.IN_QUERY,
        description="Cantidad de incidentes que gatilla la alerta.",
        type=openapi.TYPE_INTEGER,
        required=False,
    ),
    openapi.Parameter(
        "m",
        openapi.IN_QUERY,
        description="Ventana en meses a considerar para la regla.",
        type=openapi.TYPE_INTEGER,
        required=False,
    ),
    openapi.Parameter(
        "format",
        openapi.IN_QUERY,
        description="Formato opcional (csv o pdf) para exportar la vista.",
        type=openapi.TYPE_STRING,
        required=False,
    ),
]


def _serialize_asset_ticket(ticket):
    tz = timezone.get_current_timezone()
    created = timezone.localtime(ticket.created_at, tz).strftime("%Y-%m-%d %H:%M")
    updated = timezone.localtime(ticket.updated_at, tz).strftime("%Y-%m-%d %H:%M")
    return {
        "id": ticket.id,
        "title": ticket.title,
        "state": ticket.state,
        "priority": ticket.priority,
        "category": getattr(ticket.category, "name", ""),
        "assigned_to": getattr(ticket.assigned_to, "username", ""),
        "created_at": created,
        "updated_at": updated,
        "breach_risk": ticket.breach_risk,
    }


def _asset_rows(history):
    rows = []
    for ticket in history.tickets:
        data = _serialize_asset_ticket(ticket)
        rows.append([
            data["id"],
            data["title"],
            data["state"],
            data["priority"],
            data["category"],
            data["assigned_to"],
            data["created_at"],
            data["updated_at"],
            "Sí" if data["breach_risk"] else "No",
        ])
    return rows


def _record_faq_unresolved(faq, user, comment: str):
    feedback = FAQFeedback.objects.create(faq=faq, user=user, comment=comment)
    TicketLog.objects.create(
        ticket=None,
        user=user,
        action="faq.unresolved",
        is_critical=True,
        meta_json={"faq_id": faq.pk, "comment": comment},
    )
    return feedback


@swagger_auto_schema(method="get", manual_parameters=ASSET_RULE_PARAMS)
@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def asset_ticket_history(request, asset_id: str):
    qs = Ticket.objects.select_related("category", "assigned_to").filter(asset_id=asset_id)
    qs = apply_ticket_filters(qs, request)
    tickets = list(qs.order_by("-created_at"))

    history = build_asset_history(
        asset_id=asset_id,
        queryset=tickets,
        rule_n=request.GET.get("n"),
        rule_m=request.GET.get("m"),
    )

    fmt = (request.GET.get("format") or "json").lower()
    rule_payload = {
        "n": history.threshold_count,
        "m": history.threshold_months,
        "triggered": history.rule_triggered,
        "window_start": history.period_start.isoformat() if history.period_start else None,
        "window_end": history.period_end.isoformat(),
        "current_window_total": len(history.within_threshold_period),
    }

    if fmt == "json":
        return Response(
            {
                "asset_id": asset_id,
                "total": history.total,
                "rule": rule_payload,
                "results": [_serialize_asset_ticket(t) for t in history.tickets],
            }
        )

    headers = [
        "ID",
        "Título",
        "Estado",
        "Prioridad",
        "Categoría",
        "Asignado",
        "Creado",
        "Actualizado",
        "Riesgo SLA",
    ]

    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(headers)
        for row in _asset_rows(history):
            writer.writerow(row)
        writer.writerow([])
        writer.writerow([f"Regla: {rule_payload}"])
        payload = buffer.getvalue().encode("utf-8-sig")
        response = Response(payload)
        response["Content-Type"] = "text/csv; charset=utf-8"
        response["Content-Disposition"] = f'attachment; filename="asset_{asset_id}_tickets.csv"'
        return response

    if fmt == "pdf":
        if not canvas:
            return Response({"error": "reportlab no instalado"}, status=501)
        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer)
        pdf.setFont("Helvetica", 10)
        pdf.drawString(40, 800, f"Historial de activo {asset_id}")
        pdf.drawString(40, 780, f"Regla: {rule_payload}")
        y = 750
        for row in _asset_rows(history):
            line = "  ".join(str(value) for value in row)
            pdf.drawString(40, y, line[:180])
            y -= 14
            if y < 60:
                pdf.showPage()
                pdf.setFont("Helvetica", 10)
                y = 800
        pdf.showPage()
        pdf.save()
        payload = buffer.getvalue()
        response = Response(payload)
        response["Content-Type"] = "application/pdf"
        response["Content-Disposition"] = f'attachment; filename="asset_{asset_id}_tickets.pdf"'
        return response

    return Response({"error": "format inválido (json|csv|pdf)"}, status=400)


@login_required
def metrics_page(request):
    User = get_user_model()
    techs = (
        User.objects.filter(groups__name__in=["admin", "tecnico"])
        .distinct()
        .order_by("username")
    )
    categories = Category.objects.order_by("name")

    return render(
        request,
        "tickets/metrics.html",
        {
            "techs": techs,
            "categories": categories
        },
    )


@login_required
def reports_page(request):
    """
    Página HTML de reportes: filtros + gráficos + tabla.
    Solo admin/tecnico ven todos.
    """
    if not _is_admin_or_tech(request.user):
        return HttpResponseForbidden("No autorizado")

    assignees = (
        Ticket.objects.exclude(assigned_to=None)
        .values_list("assigned_to__id", "assigned_to__username")
        .distinct()
        .order_by("assigned_to__username")
    )

    ctx = {
        "states": REPORT_STATE_CHOICES,
        "assignees": assignees,
    }
    return _render(request, "tickets/reports.html", ctx)

@login_required
@require_GET
def reports_data(request):
    if not _is_admin_or_tech(request.user):
        return HttpResponseForbidden("No autorizado")

    qs = _reports_base_queryset(request).order_by("-created_at")

    # Conteo por estado
    by_state = Counter(qs.values_list("state", flat=True))

    # Serie por mes
    by_month = defaultdict(int)
    for dt in qs.values_list("created_at", flat=True):
        key = dt.strftime("%Y-%m")
        by_month[key] += 1

    # Tabla (limitamos para no enviar miles de filas)
    rows = []
    for t in qs.select_related("assigned_to")[:300]:
        rows.append(
            {
                "id": t.id,
                "title": t.title or "",
                "state": t.state or "",
                "assigned": getattr(t.assigned_to, "username", "") or "",
                "created_at": t.created_at.strftime("%Y-%m-%d %H:%M"),
            }
        )

    return JsonResponse(
        {
            "by_state": by_state,
            "by_month": dict(sorted(by_month.items())),
            "rows": rows,
            "total": qs.count(),
        }
    )

@login_required
def reports_export_csv(request):
    if not _is_admin_or_tech(request.user):
        return HttpResponseForbidden("No autorizado")

    qs = _reports_base_queryset(request).order_by("-created_at")

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["ID", "Título", "Estado", "Asignado a", "Categoría", "Creado", "Actualizado"]
    )

    for t in qs.select_related("category", "assigned_to"):
        writer.writerow(
            [
                t.id,
                t.title or "",
                t.state or "",
                getattr(t.assigned_to, "username", "") or "",
                getattr(t.category, "name", "") or "",
                t.created_at.strftime("%Y-%m-%d %H:%M"),
                t.updated_at.strftime("%Y-%m-%d %H:%M") if t.updated_at else "",
            ]
        )

    resp = HttpResponse(
        buffer.getvalue().encode("utf-8-sig"),
        content_type="text/csv; charset=utf-8",
    )
    resp["Content-Disposition"] = 'attachment; filename="tickets_report.csv"'
    return resp


def faq_page(request):
    query = (request.GET.get("q") or "").strip()
    category_param = (request.GET.get("category") or "").strip()
    faqs = FAQ.objects.filter(is_active=True).select_related("category")
    if query:
        faqs = faqs.filter(Q(question__icontains=query) | Q(answer__icontains=query))
    if category_param:
        if category_param.isdigit():
            faqs = faqs.filter(category_id=int(category_param))
        else:
            faqs = faqs.filter(category__name__iexact=category_param)
    faqs = faqs.order_by("question")

    categories = Category.objects.order_by("name")
    ctx = {
        "query": query,
        "selected_category": category_param,
        "faqs": faqs,
        "categories": categories,
        "query_params": request.GET,
    }
    return _render(request, "tickets/faq.html", ctx)


@require_POST
def faq_unresolved(request, pk: int):
    faq = get_object_or_404(FAQ, pk=pk, is_active=True)
    comment = (request.POST.get("comment") or "").strip()
    user = request.user if request.user.is_authenticated else None
    _record_faq_unresolved(faq, user, comment)
    messages.info(request, "Registramos que el artículo no resolvió tu problema.")
    params = {}
    for key in ("q", "category"):
        value = request.POST.get(key)
        if value:
            params[key] = value
    target = reverse("faq")
    if params:
        target = f"{target}?{urlencode(params)}"
    return redirect(target)


@login_required
def asset_history_page(request, asset_id: str):
    qs = Ticket.objects.select_related("category", "assigned_to").filter(asset_id=asset_id)
    qs = apply_ticket_filters(qs, request)
    tickets = list(qs.order_by("-created_at"))
    history = build_asset_history(
        asset_id=asset_id,
        queryset=tickets,
        rule_n=request.GET.get("n"),
        rule_m=request.GET.get("m"),
    )

    rule_info = {
        "n": history.threshold_count,
        "m": history.threshold_months,
        "triggered": history.rule_triggered,
        "window_start": history.period_start,
        "window_end": history.period_end,
        "current_window_total": len(history.within_threshold_period),
    }

    ctx = {
        "asset_id": asset_id,
        "rule": rule_info,
        "tickets": [_serialize_asset_ticket(t) for t in history.tickets],
        "query_params": request.GET,
    }
    return _render(request, "tickets/asset_history.html", ctx)

# ---------------------------------------------------
# MÉTRICAS API
# ---------------------------------------------------
@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
@swagger_auto_schema(manual_parameters=FILTER_QUERY_PARAMS)
def metrics_summary(request):
    """
    Endpoint de métricas con filtros:
    - from / to : rango de fechas (created_at)
    - category  : id de categoría
    - assignee  : id de técnico
    - priority  : prioridad (low/medium/high/critical...)
    """
    user = request.user
    qs = Ticket.objects.all()

    # -----------------------------
    # RBAC
    # -----------------------------
    if user.groups.filter(name="admin").exists():
        pass
    elif user.groups.filter(name="tecnico").exists():
        qs = qs.filter(assigned_to=user)
    else:
        qs = qs.filter(requester=user)

    # -----------------------------
    # Filtros básicos
    # -----------------------------
    from_date = request.GET.get("from")
    to_date = request.GET.get("to")
    category = request.GET.get("category")
    assignee = request.GET.get("assignee")
    priority = request.GET.get("priority")

    # Rango de fechas
    try:
        if from_date:
            from_date = make_aware(datetime.strptime(from_date, "%Y-%m-%d"))
            qs = qs.filter(created_at__gte=from_date)

        if to_date:
            to_date = make_aware(datetime.strptime(to_date, "%Y-%m-%d")) + timedelta(days=1)
            qs = qs.filter(created_at__lt=to_date)
    except Exception:
        pass

    if category:
        qs = qs.filter(category_id=category)

    if assignee:
        qs = qs.filter(assigned_to_id=assignee)

    # -----------------------------
    # ✔ Filtro de prioridad FIX
    # -----------------------------
    if priority:
        from tickets.models import Priority

        prio_obj = (
            Priority.objects.filter(slug__iexact=priority).first() or
            Priority.objects.filter(name__iexact=priority).first() or
            Priority.objects.filter(code__iexact=priority).first()
        )

        if prio_obj:
            qs = qs.filter(priority_id=prio_obj.id)
        else:
            # Si no existe la prioridad → devolvemos queryset vacío
            qs = qs.none()

    # -----------------------------
    # Métricas
    # -----------------------------
    service = TicketMetricsService(qs)
    summary = service.summarize()
    return Response(summary)

@login_required
def sistema_page(request):
    """
    Menú principal de herramientas de sistema (solo admin).
    """
    if not _is_admin_strict(request.user):
        return HttpResponseForbidden("No autorizado")

    User = get_user_model()
    admins_count = User.objects.filter(groups__name="admin").distinct().count()
    techs_count = User.objects.filter(groups__name="tecnico").distinct().count()
    users_count = User.objects.filter(groups__name="usuario").distinct().count()

    ctx = {
        "admins_count": admins_count,
        "techs_count": techs_count,
        "users_count": users_count,
    }
    return _render(request, "tickets/sistema_index.html", ctx)


@login_required
def sistema_logs_export(request):
    """
    Exporta logs críticos (TicketLog) a CSV respetando filtros de user y order.
    No aplica límite (exporta todos los que matchean).
    """
    if not _is_admin_strict(request.user):
        return HttpResponseForbidden("No autorizado")

    qs, meta = _filtered_critical_logs(request, apply_limit=False)

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Fecha", "Usuario", "Email", "Acción", "Detalle"])

    for log in qs:
        created = timezone.localtime(log.created_at).strftime("%Y-%m-%d %H:%M")
        username = log.user.username if log.user else ""
        email = log.user.email if (log.user and log.user.email) else ""
        detail = ""
        if log.meta_json:
            try:
                detail = json.dumps(log.meta_json, ensure_ascii=False)
            except TypeError:
                detail = str(log.meta_json)

        writer.writerow([created, username, email, log.action, detail])

    resp = HttpResponse(
        buffer.getvalue().encode("utf-8-sig"),
        content_type="text/csv; charset=utf-8",
    )
    resp["Content-Disposition"] = 'attachment; filename="logs_sistema.csv"'
    return resp





def _filtered_critical_logs(request, apply_limit=True):
    """
    Aplica filtros de usuario, orden y límite sobre TicketLog.is_critical=True.
    Devuelve (queryset o lista, meta_dict).
    """
    # límite: 20 / 50 / 100 (por defecto 20)
    raw_limit = request.GET.get("limit") or "20"
    try:
        limit = int(raw_limit)
    except ValueError:
        limit = 20
    if limit not in (20, 50, 100):
        limit = 20

    # filtro por usuario (username o email)
    user_q = (request.GET.get("user") or "").strip()

    # orden: 'desc' (default) o 'asc'
    order = (request.GET.get("order") or "desc").lower()
    if order not in ("asc", "desc"):
        order = "desc"

    qs = TicketLog.objects.select_related("user").filter(is_critical=True)

    if user_q:
        qs = qs.filter(
            Q(user__username__icontains=user_q) |
            Q(user__email__icontains=user_q)
        )

    if order == "asc":
        qs = qs.order_by("created_at")
    else:
        qs = qs.order_by("-created_at")

    if apply_limit:
        qs = qs[:limit]

    meta = {
        "limit": limit,
        "user_q": user_q,
        "order": order,
    }
    return qs, meta


@login_required
def sistema_user_activity(request):
    if not _is_admin_strict(request.user):
        return HttpResponseForbidden("No autorizado")

    User = get_user_model()
    q = (request.GET.get("q") or "").strip()
    role = (request.GET.get("role") or "").strip()

    users = User.objects.all().prefetch_related("groups").order_by("-last_login", "username")

    if q:
        users = users.filter(
            Q(username__icontains=q) |
            Q(email__icontains=q) |
            Q(first_name__icontains=q) |
            Q(last_name__icontains=q)
        )

    if role in ("admin", "tecnico", "usuario"):
        users = users.filter(groups__name=role).distinct()

    ctx = {
        "users": users,
        "q": q,
        "role": role,
    }
    return _render(request, "tickets/sistema_user_activity.html", ctx)


@login_required
@require_POST
def sistema_user_toggle_active(request, user_id: int):
    if not _is_admin_strict(request.user):
        return HttpResponseForbidden("No autorizado")

    User = get_user_model()
    target = get_object_or_404(User, pk=user_id)

    # evita que el admin se desactive a sí mismo
    if target.pk == request.user.pk:
        messages.error(request, "No puedes desactivar tu propio usuario.")
        return redirect("sistema_user_activity")

    target.is_active = not target.is_active
    target.save(update_fields=["is_active"])

    state = "activado" if target.is_active else "desactivado"
    messages.success(request, f"Usuario {target.username} ha sido {state}.")

    return redirect("sistema_user_activity")

@login_required
def sistema_auth_failed(request):
    if not _is_admin_strict(request.user):
        return HttpResponseForbidden("No autorizado")

    user_q = (request.GET.get("user") or "").strip()
    order = (request.GET.get("order") or "desc").lower()
    if order not in ("asc", "desc"):
        order = "desc"

    raw_limit = request.GET.get("limit") or "20"
    try:
        limit = int(raw_limit)
    except ValueError:
        limit = 20
    if limit not in (20, 50, 100):
        limit = 20

    logs = TicketLog.objects.select_related("user").filter(action="auth.failed")

    if user_q:
        logs = logs.filter(
            Q(meta_json__username__icontains=user_q) |
            Q(user__username__icontains=user_q) |
            Q(user__email__icontains=user_q)
        )

    logs = logs.order_by("created_at" if order == "asc" else "-created_at")[:limit]

    ctx = {
        "logs": logs,
        "user_q": user_q,
        "order": order,
        "limit": limit,
    }
    return _render(request, "tickets/sistema_auth_failed.html", ctx)

@login_required
def sistema_ticket_maintenance(request):
    if not _is_admin_strict(request.user):
        return HttpResponseForbidden("No autorizado")

    cutoff = now() - timedelta(days=60)

    tickets_no_category = Ticket.objects.filter(category__isnull=True).order_by("-created_at")[:100]
    tickets_inprogress_no_assignee = Ticket.objects.filter(
        state="in_progress", assigned_to__isnull=True
    ).order_by("-created_at")[:100]
    tickets_stale = Ticket.objects.filter(
        state__in=["open", "in_progress"],
        created_at__lt=cutoff,
    ).order_by("-created_at")[:100]

    ctx = {
        "tickets_no_category": tickets_no_category,
        "tickets_inprogress_no_assignee": tickets_inprogress_no_assignee,
        "tickets_stale": tickets_stale,
        "cutoff": cutoff,
    }
    return _render(request, "tickets/sistema_ticket_maintenance.html", ctx)

@login_required
def sistema_health(request):
    if not _is_admin_strict(request.user):
        return HttpResponseForbidden("No autorizado")

    db_ok = True
    db_error = None
    try:
        Ticket.objects.exists()
    except Exception as exc:
        db_ok = False
        db_error = str(exc)

    ctx = {
        "python_version": sys.version.split()[0],
        "django_version": django.get_version(),
        "debug": settings.DEBUG,
        "timezone": str(get_current_timezone()),
        "db_ok": db_ok,
        "db_error": db_error,
        "email_backend": getattr(settings, "EMAIL_BACKEND", "No configurado"),
    }
    return _render(request, "tickets/sistema_health.html", ctx)



class PriorityViewSet(viewsets.ModelViewSet):
    queryset = Priority.objects.all().order_by("sla_minutes")
    serializer_class = PrioritySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user

        if user.groups.filter(name="admin").exists():
            return Priority.objects.all().order_by("sla_minutes")

        if user.groups.filter(name="tecnico").exists():
            return Priority.objects.filter(is_active=True).order_by("sla_minutes")

        return Priority.objects.none()


from django.contrib.auth.decorators import login_required
from django.template.response import TemplateResponse
from tickets.models import Priority
from tickets.context import maint_sections   # ← IMPORT CORRECTO

@login_required
def maint_prioridades(request):

    priorities = Priority.objects.order_by("sla_minutes")

    ctx = {
        "priorities": priorities,
        "maint_sections": maint_sections(request)["maint_sections"],  # ← LA CLAVE
        "code": "prioridades",
    }

    return TemplateResponse(request, "tickets/maint_prioridades.html", ctx)


# ============================
#   MANTENEDOR DE FAQ (ADMIN)
# ============================
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import FAQ

@login_required
def maint_faq(request):
    """
    Página del mantenedor de FAQ.
    Solo accesible para administradores.
    """
    user = request.user

    # Solo admins
    if not user.groups.filter(name="admin").exists():
        return render(request, "tickets/403.html", status=403)

    faqs = FAQ.objects.all().order_by("id")

    ctx = {
        "faqs": faqs,
    }

    return render(request, "tickets/maint_faq.html", ctx)

@login_required
def reportes_faq(request):
    """
    Métricas completas:
    - utiles: feedback.is_useful=True
    - no_utiles: feedback.is_useful=False
    - total: todos los feedback
    - utilidad_pct: porcentaje de feedback útil
    """

    user = request.user
    if not user.groups.filter(name__in=["admin", "tecnico"]).exists():
        return JsonResponse({"error": "No autorizado"}, status=403)

    data = (
        FAQ.objects.annotate(
            total_feedback=Count("feedback"),
            utiles=Count("feedback", filter=Q(feedback__is_useful=True)),
            no_utiles=Count("feedback", filter=Q(feedback__is_useful=False)),
        )
        .values(
            "id",
            "question",
            "category__name",
            "total_feedback",
            "utiles",
            "no_utiles",
        )
        .order_by("-no_utiles")
    )

    # Calculamos % utilidad
    results = []
    for f in data:
        total = f["total_feedback"] or 0
        utiles = f["utiles"] or 0
        utilidad_pct = round((utiles / total * 100), 1) if total > 0 else 0

        results.append({
            "question": f["question"],
            "category__name": f["category__name"],
            "total": total,
            "utiles": utiles,
            "no_utiles": f["no_utiles"],
            "utilidad_pct": utilidad_pct,
        })

    return JsonResponse(results, safe=False)


