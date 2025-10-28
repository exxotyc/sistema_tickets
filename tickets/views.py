# tickets/views.py
from datetime import timedelta
from time import perf_counter
import re
import json

from django.contrib.auth import get_user_model, logout
from django.contrib.auth.models import Group
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Q, Count
from django.utils.timezone import now
from django.shortcuts import render, redirect, get_object_or_404
from django.http import Http404, HttpResponseForbidden, JsonResponse
from django.template.response import TemplateResponse
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.csrf import csrf_exempt
from django.middleware.csrf import get_token
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime
from django.db.models import Min
from datetime import datetime, time
from django.utils.timezone import make_aware, get_current_timezone
from django.db.models import Count, Q
from rest_framework.decorators import api_view, permission_classes
from rest_framework import permissions
from rest_framework.response import Response
from .models import Ticket, TicketLog
import io, csv

try:
    import openpyxl
except Exception:
    openpyxl = None

try:
    from reportlab.pdfgen import canvas
except Exception:
    canvas = None

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, permissions, filters, status, mixins
from rest_framework import serializers as drf_serializers
from rest_framework.decorators import action, api_view, permission_classes, authentication_classes
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.response import Response
from rest_framework.authentication import SessionAuthentication

from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Ticket, Category, TicketLog, Comment, Attachment, Section
from .permissions import IsTicketActorOrAdmin
from .serializers import (
    TicketSerializer, CategorySerializer, TicketLogSerializer,
    CommentSerializer, TicketAttachmentSerializer,
)
from .reports import build_report_rows, filters_footer
from .services.metrics import TicketMetricsService

# ==================== Helpers ====================

UserModel = get_user_model()
ALLOWED_ROLE_NAMES = {"admin", "tecnico", "usuario"}  # roles gestionados por el mantenedor

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

def _ensure_groups_exist():
    for name in ALLOWED_ROLE_NAMES:
        Group.objects.get_or_create(name=name)

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

class TicketViewSet(viewsets.ModelViewSet):
    queryset = Ticket.objects.select_related("requester", "assigned_to", "category").all().order_by("-created_at")
    serializer_class = TicketSerializer
    permission_classes = [IsTicketActorOrAdmin]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter, DjangoFilterBackend]
    search_fields = ["title", "description"]
    ordering_fields = ["created_at", "updated_at", "priority"]
    filterset_fields = ["state", "priority", "category"]

    def get_queryset(self):
        qs = super().get_queryset()
        u = self.request.user
        if not u.is_authenticated:
            return qs.none()
        if _is_adminlike(u):
            return qs
        return qs.filter(Q(requester=u) | Q(assigned_to=u)).distinct()

    def perform_create(self, serializer):
        serializer.save(requester=self.request.user)

    @action(detail=True, methods=["post"], permission_classes=[permissions.IsAuthenticated])
    def assign(self, request, pk=None):
        if not _is_adminlike(request.user):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)
        ticket = self.get_object()
        previous = ticket.assigned_to
        user_id = request.data.get("user_id")
        try:
            user = UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        reason = request.data.get("reason") or request.data.get("assignment_reason")
        if previous != user:
            ticket.assigned_to = user
            ticket.save(update_fields=["assigned_to"])
            meta = {
                "from": previous.id if previous else None,
                "to": user.id if user else None,
                "username": user.username if user else None,
            }
            if reason is not None:
                meta["reason"] = reason
            TicketLog.objects.create(
                ticket=ticket,
                user=request.user,
                action="reassigned",
                meta_json=meta,
            )
        elif reason is not None:
            TicketLog.objects.create(
                ticket=ticket,
                user=request.user,
                action="reassigned",
                meta_json={
                    "from": previous.id if previous else None,
                    "to": user.id if user else None,
                    "username": user.username if user else None,
                    "reason": reason,
                },
            )
        return Response({"status": "assigned", "assigned_to": user.username})

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

class UserReadOnlyViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = UserModel.objects.order_by("username")
    serializer_class = drf_serializers.Serializer
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request, *args, **kwargs):
        qs = self.get_queryset()
        u = request.user
        if not _is_adminlike(u):
            qs = qs.filter(pk=u.pk)
        data = [{"id": usr.id, "username": usr.username} for usr in qs]
        return Response(data)

@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def stats(request):
    u = request.user
    qs = Ticket.objects.all() if _is_adminlike(u) else Ticket.objects.filter(Q(requester=u) | Q(assigned_to=u))
    return Response({
        "open": qs.filter(state="open").count(),
        "in_progress": qs.filter(state="in_progress").count(),
        "resolved": qs.filter(state="resolved").count(),
        "closed": qs.filter(state="closed").count(),
    })

@api_view(["POST"])
@permission_classes([permissions.IsAuthenticated])
@authentication_classes([SessionAuthentication])
def session_token(request):
    refresh = RefreshToken.for_user(request.user)
    return Response({"access": str(refresh.access_token), "refresh": str(refresh)})

# ==================== Vistas HTML ====================

@login_required
def ticket_new(request):
    return _render(request, "tickets/ticket_new.html")

def index(request):
    return _render(request, "tickets/index.html")

@login_required
def dashboard(request):
    total = Ticket.objects.count()
    abiertos = Ticket.objects.filter(state="open").count()
    en_progreso = Ticket.objects.filter(state="in_progress").count()
    resueltos = Ticket.objects.filter(state="resolved").count()
    mios = Ticket.objects.filter(requester=request.user).count()

    if total:
        pa = round(abiertos * 100 / total)
        pp = round(en_progreso * 100 / total)
        pr = round(resueltos * 100 / total)
    else:
        pa = pp = pr = 0

    por_categoria = (
        Ticket.objects.values("category__name")
        .annotate(c=Count("id"))
        .order_by("-c")[:6]
    )

    ultimos_7d = now() - timedelta(days=7)
    recientes = (
        Ticket.objects.select_related("requester", "category")
        .filter(created_at__gte=ultimos_7d)
        .order_by("-created_at")[:8]
    )

    ctx = {
        "total": total,
        "abiertos": abiertos,
        "en_progreso": en_progreso,
        "resueltos": resueltos,
        "mios": mios,
        "por_categoria": por_categoria,
        "recientes": recientes,
        "pa": pa, "pp": pp, "pr": pr,
    }
    return _render(request, "tickets/dashboard.html", ctx)

@login_required
def ticket_list(request):
    qs = Ticket.objects.select_related("requester", "assigned_to", "category").order_by("-created_at")

    state = (request.GET.get("state") or "").strip()
    q = (request.GET.get("q") or "").strip()

    if state:
        qs = qs.filter(state=state)

    if q:
        m = re.fullmatch(r"#?\s*(\d+)", q)  # "#14" o "14"
        if m:
            ticket_id = int(m.group(1))
            qs = qs.filter(Q(id=ticket_id) | Q(title__icontains=q) | Q(description__icontains=q))
        else:
            qs = qs.filter(Q(title__icontains=q) | Q(description__icontains=q))

    return _render(request, "tickets/tickets_list.html", {
        "tickets": qs, "state": state, "q": q
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
    if not (_is_adminlike(request.user) or request.user.has_perm("tickets.access_maint")):
        return HttpResponseForbidden("No autorizado")

    sections = Section.objects.filter(is_active=True).order_by("title")
    allowed = []
    for s in sections:
        if _is_adminlike(request.user) or s.groups.filter(
            id__in=request.user.groups.values_list("id", flat=True)
        ).exists():
            allowed.append(s)

    return _render(request, "tickets/maint_index.html", {
        "sections": allowed,
        "maint_sections": [{"code": s.code, "name": s.title, "title": s.title} for s in allowed],
    })

@login_required
def maint_section(request, code: str):
    sec = get_object_or_404(Section, code=code, is_active=True)
    if not (_is_adminlike(request.user) or sec.groups.filter(
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
    return TemplateResponse(request, template=[tpl_specific, tpl_fallback], context=ctx)

# ---------- Roles (UI) ----------

ALLOWED_ROLE_NAMES = {"admin", "tecnico", "usuario"}

def _ensure_groups_exist():
    for name in ALLOWED_ROLE_NAMES:
        Group.objects.get_or_create(name=name)

def _is_admin_or_tech(u):
    return u.is_authenticated and (u.is_staff or u.groups.filter(name__in=["admin","tecnico"]).exists())

@login_required
@user_passes_test(_is_admin_or_tech)
def maint_roles(request):
    _ensure_groups_exist()
    # Query único para evitar listas vacías por values() mal usados
    users_qs = get_user_model().objects.order_by("username").only("id","username")
    users = list(users_qs.values("id","username"))
    roles_map = { str(u.id): list(u.groups.values_list("name", flat=True)) for u in users_qs }
    return render(request, "tickets/maint_roles.html", {
        "users": users,
        "roles_map": roles_map,               # <- se inyecta como JSON seguro en el template
    })

# ---------- Roles (API simple para búsquedas opcionales) ----------

@login_required
@require_GET
def roles_data(request):
    if not _is_adminlike(request.user):
        return HttpResponseForbidden("No autorizado")
    q = (request.GET.get("q") or "").strip().lower()
    users = UserModel.objects.order_by("username")
    if q:
        users = users.filter(username__icontains=q)
    data = []
    for u in users:
        roles = [r for r in u.groups.values_list("name", flat=True) if r in ALLOWED_ROLE_NAMES]
        data.append({
            "id": u.id,
            "username": u.username,
            "is_staff": u.is_staff,
            "roles": roles,
        })
    return JsonResponse({"users": data, "csrfToken": get_token(request)})

# ---------- Roles (mutación) ----------

@login_required
@require_POST
@csrf_exempt  # simplifica fetch JSON; quita si ya envías CSRF desde el front
def roles_update(request):
    if not _is_adminlike(request.user):
        return HttpResponseForbidden("No autorizado")
    _ensure_groups_exist()

    try:
        payload = json.loads(request.body.decode("utf-8"))
        user_id = int(payload.get("user_id"))
        roles = payload.get("roles", [])
        is_staff = bool(payload.get("is_staff", False))
    except Exception:
        return JsonResponse({"ok": False, "error": "JSON inválido"}, status=400)

    try:
        u = UserModel.objects.get(pk=user_id)
    except UserModel.DoesNotExist:
        return JsonResponse({"ok": False, "error": "Usuario no existe"}, status=404)

    roles = {str(r).strip() for r in roles if str(r).strip() in ALLOWED_ROLE_NAMES}
    if "admin" in roles and "tecnico" in roles:
        return JsonResponse({"ok": False, "error": "admin y técnico son excluyentes"}, status=400)

    # no dejar el sistema sin admin
    if "admin" not in roles and (
        u.groups.filter(name="admin").exists() or u.is_superuser or u.is_staff
    ):
        if not UserModel.objects.filter(groups__name="admin").exclude(pk=u.pk).exists():
            return JsonResponse({"ok": False, "error": "Debe quedar al menos un admin"}, status=400)

    u.is_staff = is_staff
    u.save(update_fields=["is_staff"])

    # reemplaza los grupos gestionados
    current = set(u.groups.values_list("name", flat=True))
    managed_current = current & ALLOWED_ROLE_NAMES
    if managed_current:
        u.groups.remove(*Group.objects.filter(name__in=managed_current))
    if roles:
        u.groups.add(*Group.objects.filter(name__in=roles))

    return JsonResponse({"ok": True})

@login_required
@user_passes_test(_is_admin_or_tech)
def maint_roles_set(request):
    import json
    try:
        payload = json.loads(request.body or "{}")
        user_id = int(payload.get("user_id"))
        roles = payload.get("roles", [])
    except Exception:
        return JsonResponse({"error":"JSON inválido"}, status=400)

    if not user_id:
        return JsonResponse({"error":"user_id requerido"}, status=400)

    # Exclusión admin/tecnico
    if "admin" in roles and "tecnico" in roles:
        return JsonResponse({"error":"admin y técnico son excluyentes"}, status=400)

    _ensure_groups_exist()
    user = get_user_model().objects.filter(pk=user_id).first()
    if not user:
        return JsonResponse({"error":"Usuario no existe"}, status=404)

    # No dejar el sistema sin admin
    if "admin" not in roles:
        hay_otro_admin = get_user_model().objects.filter(groups__name="admin").exclude(pk=user.pk).exists()
        if not hay_otro_admin:
            return JsonResponse({"error":"Debe quedar al menos un admin en el sistema"}, status=400)

    # Normaliza y aplica
    roles = [r for r in {str(r).strip() for r in roles} if r in ALLOWED_ROLE_NAMES]
    # Limpia solo roles manejados
    current = set(user.groups.values_list("name", flat=True))
    manejados = current & ALLOWED_ROLE_NAMES
    if manejados:
        user.groups.remove(*Group.objects.filter(name__in=manejados))
    if roles:
        user.groups.add(*Group.objects.filter(name__in=roles))

    return JsonResponse({"ok": True, "roles": list(user.groups.values_list("name", flat=True))})


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


@swagger_auto_schema(method="get", manual_parameters=FILTER_QUERY_PARAMS)
@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def metrics_summary(request):
    qs = _visible_qs(request.user)
    qs = apply_ticket_filters(qs, request)
    service = TicketMetricsService(
        qs.only("id", "created_at", "requester_id", "priority", "state")
    )
    summary = service.summarize()
    payload = {
        "total": summary["total"],
        "by_state": summary["by_state"],
        "critical": summary["critical"],
        "mttr_minutes": summary["mttr_minutes"],
        "frt_minutes": summary["frt_minutes"],
    }
    payload.update(summary["by_state"])
    return Response(payload)

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
            "techs": techs,          # para el filtro de técnico/asignado
            "categories": categories # para el filtro de categoría
        },
    )