# tickets/views.py
from datetime import timedelta
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

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Ticket, Category, TicketLog, Comment, Attachment, Section
from .permissions import IsRequesterOrAssignedOrAdmin
from .serializers import (
    TicketSerializer, CategorySerializer, TicketLogSerializer,
    CommentSerializer, AttachmentSerializer,
)

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
    permission_classes = [IsRequesterOrAssignedOrAdmin]
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
        user_id = request.data.get("user_id")
        try:
            user = UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        ticket.assigned_to = user
        ticket.save()
        TicketLog.objects.create(
            ticket=ticket,
            user=request.user,
            action="reassigned",
            meta_json={"to": user.id, "username": user.username},
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
    serializer_class = AttachmentSerializer
    permission_classes = [permissions.IsAuthenticated, IsRequesterOrAssignedOrAdmin]
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
def _parse_range(request):
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

def _apply_filters(qs, request):
    fdt, tdt = _parse_range(request)
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

def _first_resolution_dt(ticket):
    """Primera fecha de resolución basada en TicketLog (resolved/closed) si existe; si no, None."""
    log = (TicketLog.objects
           .filter(ticket=ticket, action__in=["resolved", "closed"])
           .order_by("created_at")
           .first())
    return log.created_at if log else None

def _first_response_dt(ticket):
    """
    FRT: primera respuesta de alguien distinto del solicitante.
    Preferimos primer Comment de user != requester; si no, primer log de otro user.
    """
    c = (Comment.objects
         .filter(ticket=ticket)
         .exclude(user=ticket.requester)
         .order_by("created_at")
         .first())
    if c:
        return c.created_at
    l = (TicketLog.objects
         .filter(ticket=ticket)
         .exclude(user=ticket.requester)
         .order_by("created_at")
         .first())
    return l.created_at if l else None

def _compute_summary(qs):
    total = qs.count()
    states = {
        "open": qs.filter(state="open").count(),
        "in_progress": qs.filter(state="in_progress").count(),
        "resolved": qs.filter(state="resolved").count(),
        "closed": qs.filter(state="closed").count(),
    }
    crit = qs.filter(priority__in=["high", "critical"]).count()

    # MTTR en horas y FRT en minutos (promedios)
    mttr_sum = 0.0
    mttr_n = 0
    frt_sum = 0.0
    frt_n = 0

    # Optimiza trayendo relaciones
    qs_iter = qs.select_related("requester", "assigned_to", "category").only(
        "id", "created_at", "requester_id", "priority", "state"
    )

    for t in qs_iter:
        # MTTR
        rdt = _first_resolution_dt(t)
        if rdt:
            delta = rdt - t.created_at
            mttr_sum += delta.total_seconds() / 3600.0
            mttr_n += 1
        # FRT
        fdt = _first_response_dt(t)
        if fdt:
            delta = fdt - t.created_at
            frt_sum += delta.total_seconds() / 60.0
            frt_n += 1

    mttr_hours = round(mttr_sum / mttr_n, 2) if mttr_n else None
    frt_minutes = round(frt_sum / frt_n, 2) if frt_n else None

    return {
        "total": total,
        "by_state": states,
        "critical": crit,
        "mttr_hours": mttr_hours,
        "frt_minutes": frt_minutes,
    }

# --- ENDPOINT: /api/metrics/summary ---
def _visible_qs(u):
    return Ticket.objects.all() if _is_admin_or_tech(u) else Ticket.objects.filter(Q(requester=u)|Q(assigned_to=u))

@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def metrics_summary(request):
    qs = _visible_qs(request.user)

    f = (request.GET.get("from") or "").strip()
    t = (request.GET.get("to") or "").strip()
    cat = (request.GET.get("category") or "").strip()
    asg = (request.GET.get("assignee") or "").strip()
    prio = (request.GET.get("priority") or "").strip()

    tz = get_current_timezone()
    # fechas inclusivas
    try:
        if f:
            start = make_aware(datetime.combine(datetime.fromisoformat(f).date(), time.min), tz)
            qs = qs.filter(created_at__gte=start)
        if t:
            end = make_aware(datetime.combine(datetime.fromisoformat(t).date(), time.max), tz)
            qs = qs.filter(created_at__lte=end)
    except ValueError:
        pass

    if cat.isdigit():
        qs = qs.filter(category_id=int(cat))
    if asg.isdigit():
        qs = qs.filter(assigned_to_id=int(asg))
    if prio in ("low","medium","high"):
        qs = qs.filter(priority=prio)

    # conteos por estado
    state_counts = {s:0 for s in ("open","in_progress","resolved","closed")}
    for row in qs.values("state").annotate(c=Count("id")):
        state_counts[row["state"]] = row["c"]

    critical = qs.filter(priority="high").count()

    # MTTR (resuelto/cerrado) y FRT (primer log distinto al creador)
    tickets = list(qs.only("id","created_at","updated_at","state","requester_id"))
    ids = [t.id for t in tickets]
    logs = TicketLog.objects.filter(ticket_id__in=ids).order_by("created_at") \
            .values("ticket_id","user_id","created_at")

    first_log = {}
    for lg in logs:
        if lg["ticket_id"] not in first_log:
            first_log[lg["ticket_id"]] = lg["created_at"]

    mttr_sum = mttr_n = frt_sum = frt_n = 0
    for t in tickets:
        if t.state in ("resolved","closed") and t.updated_at and t.updated_at > t.created_at:
            mttr_sum += (t.updated_at - t.created_at).total_seconds(); mttr_n += 1
        fl = first_log.get(t.id)
        if fl and fl > t.created_at:
            frt_sum += (fl - t.created_at).total_seconds(); frt_n += 1

    def to_hours(total, n): return round((total/n)/3600, 2) if n else 0.0

    return Response({
        **state_counts,
        "critical": critical,
        "mttr_hours": to_hours(mttr_sum, mttr_n),
        "frt_hours": to_hours(frt_sum, frt_n),
    })

# --- ENDPOINT: /api/reports/export ---
@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def reports_export(request):
    fmt = (request.GET.get("format") or "csv").lower()
    qs = Ticket.objects.select_related("category", "assigned_to", "requester")
    if not _is_admin_or_tech(request.user):
        qs = qs.filter(Q(requester=request.user) | Q(assigned_to=request.user))
    qs = _apply_filters(qs, request).order_by("-created_at")

    # compone filas
    rows = []
    for t in qs:
        rdt = _first_resolution_dt(t)
        frt = _first_response_dt(t)
        mttr_h = round(((rdt - t.created_at).total_seconds() / 3600.0), 2) if rdt else ""
        frt_m = round(((frt - t.created_at).total_seconds() / 60.0), 2) if frt else ""
        rows.append([
            t.id,
            t.title or "",
            t.state,
            t.priority,
            getattr(t.category, "name", "") if t.category_id else "",
            getattr(t.assigned_to, "username", "") if t.assigned_to_id else "",
            t.created_at.astimezone(timezone.get_current_timezone()).strftime("%Y-%m-%d %H:%M"),
            rdt.astimezone(timezone.get_current_timezone()).strftime("%Y-%m-%d %H:%M") if rdt else "",
            mttr_h,
            frt_m,
        ])

    # pie con filtros
    footer = {
        "from": request.GET.get("from") or "",
        "to": request.GET.get("to") or "",
        "category": request.GET.get("category") or "",
        "assignee": request.GET.get("assignee") or "",
        "priority": request.GET.get("priority") or "",
    }

    # CSV siempre disponible
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["ID","Título","Estado","Prioridad","Categoría","Asignado a","Creado","Resuelto","MTTR(h)","FRT(min)"])
        for r in rows:
            w.writerow(r)
        w.writerow([])
        w.writerow([f"Parámetros: {footer}"])
        out = buf.getvalue().encode("utf-8-sig")
        return Response(out, headers={
            "Content-Type": "text/csv; charset=utf-8",
            "Content-Disposition": 'attachment; filename="tickets_report.csv"',
        })

    # XLSX si openpyxl presente
    if fmt == "xlsx":
        if not openpyxl:
            return Response({"error":"openpyxl no instalado"}, status=501)
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Reporte"
        ws.append(["ID","Título","Estado","Prioridad","Categoría","Asignado a","Creado","Resuelto","MTTR(h)","FRT(min)"])
        for r in rows:
            ws.append(r)
        ws.append([])
        ws.append([f"Parámetros: {footer}"])
        b = io.BytesIO(); wb.save(b)
        return Response(b.getvalue(), headers={
            "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "Content-Disposition": 'attachment; filename="tickets_report.xlsx"',
        })

    # PDF simple si reportlab presente
    if fmt == "pdf":
        if not canvas:
            return Response({"error":"reportlab no instalado"}, status=501)
        b = io.BytesIO()
        c = canvas.Canvas(b)
        c.setFont("Helvetica", 10)
        y = 800
        c.drawString(40, y, "Reporte de Tickets"); y -= 20
        c.drawString(40, y, f"Parámetros: {footer}"); y -= 30
        c.drawString(40, y, "ID  Título  Estado  Prioridad  Categoría  Asignado  Creado  Resuelto  MTTR  FRT"); y -= 15
        for r in rows[:600]:  # corte simple
            line = "  ".join(str(x) for x in r[:10])
            c.drawString(40, y, line[:180]); y -= 12
            if y < 60:
                c.showPage(); y = 800
                c.setFont("Helvetica", 10)
        c.showPage(); c.save()
        return Response(b.getvalue(), headers={
            "Content-Type": "application/pdf",
            "Content-Disposition": 'attachment; filename="tickets_report.pdf"',
        })

    return Response({"error":"format inválido (csv|xlsx|pdf)"}, status=400) 

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