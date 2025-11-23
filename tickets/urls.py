# tickets/urls.py
from django.urls import path, include
from django.views.generic import RedirectView
from django.contrib.auth.views import LoginView
from rest_framework import routers
from rest_framework_simplejwt.views import TokenRefreshView

# Views
from . import views, views_users
from .views import (
    TicketViewSet,
    CategoryViewSet,
    FAQViewSet,
    TicketLogViewSet,
    MyTokenObtainPairView,
    UserViewSet,
    stats,
    CommentViewSet,
    AttachmentViewSet,
    PriorityViewSet,
)

# ============================================================
#   API ROUTER (DRF)
# ============================================================
router = routers.DefaultRouter()
router.register(r"tickets", TicketViewSet, basename="tickets")
router.register(r"categories", CategoryViewSet, basename="categories")
router.register(r"logs", TicketLogViewSet, basename="logs")
router.register(r"faqs", FAQViewSet, basename="faqs")  # ← API FAQ OK
router.register(r"users", UserViewSet, basename="users")
router.register(r"comments", CommentViewSet, basename="comments")
router.register(r"attachments", AttachmentViewSet, basename="attachments")
router.register(r"priorities", PriorityViewSet, basename="priorities")  # ← API Prioridades OK

api_urlpatterns = [
    # JWT
    path("token/", MyTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("token/session/", views.session_token, name="token_session"),

    # API utilidades
    path("stats/", stats, name="stats"),

    # Métricas / Reportes
    path("metrics/summary/", views.metrics_summary, name="metrics_summary"),
    path("reports/export/", views.reports_export, name="reports_export"),

    # Histórico de activos
    path("assets/<slug:asset_id>/tickets/", views.asset_ticket_history, name="asset_ticket_history"),

    # Router DRF
    path("", include(router.urls)),
]

# ============================================================
#   WEB PAGES
# ============================================================
web_urlpatterns = [

    # Home
    path("", views.index, name="index"),
    path("dashboard/", views.dashboard, name="dashboard"),

    # Tickets
    path("listado/", views.ticket_list, name="ticket_list"),
    path("tickets/new/", views.ticket_new, name="ticket_new"),
    path("tickets/<int:pk>/", views.ticket_detail, name="ticket_detail"),
    path("tickets/", views.tickets_alias, name="ticket_list_legacy"),
    path("tickets/todos/", views.ticket_list_all, name="ticket_list_all"),
    path("tickets/mios/", views.ticket_list_assigned, name="ticket_list_assigned"),


    # FAQ del Usuario (vista pública del sistema)
    path("faq/", views.faq_page, name="faq"),
    path("faq/<int:pk>/unresolved/", views.faq_unresolved, name="faq_unresolved"),

    # Activos
    path("assets/<slug:asset_id>/", views.asset_history_page, name="asset_history"),

    # Auth
    path(
        "auth/login/",
        LoginView.as_view(template_name="tickets/login.html", redirect_authenticated_user=True),
        name="login",
    ),
    path("login/", RedirectView.as_view(pattern_name="login", permanent=False)),
    path("login", RedirectView.as_view(pattern_name="login", permanent=False)),
    path("logout/", views.logout_view, name="logout"),

    # ============================================================
    #   MANTENEDOR
    # ============================================================
    path("mantenedor/", views.maint_index, name="maint_index"),

    # Roles
    path("mantenedor/roles/", views.maint_roles, name="maint_roles"),
    path("mantenedor/roles/data/", views.roles_data, name="roles_data"),
    path("mantenedor/roles/update/", views.roles_update, name="roles_update"),
    path("mantenedor/roles/set/", views.maint_roles_set, name="maint_roles_set"),

    # Usuarios
    path("mantenedor/usuarios/", views_users.users_page, name="maint_usuarios"),
    path("mantenedor/usuarios/data/", views_users.users_data, name="users_data"),
    path("mantenedor/usuarios/save/", views_users.users_save, name="users_save"),
    path("mantenedor/usuarios/toggle/", views_users.users_toggle_active, name="users_toggle"),

    # Prioridades
    path("mantenedor/prioridades/", views.maint_prioridades, name="maint_prioridades"),

    # FAQ (🔥 mantenedor FAQ)
    path("mantenedor/faq/", views.maint_faq, name="maint_faq"),

    # ESTE SIEMPRE AL FINAL (genérico)
    path("mantenedor/<slug:code>/", views.maint_section, name="maint_section"),

    # ============================================================
    #   REPORTES / MÉTRICAS / SISTEMA
    # ============================================================
    path("reportes/", views.reports_page, name="reports_page"),
    path("reportes/data/", views.reports_data, name="reports_data"),
    path("reportes/export.csv", views.reports_export_csv, name="reports_export_csv"),
    # Reportes faq metrics 
    path("reportes/faq/", views.reportes_faq, name="reportes_faq"),



    path("metrics/", views.metrics_page, name="metrics_page"),

    path("sistema/", views.sistema_page, name="sistema_page"),
    path("sistema/logs/export/", views.sistema_logs_export, name="sistema_logs_export"),
    path("sistema/usuarios/", views.sistema_user_activity, name="sistema_user_activity"),
    path("sistema/usuarios/toggle/<int:user_id>/", views.sistema_user_toggle_active, name="sistema_user_toggle_active"),
    path("sistema/auth-failed/", views.sistema_auth_failed, name="sistema_auth_failed"),
    path("sistema/mantenimiento-tickets/", views.sistema_ticket_maintenance, name="sistema_ticket_maintenance"),
    path("sistema/health/", views.sistema_health, name="sistema_health"),
    
]

# ============================================================
#   URL FINAL
# ============================================================
urlpatterns = web_urlpatterns + [
    path("api/", include((api_urlpatterns, "tickets"), namespace="api")),
]

