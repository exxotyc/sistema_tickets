# tickets/urls.py
from django.urls import path, include
from django.views.generic import RedirectView
from django.contrib.auth.views import LoginView
from rest_framework import routers
from rest_framework_simplejwt.views import TokenRefreshView
from . import views_users
from . import views
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
)

# ----------------------------
# API router
# ----------------------------
router = routers.DefaultRouter()
router.register(r"tickets", TicketViewSet, basename="tickets")
router.register(r"categories", CategoryViewSet, basename="categories")
router.register(r"logs", TicketLogViewSet, basename="logs")
router.register(r"faqs", FAQViewSet, basename="faqs")
router.register(r"users", UserViewSet, basename="users")
router.register(r"comments", CommentViewSet, basename="comments")
router.register(r"attachments", AttachmentViewSet, basename="attachments")

api_urlpatterns = [
    path("token/", MyTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("token/session/", views.session_token, name="token_session"),
    path("stats/", stats, name="stats"),

    # Extra Sprint 3
    path("metrics/summary/", views.metrics_summary, name="metrics_summary"),
    path("reports/export/", views.reports_export, name="reports_export"),
    path("assets/<slug:asset_id>/tickets/", views.asset_ticket_history, name="asset_ticket_history"),

    path("", include(router.urls)),
]

# ----------------------------
# Web URLs
# ----------------------------
web_urlpatterns = [
    path("", views.index, name="index"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("listado/", views.ticket_list, name="ticket_list"),
    path("faq/", views.faq_page, name="faq"),
    path("faq/<int:pk>/unresolved/", views.faq_unresolved, name="faq_unresolved"),
    path("assets/<slug:asset_id>/", views.asset_history_page, name="asset_history"),

    # Tickets
    path("tickets/new/", views.ticket_new, name="ticket_new"),
    path("tickets/<int:pk>/", views.ticket_detail, name="ticket_detail"),
    path("tickets/", views.tickets_alias, name="ticket_list_legacy"),

    # Auth
    path(
        "auth/login/",
        LoginView.as_view(template_name="tickets/login.html", redirect_authenticated_user=True),
        name="login",
    ),
    path("login/", RedirectView.as_view(pattern_name="login", permanent=False)),
    path("login", RedirectView.as_view(pattern_name="login", permanent=False)),
    path("logout/", views.logout_view, name="logout"),

    # ----------------------------
    # Mantenedor
    # ----------------------------
    path("mantenedor/", views.maint_index, name="maint_index"),

    #  MANTENEDOR DE ROLES
    path("mantenedor/roles/", views.maint_roles, name="maint_roles"),
    path("mantenedor/roles/data/", views.roles_data, name="roles_data"),
    path("mantenedor/roles/update/", views.roles_update, name="roles_update"),
    path("mantenedor/roles/set/", views.maint_roles_set, name="maint_roles_set"),


    #Mantenedor de usuarios
    path("mantenedor/usuarios/", views_users.users_page, name="maint_usuarios"),
    path("mantenedor/usuarios/data/", views_users.users_data, name="users_data"),
    path("mantenedor/usuarios/save/", views_users.users_save, name="users_save"),
    path("mantenedor/usuarios/toggle/", views_users.users_toggle_active, name="users_toggle"),
    # Luego la genérica (debe ir al final)
    path("mantenedor/<slug:code>/", views.maint_section, name="maint_section"),

    # Métricas
    path("metrics/", views.metrics_page, name="metrics_page"),
]

urlpatterns = web_urlpatterns + [
    path("api/", include((api_urlpatterns, "tickets"), namespace="api")),
]
