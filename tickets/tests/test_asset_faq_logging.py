from datetime import timedelta

from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from tickets.models import Category, FAQ, Ticket, TicketLog


class BaseApiTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        Group.objects.get_or_create(name="tecnico")
        self.user = User.objects.create_user("tester", password="pass")
        self.category = Category.objects.create(name="Infraestructura")
        self.client.login(username="tester", password="pass")


class AssetHistoryTests(BaseApiTestCase):
    def _create_ticket(self, days_ago, title):
        ticket = Ticket.objects.create(
            title=title,
            description="desc",
            requester=self.user,
            category=self.category,
            asset_id="router-01",
        )
        created_at = timezone.now() - timedelta(days=days_ago)
        Ticket.objects.filter(pk=ticket.pk).update(created_at=created_at)
        ticket.refresh_from_db()
        return ticket

    def test_asset_history_applies_n_m_rule(self):
        recent = self._create_ticket(1, "Reciente")
        self._create_ticket(2, "Segundo")
        self._create_ticket(9, "Viejo")

        response = self.client.get("/api/assets/router-01/tickets/?n=2&m=7")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["asset"], "router-01")
        tickets = payload["tickets"]
        self.assertEqual(len(tickets), 2)
        self.assertEqual(tickets[0]["id"], recent.id)
        self.assertTrue(all(t["asset_id"] == "router-01" for t in tickets))

    @override_settings(REST_FRAMEWORK={
        "DEFAULT_AUTHENTICATION_CLASSES": ("rest_framework_simplejwt.authentication.JWTAuthentication",),
        "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
        "DEFAULT_FILTER_BACKENDS": (
            "django_filters.rest_framework.DjangoFilterBackend",
            "rest_framework.filters.SearchFilter",
            "rest_framework.filters.OrderingFilter",
        ),
        "DEFAULT_THROTTLE_CLASSES": (
            "rest_framework.throttling.UserRateThrottle",
            "rest_framework.throttling.AnonRateThrottle",
            "rest_framework.throttling.ScopedRateThrottle",
        ),
        "DEFAULT_THROTTLE_RATES": {
            "user": "1000/day",
            "anon": "100/day",
            "assets": "1/minute",
        },
    })
    def test_asset_history_enforces_throttle(self):
        self.client.force_login(self.user)
        url = "/api/assets/router-01/tickets/"
        first = self.client.get(url)
        self.assertEqual(first.status_code, 200)
        second = self.client.get(url)
        self.assertEqual(second.status_code, 429)


class FAQTests(BaseApiTestCase):
    def setUp(self):
        super().setUp()
        self.faq = FAQ.objects.create(
            category=self.category,
            question="Cómo reinicio el router?",
            answer="Desconectar y conectar",
        )
        FAQ.objects.create(
            category=self.category,
            question="Configurar switch",
            answer="Manual",
        )

    def test_faq_search_by_text(self):
        response = self.client.get("/api/faqs/?search=router")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["results"]), 1)
        self.assertEqual(data["results"][0]["id"], self.faq.id)

    def test_faq_metrics_include_unresolved_counts(self):
        response = self.client.post(
            f"/api/faqs/{self.faq.id}/mark_unresolved/",
            {"comment": "No funcionó"},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        metrics = self.client.get("/api/faqs/metrics/")
        self.assertEqual(metrics.status_code, 200)
        payload = metrics.json()
        self.assertEqual(payload["total_faqs"], 2)
        self.assertEqual(payload["unresolved_events"], 1)
        self.assertTrue(any(item["faq_id"] == self.faq.id for item in payload["by_faq"]))
        log = TicketLog.objects.filter(action="faq.unresolved").latest("created_at")
        self.assertFalse(log.is_critical)


class SecurityLoggingTests(BaseApiTestCase):
    def test_access_logging_emits_records(self):
        with self.assertLogs("tickets.access", level="INFO") as captured:
            response = self.client.get("/api/stats/")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any("/api/stats/" in line for line in captured.output))

    def test_login_failure_creates_critical_log(self):
        self.client.logout()
        User.objects.create_user("other", password="pass")
        login_page = self.client.get("/auth/login/")
        self.assertEqual(login_page.status_code, 200)
        csrf = self.client.cookies.get("csrftoken")
        response = self.client.post(
            "/auth/login/",
            {"username": "other", "password": "bad", "csrfmiddlewaretoken": csrf.value if csrf else ""},
            HTTP_REFERER="/auth/login/",
        )
        self.assertEqual(response.status_code, 200)
        log = TicketLog.objects.filter(action="auth.login_failed").latest("created_at")
        self.assertTrue(log.is_critical)
        self.assertIsNone(log.ticket)
