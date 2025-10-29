from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from tickets.models import Category, FAQ, FAQFeedback, Ticket, TicketLog


class AssetHistoryAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.admin = User.objects.create_user("admin", password="pass", is_staff=True)
        category = Category.objects.create(name="Servidores")
        now = timezone.now()
        for idx in range(3):
            ticket = Ticket.objects.create(
                title=f"Incidente {idx}",
                description="",
                requester=self.admin,
                category=category,
                asset_id="SRV-01",
                priority="high" if idx else "medium",
                sla_minutes=60,
            )
            Ticket.objects.filter(pk=ticket.pk).update(created_at=now - timedelta(days=idx * 15))
        self.client.login(username="admin", password="pass")

    def test_history_flags_threshold(self):
        response = self.client.get("/api/assets/SRV-01/tickets/?n=2&m=2")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["asset_id"], "SRV-01")
        self.assertEqual(payload["total"], 3)
        self.assertTrue(payload["rule"]["triggered"])
        self.assertEqual(len(payload["results"]), 3)

    def test_history_csv_export(self):
        response = self.client.get("/api/assets/SRV-01/tickets/?format=csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response["Content-Type"])
        self.assertIn("asset_SRV-01_tickets.csv", response["Content-Disposition"])


class FAQViewsTests(TestCase):
    def setUp(self):
        self.category = Category.objects.create(name="Correo")
        self.faq = FAQ.objects.create(
            category=self.category,
            question="¿Cómo reinicio mi correo?",
            answer="Sigue estos pasos...",
        )
        self.user = User.objects.create_user("jane", password="pass")

    def test_api_search_filters_by_query(self):
        client = APIClient()
        response = client.get(f"/api/faqs/?search=reinicio&category={self.category.pk}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["question"], self.faq.question)

    def test_web_feedback_records_ticketlog(self):
        self.client.login(username="jane", password="pass")
        response = self.client.post(
            f"/faq/{self.faq.pk}/unresolved/",
            {"comment": "No encontré mi versión", "q": "correo"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        feedback = FAQFeedback.objects.latest("created_at")
        self.assertEqual(feedback.faq, self.faq)
        log = TicketLog.objects.filter(action="faq.unresolved").latest("created_at")
        self.assertEqual(log.meta_json.get("faq_id"), self.faq.pk)
        self.assertTrue(log.is_critical)


class SecurityLoggingTests(TestCase):
    def setUp(self):
        User.objects.create_user("agent", password="pass")

    def test_failed_login_is_audited(self):
        response = self.client.post("/auth/login/", {"username": "agent", "password": "wrong"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(TicketLog.objects.filter(action="auth.login_failed").exists())
