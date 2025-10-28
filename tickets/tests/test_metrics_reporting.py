from datetime import datetime, timedelta
import json
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth.models import Group, User
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from tickets.models import Category, Comment, Ticket, TicketLog


class MetricsAndReportsTests(TestCase):
    maxDiff = None

    def setUp(self):
        self.client = APIClient()
        self.group = Group.objects.get_or_create(name="tecnico")[0]
        self.requester = User.objects.create_user("requester", password="pass")
        self.agent = User.objects.create_user("agent", password="pass")
        self.agent.groups.add(self.group)

        self.category = Category.objects.create(name="Soporte")
        self._create_sample_tickets()

    def _create_sample_tickets(self):
        base_dt = timezone.make_aware(datetime(2023, 1, 1, 8, 0))

        critical_ticket = Ticket.objects.create(
            title="Corte crítico",
            description="",
            requester=self.requester,
            assigned_to=self.agent,
            category=self.category,
            priority="critical",
            state="closed",
        )
        Ticket.objects.filter(pk=critical_ticket.pk).update(created_at=base_dt)
        critical_ticket.refresh_from_db()

        comment = Comment.objects.create(
            ticket=critical_ticket,
            user=self.agent,
            body="Primera respuesta",
        )
        Comment.objects.filter(pk=comment.pk).update(
            created_at=base_dt + timedelta(minutes=60)
        )

        resolution_log = TicketLog.objects.create(
            ticket=critical_ticket,
            user=self.agent,
            action="state_change",
            meta_json={"from": "open", "to": "closed"},
        )
        TicketLog.objects.filter(pk=resolution_log.pk).update(
            created_at=base_dt + timedelta(minutes=180)
        )

        secondary = Ticket.objects.create(
            title="Consulta general",
            description="",
            requester=self.requester,
            category=self.category,
            priority="medium",
        )
        Ticket.objects.filter(pk=secondary.pk).update(
            created_at=base_dt + timedelta(days=1)
        )

    def _login(self):
        logged = self.client.login(username="agent", password="pass")
        self.assertTrue(logged)

    def test_metrics_summary_matches_fixture(self):
        self._login()
        response = self.client.get("/api/metrics/summary/")
        self.assertEqual(response.status_code, 200)

        fixture_path = Path(__file__).resolve().parent / "fixtures" / "metrics_summary.json"
        with fixture_path.open("r", encoding="utf-8") as fh:
            expected = json.load(fh)

        self.assertEqual(response.json(), expected)

    def test_reports_export_includes_footer_and_elapsed_header(self):
        self._login()
        with patch("tickets.views.perf_counter", side_effect=[100.0, 100.42]):
            response = self.client.get("/api/reports/export/?format=csv")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["X-Export-Generation"], "0.420000")

        content = response.content.decode("utf-8-sig")
        self.assertIn("MTTR(min)", content)
        self.assertIn("FRT(min)", content)
        self.assertIn("Parámetros: {'from': '', 'to': '', 'category': '', 'assignee': '', 'priority': ''}", content)
