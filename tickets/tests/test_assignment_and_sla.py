from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from tickets.models import Category, Ticket, TicketLog
from tickets.services.sla import refresh_ticket_sla


class TicketAssignmentTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.admin = User.objects.create_user("admin", password="pass", is_staff=True)
        self.agent = User.objects.create_user("agent", password="pass")
        self.requester = User.objects.create_user("requester", password="pass")
        self.category = Category.objects.create(name="General")
        self.ticket = Ticket.objects.create(
            title="Solicitud",
            description="Detalle",
            requester=self.requester,
            category=self.category,
        )

    def test_reassignment_records_reason_in_log(self):
        self.client.login(username="admin", password="pass")
        response = self.client.patch(
            f"/api/tickets/{self.ticket.pk}/",
            {"assigned_to": self.agent.pk, "assignment_reason": "Cobertura de turnos"},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        log = TicketLog.objects.filter(ticket=self.ticket, action="reassigned").latest("created_at")
        self.assertEqual(log.meta_json.get("to"), self.agent.pk)
        self.assertEqual(log.meta_json.get("reason"), "Cobertura de turnos")
        self.assertIsNone(log.meta_json.get("from"))


class TicketSlaTests(TestCase):
    def setUp(self):
        self.requester = User.objects.create_user("req", password="pass")
        self.category = Category.objects.create(name="General")

    def test_sla_risk_triggers_notification_once(self):
        ticket = Ticket.objects.create(
            title="Incidente",
            description="",
            requester=self.requester,
            category=self.category,
            sla_minutes=30,
        )
        Ticket.objects.filter(pk=ticket.pk).update(created_at=timezone.now() - timedelta(minutes=28))
        ticket.refresh_from_db()

        with patch("tickets.notifications._dispatch") as dispatch:
            refresh_ticket_sla(ticket, reference=timezone.now())
            self.assertTrue(dispatch.called)
            dispatch.reset_mock()
            refresh_ticket_sla(ticket, reference=timezone.now())
            dispatch.assert_not_called()

        ticket.refresh_from_db()
        self.assertTrue(ticket.breach_risk)
        self.assertTrue(TicketLog.objects.filter(ticket=ticket, action="sla_at_risk").exists())
