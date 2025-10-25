from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from tickets.models import Ticket, Category

class RBACCrud(TestCase):
    def setUp(self):
        self.req = User.objects.create_user("req", password="x")
        self.tech = User.objects.create_user("tech", password="x")
        self.admin = User.objects.create_superuser("admin","a@a.com","x")
        self.cat = Category.objects.create(name="General")
        self.t = Ticket.objects.create(title="A", description="d", requester=self.req, category=self.cat)

    def test_owner_reads_own(self):
        c = APIClient(); c.login(username="req", password="x")
        r = c.get("/api/tickets/")
        self.assertEqual(r.status_code, 200); self.assertEqual(r.data["count"], 1)

    def test_tech_sees_assigned(self):
        self.t.assigned_to = self.tech; self.t.save()
        c = APIClient(); c.login(username="tech", password="x")
        r = c.get("/api/tickets/")
        self.assertEqual(r.data["count"], 1)

    def test_admin_sees_all(self):
        c = APIClient(); c.login(username="admin", password="x")
        r = c.get("/api/tickets/")
        self.assertGreaterEqual(r.data["count"], 1)

    def test_invalid_transition(self):
        c = APIClient(); c.login(username="req", password="x")
        r = c.patch(f"/api/tickets/{self.t.id}/", {"state": "closed"}, format="json")
        self.assertEqual(r.status_code, 400)
