import hashlib

from django.contrib.auth.models import Group, User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from rest_framework.test import APIClient

from tickets.models import Attachment, Category, Comment, Ticket, TicketLog


class TicketApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.requester = User.objects.create_user("requester", password="pass")
        self.assignee = User.objects.create_user("assignee", password="pass")
        self.stranger = User.objects.create_user("stranger", password="pass")
        Group.objects.get_or_create(name="tecnico")
        self.category = Category.objects.create(name="General")
        self.ticket = Ticket.objects.create(
            title="Issue",
            description="desc",
            requester=self.requester,
            category=self.category,
        )

    def _login(self, user):
        self.client.logout()
        self.client.login(username=user.username, password="pass")

    def test_stranger_cannot_modify_ticket(self):
        self._login(self.stranger)
        response = self.client.patch(
            f"/api/tickets/{self.ticket.id}/",
            {"title": "New"},
            format="json",
        )
        self.assertEqual(response.status_code, 403)

    def test_assigned_user_can_modify_ticket(self):
        self.ticket.assigned_to = self.assignee
        self.ticket.save()

        self._login(self.assignee)
        response = self.client.patch(
            f"/api/tickets/{self.ticket.id}/",
            {"title": "Updated"},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.title, "Updated")

    def test_valid_transition_creates_log(self):
        self.ticket.assigned_to = self.assignee
        self.ticket.save()

        self._login(self.assignee)
        response = self.client.patch(
            f"/api/tickets/{self.ticket.id}/",
            {"state": "in_progress"},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.state, "in_progress")

        log = TicketLog.objects.filter(ticket=self.ticket).order_by("-created_at").first()
        self.assertIsNotNone(log)
        self.assertEqual(log.meta_json, {"from": "open", "to": "in_progress"})
        self.assertEqual(log.user, self.assignee)

    def test_invalid_transition_returns_error(self):
        self._login(self.requester)
        response = self.client.patch(
            f"/api/tickets/{self.ticket.id}/",
            {"state": "closed"},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.state, "open")

    def test_reopen_transition_allowed(self):
        self.ticket.assigned_to = self.assignee
        self.ticket.state = "in_progress"
        self.ticket.save()
        self.ticket.state = "resolved"
        self.ticket.save()
        self.ticket.state = "closed"
        self.ticket.save()

        self._login(self.assignee)
        response = self.client.patch(
            f"/api/tickets/{self.ticket.id}/",
            {"state": "open"},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.state, "open")

        log = TicketLog.objects.filter(ticket=self.ticket).order_by("-created_at").first()
        self.assertIsNotNone(log)
        self.assertEqual(log.meta_json, {"from": "closed", "to": "open"})
        self.assertEqual(log.user, self.assignee)

    def test_comment_creation(self):
        self.ticket.assigned_to = self.assignee
        self.ticket.save()

        self._login(self.assignee)
        response = self.client.post(
            "/api/comments/",
            {"ticket": self.ticket.id, "content": "Comentario"},
            format="json",
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(Comment.objects.count(), 1)
        comment = Comment.objects.first()
        self.assertEqual(comment.body, "Comentario")
        self.assertEqual(comment.user, self.assignee)

    def test_attachment_metadata_is_populated(self):
        self.ticket.assigned_to = self.assignee
        self.ticket.save()

        self._login(self.assignee)
        payload = SimpleUploadedFile(
            "evidence.txt",
            b"important evidence",
            content_type="text/plain",
        )
        response = self.client.post(
            "/api/attachments/",
            {"ticket": self.ticket.id, "file": payload},
            format="multipart",
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(Attachment.objects.count(), 1)
        attachment = Attachment.objects.first()
        self.assertEqual(attachment.user, self.assignee)
        self.assertEqual(attachment.mime, "text/plain")
        self.assertEqual(attachment.size_bytes, len(b"important evidence"))
        self.assertEqual(
            attachment.sha256,
            hashlib.sha256(b"important evidence").hexdigest(),
        )
