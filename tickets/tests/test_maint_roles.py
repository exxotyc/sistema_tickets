from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse


class MaintRolesViewTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user("admin", password="pass", is_staff=True)
        self.regular = User.objects.create_user("tecnico", password="pass")

    def test_dropdown_lists_existing_users(self):
        self.client.login(username="admin", password="pass")
        response = self.client.get(reverse("maint_roles"))
        self.assertEqual(response.status_code, 200)

        users = response.context["users"]
        self.assertTrue(any(u["username"] == self.regular.username for u in users))

        roles_map = response.context["roles_map"]
        self.assertIn(str(self.regular.id), roles_map)
        self.assertEqual(roles_map[str(self.regular.id)], [])
