# tickets/management/commands/seed_roles.py
from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group

class Command(BaseCommand):
    help = "Crea los grupos: admin, tecnico, usuario"

    def handle(self, *args, **kwargs):
        for g in ("admin", "tecnico", "usuario"):
            Group.objects.get_or_create(name=g)
        self.stdout.write(self.style.SUCCESS("Grupos creados: admin, tecnico, usuario"))
