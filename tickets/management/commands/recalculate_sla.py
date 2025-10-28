import logging

from django.core.management.base import BaseCommand
from django.utils import timezone

from ...models import Ticket
from ...services.sla import refresh_ticket_sla

logger = logging.getLogger("tickets.sla")


class Command(BaseCommand):
    help = "Recalcula los vencimientos de SLA y marca tickets en riesgo."

    def add_arguments(self, parser):
        parser.add_argument(
            "--only-open",
            action="store_true",
            help="Procesa solo tickets abiertos o en progreso.",
        )

    def handle(self, *args, **options):
        qs = Ticket.objects.all()
        if options.get("only_open"):
            qs = qs.filter(state__in=["open", "in_progress"])
        total = qs.count()
        updated = 0
        for ticket in qs.iterator():
            changes = refresh_ticket_sla(ticket, reference=timezone.now())
            if changes:
                updated += 1
                logger.info("Ticket %s con SLA actualizado: %s", ticket.pk, changes)
        self.stdout.write(self.style.SUCCESS(f"Tickets procesados: {total}, actualizados: {updated}"))
