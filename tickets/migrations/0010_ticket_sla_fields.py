from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("tickets", "0009_ticket_frt_due_at_ticket_resolve_due_at"),
    ]

    operations = [
        migrations.AddField(
            model_name="ticket",
            name="breach_risk",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="ticket",
            name="due_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="ticket",
            name="sla_minutes",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
    ]
