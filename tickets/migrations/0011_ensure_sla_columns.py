from django.db import migrations, models


def ensure_sla_columns(apps, schema_editor):
    Ticket = apps.get_model("tickets", "Ticket")
    table_name = Ticket._meta.db_table
    connection = schema_editor.connection
    with connection.cursor() as cursor:
        existing_columns = {
            column.name for column in connection.introspection.get_table_description(cursor, table_name)
        }

    field_definitions = [
        ("sla_minutes", models.PositiveIntegerField(null=True, blank=True)),
        ("due_at", models.DateTimeField(null=True, blank=True)),
        ("breach_risk", models.BooleanField(default=False)),
    ]

    for field_name, field in field_definitions:
        if field_name in existing_columns:
            continue
        field.set_attributes_from_name(field_name)
        schema_editor.add_field(Ticket, field)


class Migration(migrations.Migration):

    dependencies = [
        ("tickets", "0010_ticket_sla_fields"),
    ]

    operations = [
        migrations.RunPython(ensure_sla_columns, migrations.RunPython.noop),
    ]
