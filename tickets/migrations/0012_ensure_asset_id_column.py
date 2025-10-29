from django.db import migrations, models


def ensure_asset_id_column(apps, schema_editor):
    Ticket = apps.get_model("tickets", "Ticket")
    table_name = Ticket._meta.db_table
    connection = schema_editor.connection
    with connection.cursor() as cursor:
        existing_columns = {
            column.name for column in connection.introspection.get_table_description(cursor, table_name)
        }

    if "asset_id" in existing_columns:
        return

    field = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    field.set_attributes_from_name("asset_id")
    schema_editor.add_field(Ticket, field)


class Migration(migrations.Migration):

    dependencies = [
        ("tickets", "0011_ensure_sla_columns"),
    ]

    operations = [
        migrations.RunPython(ensure_asset_id_column, migrations.RunPython.noop),
    ]
