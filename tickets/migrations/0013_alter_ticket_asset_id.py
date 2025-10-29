from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("tickets", "0012_ensure_asset_id_column"),
    ]

    operations = [
        migrations.AlterField(
            model_name="ticket",
            name="asset_id",
            field=models.CharField(
                max_length=120,
                blank=True,
                db_index=True,
                null=True,
            ),
        ),
    ]
