from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [("tickets", "0004_category_created_at_alter_category_name")]
    operations = [
        migrations.AddField(
            model_name="ticketlog",
            name="meta_json",
            field=models.JSONField(default=dict, blank=True),
        ),
    ]
