from django.db import migrations

DEFAULT_CATEGORIES = [
    "Incidente","Solicitud","Hardware","Software","Red",
    "Accesos","Infraestructura","Seguridad","Compras TI",
    "Soporte remoto","Otro"
]

def seed(apps, schema_editor):
    Category = apps.get_model("tickets", "Category")
    for name in DEFAULT_CATEGORIES:
        Category.objects.get_or_create(name=name)

def unseed(apps, schema_editor):
    Category = apps.get_model("tickets", "Category")
    Category.objects.filter(name__in=DEFAULT_CATEGORIES).delete()

class Migration(migrations.Migration):

    dependencies = [
        ("tickets", "0001_initial"),  # ajusta si tu inicial no es 0001
    ]

    operations = [
        migrations.RunPython(seed, unseed),
    ]
