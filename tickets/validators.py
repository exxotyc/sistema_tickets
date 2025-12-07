from django.core.exceptions import ValidationError
from PIL import Image

def validate_safe_image(file):
    """
    Valida una imagen con Pillow:
    - No excede 2MB
    - El archivo contiene una imagen REAL
    - El formato es válido (JPEG, PNG, WEBP)
    """

    # -------------------------
    # 1. Tamaño máximo (2MB)
    # -------------------------
    max_size = 2 * 1024 * 1024
    if file.size > max_size:
        raise ValidationError("La imagen excede el tamaño máximo permitido (2MB).")

    # -------------------------
    # 2. Validar tipo real de imagen
    # -------------------------
    try:
        img = Image.open(file)
        img.verify()  # Detecta imágenes corruptas o manipuladas
    except Exception:
        raise ValidationError("El archivo no es una imagen válida o está dañado.")

    # -------------------------
    # 3. Revisar formato permitido
    # -------------------------
    allowed_formats = ["JPEG", "PNG", "WEBP"]
    if img.format not in allowed_formats:
        raise ValidationError("Formato de imagen no permitido. Use JPG, PNG o WebP.")

    return file
