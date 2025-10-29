# Checklist OWASP API/Aplicación

- [x] Autenticación fuerte mediante JWT y sesión con expiración controlada.
- [x] Autorización granular basada en roles para proteger recursos sensibles.
- [x] Registro de eventos críticos (intentos de login fallidos, cambios de permisos, feedback negativo).
- [x] Limitación de tasa para mitigar ataques de fuerza bruta y abuso de endpoints.
- [x] Validación estricta de parámetros en filtros y exportaciones.
- [x] Protección CSRF activa en vistas web y uso de `@csrf_exempt` solo donde existe mitigación alternativa.
- [x] Uso de HTTPS recomendado (configurable mediante variables de entorno en despliegue).
- [x] Gestión de errores controlada con mensajes genéricos para evitar filtración de detalles internos.
- [x] Auditoría de accesos mediante middleware de logging dedicado.
- [x] Respaldo de configuraciones sensibles via variables de entorno (`SECRET_KEY`, credenciales DB).
