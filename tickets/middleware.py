import logging
from datetime import datetime

from django.utils.deprecation import MiddlewareMixin


class AccessLogMiddleware(MiddlewareMixin):
    logger = logging.getLogger("tickets.access")

    def process_response(self, request, response):
        user = getattr(request, "user", None)
        username = getattr(user, "username", None) if user and user.is_authenticated else "anon"
        ip = request.META.get("REMOTE_ADDR") if hasattr(request, "META") else None
        self.logger.info(
            "method=%s path=%s status=%s user=%s ip=%s ts=%s",
            request.method,
            request.get_full_path() if hasattr(request, "get_full_path") else getattr(request, "path", ""),
            response.status_code,
            username,
            ip,
            datetime.utcnow().isoformat(),
        )
        return response
