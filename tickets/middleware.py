"""Custom middleware utilities for observability and hardening."""
from __future__ import annotations

import logging
from typing import Callable

from django.utils import timezone


access_logger = logging.getLogger("tickets.access")


class AccessLogMiddleware:
    """Log every incoming request once it has been processed."""

    def __init__(self, get_response: Callable):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        user = getattr(request, "user", None)
        username = getattr(user, "username", "anon") if getattr(user, "is_authenticated", False) else "anon"
        access_logger.info(
            "method=%s path=%s status=%s user=%s ip=%s ts=%s",
            request.method,
            request.path,
            getattr(response, "status_code", "?"),
            username,
            request.META.get("REMOTE_ADDR", ""),
            timezone.now().isoformat(),
        )
        return response

