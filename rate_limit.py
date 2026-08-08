"""
Lightweight in-memory rate limiter, scoped to AI endpoints only
(e.g. /ask-ai). Does not affect the URL/QR/camera/voice/email/IDS routes.

This uses a per-client fixed window counter. It is process-local, which is
fine for a single-instance deployment; for multi-instance production
deployments, swap the in-memory store for Redis (the interface below is
small and easy to replace).
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict, Iterable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from config import settings
from utils.logger import get_logger

logger = get_logger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        protected_paths: Iterable[str] = ("/ask-ai",),
        max_requests: int | None = None,
        window_seconds: int | None = None,
    ) -> None:
        super().__init__(app)
        self.protected_paths = tuple(protected_paths)
        self.max_requests = max_requests or settings.RATE_LIMIT_REQUESTS
        self.window_seconds = window_seconds or settings.RATE_LIMIT_WINDOW_SECONDS
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    @staticmethod
    def _client_key(request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith(self.protected_paths):
            return await call_next(request)

        key = self._client_key(request)
        now = time.time()
        window = self._hits[key]

        while window and now - window[0] > self.window_seconds:
            window.popleft()

        if len(window) >= self.max_requests:
            retry_after = max(1, int(self.window_seconds - (now - window[0])))
            logger.warning(
                "rate_limit_exceeded client=%s path=%s", key, request.url.path
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limited",
                    "message": "Too many AI requests. Please slow down and try again.",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        window.append(now)
        return await call_next(request)
