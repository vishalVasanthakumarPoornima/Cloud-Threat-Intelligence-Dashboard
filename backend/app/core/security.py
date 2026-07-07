import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable

from fastapi import Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import Settings


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_bytes: int, upload_max_bytes: int):
        super().__init__(app)
        self.max_bytes = max_bytes
        self.upload_max_bytes = upload_max_bytes

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        content_length = request.headers.get("content-length")
        max_bytes = self.upload_max_bytes if _is_file_upload(request) else self.max_bytes
        if content_length and int(content_length) > max_bytes:
            return Response(
                content="Request body too large.",
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            )
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response


class AnalyzeRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings: Settings):
        super().__init__(app)
        self.limit = settings.analyze_rate_limit_per_minute
        self.window_seconds = 60
        self._requests: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if _is_analyze_request(request):
            key = request.client.host if request.client else "unknown"
            now = time.monotonic()
            bucket = self._requests[key]
            while bucket and now - bucket[0] > self.window_seconds:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return Response(
                    content="Rate limit exceeded.",
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                )
            bucket.append(now)
        return await call_next(request)


def _is_file_upload(request: Request) -> bool:
    return request.url.path.endswith("/analyze/file") and request.method == "POST"


def _is_analyze_request(request: Request) -> bool:
    return request.method == "POST" and (
        request.url.path.endswith("/analyze")
        or request.url.path.endswith("/analyze/file")
        or request.url.path.endswith("/active-scan/ports")
        or request.url.path.endswith("/active-scan/nmap")
    )
