import time
from collections import defaultdict
from typing import Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse


class InMemoryRateLimiter:
    def __init__(self, max_requests: int = 5, window_seconds: int = 60):
        self._max_requests = max_requests
        self._window = window_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)

    def check(self, key: str) -> bool:
        now = time.time()
        self._attempts[key] = [t for t in self._attempts[key] if now - t < self._window]
        if len(self._attempts[key]) >= self._max_requests:
            return False
        self._attempts[key].append(now)
        return True

    def get_remaining(self, key: str) -> int:
        now = time.time()
        self._attempts[key] = [t for t in self._attempts[key] if now - t < self._window]
        return max(0, self._max_requests - len(self._attempts[key]))


login_limiter = InMemoryRateLimiter(max_requests=5, window_seconds=60)


def rate_limit_middleware(max_requests: int = 100, window_seconds: int = 60) -> Callable:
    limiter = InMemoryRateLimiter(max_requests, window_seconds)

    async def middleware(request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        if not limiter.check(client_ip):
            return JSONResponse(
                status_code=429,
                content={
                    "status": "error",
                    "error": {
                        "error_code": "RATE_LIMIT_EXCEEDED",
                        "message": "Too many requests. Please try again later.",
                    },
                },
            )
        response = await call_next(request)
        response.headers["X-RateLimit-Remaining"] = str(limiter.get_remaining(client_ip))
        return response

    return middleware
