import os
import uuid
import time
from typing import Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from cache import cache
from api import api, llm_api, new_api
from config import LOGS, REQUEST_COUNTER, RATE_LIMIT_WINDOW_SEC, RATE_LIMIT_MAX_REQS

app = FastAPI(title="Tds GA2")

origins = [
    "https://dash-wobted.example.com",
    "https://exam.sanand.workers.dev",  # <-- Removed the path here
    "https://app-aqq91j.example.com"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_headers=["*"],
    allow_methods=["*"],
    expose_headers=["X-Request-ID", "Retry-After"] 
)

app.include_router(api.app)
app.include_router(llm_api.app)
app.include_router(new_api.app)


@app.middleware("http")
async def track_and_log_requests(request: Request, call_next: Callable):
    REQUEST_COUNTER.inc()
    
    # Read the request_id created by the Request Context Middleware
    req_id = getattr(request.state, "request_id", str(uuid.uuid4()))

    log_entry = {
        "level": "INFO",
        "ts": time.time(),
        "path": request.url.path,
        "request_id": req_id
    }
    LOGS.append(log_entry)

    response = await call_next(request)
    return response


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next: Callable):
    if request.method == "OPTIONS":
        return await call_next(request)

    client_id = request.headers.get("x-client-id")
    if client_id:
        now = time.time()
        redis_key = f"rate_limit:{client_id}"
        cutoff = now - RATE_LIMIT_WINDOW_SEC

        # Drop old requests from the Redis Sorted Set
        await cache.zremrangebyscore(redis_key, 0, cutoff)
        
        # Count how many requests are left in the current 10-second window
        current_count = await cache.zcard(redis_key)

        # Check if they hit the limit
        if current_count >= RATE_LIMIT_MAX_REQS:
            oldest_entry = await cache.zrange(redis_key, 0, 0, withscores=True)
            if oldest_entry:
                oldest_ts = oldest_entry[0][1]
                retry_after = max(1, int(RATE_LIMIT_WINDOW_SEC - (now - oldest_ts)))
            else:
                retry_after = int(RATE_LIMIT_WINDOW_SEC)

            origin = request.headers.get("origin")
            headers = {
                "Retry-After": str(retry_after),
                "X-Request-Id": getattr(request.state, "request_id", "")
            }
            
            if origin in origins:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
                headers["Access-Control-Expose-Headers"] = "X-Request-Id, Retry-After"

            return Response(
                content='{"detail": "Too Many Requests"}',
                status_code=429,
                media_type="application/json",
                headers=headers
            )

        # Record the new request
        request_id = str(uuid.uuid4())
        await cache.zadd(redis_key, {request_id: now})
        await cache.expire(redis_key, int(RATE_LIMIT_WINDOW_SEC) + 2)

    return await call_next(request)


@app.middleware("http")
async def request_context_middleware(request: Request, call_next: Callable):
    req_id = request.headers.get("x-request-id")
    if not req_id:
        req_id = str(uuid.uuid4())

    # Attach to request state so /ping and the logger can read it
    request.state.request_id = req_id

    response = await call_next(request)

    # Attach to the response headers
    response.headers["X-Request-ID"] = req_id
    return response

