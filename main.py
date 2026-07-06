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
    "https://exam.sanand.workers.dev/tds-2026-05-ga2"
]

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,
#     allow_credentials=True,
#     allow_headers=["Authorization", "Content-Type"],
#     allow_methods=["GET", "POST"],
# )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Header Middleware
# @app.middleware("http")
# async def add_process_time_and_id_header(request: Request, call_next: Callable):
#     request_id = str(uuid.uuid4())
#     start_time = time.perf_counter()

#     response = await call_next(request)

#     process_time = time.perf_counter() - start_time

#     response.headers["X-Request-ID"] = request_id
#     response.headers["X-Process-Time"] = str(process_time)

#     return response

app.include_router(api.app)
app.include_router(llm_api.app)
app.include_router(new_api.app)

@app.middleware("http")
async def track_and_log_requests(request: Request, call_next: Callable):
    REQUEST_COUNTER.inc()
    req_id = str(uuid.uuid4())

    log_entry = {
        "level": "INFO",
        "ts": time.time(),
        "path": request.url.path,
        "request_id": req_id
    }
    LOGS.append(log_entry)

    response = await call_next(request)
    response.headers["X-Request-ID"] = req_id
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
            # Fetch the oldest request in the window to calculate accurate Retry-After
            oldest_entry = await cache.zrange(redis_key, 0, 0, withscores=True)
            if oldest_entry:
                oldest_ts = oldest_entry[0][1]
                retry_after = max(1, int(RATE_LIMIT_WINDOW_SEC - (now - oldest_ts)))
            else:
                retry_after = int(RATE_LIMIT_WINDOW_SEC)

            return Response(
                content='{"detail": "Too Many Requests"}',
                status_code=429,
                media_type="application/json",
                headers={
                    "Retry-After": str(retry_after),
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Expose-Headers": "Retry-After"
                }
            )

        # if allowed, record the new request
        request_id = str(uuid.uuid4())
        await cache.zadd(redis_key, {request_id: now})

        # set a TTL on the whole key
        await cache.expire(redis_key, int(RATE_LIMIT_WINDOW_SEC) + 2)

    return await call_next(request)



# if __name__ == "__main__":
#     port = int(os.environ.get("PORT", 8000))

#     uvicorn.run("main:app", host="0.0.0.0", port=port)
