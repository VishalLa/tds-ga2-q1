import os
import uuid
import time
from typing import Callable

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

import api
from config import LOGS, REQUEST_COUNTER

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



# if __name__ == "__main__":
#     port = int(os.environ.get("PORT", 8000))
    
#     uvicorn.run("main:app", host="0.0.0.0", port=port)
