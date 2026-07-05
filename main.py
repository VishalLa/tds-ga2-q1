import os
import uuid
import time
from typing import Callable

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

import api

app = FastAPI(title="Tds GA2")

origins = [
    "https://dash-wobted.example.com"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_headers=["Authorization", "Content-Type"],
    allow_methods=["GET", "POST"],
)

# Header Middleware 
@app.middleware("http")
async def add_process_time_and_id_header(request: Request, call_next: Callable):
    request_id = str(uuid.uuid4())
    start_time = time.perf_counter()

    response = await call_next(request)

    process_time = time.perf_counter() - start_time

    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = str(process_time)

    return response


app.include_router(api.app)



# if __name__ == "__main__":
#     port = int(os.environ.get("PORT", 8000))
    
#     uvicorn.run("main:app", host="0.0.0.0", port=port)
