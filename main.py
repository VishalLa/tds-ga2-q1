import os
import uuid
import time
from typing import Callable

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

import uvicorn

class StatsResponse(BaseModel):
    email: EmailStr
    count: int 
    sum: int 
    min: int
    max: int 
    mean: float

app = FastAPI(title="Tds GA1")

origins = [
    "https://dash-wobted.example.com"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_headers=["Authorization", "Content-Type"],
    allow_methods=["GET"],
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

# API's
@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/stats", response_model=StatsResponse, status_code=200)
def stats(values: str): 
    str_values = values.split(",")
    
    try: 
        int_values = [int(i) for i in str_values]
    except ValueError:
        raise HTTPException(status_code=400, detail="Query values must be comma-separated integers.")

    stats_dict = {
        "email": "23f2003086@ds.study.iitm.ac.in",
        "count": len(int_values),
        "sum": sum(int_values),
        "min": min(int_values),
        "max": max(int_values),
        "mean": sum(int_values) / len(int_values)
    }

    return stats_dict

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    
    uvicorn.run("main:app", host="0.0.0.0", port=port)