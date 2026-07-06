import json
import base64
import uuid
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, Response

from config import CATALOG, TOTAL_ORDERS, IDEMPOTENCY_TTL_SEC
from cache import cache

app = APIRouter()

@app.get("/extract/orders")
def get_paginated_order(limit: int = 10, cursor: Optional[str] = None):
    start_index = 0

    if cursor:
        try:
            decoded_cursor = base64.b64decode(cursor).decode('utf-8')
            start_index = int(decoded_cursor)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid cursor format")

    end_index = start_index + limit

    items = CATALOG[start_index:end_index]
    next_cursor = None
    if end_index < TOTAL_ORDERS:
        next_cursor = base64.b64encode(str(end_index).encode('utf-8')).decode('utf-8')

    return {
        "items": items,
        "next_cursor": next_cursor
    }


@app.post("/extract/orders", status_code=201)
async def create_idempotent_order(request: Request, response: Response):
    idempotency_key = request.headers.get("idempotency-key")

    if not idempotency_key:
        raise HTTPException(status_code=400, detail="Idempotency-Key header is required")

    redis_key = f"idempotency:order:{idempotency_key}"
    cached_response = await cache.get(redis_key)

    if cached_response:
        response.status_code = 201
        return json.loads(cached_response)

    new_order = {
        "id": str(uuid.uuid4()),
        "status": "processing"
    }

    await cache.setex(
        redis_key,
        IDEMPOTENCY_TTL_SEC,
        json.dumps(new_order)
    )

    return new_order
