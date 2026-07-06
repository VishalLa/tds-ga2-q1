import os
import jwt
import time
import yaml
import redis

from fastapi import APIRouter, HTTPException, Depends, Query, Header, Response
from fastapi.responses import JSONResponse
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from schema import StatsResponse, TokenRequest, Event, AnalyticsRequest
from config import get_setting, START_TIME, LOGS
from cache import cache

from typing import Optional, List
from collections import defaultdict
from dotenv import dotenv_values

app = APIRouter()


@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/healthz")
def healthz():
    uptime = time.time() - START_TIME
    try:
        if cache.ping():
            return {"status": "ok", "redis": "up", "uptime_s": uptime}
    except redis.ConnectionError:
        raise HTTPException(
            status_code=503, 
            detail={"status": "error", "redis": "down", "uptime_s": uptime}
        )


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


@app.post("/verify")
def verify(payload: TokenRequest, settings = Depends(get_setting)):
    try: 
        public_key = settings.idp_public_key.replace("\\n", "\n")
        
        decoded_claims = jwt.decode(
            payload.token,
            public_key,
            algorithms=["RS256"],
            audience=settings.expected_audience,
            issuer=settings.expected_issuer
        )
        
        return {
            "valid": True,
            "email": decoded_claims.get("email"),
            "sub": decoded_claims.get("sub"),
            "aud": decoded_claims.get("aud")
        }
    
    except jwt.PyJWTError:
        return JSONResponse(
            status_code=401,
            content={"valid": False}
        )
    


def coerce_types(config_dict: dict) -> dict:
    """
    1. defaults (hardcoded)
    port: 8000
    workers: 1
    debug: false
    log_level: info
    api_key: default-secret-000

    2. config.development.yaml
    port: 8610
    log_level: warning
    api_key: key-dmiwtwryrj

    3. .env file
    APP_LOG_LEVEL=error

    4. OS env vars (APP_* prefix)
    APP_PORT=8695
    APP_WORKERS=11
    APP_DEBUG=false
    APP_LOG_LEVEL=warning
    APP_API_KEY=key-mm2cy4lc0j
    """

    coerced = {}

    for key, value in config_dict.items():
        if key in ["port", "workers"]:
            try:
                coerced[key] = int(value)
            except (ValueError, TypeError):
                coerced[key] = value 
        elif key == "debug":
            if isinstance(value, bool):
                coerced[key] = value
            elif isinstance(value, str):
                coerced[key] = value.lower() in ("true", "1", "yes", "on")
            else:
                coerced[key] = bool(value)
        else: 
            coerced[key] = value
    
    return coerced


@app.get("/effective-config")
def get_effective_config(set: Optional[List[str]] = Query(None)):
    # --- Layer 1: Defaults (Lowest Precedence) ---
    merged_config = {
        "port": 8000,
        "workers": 1,
        "debug": False,
        "log_level": "info",
        "api_key": "default-secret-000"
    }

    # --- Layer 2: config.development.yaml ---
    try:
        with open("config.development.yaml", "r") as f:
            yaml_config = yaml.safe_load(f)
            if yaml_config:
                merged_config.update(yaml_config)
    except FileNotFoundError:
        pass

    # --- Layer 3: .env file ---
    # dotenv_values reads the file directly without touching OS env vars
    env_file_config = dotenv_values(".env")
    for k, v in env_file_config.items():
        if k == "NUM_WORKERS":
            merged_config["workers"] = v
        elif k.startswith("APP_"):
            clean_key = k[4:].lower() # strips "APP_" and makes lowercase
            merged_config[clean_key] = v

    # --- Layer 4: OS Environment Variables ---
    for k, v in os.environ.items():
        if k.startswith("APP_"):
            clean_key = k[4:].lower()
            merged_config[clean_key] = v

    # --- Layer 5: CLI Overrides (Highest Precedence) ---
    # Handled via ?set=key=value query parameters
    if set:
        for override in set:
            if "=" in override:
                key, value = override.split("=", 1)
                merged_config[key] = value

    # --- Apply Formatting ---
    final_config = coerce_types(merged_config)

    # --- Secret Masking ---
    if "api_key" in final_config:
        final_config["api_key"] = "****"
    return final_config

@app.post("/hit/{key}")
def hut(key: str):
    count = cache.incr(key)
    return {"key": key, "count": count}


@app.get("/count/{key}")
def get_count(key: str):
    count = cache.get(key) 
    if count is None: count = 0
    return {"key": key, "count": int(count)}


def verify_api_key(x_api_key: Optional[str] = Header(None), settings = Depends(get_setting)):
    expected_key = settings.api_key
    
    if not expected_key or x_api_key != expected_key:
        raise HTTPException(
            status_code=401, 
            detail="Unauthorized: Invalid or missing API Key"
        )

@app.post("/analytics", dependencies=[Depends(verify_api_key)])
def process_analytics(
    payload: AnalyticsRequest,
):
    
    events = payload.events

    unique_users = set()
    user_revenue = defaultdict(float)
    total_revenue = 0.0

    for event in events:
        unique_users.add(event.user)

        if event.amount > 0:
            total_revenue += event.amount
            user_revenue[event.user] += event.amount

    top_user = ""
    if user_revenue:
        top_user = max(user_revenue, key=user_revenue.get)

    return {
        "email": "23f2003086@ds.study.iitm.ac.in", 
        "total_events": len(events),
        "unique_users": len(unique_users),
        "revenue": total_revenue,
        "top_user": top_user
    }


@app.get("/work")
def get_work(n: str):
    return {
        "email": "23f2003086@ds.study.iitm.ac.in", 
        "done": n
    }

@app.get("/metrics")
def get_metrics():
    return Response(
        content=generate_latest(), 
        media_type=CONTENT_TYPE_LATEST
    )

@app.get("/logs/tail")
def log_tail(limit: int = 10):
    log_list = list(LOGS)
    return log_list[-limit:]

