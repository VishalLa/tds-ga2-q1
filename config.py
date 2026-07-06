import time
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from collections import deque
from prometheus_client import Counter

LOGS = deque(maxlen=2000)
START_TIME = time.time()
REQUEST_COUNTER = Counter("http_requests", "Total HTTP Requests")

TOTAL_ORDERS = 51
RATE_LIMIT_MAX_REQS = 10
RATE_LIMIT_WINDOW_SEC = 10.0

CATALOG = [
    {
        "id": i,
        "description": f"Order {i} from catalog"
    } for i in range(1, TOTAL_ORDERS + 1)
]

IDEMPOTENCY_TTL_SEC = 60 * 60 * 24

class Settings(BaseSettings):
    idp_public_key: str
    expected_issuer: str
    expected_audience: str
    api_key: str 

    ollama_api_url: str = "http://localhost:11434/v1/chat/completions"
    model_name: str = "qwen2.5:0.5b"

    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8",
        extra="ignore"
    )

@lru_cache
def get_setting() -> Settings:
    return Settings()
