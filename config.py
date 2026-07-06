import time
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from collections import deque
from prometheus_client import Counter

LOGS = deque(maxlen=2000)
START_TIME = time.time()
REQUEST_COUNTER = Counter("http_requests", "Total HTTP Requests")

class Settings(BaseSettings):
    idp_public_key: str
    expected_issuer: str
    expected_audience: str

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

@lru_cache
def get_setting() -> Settings:
    return Settings()
