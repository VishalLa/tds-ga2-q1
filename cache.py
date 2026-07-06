import redis.asyncio as redis

cache = redis.Redis(
    host="redis",
    port=6379,
    db=0,
    decode_responses=True
)
