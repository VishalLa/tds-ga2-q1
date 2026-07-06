from redis import Redis

cache = Redis(
    host="localhost",
    port=6379,
    db=0,
    decode_responses=True
)
