import os
import redis
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
MASTER_SECRET = os.getenv("MASTER_SECRET")
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "30"))
REFRESH_TOKEN_DAYS = int(os.getenv("REFRESH_TOKEN_DAYS", "7"))
TTL = REFRESH_TOKEN_DAYS * 24 * 3600
LOGIN_LIMIT = int(os.getenv("LOGIN_LIMIT", "5"))
LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "60"))

storage = redis.from_url(REDIS_URL, decode_responses=True)
