import secrets
from datetime import datetime, timezone, timedelta
from jose import jwt, JWTError
from fastapi import HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer
from app.config import MASTER_SECRET, ALGORITHM, ACCESS_TOKEN_MINUTES, storage, LOGIN_LIMIT, LOGIN_WINDOW_SECONDS

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def authenticate(user, passw):
    if user == "admin" and passw == "admin":
        return "admin"
    if user == "user" and passw == "user":
        return "user"
    return False

def create_access_token(sub: str, role: str):
    """Crafting Token using JWT"""
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    payload = {"sub": sub, "role": role, "exp": expire}
    return jwt.encode(payload, MASTER_SECRET, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    """Decoding a given Token"""
    try:
        payload = jwt.decode(token, MASTER_SECRET, algorithms=[ALGORITHM])
        return {"sub": payload["sub"], "role": payload["role"]}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def create_refresh_token():
    return secrets.token_urlsafe(48)

def require_role(required_role: str):
    def role_checker(user=Depends(get_current_user)):
        if user["role"] != required_role:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return role_checker


def check_login_rate_limit(ip: str):
    key = f"rl:login:{ip}"
    count = storage.incr(key)  # increments and returns new value
    if count == 1:
        storage.expire(key, LOGIN_WINDOW_SECONDS)  # set TTL on first hit

    if count > LOGIN_LIMIT:
        ttl = storage.ttl(key)
        raise HTTPException(
            status_code=429,
            detail=f"Too many login attempts. Try again in {ttl}s"
        )
