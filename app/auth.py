import secrets
from datetime import datetime, timezone, timedelta
from jose import jwt, JWTError
from fastapi import HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from app.config import MASTER_SECRET, ALGORITHM, ACCESS_TOKEN_MINUTES, storage, LOGIN_LIMIT, LOGIN_WINDOW_SECONDS
from app.models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate(db: Session, sub: str, password: str):
    user = db.query(User).filter(User.sub == sub).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

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

def revoke_all_sessions(email: str):
    key = f"user_sessions:{email}"
    tokens = storage.smembers(key)  # set of refresh tokens

    if tokens:
        # delete refresh:<token> keys
        storage.delete(*[f"refresh:{t}" for t in tokens])

    # delete the set itself
    storage.delete(key)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

