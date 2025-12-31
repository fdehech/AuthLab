import os
import redis #Library for Redis, Storing Tokens
import uvicorn
import secrets #Library for generating random tokens
from jose import jwt, JWTError 
from pydantic import BaseModel
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timezone, timedelta

load_dotenv()

app = FastAPI(title="AuthLab")
REDIS_URL = os.getenv("REDIS_URL")
ALGORITHM = os.getenv("ALGORITHM")
MASTER_SECRET = os.getenv("MASTER_SECRET")
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES"))
REFRESH_TOKEN_DAYS = int(os.getenv("REFRESH_TOKEN_DAYS", "7"))
TTL = REFRESH_TOKEN_DAYS * 24 * 3600
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
storage = redis.from_url(REDIS_URL, decode_responses=True)

class LoginRequest(BaseModel):
    sub: str
    password: str

class LogoutRequest(BaseModel):
    refresh_token: str

class RefreshRequest(BaseModel):
    refresh_token: str


def Auth(user, passw):
    if user == "admin" and passw == "admin":
        return "admin"
    if user == "user" and passw == "user":
        return "user"
        
    return False

def create_access_token(sub: str, role: str):
    """Crafting Token using JWT"""
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_MINUTES) #Expiration timestamp
    payload = {"sub": sub, "role": role, "exp": expire} #Payload
    return jwt.encode(payload, MASTER_SECRET, algorithm=ALGORITHM) #Encoding

def get_current_user(token: str = Depends(oauth2_scheme)):
    """Decoding a given Token"""
    try:
        payload = jwt.decode(token, MASTER_SECRET, algorithms=[ALGORITHM]) #Decoding
        return {"sub": payload["sub"], "role": payload["role"]} #Returning decoded data
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token") #Exception handling

def create_refresh_token():
    return secrets.token_urlsafe(48)

def require_role(required_role: str):
    def role_checker(user=Depends(get_current_user)):
        if user["role"] != required_role:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return role_checker


@app.get("/me")
def me(user=Depends(get_current_user)):
    return user

@app.post("/login")
def Login(request: LoginRequest):
    """Login endpoint"""
    sub = request.sub
    password = request.password

    if not Auth(sub, password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token (sub=sub, role="user")

    refresh = create_refresh_token()

    storage.set(f"refresh:{refresh}", sub, ex=TTL)

    return {"token_type": "bearer",
            "access_token": token,
            "refresh_token": refresh
    }

@app.post("/logout")
def Logout(request: LogoutRequest):
    storage.delete(f"refresh:{request.refresh_token}")
    return {"message": "Logout successful"}

@app.post("/refresh")
def refresh(request: RefreshRequest):
    """ Refresh endpoint with Token Rotation """

    key = f"refresh:{request.refresh_token}"
    sub = storage.get(key)

    if not sub:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    storage.delete(key) # Invalidating the old refresh token to keep it Single Use
    
    new_refresh_token = create_refresh_token() # New Refresh Token
    storage.set(f"refresh:{new_refresh_token}", sub, ex=TTL)

    new_access_token = create_access_token(sub=sub, role="user") # New Access Token
    return {"token_type": "bearer", 
            "access_token": new_access_token,
            "refresh_token": new_refresh_token
    }

@app.get("/admin", dependencies=[Depends(require_role("admin"))])
def admin(user=Depends(get_current_user)):
    return {"message": "Admin only", "user": user}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)