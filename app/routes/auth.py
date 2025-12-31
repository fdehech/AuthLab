from fastapi import APIRouter, HTTPException, Request
from app.models import LoginRequest, LogoutRequest, RefreshRequest
from app.auth import authenticate, create_access_token, create_refresh_token, check_login_rate_limit
from app.config import storage, TTL

router = APIRouter()

@router.post("/login")
def login(request: LoginRequest, req: Request):
    """Login endpoint"""
    sub = request.sub
    password = request.password
    ip = req.client.host
    check_login_rate_limit(ip)

    if not authenticate(sub, password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = create_access_token(sub=sub, role="user")
    refresh = create_refresh_token()

    storage.set(f"refresh:{refresh}", sub, ex=TTL)

    return {
        "token_type": "bearer",
        "access_token": token,
        "refresh_token": refresh
    }

@router.post("/logout")
def logout(request: LogoutRequest):
    storage.delete(f"refresh:{request.refresh_token}")
    return {"message": "Logout successful"}

@router.post("/refresh")
def refresh(request: RefreshRequest):
    """ Refresh endpoint with Token Rotation """
    key = f"refresh:{request.refresh_token}"
    sub = storage.get(key)

    if not sub:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    storage.delete(key) # Invalidating the old refresh token to keep it Single Use
    
    new_refresh_token = create_refresh_token()
    storage.set(f"refresh:{new_refresh_token}", sub, ex=TTL)

    new_access_token = create_access_token(sub=sub, role="user")
    return {
        "token_type": "bearer", 
        "access_token": new_access_token,
        "refresh_token": new_refresh_token
    }
