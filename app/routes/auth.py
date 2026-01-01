from fastapi import APIRouter, HTTPException, Request, Depends
from sqlalchemy.orm import Session
from app.models import LoginRequest, LogoutRequest, RefreshRequest, User
from app.auth import authenticate, create_access_token, create_refresh_token, check_login_rate_limit, get_password_hash
from app.config import storage, TTL
from app.db import get_db

router = APIRouter()

@router.post("/register")
def register(request: LoginRequest, db: Session = Depends(get_db)):
    """User registration endpoint"""
    existing_user = db.query(User).filter(User.email == request.sub).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(request.password)
    new_user = User(email=request.sub, hashed_password=hashed_password, role="user")
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created successfully"}

@router.post("/login")
def login(request: LoginRequest, req: Request, db: Session = Depends(get_db)):
    """Login endpoint"""
    sub = request.sub
    password = request.password
    ip = req.client.host
    check_login_rate_limit(ip)

    user = authenticate(db, sub, password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = create_access_token(sub=user.email, role=user.role)
    refresh = create_refresh_token()

    storage.set(f"refresh:{refresh}", user.email, ex=TTL)

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
def refresh(request: RefreshRequest, db: Session = Depends(get_db)):
    """ Refresh endpoint with Token Rotation """
    key = f"refresh:{request.refresh_token}"
    sub = storage.get(key)

    if not sub:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    # Fetch user to get current role
    user = db.query(User).filter(User.email == sub).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    storage.delete(key) # Invalidating the old refresh token to keep it Single Use
    
    new_refresh_token = create_refresh_token()
    storage.set(f"refresh:{new_refresh_token}", sub, ex=TTL)

    new_access_token = create_access_token(sub=sub, role=user.role)
    return {
        "token_type": "bearer", 
        "access_token": new_access_token,
        "refresh_token": new_refresh_token
    }
