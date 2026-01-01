from fastapi import APIRouter, HTTPException, Request, Depends
from sqlalchemy.orm import Session
from app.models import LoginRequest, LogoutRequest, RefreshRequest, RegisterRequest, User, ChangePasswordRequest
from app.auth import authenticate, create_access_token, create_refresh_token, check_login_rate_limit, get_password_hash, get_current_user, verify_password, revoke_all_sessions
from app.config import storage, TTL
from app.db import get_db

router = APIRouter()

@router.post("/register")
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.sub == request.sub).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User/Email already registered")

    hashed_password = get_password_hash(request.password)
    new_user = User(sub=request.sub, hashed_password=hashed_password, role=request.role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created successfully"}

@router.post("/login")
def login(request: LoginRequest, req: Request, db: Session = Depends(get_db)):
    """Login endpoint"""
    ip = req.client.host
    check_login_rate_limit(ip)

    user = authenticate(db, request.sub, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = create_access_token(sub=user.sub, role=user.role)
    refresh = create_refresh_token()

    storage.set(f"refresh:{refresh}", user.sub, ex=TTL)
    storage.sadd(f"user_sessions:{user.sub}", refresh)
    storage.expire(f"user_sessions:{user.sub}", TTL)

    return {
        "token_type": "bearer",
        "access_token": token,
        "refresh_token": refresh
    }

@router.post("/logout")
def logout(request: LogoutRequest):
    key = f"refresh:{request.refresh_token}"
    sub = storage.get(key)
    storage.delete(key)
    if sub:
        storage.srem(f"user_sessions:{sub}", request.refresh_token)
    return {"message": "Logout successful"}

@router.post("/refresh")
def refresh(request: RefreshRequest, db: Session = Depends(get_db)):
    """ Refresh endpoint with Token Rotation """
    key = f"refresh:{request.refresh_token}"
    sub = storage.get(key)

    if not sub:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    # Fetch user to get current role
    user = db.query(User).filter(User.sub == sub).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Invalidate old refresh token
    storage.delete(key)
    storage.srem(f"user_sessions:{sub}", request.refresh_token)

    # Create and store new refresh token
    new_refresh_token = create_refresh_token()
    storage.set(f"refresh:{new_refresh_token}", sub, ex=TTL)
    storage.sadd(f"user_sessions:{sub}", new_refresh_token)
    storage.expire(f"user_sessions:{sub}", TTL)

    new_access_token = create_access_token(sub=sub, role=user.role)
    return {
        "token_type": "bearer", 
        "access_token": new_access_token,
        "refresh_token": new_refresh_token
    }

@router.post("/change-password")
def change_password(request: ChangePasswordRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    """Change password endpoint"""

    sub = user["sub"]

    db_user = db.query(User).filter(User.sub == sub).first()

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(request.current_password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Wrong current password")

    db_user.hashed_password = get_password_hash(request.new_password)
    db.commit()

    revoke_all_sessions(sub)

    return {"message": "Password updated. Logged out from all sessions."}