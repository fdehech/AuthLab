from fastapi import APIRouter, Depends
from app.auth import get_current_user, require_role

router = APIRouter()

@router.get("/me")
def me(user=Depends(get_current_user)):
    return user

@router.get("/admin", dependencies=[Depends(require_role("admin"))])
def admin(user=Depends(get_current_user)):
    return {"message": "Admin only", "user": user}
