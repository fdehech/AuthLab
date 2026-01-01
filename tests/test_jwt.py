import pytest
from app.auth import create_access_token, get_current_user
from jose import jwt
from app.config import MASTER_SECRET, ALGORITHM

def test_create_access_token():
    sub = "testuser"
    role = "admin"
    token = create_access_token(sub, role)
    
    payload = jwt.decode(token, MASTER_SECRET, algorithms=[ALGORITHM])
    assert payload["sub"] == sub
    assert payload["role"] == role
    assert "exp" in payload

def test_get_current_user_valid_token():
    sub = "testuser"
    role = "user"
    token = create_access_token(sub, role)
    
    user = get_current_user(token)
    assert user["sub"] == sub
    assert user["role"] == role

def test_get_current_user_invalid_token():
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as excinfo:
        get_current_user("invalid_token")
    assert excinfo.value.status_code == 401
