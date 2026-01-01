from pydantic import BaseModel
from enum import Enum
class LoginRequest(BaseModel):
    sub: str
    password: str

class LogoutRequest(BaseModel):
    refresh_token: str

class RefreshRequest(BaseModel):
    refresh_token: str

class RoleEnum(str, Enum):
    user = "user"
    admin = "admin"

class RegisterRequest(BaseModel):
    sub: str
    password: str
    role: RoleEnum = RoleEnum.user