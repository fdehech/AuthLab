from pydantic import BaseModel

class LoginRequest(BaseModel):
    sub: str
    password: str

class LogoutRequest(BaseModel):
    refresh_token: str

class RefreshRequest(BaseModel):
    refresh_token: str
