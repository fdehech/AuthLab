import uvicorn
from fastapi import FastAPI
from app.routes import auth, user

app = FastAPI(title="AuthLab")

# Include routers
app.include_router(auth.router, tags=["Authentication"])
app.include_router(user.router, tags=["User"])

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)