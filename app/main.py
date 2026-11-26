from fastapi import FastAPI

from app.database import engine, Base
from app.models.user import User
from app.models.revoked_token import RevokedToken
from app.routers import auth

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="JWT Authentication Microservice",
    description="REST API using FastAPI and SQLite",
    version="1.0.0"
)

# Register authentication router
app.include_router(auth.router)


@app.get("/")
def home():
    return {
        "message": "Welcome to FastAPI JWT Authentication Microservice"
    }