from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.auth.router import router as auth_router
from src.auth.models import create_tables


app = FastAPI(title='auth_service')


app.include_router(auth_router)


@app.on_event("startup")
async def startup_event():
    await create_tables()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)