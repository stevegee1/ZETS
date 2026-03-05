from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import init_db, AsyncSessionLocal
from config import CORS_ORIGINS
from auth.router import router as auth_router
from files.router import router as files_router
from admin import router as admin_router
from anomaly.router import router as anomaly_router
from anomaly.engine import anomaly_engine
from pep.middleware import PEPMiddleware

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    async with AsyncSessionLocal() as db:
        await anomaly_engine.load_history(db)
    yield

app = FastAPI(
    title="ZETS – Zero Trust Educational Security Platform",
    description="Milestone 2: PEP, PDP, integrity verification, micro-segmentation, monitoring",
    version="2.0.0",
    lifespan=lifespan,
)

# Order matters: CORSMiddleware first, then PEP (innermost — runs after CORS headers are set)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(PEPMiddleware)

app.include_router(auth_router)
app.include_router(files_router)
app.include_router(admin_router)
app.include_router(anomaly_router)

@app.get("/health")
async def health():
    return {"status": "ok", "service": "ZETS Backend", "milestone": "2"}
