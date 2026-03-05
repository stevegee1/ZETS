import os
import sys
from dotenv import load_dotenv

load_dotenv()

# In production (Railway etc.) DATABASE_URL must be set explicitly.
# For local development, .env defaults to SQLite for convenience.
_default_db = "sqlite+aiosqlite:///./zets.db" if "pytest" in sys.modules or os.getenv("ENV") != "production" else None
DATABASE_URL: str = os.getenv("DATABASE_URL") or _default_db or ""
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set. Set it in .env or your hosting provider.")

JWT_SECRET: str = os.getenv("JWT_SECRET", "change-me")
JWT_ALGORITHM: str = "HS256"
JWT_EXPIRY_MINUTES: int = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))
UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "./uploads")
CORS_ORIGINS: list[str] = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

os.makedirs(UPLOAD_DIR, exist_ok=True)
