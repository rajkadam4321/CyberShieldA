import os, secrets
from dotenv import load_dotenv
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_urlsafe(48)
RAW_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cybershield.db")

# Normalize PostgreSQL URL scheme for SQLAlchemy 2.0 (Supabase and Render supply postgres://)
if RAW_DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = RAW_DATABASE_URL.replace("postgres://", "postgresql://", 1)
else:
    DATABASE_URL = RAW_DATABASE_URL

ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "60"))
CORS_ORIGINS_RAW = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
CORS_ORIGIN_REGEX = os.getenv("CORS_ORIGIN_REGEX", r"^https:\/\/.*\.vercel\.app$")
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "5"))

