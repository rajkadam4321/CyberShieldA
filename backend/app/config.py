from dotenv import load_dotenv
load_dotenv()
import os, secrets
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_urlsafe(48)  # random per run if unset (tokens reset on restart)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cybershield.db")
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "60"))
