import os
from pathlib import Path


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "development-key-change-me")
    DATABASE = Path(__file__).resolve().parent / "passwords.db"