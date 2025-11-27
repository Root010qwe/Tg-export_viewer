# backend/db.py
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Убедимся, что папка data существует
os.makedirs("data", exist_ok=True)

DATABASE_URL = "sqlite:///./data/db.sqlite3"

# Для SQLite нужно check_same_thread=False
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)
