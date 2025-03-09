# database.py

import os
from dotenv import load_dotenv

# Load environment variables before importing config
ENV = os.getenv('ENV', 'production')

if ENV == 'testing':
    load_dotenv('.env.test')
else:
    load_dotenv('.env')

from config import ProductionConfig, TestingConfig

if ENV == 'testing':
    app_config = TestingConfig()
else:
    app_config = ProductionConfig()

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Use DATABASE_URL from configuration
SQLALCHEMY_DATABASE_URL = app_config.DATABASE_URL

# Create the SQLAlchemy engine with increased timeout and WAL mode
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={
        "check_same_thread": False,  # Needed for SQLite
        "timeout": 30,               # Increase timeout to prevent 'database is locked' errors
    },
    pool_pre_ping=True,             # Check connections before using them
)

# Create a configured "SessionLocal" class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create a base class for declarative class definitions
Base = declarative_base()

# Enable WAL mode
with engine.connect() as connection:
    connection.execute("PRAGMA journal_mode=WAL;")
    connection.execute("PRAGMA synchronous=NORMAL;")
