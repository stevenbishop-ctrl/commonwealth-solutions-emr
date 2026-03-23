from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
import logging
import sys

_db_logger = logging.getLogger("zelphon.database")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./zelphon.db")

# ── HIPAA Production Guard ────────────────────────────────────────────────────
# SQLite is unencrypted and unsuitable for PHI in production.
# If DATABASE_URL is still the SQLite default in a non-development environment,
# emit a loud warning so it doesn't silently go unnoticed.
if "sqlite" in DATABASE_URL and os.getenv("ENVIRONMENT", "").lower() not in ("development", "dev", "local", "test"):
    _db_logger.critical(
        "HIPAA WARNING: SQLite is configured as the database. "
        "SQLite stores data unencrypted on disk and is NOT suitable for PHI in production. "
        "Set DATABASE_URL to a PostgreSQL connection string in your environment variables."
    )
    print(
        "\n⚠️  HIPAA CRITICAL: SQLite detected — this stores PHI unencrypted on disk.\n"
        "   Set DATABASE_URL to a PostgreSQL URL before handling any patient data.\n",
        file=sys.stderr, flush=True
    )

# Railway (and some other hosts) provide postgres:// URLs but
# SQLAlchemy 2.x requires postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Build connection args.
# For PostgreSQL: require SSL by default (HIPAA encryption-in-transit).
# Override with DB_SSL_MODE env var if needed (e.g. "disable" for local dev without SSL cert).
if "sqlite" in DATABASE_URL:
    _connect_args = {"check_same_thread": False}
else:
    _ssl_mode     = os.getenv("DB_SSL_MODE", "require")
    _connect_args = {"sslmode": _ssl_mode}

engine = create_engine(
    DATABASE_URL,
    connect_args=_connect_args,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, expire_on_commit=False)
Base = declarative_base()
