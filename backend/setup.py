"""
Run this once to create the database and seed initial users.
  python setup.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from database import SessionLocal, engine, Base
import models
import bcrypt
from datetime import datetime

Base.metadata.create_all(bind=engine)
db = SessionLocal()

# ── Admin user ──────────────────────────────────────────────────────────────
existing = db.query(models.User).filter(models.User.username == "admin").first()
if not existing:
    admin = models.User(
        username="admin",
        email="admin@medflow.local",
        password_hash=bcrypt.hashpw(b"Admin123!", bcrypt.gensalt()).decode(),
        full_name="System Administrator",
        npi_number="",
        specialty="Administration",
        role="admin",
        is_active=True,
    )
    db.add(admin)

    # ── Demo physician ───────────────────────────────────────────────────────
    physician = models.User(
        username="drsmith",
        email="drsmith@medflow.local",
        password_hash=bcrypt.hashpw(b"Doctor123!", bcrypt.gensalt()).decode(),
        full_name="Dr. Jane Smith, MD",
        npi_number="1234567890",
        specialty="Internal Medicine",
        role="physician",
        is_active=True,
    )
    db.add(physician)

    # ── Demo patient ─────────────────────────────────────────────────────────
    db.flush()
    patient = models.Patient(
        first_name="John",
        last_name="Doe",
        dob="1965-04-12",
        gender="Male",
        phone="555-867-5309",
        email="john.doe@example.com",
        address="123 Main St",
        city="Anytown",
        state="TX",
        zip_code="75001",
        insurance_name="Blue Cross Blue Shield",
        insurance_id="XYZ123456",
        insurance_group="GRP001",
        created_by=admin.id,
    )
    db.add(patient)

    db.commit()
    print("✅ Database created.")
    print("   Admin login  →  admin / Admin123!")
    print("   Doctor login →  drsmith / Doctor123!")
else:
    print("ℹ️  Database already initialised — skipping seed.")

# SQLAlchemy's QueuePool keeps PostgreSQL sockets open even after db.close(),
# causing this script to hang indefinitely. os._exit(0) forces an immediate
# process exit with code 0, bypassing all pool/cleanup hooks.
sys.stdout.flush()
os._exit(0)
