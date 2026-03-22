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
from sqlalchemy import text

Base.metadata.create_all(bind=engine)

# ── Schema migrations (safe to run on every deploy) ─────────────────────────
_migrations = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_active TIMESTAMP",
    # Reset stale last_active so the idle-timeout check doesn't fire on first login
    # after a deploy. The login endpoint now sets this fresh, but clearing it here
    # ensures any existing stale value doesn't block login on the very first request.
    "UPDATE users SET last_active = NULL WHERE last_active < NOW() - INTERVAL '30 minutes'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_required BOOLEAN DEFAULT FALSE",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS user_agent VARCHAR DEFAULT ''",
    "ALTER TABLE patients ADD COLUMN IF NOT EXISTS portal_last_active TIMESTAMP",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS telnyx_sms_number VARCHAR DEFAULT ''",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS cell_phone VARCHAR DEFAULT ''",
    "ALTER TABLE patient_messages ADD COLUMN IF NOT EXISTS provider_id INTEGER REFERENCES users(id)",
    "ALTER TABLE patients ADD COLUMN IF NOT EXISTS sms_consent BOOLEAN DEFAULT FALSE",
    "ALTER TABLE patients ADD COLUMN IF NOT EXISTS sms_consent_date TIMESTAMP",
    "ALTER TABLE patients ADD COLUMN IF NOT EXISTS email_consent BOOLEAN DEFAULT FALSE",
    "ALTER TABLE patients ADD COLUMN IF NOT EXISTS email_consent_date TIMESTAMP",
    # patient_messages table — created by Base.metadata.create_all above if new DB,
    # but existing DBs need these explicit statements to be safe
    """CREATE TABLE IF NOT EXISTS patient_messages (
        id SERIAL PRIMARY KEY,
        patient_id INTEGER NOT NULL REFERENCES patients(id),
        direction VARCHAR NOT NULL,
        body TEXT NOT NULL,
        sms_status VARCHAR DEFAULT 'pending',
        telnyx_msg_id VARCHAR,
        read_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
    )""",
    """CREATE TABLE IF NOT EXISTS imported_records (
        id SERIAL PRIMARY KEY,
        patient_id INTEGER NOT NULL REFERENCES patients(id),
        uploaded_by INTEGER NOT NULL REFERENCES users(id),
        filename VARCHAR DEFAULT '',
        source_type VARCHAR DEFAULT 'pdf',
        raw_text TEXT DEFAULT '',
        ai_summary TEXT DEFAULT '',
        notes_filed INTEGER DEFAULT 0,
        labs_filed INTEGER DEFAULT 0,
        imaging_filed INTEGER DEFAULT 0,
        meds_filed INTEGER DEFAULT 0,
        status VARCHAR DEFAULT 'pending',
        error_detail TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW()
    )""",
    # ── Import review gate columns ────────────────────────────────────────────
    "ALTER TABLE imported_records ADD COLUMN IF NOT EXISTS medical_history_summary TEXT DEFAULT ''",
    "ALTER TABLE imported_records ADD COLUMN IF NOT EXISTS recommended_next_steps TEXT DEFAULT '[]'",
    "ALTER TABLE imported_records ADD COLUMN IF NOT EXISTS review_status VARCHAR DEFAULT 'pending_review'",
    # source_import_id on each record type — links filed records back to their import
    "ALTER TABLE clinical_notes ADD COLUMN IF NOT EXISTS source_import_id INTEGER",
    "ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS source_import_id INTEGER",
    "ALTER TABLE imaging_orders ADD COLUMN IF NOT EXISTS source_import_id INTEGER",
    "ALTER TABLE patient_medications ADD COLUMN IF NOT EXISTS source_import_id INTEGER",
]
with engine.connect() as _conn:
    for _sql in _migrations:
        _conn.execute(text(_sql))
    _conn.commit()
print("✅ Schema migrations applied.")

db = SessionLocal()

# ── Admin user ──────────────────────────────────────────────────────────────
# If RESET_ADMIN_PW is set, forcibly update the admin password and exit.
# Use this to recover a forgotten/unknown admin password:
#   1. Set RESET_ADMIN_PW=YourNewPassword123! in Railway environment variables
#   2. Redeploy — setup.py will reset the password and print confirmation
#   3. Log in with admin / <RESET_ADMIN_PW value>
#   4. Change your password in Settings, then remove RESET_ADMIN_PW from Railway
_reset_pw = os.environ.get("RESET_ADMIN_PW", "").strip()
if _reset_pw:
    _admin = db.query(models.User).filter(models.User.username == "admin").first()
    if _admin:
        _admin.password_hash = bcrypt.hashpw(_reset_pw.encode(), bcrypt.gensalt()).decode()
        _admin.token_version = (_admin.token_version or 0) + 1  # invalidate all existing sessions
        db.commit()
        print(f"✅ Admin password reset via RESET_ADMIN_PW env var.")
        print(f"   Login with: admin / {_reset_pw}")
        print(f"   IMPORTANT: remove RESET_ADMIN_PW from your environment after logging in!")
    else:
        print("⚠️  RESET_ADMIN_PW set but no admin user found — will be created below.")
    sys.stdout.flush()

existing = db.query(models.User).filter(models.User.username == "admin").first()
if not existing:
    admin = models.User(
        username="admin",
        email="admin@commonwealth.local",
        password_hash=bcrypt.hashpw(b"Commonwealth1!", bcrypt.gensalt()).decode(),
        full_name="System Administrator",
        npi_number="",
        specialty="Administration",
        role="admin",
        is_active=True,
    )
    db.add(admin)

    # ── Demo physician ───────────────────────────────────────────────────────
    physician = models.User(
        username="drbishop",
        email="stevenbishop@protonmail.com",
        password_hash=bcrypt.hashpw(b"Commonwealth1!", bcrypt.gensalt()).decode(),
        full_name="Dr. Steven Bishop, MD",
        npi_number="",
        specialty="Internal Medicine",
        role="physician",
        is_active=True,
    )
    db.add(physician)

    db.commit()
    print("✅ Database created.")
    print("   Admin login   →  admin / Commonwealth1!")
    print("   Doctor login  →  drbishop / Commonwealth1!")
else:
    # ── Force-reset admin password on every deploy so credentials are always known ──
    existing.password_hash = bcrypt.hashpw(b"Commonwealth1!", bcrypt.gensalt()).decode()
    existing.password_changed_at = datetime.utcnow()
    existing.is_active = True
    # Ensure drbishop account exists
    bishop = db.query(models.User).filter(models.User.username == "drbishop").first()
    if not bishop:
        bishop = models.User(
            username="drbishop",
            email="stevenbishop@protonmail.com",
            password_hash=bcrypt.hashpw(b"Commonwealth1!", bcrypt.gensalt()).decode(),
            full_name="Dr. Steven Bishop, MD",
            npi_number="",
            specialty="Internal Medicine",
            role="physician",
            is_active=True,
        )
        db.add(bishop)
    db.commit()
    print("✅ Admin password reset. drbishop account ensured.")
    print("   Admin login   →  admin / Commonwealth1!")
    print("   Doctor login  →  drbishop / Commonwealth1!")

# SQLAlchemy's QueuePool keeps PostgreSQL sockets open even after db.close(),
# causing this script to hang indefinitely. os._exit(0) forces an immediate
# process exit with code 0, bypassing all pool/cleanup hooks.
sys.stdout.flush()
os._exit(0)
