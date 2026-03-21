from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey
from database import Base
from datetime import datetime


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String)
    password_hash = Column(String)
    full_name = Column(String)
    npi_number = Column(String, default="")
    specialty = Column(String, default="")
    role = Column(String, default="physician")  # admin, physician, staff
    is_active = Column(Boolean, default=True)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String, nullable=True)
    mfa_required = Column(Boolean, default=False)  # Force MFA before clinical access
    password_changed_at = Column(DateTime, nullable=True)
    token_version = Column(Integer, default=0)      # Invalidates all prior tokens on pw change
    created_at = Column(DateTime, default=datetime.utcnow)


class Patient(Base):
    __tablename__ = "patients"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    dob = Column(String)
    gender = Column(String)
    ssn_last4 = Column(String, default="")
    phone = Column(String, default="")
    email = Column(String, default="")
    address = Column(String, default="")
    city = Column(String, default="")
    state = Column(String, default="")
    zip_code = Column(String, default="")
    insurance_name = Column(String, default="")
    insurance_id = Column(String, default="")
    insurance_group = Column(String, default="")
    emergency_contact = Column(String, default="")
    emergency_phone = Column(String, default="")
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    # Patient portal
    portal_email = Column(String, default="")
    portal_password_hash = Column(String, default="")
    portal_active = Column(Boolean, default=False)


class ClinicalNote(Base):
    __tablename__ = "clinical_notes"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"))
    physician_id = Column(Integer, ForeignKey("users.id"))
    visit_date = Column(DateTime)
    chief_complaint = Column(Text, default="")
    hpi = Column(Text, default="")
    pmh = Column(Text, default="")
    medications = Column(Text, default="")
    allergies = Column(Text, default="")
    ros = Column(Text, default="")
    physical_exam = Column(Text, default="")
    assessment = Column(Text, default="")
    plan = Column(Text, default="")
    icd10_codes = Column(Text, default="[]")   # JSON string
    cpt_codes = Column(Text, default="[]")     # JSON string
    note_type = Column(String, default="SOAP")
    ai_generated = Column(Boolean, default=False)
    status = Column(String, default="draft")   # draft, signed, amended
    patient_visible = Column(Boolean, default=False)  # released to patient portal
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class LabOrder(Base):
    __tablename__ = "lab_orders"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"))
    physician_id = Column(Integer, ForeignKey("users.id"))
    tests = Column(Text, default="[]")            # JSON array of test names (legacy display)
    test_objects = Column(Text, nullable=True)    # JSON array of {name, code, category, specimen}
    clinical_indication = Column(Text, default="")
    priority = Column(String, default="routine")  # routine, stat, asap
    facility = Column(String, default="LabCorp")
    status = Column(String, default="pending")    # pending, transmitted, resulted
    icd10_codes = Column(Text, default="[]")      # JSON
    notes = Column(Text, default="")
    transmitted_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    # LabCorp Beacon API fields
    labcorp_order_id  = Column(String, nullable=True)   # LabCorp's returned order ID
    labcorp_accession = Column(String, nullable=True)   # Lab accession # assigned at receipt
    labcorp_status    = Column(String, nullable=True)   # LabCorp's own status string
    result_received_at = Column(DateTime, nullable=True)
    result_data       = Column(Text, nullable=True)     # JSON array of observations
    result_pdf        = Column(Text, nullable=True)     # Base64-encoded result PDF


class ImagingOrder(Base):
    __tablename__ = "imaging_orders"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"))
    physician_id = Column(Integer, ForeignKey("users.id"))
    study_type = Column(String, default="")
    body_part = Column(String, default="")
    clinical_indication = Column(Text, default="")
    priority = Column(String, default="routine")
    facility = Column(String, default="")
    fax_number = Column(String, default="")
    icd10_codes = Column(Text, default="[]")
    notes = Column(Text, default="")
    status      = Column(String, default="ordered")   # ordered, faxed, scheduled, completed, results_received, cancelled
    fax_status  = Column(String, default="pending")   # pending, queued, sending, delivered, failed
    fax_sent_at = Column(DateTime, nullable=True)
    telnyx_fax_id = Column(String, nullable=True)
    cpt_code    = Column(String, default="")
    scheduled_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    results_received_at = Column(DateTime, nullable=True)
    result_notes = Column(Text, default="")           # radiologist report / impression
    result_file_path = Column(String, default="")     # legacy filesystem path (deprecated)
    result_file_data = Column(Text, nullable=True)    # base64-encoded PDF stored in DB (Risk 12)
    result_file_name = Column(String, default="")     # original filename for download
    created_at  = Column(DateTime, default=datetime.utcnow)


class FaxLog(Base):
    __tablename__ = "fax_logs"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"), nullable=True)
    physician_id = Column(Integer, ForeignKey("users.id"))
    direction = Column(String, default="sent")    # sent, received
    from_number = Column(String, default="")
    to_number = Column(String, default="")
    subject = Column(String, default="")
    pages = Column(Integer, default=1)
    status = Column(String, default="pending")    # pending, queued, sending, delivered, failed, received
    telnyx_fax_id = Column(String, nullable=True) # Telnyx fax ID for status polling
    file_path = Column(String, default="")
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class Membership(Base):
    __tablename__ = "memberships"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"))
    plan_name = Column(String)
    price_monthly = Column(Float, default=0.0)
    start_date = Column(DateTime)
    end_date = Column(DateTime, nullable=True)
    status = Column(String, default="active")   # active, cancelled, expired
    square_customer_id = Column(String, default="", name="stripe_customer_id")
    square_card_id = Column(String, default="", name="stripe_subscription_id")
    # Billing cycle tracking
    next_billing_date  = Column(DateTime, nullable=True)   # next scheduled charge
    last_billed_at     = Column(DateTime, nullable=True)   # last successful charge
    billing_failure_count = Column(Integer, default=0)     # consecutive failures
    billing_status     = Column(String, default="ok")      # ok, past_due, suspended
    payment_provider   = Column(String, default="square")  # square or zaprite
    billing_cycle      = Column(String, default="monthly")  # monthly | annual
    price_annual       = Column(Float, nullable=True)       # actual annual amount charged
    created_at = Column(DateTime, default=datetime.utcnow)


class Payment(Base):
    __tablename__ = "payments"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"))
    amount = Column(Float, default=0.0)
    description = Column(String, default="")
    payment_method = Column(String, default="card")
    status = Column(String, default="pending")  # pending, completed, failed, refunded
    payment_ref_id = Column(String, default="", name="stripe_payment_intent_id")
    created_at = Column(DateTime, default=datetime.utcnow)


class CryptoPayment(Base):
    __tablename__ = "crypto_payments"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"))
    amount_usd = Column(Float)                   # amount in USD
    currency = Column(String)                    # BTC, USDC, USDT
    network = Column(String)                     # bitcoin, solana
    address = Column(String, default="")         # receiving wallet address
    reference = Column(String, default="")       # unique 6-char ref code (Solana memo)
    crypto_amount = Column(Float, nullable=True) # amount in crypto (BTC only)
    zaprite_order_id = Column(String, default="")
    zaprite_checkout_url = Column(String, default="")
    tx_signature = Column(String, default="")    # Solana tx signature or BTC txid
    status = Column(String, default="pending")   # pending, confirmed, expired, failed
    description = Column(String, default="")
    expires_at = Column(DateTime, nullable=True)
    confirmed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class PatientMedication(Base):
    __tablename__ = "patient_medications"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"), nullable=False)
    name = Column(String, nullable=False)
    dosage = Column(String, default="")
    frequency = Column(String, default="")
    route = Column(String, default="oral")
    start_date = Column(String, default="")
    end_date = Column(String, default="")
    prescriber = Column(String, default="")
    indication = Column(String, default="")
    is_active = Column(Boolean, default=True)
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class PatientHistoryEntry(Base):
    __tablename__ = "patient_history"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"), nullable=False)
    entry_type = Column(String, nullable=False)  # problem|allergy|surgical|family|social|immunization
    description = Column(String, nullable=False)
    detail = Column(String, default="")   # reaction/severity for allergies, relationship for family hx
    onset_date = Column(String, default="")
    status = Column(String, default="active")  # active|resolved|inactive
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class AppointmentType(Base):
    __tablename__ = "appointment_types"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    duration_minutes = Column(Integer, default=30)
    color = Column(String, default="#2563eb")
    description = Column(String, default="")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Appointment(Base):
    __tablename__ = "appointments"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"), nullable=True)
    provider_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    appointment_type_id = Column(Integer, ForeignKey("appointment_types.id"), nullable=True)
    title = Column(String, nullable=False)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    status = Column(String, default="scheduled")  # scheduled|confirmed|completed|cancelled|no_show
    notes = Column(Text, default="")
    color = Column(String, nullable=True)
    reminder_sent = Column(Boolean, default=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class ProviderSchedule(Base):
    """Weekly recurring availability for a provider."""
    __tablename__ = "provider_schedules"
    id = Column(Integer, primary_key=True, index=True)
    provider_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    day_of_week = Column(Integer, nullable=False)  # 0=Mon … 6=Sun
    start_time = Column(String, default="09:00")   # "HH:MM" local time
    end_time = Column(String, default="17:00")
    is_active = Column(Boolean, default=True)


class ScheduleBlock(Base):
    """One-off blocked time (vacation, meeting, etc.)."""
    __tablename__ = "schedule_blocks"
    id = Column(Integer, primary_key=True, index=True)
    provider_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    start_datetime = Column(DateTime, nullable=False)
    end_datetime = Column(DateTime, nullable=False)
    reason = Column(String, default="Blocked")
    created_at = Column(DateTime, default=datetime.utcnow)


class Prescription(Base):
    __tablename__ = "prescriptions"
    id               = Column(Integer, primary_key=True, index=True)
    patient_id       = Column(Integer, ForeignKey("patients.id"), nullable=False)
    physician_id     = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Drug
    drug_name        = Column(String, nullable=False)
    rxcui            = Column(String, default="")        # RxNorm concept ID
    ndc              = Column(String, default="")        # NDC code
    strength         = Column(String, default="")        # e.g. "10 mg"
    dosage_form      = Column(String, default="")        # tablet, capsule, liquid…
    sig              = Column(Text, default="")          # directions / sig line
    quantity         = Column(Float, default=30)
    quantity_unit    = Column(String, default="tablet(s)")
    days_supply      = Column(Integer, default=30)
    refills          = Column(Integer, default=0)
    daw              = Column(Boolean, default=False)    # Dispense as Written

    # Controlled substance
    dea_schedule     = Column(String, nullable=True)     # II | III | IV | V | None
    is_controlled    = Column(Boolean, default=False)
    epcs_verified    = Column(Boolean, default=False)    # EPCS two-factor completed

    # Pharmacy
    pharmacy_name    = Column(String, default="")
    pharmacy_npi     = Column(String, default="")
    pharmacy_address = Column(String, default="")
    pharmacy_phone   = Column(String, default="")
    pharmacy_fax     = Column(String, default="")

    # Diagnosis link
    icd10_codes      = Column(Text, default="[]")        # JSON

    # Status
    status           = Column(String, default="draft")   # draft|signed|transmitted|filled|cancelled
    signed_at        = Column(DateTime, nullable=True)
    transmitted_at   = Column(DateTime, nullable=True)
    filled_at        = Column(DateTime, nullable=True)

    # E-prescribing platform fields (adapter-ready)
    eprescribe_platform  = Column(String, nullable=True)  # dosespot|drfirst|surescripts
    eprescribe_rx_id     = Column(String, nullable=True)  # Platform's prescription reference
    eprescribe_status    = Column(String, nullable=True)  # Platform's status string
    eprescribe_response  = Column(Text, nullable=True)    # Raw JSON response from platform

    # Telnyx fax fields
    fax_pdf_token    = Column(String, nullable=True)      # UUID token for public PDF URL
    fax_pdf_data     = Column(Text, nullable=True)        # base64-encoded PDF for Telnyx to fetch
    fax_id           = Column(String, nullable=True)      # Telnyx fax ID
    fax_status       = Column(String, nullable=True)      # queued|sending|delivered|failed
    fax_sent_at      = Column(DateTime, nullable=True)

    notes            = Column(Text, default="")
    created_at       = Column(DateTime, default=datetime.utcnow)
    updated_at       = Column(DateTime, default=datetime.utcnow)


class SavedPharmacy(Base):
    """Pharmacies saved by the practice for quick selection."""
    __tablename__ = "saved_pharmacies"
    id       = Column(Integer, primary_key=True, index=True)
    name     = Column(String, nullable=False)
    npi      = Column(String, default="")
    address  = Column(String, default="")
    city     = Column(String, default="")
    state    = Column(String, default="")
    zip_code = Column(String, default="")
    phone    = Column(String, default="")
    fax      = Column(String, default="")
    chain    = Column(String, default="")   # CVS | Walgreens | Walmart | etc.
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class MembershipPlan(Base):
    """Membership plan templates — Valiant, Valiant Premier, Young Valiant."""
    __tablename__ = "membership_plans"
    id              = Column(Integer, primary_key=True, index=True)
    name            = Column(String, nullable=False)          # "Valiant", "Valiant Premier", "Young Valiant"
    slug            = Column(String, nullable=False, unique=True)  # "valiant", "valiant-premier", "young-valiant"
    description     = Column(Text, default="")
    price_monthly   = Column(Float, default=0.0)              # Monthly fee (placeholder until set)
    price_annual    = Column(Float, nullable=True)            # Optional annual price
    enrollment_fee  = Column(Float, default=0.0)              # One-time enrollment fee
    features        = Column(Text, default="[]")              # JSON array of feature strings
    age_min         = Column(Integer, nullable=True)          # Minimum age (Young Valiant: 0)
    age_max         = Column(Integer, nullable=True)          # Maximum age (Young Valiant: 17)
    color           = Column(String, default="#1e3a5f")       # Brand color for UI
    badge           = Column(String, nullable=True)           # "Most Popular", "Best Value", etc.
    is_active       = Column(Boolean, default=True)
    square_plan_id  = Column(String, default="")              # Square subscription plan variation ID
    zaprite_plan_id = Column(String, default="")              # Zaprite plan ID
    sort_order      = Column(Integer, default=0)
    created_at      = Column(DateTime, default=datetime.utcnow)
    updated_at      = Column(DateTime, default=datetime.utcnow)


class EnrollmentApplication(Base):
    """Patient self-enrollment applications submitted via the public /enroll page."""
    __tablename__ = "enrollment_applications"
    id                   = Column(Integer, primary_key=True, index=True)
    enrollment_token     = Column(String, unique=True, nullable=False)  # UUID for tracking
    plan_id              = Column(Integer, ForeignKey("membership_plans.id"), nullable=True)
    plan_name            = Column(String, default="")        # Denormalized for display
    status               = Column(String, default="pending") # pending|payment_pending|active|rejected|cancelled

    # Demographics
    first_name           = Column(String, default="")
    last_name            = Column(String, default="")
    dob                  = Column(String, default="")
    gender               = Column(String, default="")
    email                = Column(String, default="")
    phone                = Column(String, default="")
    address              = Column(String, default="")
    city                 = Column(String, default="")
    state                = Column(String, default="")
    zip_code             = Column(String, default="")

    # Emergency contact
    emergency_name       = Column(String, default="")
    emergency_phone      = Column(String, default="")
    emergency_relation   = Column(String, default="")

    # Insurance (for referrals — not billed by practice)
    insurance_name       = Column(String, default="")
    insurance_id         = Column(String, default="")

    # Medical history (JSON)
    allergies            = Column(Text, default="[]")
    medications          = Column(Text, default="[]")
    conditions           = Column(Text, default="[]")

    # Signed consents (JSON array: [{type, version, signed_at, ip, signature}])
    consents             = Column(Text, default="[]")

    # Payment
    payment_provider     = Column(String, default="")        # square | zaprite
    payment_status       = Column(String, default="pending") # pending|completed|failed
    payment_reference    = Column(String, default="")        # Square order ID / Zaprite checkout ID
    payment_amount       = Column(Float, default=0.0)

    # Linked patient (set by staff after approval)
    patient_id           = Column(Integer, ForeignKey("patients.id"), nullable=True)
    reviewed_by          = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at          = Column(DateTime, nullable=True)
    review_notes         = Column(Text, default="")

    ip_address           = Column(String, default="")
    user_agent           = Column(String, default="")
    created_at           = Column(DateTime, default=datetime.utcnow)
    updated_at           = Column(DateTime, default=datetime.utcnow)


class PatientConsent(Base):
    """Individual consent records — one row per consent type per patient/enrollment."""
    __tablename__ = "patient_consents"
    id               = Column(Integer, primary_key=True, index=True)
    patient_id       = Column(Integer, ForeignKey("patients.id"), nullable=True)
    enrollment_id    = Column(Integer, ForeignKey("enrollment_applications.id"), nullable=True)
    consent_type     = Column(String, nullable=False)  # hipaa|telehealth|communication|membership
    document_version = Column(String, default="1.0")
    signed_at        = Column(DateTime, nullable=False)
    ip_address       = Column(String, default="")
    user_agent       = Column(String, default="")
    signature_text   = Column(String, default="")      # Typed full name as e-signature
    consented        = Column(Boolean, default=True)
    created_at       = Column(DateTime, default=datetime.utcnow)


class AdvanceBeneficiaryNotice(Base):
    """
    Advance Beneficiary Notice of Non-coverage (ABN) — CMS Form CMS-R-131.
    Required before ordering tests for Medicare patients when coverage is uncertain.
    42 C.F.R. § 411.408(f); CMS Pub. 100-04, Ch. 30.
    """
    __tablename__ = "abns"
    id               = Column(Integer, primary_key=True, index=True)
    lab_order_id     = Column(Integer, ForeignKey("lab_orders.id"), nullable=True)
    patient_id       = Column(Integer, ForeignKey("patients.id"), nullable=False)
    created_by       = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Tests listed on this ABN (JSON array of {name, code, estimated_cost})
    items            = Column(Text, default="[]")
    # Reason coverage may be denied (free text, e.g. "Diagnosis may not support medical necessity")
    reason           = Column(Text, default="")
    # Estimated cost the patient may owe
    estimated_cost   = Column(Float, default=0.0)

    # Patient decision — CMS option boxes:
    #   OPTION_1 = "I want the item; bill Medicare and I'll pay if denied"
    #   OPTION_2 = "I want the item but do NOT want Medicare billed; I will pay"
    #   OPTION_3 = "I do NOT want the item"
    patient_decision = Column(String, nullable=True)   # OPTION_1 | OPTION_2 | OPTION_3

    # Signature block
    signed_at        = Column(DateTime, nullable=True)
    signed_by_name   = Column(String, default="")       # patient typed full name
    witness_name     = Column(String, default="")

    # Lifecycle
    status           = Column(String, default="pending")  # pending | signed | declined | voided
    notes            = Column(Text, default="")
    created_at       = Column(DateTime, default=datetime.utcnow)
    updated_at       = Column(DateTime, default=datetime.utcnow)


class SkinLesion(Base):
    """
    A named, located skin lesion being monitored over time for a patient.
    Multiple LesionImage records are attached as the lesion is photographed.
    """
    __tablename__ = "skin_lesions"
    id            = Column(Integer, primary_key=True, index=True)
    patient_id    = Column(Integer, ForeignKey("patients.id"), nullable=False)
    created_by    = Column(Integer, ForeignKey("users.id"), nullable=False)
    name          = Column(String, nullable=False)           # e.g. "Left forearm — compound nevus"
    body_location = Column(String, default="")               # e.g. "Left forearm, lateral aspect"
    description   = Column(Text, default="")                 # Initial clinical description
    first_noted   = Column(String, default="")               # ISO date string
    status        = Column(String, default="monitoring")     # monitoring | resolved | referred | excised
    notes         = Column(Text, default="")
    created_at    = Column(DateTime, default=datetime.utcnow)
    updated_at    = Column(DateTime, default=datetime.utcnow)


class LesionImage(Base):
    """
    A single photograph of a SkinLesion at a point in time.
    Stores image data as base64 and the AI analysis result as JSON.
    """
    __tablename__ = "lesion_images"
    id            = Column(Integer, primary_key=True, index=True)
    lesion_id     = Column(Integer, ForeignKey("skin_lesions.id"), nullable=False)
    patient_id    = Column(Integer, ForeignKey("patients.id"), nullable=False)
    uploaded_by   = Column(Integer, ForeignKey("users.id"), nullable=False)
    image_data    = Column(Text, nullable=False)             # base64-encoded image bytes
    image_mime    = Column(String, default="image/jpeg")     # image/jpeg or image/png
    image_filename= Column(String, default="")
    taken_at      = Column(String, default="")               # ISO date when photo was taken
    notes         = Column(Text, default="")                 # Clinical notes for this photo
    # AI analysis result — populated by POST /api/skin-lesions/{id}/analyze
    ai_analysis   = Column(Text, nullable=True)              # JSON: {summary, abcde, changes, recommendation, urgency}
    ai_analyzed_at= Column(DateTime, nullable=True)
    created_at    = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String)
    resource_type = Column(String)
    resource_id = Column(String)
    ip_address = Column(String, default="")
    details = Column(Text, default="")
    timestamp = Column(DateTime, default=datetime.utcnow)


class TrainingRecord(Base):
    """Workforce HIPAA training completion records — POL-HIPAA-001."""
    __tablename__ = "training_records"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    training_name = Column(String, nullable=False)
    training_type = Column(String, default="hipaa_annual")  # hipaa_initial|hipaa_annual|security|custom
    completed_at = Column(DateTime, nullable=False)
    recorded_by = Column(Integer, ForeignKey("users.id"), nullable=True)  # admin who logged it
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
