# MedFlow EMR — Setup Guide

## Quick Start (Local Development)

### Prerequisites
- Python 3.10+
- pip

### 1. Install dependencies
```bash
cd "EMR Project/backend"
pip install -r requirements.txt
```

### 2. Configure environment
```bash
cp .env.example .env
# Edit .env — at minimum change SECRET_KEY
```

### 3. Seed the database & start
```bash
python setup.py     # creates DB + demo users (run once)
python main.py      # starts server on http://localhost:8000
```

### 4. Open the app
Navigate to **http://localhost:8000** in your browser.

**Demo credentials:**
| Username | Password   | Role       |
|----------|------------|------------|
| admin    | Admin123!  | Admin      |
| drsmith  | Doctor123! | Physician  |

---

## AI Note Generation (Ollama)

MedFlow uses a **local LLM** so patient data never leaves your server.

```bash
# Install Ollama: https://ollama.ai
ollama pull llama3.1       # ~4.7 GB download
# Ollama runs on http://localhost:11434 by default
```

The AI generates complete Medicare-compliant SOAP notes with ICD-10 and CPT codes from a plain-English prompt. **Always review AI output before signing.**

---

## Docker Deployment (Production)

```bash
cp .env.example .env
# Edit .env with your real SECRET_KEY
docker compose up -d
```

The app will be available at **http://your-server:8000**.

---

## HIPAA Compliance Checklist

MedFlow provides the technical foundation — your deployment must also address:

- **Encryption at rest**: Use SQLCipher (SQLite) or PostgreSQL with pgcrypto; enable full-disk encryption on the server
- **Encryption in transit**: Put MedFlow behind NGINX with a valid TLS certificate (Let's Encrypt)
- **Audit logs**: Built-in — every PHI access is logged with user ID, IP, and timestamp
- **Access control**: JWT tokens expire in 8 hours; role-based (admin / physician / staff)
- **BAA agreements**: Sign BAAs with all vendors (cloud host, Twilio, LabCorp, Stripe)
- **Backups**: Schedule encrypted daily backups of the database
- **Minimum necessary**: Users only see data relevant to their role

---

## Integrating Third-Party Services

All integrations are stubbed with clear `# PLACEHOLDER` comments in `backend/main.py`.

### Fax (Twilio)
```python
# In send_fax() and fax_imaging_order():
from twilio.rest import Client
client = Client(TWILIO_SID, TWILIO_TOKEN)
client.fax.faxes.create(from_=FAX_NUMBER, to=to_number, media_url=pdf_url)
```

### LabCorp Link API
```python
# In transmit_lab_order():
# POST to https://api.labcorp.com/ehr/fhir/v1/ServiceRequest
# with OAuth2 bearer token + HL7 FHIR R4 ServiceRequest resource
```

### Stripe Payments
```python
# In create_payment() and create_membership():
import stripe
stripe.api_key = STRIPE_SECRET_KEY
intent = stripe.PaymentIntent.create(amount=int(amount*100), currency="usd")
subscription = stripe.Subscription.create(customer=cus_id, items=[{"price": price_id}])
```

---

## File Structure
```
EMR Project/
├── backend/
│   ├── main.py          # FastAPI app — all API routes
│   ├── models.py        # SQLAlchemy database models
│   ├── database.py      # DB connection
│   ├── setup.py         # One-time DB seed script
│   └── requirements.txt
├── frontend/
│   └── index.html       # React SPA (no build step required)
├── docker-compose.yml
├── Dockerfile
├── .env.example
└── SETUP.md
```
