# AstraNexus 🛡️⚡
> **AI-Powered Digital Trust & Threat Intelligence Platform**

AstraNexus is an autonomous cybersecurity platform engineered to detect, investigate, correlate, and prevent modern digital threats:
- **Phishing & Fraudulent URLs**: Deep reconnaissance across DNS, TLS certificate chains, typosquatting homographs, and real-time feeds.
- **Scam & Social Engineering Messages**: Psychological manipulation triage (artificial urgency, authority impersonation, fear coercion, financial lures) powered by Google Gemini with deterministic scoring rules.
- **Threat Correlation Graph**: Interconnecting disparate infrastructure anomalies across ASNs, DNS nameservers, and certificate subjects.
- **Blockchain Evidence Notary**: Cryptographic SHA-256 evidence digests immutably notarized on an EVM smart contract without exposing sensitive user PII.

---

## Architecture Overview

- **Frontend**: Next.js 15 (App Router), TypeScript, Tailwind CSS (Astra Cybernetic design system), Lucide icons, Framer Motion.
- **Backend**: Python 3.9+ FastAPI asynchronous gateway, Pydantic v2 schemas, strict SSRF quarantine, dnspython, cryptography.
- **Threat Intelligence**: Abuse.ch URLhaus & OpenPhish feeds.
- **Cognitive AI**: Google Gemini API (structured explanation layer; final verdicts remain strictly deterministic).
- **Database**: Supabase PostgreSQL with Row-Level Security (RLS).
- **Blockchain**: Solidity smart contract (`AstraTrustRegistry.sol`) on EVM-compatible testnets.

---

## Project Structure

```
AstraNexus/
├── backend/                  # FastAPI Python backend
│   ├── app/
│   │   ├── api/v1/           # API version 1 endpoints (health, scan, etc.)
│   │   ├── core/             # Configuration, SSRF filter, custom exceptions
│   │   ├── schemas/          # Pydantic v2 models
│   │   ├── services/         # Domain engines (DNS, SSL, Typosquat, AI, Blockchain)
│   │   └── main.py           # FastAPI ASGI entrypoint
│   ├── tests/                # Pytest test suite (health, SSRF defense)
│   ├── requirements.txt      # Python dependencies
│   └── .env.example
├── frontend/                 # Next.js 15 frontend
│   ├── public/               # Manifest, icons, static assets
│   ├── src/
│   │   ├── app/              # Next.js App Router (Dashboard, Scan, Scam Analyzer, etc.)
│   │   ├── components/       # UI layout, HUD badges, radar scanners
│   │   ├── lib/              # Utility helpers, score classifiers
│   │   ├── styles/           # Tailwind CSS & cybernetic glow tokens
│   │   └── types/            # TypeScript interfaces
│   ├── package.json
│   ├── tailwind.config.ts
│   └── next.config.ts
├── supabase/
│   └── migrations/           # PostgreSQL DDL & RLS security policies
│       ├── 001_initial_schema.sql
│       └── 002_rls_policies.sql
├── pytest.ini                # Pytest configuration
└── README.md
```

---

## Getting Started

### 1. Backend (FastAPI)

```bash
# Navigate to backend directory
cd backend

# Activate virtual environment
# Windows:
.\venv\Scripts\Activate.ps1
# Linux/macOS:
source venv/bin/activate

# Install dependencies (already prepared in Phase 1)
pip install -r requirements.txt

# Run backend test suite
pytest backend/tests -v

# Start FastAPI server (development mode with hot-reload)
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
*Backend Swagger Docs*: `http://127.0.0.1:8000/api/v1/docs`  
*Health Check*: `http://127.0.0.1:8000/api/v1/health`

### 2. Frontend (Next.js)

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies (already installed in Phase 1)
npm install

# Build production bundle
npm run build

# Start Next.js development server
npm run dev
```
*Frontend Application*: `http://localhost:3000`

---

## Phase 1 Verification Summary

- [x] Monorepo folder hierarchy created
- [x] Supabase SQL migrations (tables & RLS policies) implemented
- [x] FastAPI gateway with Pydantic v2 settings, CORS, and SSRF security defense created
- [x] Backend test suite passing 7/7 unit tests (SSRF IP quarantine, scheme rejection, health endpoints)
- [x] Next.js 15 frontend initialized with Astra Cybernetic design system (Obsidian void palette, neon cyan & violet glow, radar sweep animations)
- [x] Production build (`npm run build`) succeeded with 0 errors across all 10 routes
