# AstraNexus Deployment & Operations Guide

## 1. Overview & Security Mandate

> [!IMPORTANT]
> **No external deployments or repository publishing** may be executed without explicit operator approval. All instructions below are prepared for reproducible staging, evaluation, and eventual production deployment. **Never commit secrets, private keys, or API credentials to version control.**

---

## 2. Environment Variables Specification

Create `.env` at the project root based on this reference:

| Variable | Required | Default / Example | Purpose |
| :--- | :---: | :--- | :--- |
| `PROJECT_NAME` | No | `"AstraNexus Intelligence Gateway"` | Platform display name in OpenAPI docs and health checks. |
| `ENVIRONMENT` | No | `"development"` | Environment mode (`development`, `staging`, `production`). |
| `DEBUG` | No | `false` | Enables verbose FastAPI debugging (must be `false` in production). |
| `CORS_ORIGINS` | Yes | `["http://localhost:3000","https://astranexus.vercel.app"]` | Whitelisted frontend origins permitted to make cross-origin requests. |
| `SSRF_MAX_REDIRECTS` | No | `5` | Maximum HTTP redirect depth before terminating inspection. |
| `HTTP_TIMEOUT_SECONDS` | No | `6.0` | Socket timeout for passive HTTP and TLS inspection. |
| `MAX_RESPONSE_BYTES` | No | `1048576` | Maximum bytes downloaded during passive HTML inspection (1 MB). |
| `GEMINI_API_KEY` | Optional | `""` | Google Gemini API key for natural language cognitive explainer. |
| `GEMINI_MODEL` | No | `"gemini-2.5-flash"` | Model identifier for cognitive explanation generation. |
| `SUPABASE_URL` | Optional | `"https://your-project.supabase.co"` | Supabase PostgreSQL project URL for persistent incident reports. |
| `SUPABASE_SERVICE_KEY` | Optional | `""` | Supabase service role key for privileged backend operations. |
| `SUPABASE_ANON_KEY` | Optional | `""` | Supabase anonymous public key. |
| `URLHAUS_API_URL` | No | `"https://urlhaus-api.abuse.ch/v1"` | URLhaus REST API endpoint. |
| `URLHAUS_AUTH_KEY` | Optional | `""` | Abuse.ch API authentication key for elevated rate limits. |
| `OPENPHISH_FEED_URL` | No | `"https://openphish.com/feed.txt"` | OpenPhish plain-text phishing feed URL. |
| `SAFE_BROWSING_API_KEY`| Optional | `""` | Google Safe Browsing v4 Lookup API key. |
| `FEED_CACHE_TTL_SECONDS`| No | `3600` | In-memory cache TTL for external threat feeds (1 hour). |
| `EVM_RPC_URL` | Yes | `"http://127.0.0.1:8545"` | EVM JSON-RPC endpoint (Local Hardhat, Sepolia, Arbitrum, Base). |
| `ASTRA_REGISTRY_CONTRACT_ADDRESS` | Yes | `"0x5FbDB2315678afecb367f032d93F642f64180aa3"` | Deployed address of `ThreatRegistry` smart contract. |
| `NOTARY_SIGNER_PRIVATE_KEY` | Yes | `"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"` | Private key authorized to submit report commitments on-chain. |

---

## 3. Blockchain Deployment Instructions

### 3.1 Local Reproducible EVM Node (Hackathon / Staging)
```bash
# 1. Navigate to blockchain directory
cd blockchain

# 2. Install dependencies
npm install

# 3. Start local Hardhat EVM node (persists on http://127.0.0.1:8545)
npm run node

# In a separate terminal, deploy the smart contract:
npx hardhat run scripts/deploy.js --network localhost
```
The deploy script outputs the deployed contract address:
```
ThreatRegistry deployed to: 0x5FbDB2315678afecb367f032d93F642f64180aa3
```

### 3.2 Public EVM Testnet Deployment (Sepolia / Base Sepolia / Arbitrum Sepolia)
```bash
# Set your deployment private key and RPC URL
export SEPOLIA_RPC_URL="https://sepolia.infura.io/v3/YOUR_INFURA_KEY"
export DEPLOYER_PRIVATE_KEY="0xYOUR_TESTNET_PRIVATE_KEY"

# Deploy contract to Sepolia
npx hardhat run scripts/deploy.js --network sepolia
```
Update `ASTRA_REGISTRY_CONTRACT_ADDRESS` and `EVM_RPC_URL` in `.env`.

---

## 4. Backend Deployment Instructions

### 4.1 Production Linux / Systemd Setup
```bash
# 1. Clone repository into production directory
cd /opt/astranexus/backend

# 2. Set up isolated virtualenv
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 3. Verify tests pass prior to serving
pytest tests -v

# 4. Run via production ASGI server (Gunicorn with Uvicorn workers)
gunicorn -w 4 -k uvicorn.workers.UvicornWorker app.main:app \
  --bind 127.0.0.1:8000 \
  --access-logfile /var/log/astranexus/access.log \
  --error-logfile /var/log/astranexus/error.log
```

### 4.2 Systemd Service Unit (`/etc/systemd/system/astranexus-backend.service`)
```ini
[Unit]
Description=AstraNexus Threat Intelligence Gateway
After=network.target

[Service]
User=astranexus
Group=astranexus
WorkingDirectory=/opt/astranexus/backend
EnvironmentFile=/opt/astranexus/.env
ExecStart=/opt/astranexus/backend/venv/bin/gunicorn -w 4 -k uvicorn.workers.UvicornWorker app.main:app --bind 127.0.0.1:8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## 5. Frontend Deployment Instructions

### 5.1 Standalone Production Node.js Server
```bash
cd frontend

# 1. Install production dependencies
npm ci

# 2. Compile optimized production build
npm run build

# 3. Run production server
npm run start -p 3000
```

### 5.2 Vercel Deployment Configuration
Configure the following Environment Variables in the Vercel Dashboard:
- `NEXT_PUBLIC_API_URL`: URL of your backend gateway (e.g. `https://api.astranexus.yourdomain.com/api/v1`)
- `NEXT_PUBLIC_EVM_RPC_URL`: Public EVM RPC endpoint for client-side direct verification
- `NEXT_PUBLIC_REGISTRY_CONTRACT`: Deployed `ThreatRegistry` smart contract address

---

## 6. Database Migrations (Supabase PostgreSQL)

Supabase DDL migrations are located in `supabase/migrations/`:
- `001_initial_schema.sql`: Core tables for `scam_reports`, `threat_indicators`, `risk_classifications`, and `audit_commitments`.
- `002_rls_policies.sql`: Strict Row-Level Security (RLS) rules:
  - Public anonymous users can read verified reports and public advisories.
  - Only authenticated users or backend service role can insert community reports.
  - Administrative attestation updates are restricted to authorized addresses.

### Execution via Supabase CLI
```bash
# Link local repository to Supabase project
supabase link --project-ref your-project-id

# Push migrations
supabase db push
```
