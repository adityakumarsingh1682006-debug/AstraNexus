-- =============================================================================
-- AstraNexus: Initial Database Schema (PostgreSQL / Supabase)
-- Mission: Threat Intelligence, Digital Forensics, and Cryptographic Notary
-- =============================================================================

-- Enable pgcrypto for UUID generation if not already active
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- -----------------------------------------------------------------------------
-- 1. URL & Infrastructure Scans Table
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_url TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    domain TEXT NOT NULL,
    ip_address INET,
    verdict VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN', -- 'SAFE', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN'
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    threat_types TEXT[] DEFAULT '{}',
    confidence_score NUMERIC(5,2) DEFAULT 0.0,
    
    -- Telemetry & Forensics Evidence (JSONB)
    dns_records JSONB DEFAULT '{}'::jsonb,
    ssl_certificate JSONB DEFAULT '{}'::jsonb,
    http_inspection JSONB DEFAULT '{}'::jsonb,
    urlhaus_match JSONB DEFAULT NULL,
    openphish_match JSONB DEFAULT NULL,
    
    -- AI Contextual Explanation (Explanation ONLY, not final verdict decider)
    ai_analysis JSONB DEFAULT '{}'::jsonb,
    
    -- Chronological Forensic Steps
    evidence_timeline JSONB DEFAULT '[]'::jsonb,
    
    -- Cryptographic Tamper-Proof Seal
    evidence_hash VARCHAR(66) NOT NULL, -- SHA-256 (0x...) canonical digest
    blockchain_tx VARCHAR(66) DEFAULT NULL,
    blockchain_network VARCHAR(64) DEFAULT NULL,
    
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for lightning fast threat lookups
CREATE INDEX IF NOT EXISTS idx_scans_domain ON public.scans (domain);
CREATE INDEX IF NOT EXISTS idx_scans_normalized_url ON public.scans (normalized_url);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON public.scans (verdict);
CREATE INDEX IF NOT EXISTS idx_scans_evidence_hash ON public.scans (evidence_hash);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON public.scans (scanned_at DESC);

-- -----------------------------------------------------------------------------
-- 2. Scam Message & Social Engineering Analyses Table
-- (Strict Privacy: No raw sensitive PII/passwords stored)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scam_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_hash VARCHAR(66) NOT NULL, -- SHA-256 hash of normalized content
    channel_type VARCHAR(32) NOT NULL DEFAULT 'SMS', -- 'SMS', 'EMAIL', 'CHAT', 'WHATSAPP'
    verdict VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN', -- 'CLEAN', 'SUSPICIOUS', 'MALICIOUS'
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    
    -- Forensic Psychological Markers
    psychological_triggers JSONB DEFAULT '[]'::jsonb, -- ['URGENCY', 'AUTHORITY_IMPERSONATION', 'FINANCIAL_LURE', 'FEAR_COERCION']
    extracted_iocs JSONB DEFAULT '{}'::jsonb, -- sanitized domains, phone numbers, crypto addrs
    
    -- Explanation and Actionable Mitigation
    ai_explanation TEXT,
    recommended_actions JSONB DEFAULT '[]'::jsonb,
    
    evidence_hash VARCHAR(66) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scam_message_hash ON public.scam_analyses (message_hash);
CREATE INDEX IF NOT EXISTS idx_scam_verdict ON public.scam_analyses (verdict);

-- -----------------------------------------------------------------------------
-- 3. Threat Intelligence Feed Cache Table (URLhaus, OpenPhish)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.threat_feeds_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feed_source VARCHAR(32) NOT NULL, -- 'URLHAUS', 'OPENPHISH'
    indicator TEXT NOT NULL,
    indicator_hash VARCHAR(66) NOT NULL,
    threat_category VARCHAR(64) NOT NULL,
    tags TEXT[] DEFAULT '{}',
    feed_metadata JSONB DEFAULT '{}'::jsonb,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_feeds_source_indicator_hash ON public.threat_feeds_cache (feed_source, indicator_hash);
CREATE INDEX IF NOT EXISTS idx_feeds_expires_at ON public.threat_feeds_cache (expires_at);

-- -----------------------------------------------------------------------------
-- 4. Community Threat Reports Table
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.community_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_indicator TEXT NOT NULL,
    indicator_type VARCHAR(32) NOT NULL, -- 'URL', 'DOMAIN', 'PHONE', 'WALLET'
    threat_category VARCHAR(64) NOT NULL,
    description TEXT,
    evidence_url TEXT,
    reporter_pseudonym VARCHAR(64) DEFAULT 'Anonymous Sentinel',
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING', -- 'PENDING', 'VERIFIED', 'RESOLVED', 'REJECTED'
    upvotes INTEGER NOT NULL DEFAULT 1,
    verified_scan_id UUID REFERENCES public.scans(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_community_reports_target ON public.community_reports (target_indicator);
CREATE INDEX IF NOT EXISTS idx_community_reports_status ON public.community_reports (status);

-- -----------------------------------------------------------------------------
-- 5. Blockchain Notarization Audit Log
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.blockchain_notarizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id UUID NOT NULL,
    report_type VARCHAR(32) NOT NULL, -- 'SCAN', 'SCAM_ANALYSIS', 'COMMUNITY'
    report_hash VARCHAR(66) NOT NULL UNIQUE,
    blockchain_network VARCHAR(64) NOT NULL,
    contract_address VARCHAR(42) NOT NULL,
    tx_hash VARCHAR(66) NOT NULL,
    block_number BIGINT,
    signer_address VARCHAR(42) NOT NULL,
    notarized_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notarizations_report_hash ON public.blockchain_notarizations (report_hash);
CREATE INDEX IF NOT EXISTS idx_notarizations_tx_hash ON public.blockchain_notarizations (tx_hash);
