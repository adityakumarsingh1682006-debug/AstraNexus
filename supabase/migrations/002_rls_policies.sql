-- =============================================================================
-- AstraNexus: Row Level Security (RLS) Policies
-- Enforce strict data boundaries, public read for threat verifications,
-- and backend-only authenticated mutation.
-- =============================================================================

-- Enable Row Level Security on all core tables
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scam_analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_feeds_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.community_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.blockchain_notarizations ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- 1. Scans Policies
-- Anyone (anons, SOC analysts, victims) can read scan reports by ID, URL, or hash.
-- Only the backend service role or authenticated system worker can insert/update.
-- -----------------------------------------------------------------------------
CREATE POLICY "Public read access for scans" 
ON public.scans 
FOR SELECT 
USING (true);

CREATE POLICY "Service role write access for scans" 
ON public.scans 
FOR ALL 
TO service_role 
USING (true) 
WITH CHECK (true);

-- -----------------------------------------------------------------------------
-- 2. Scam Analyses Policies
-- Analyses are publicly viewable by their cryptographic hash or ID.
-- -----------------------------------------------------------------------------
CREATE POLICY "Public read access for scam analyses" 
ON public.scam_analyses 
FOR SELECT 
USING (true);

CREATE POLICY "Service role write access for scam analyses" 
ON public.scam_analyses 
FOR ALL 
TO service_role 
USING (true) 
WITH CHECK (true);

-- -----------------------------------------------------------------------------
-- 3. Threat Feeds Cache Policies
-- Threat feeds cache is strictly read-only for public/client queries.
-- -----------------------------------------------------------------------------
CREATE POLICY "Public read access for threat feeds" 
ON public.threat_feeds_cache 
FOR SELECT 
USING (true);

CREATE POLICY "Service role manages threat feeds" 
ON public.threat_feeds_cache 
FOR ALL 
TO service_role 
USING (true) 
WITH CHECK (true);

-- -----------------------------------------------------------------------------
-- 4. Community Reports Policies
-- Anyone can view community threat alerts.
-- Anyone can submit a community threat report (with backend validation/honeypot).
-- Upvoting allowed via public RPC or authenticated client.
-- -----------------------------------------------------------------------------
CREATE POLICY "Public read access for community reports" 
ON public.community_reports 
FOR SELECT 
USING (true);

CREATE POLICY "Public insert access for community reports" 
ON public.community_reports 
FOR INSERT 
WITH CHECK (true);

CREATE POLICY "Service role full access for community reports" 
ON public.community_reports 
FOR ALL 
TO service_role 
USING (true) 
WITH CHECK (true);

-- -----------------------------------------------------------------------------
-- 5. Blockchain Notarization Policies
-- Publicly readable to allow trustless on-chain proof verification.
-- Only backend service can record notarizations.
-- -----------------------------------------------------------------------------
CREATE POLICY "Public read access for blockchain notarizations" 
ON public.blockchain_notarizations 
FOR SELECT 
USING (true);

CREATE POLICY "Service role full access for blockchain notarizations" 
ON public.blockchain_notarizations 
FOR ALL 
TO service_role 
USING (true) 
WITH CHECK (true);
