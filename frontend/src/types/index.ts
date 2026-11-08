export type ThreatVerdict = "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN";

export interface ScanResult {
  id: string;
  target_url: string;
  normalized_url: string;
  domain: string;
  ip_address?: string;
  verdict: ThreatVerdict;
  risk_score: number;
  threat_types: string[];
  confidence_score: number;
  dns_records?: {
    a_records?: string[];
    mx_records?: string[];
    ns_records?: string[];
    txt_records?: string[];
  };
  ssl_certificate?: {
    issuer?: string;
    valid_from?: string;
    valid_to?: string;
    is_expired?: boolean;
    subject_alt_names?: string[];
    days_remaining?: number;
  };
  urlhaus_match?: {
    found: boolean;
    threat?: string;
    tags?: string[];
    urlhaus_reference?: string;
  };
  openphish_match?: {
    found: boolean;
    threat_category?: string;
  };
  ai_analysis?: {
    executive_summary?: string;
    brand_impersonation_target?: string;
    deception_techniques?: string[];
    plain_language_warning?: string;
  };
  evidence_timeline: Array<{
    timestamp: string;
    phase: string;
    detail: string;
    status: "pass" | "warn" | "fail";
    hash?: string;
  }>;
  evidence_hash: string;
  blockchain_tx?: string;
  blockchain_network?: string;
  scanned_at: string;
}

export interface ScamAnalysisResult {
  id: string;
  message_hash: string;
  channel_type: "SMS" | "EMAIL" | "CHAT" | "WHATSAPP";
  verdict: "CLEAN" | "SUSPICIOUS" | "MALICIOUS";
  risk_score: number;
  psychological_triggers: Array<{
    type: string;
    severity: "low" | "medium" | "high";
    snippet?: string;
    explanation: string;
  }>;
  extracted_iocs: {
    urls?: string[];
    phone_numbers?: string[];
    crypto_addresses?: string[];
    urgency_keywords?: string[];
  };
  ai_explanation: string;
  recommended_actions: string[];
  evidence_hash: string;
  created_at: string;
}

export interface SystemHealthStatus {
  project: string;
  status: string;
  version: string;
  timestamp: string;
  environment: string;
  services: Record<
    string,
    {
      status: string;
      latency_ms?: number;
      details?: string;
    }
  >;
}
