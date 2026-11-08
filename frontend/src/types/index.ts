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
  google_safebrowsing_match?: {
    found: boolean;
    threat?: string;
    threat_type?: string;
  };
  phishtank_match?: {
    found: boolean;
    threat?: string;
    evidence_reference?: string;
  };
  virustotal_match?: {
    found: boolean;
    threat?: string;
    malicious_count?: number;
    total_engines?: number;
  };
  website_security?: {
    grade?: string;
    https_enforced?: boolean;
    http_to_https_redirect?: boolean;
    headers_evaluated?: Record<string, {
      header_name: string;
      present: boolean;
      value?: string;
      status: string;
      summary: string;
    }>;
    redirect_analysis?: {
      initial_url: string;
      final_url: string;
      redirect_count: number;
      has_redirects: boolean;
      has_cross_domain: boolean;
      has_protocol_downgrade: boolean;
      chain?: Array<{
        hop_number: number;
        url: string;
        domain: string;
        scheme: string;
        is_cross_domain: boolean;
        is_downgrade: boolean;
      }>;
      summary: string;
    };
    mixed_content?: {
      has_mixed_content: boolean;
      active_count: number;
      passive_count: number;
      sample_active?: string[];
      sample_passive?: string[];
      summary: string;
    };
    software_security?: {
      is_version_disclosed: boolean;
      disclosed_banners?: Array<{ source: string; banner: string }>;
      known_vulnerabilities?: Array<any>;
      summary: string;
    };
    findings?: Array<{
      id: string;
      title: string;
      severity: string;
      technical_evidence?: Record<string, any>;
      potential_impact: string;
      recommended_remediation: string;
      limitations: string;
    }>;
    findings_count?: number;
    consumer_explanation?: string;
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
