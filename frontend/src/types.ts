
export type Verdict = "low_risk" | "suspicious" | "malicious";

export interface AuthSignal {
  result: string;
  domain?: string | null;
  aligned?: boolean | null;
}

export interface EmailAnalysis {
  metadata: {
    subject?: string | null;
    date?: string | null;
    message_id?: string | null;
    content_types: string[];
  };
  sender: {
    address?: string | null;
    display_name?: string | null;
    domain?: string | null;
  };
  reply_to: {
    address?: string | null;
    display_name?: string | null;
    domain?: string | null;
  };
  return_path: {
    address?: string | null;
    display_name?: string | null;
    domain?: string | null;
  };
  authentication: {
    spf: AuthSignal;
    dkim: AuthSignal;
    dmarc: AuthSignal;
    source_headers: number;
  };
  delivery: {
    hop_count: number;
    earliest_public_ip?: string | null;
    received: {
      index: number;
      raw: string;
      from_host?: string | null;
      by_host?: string | null;
      ips: string[];
      public_ips: string[];
    }[];
  };
  urls: {
    url: string;
    hostname?: string | null;
    path?: string | null;
    has_ip_host: boolean;
    is_punycode: boolean;
    has_userinfo: boolean;
    is_shortener: boolean;
    suspicious_path: boolean;
    sender_domain_match?: boolean | null;
  }[];
  domains: string[];
  ips: string[];
  detections: {
    id: string;
    name: string;
    category: string;
    severity: string;
    confidence: number;
    score: number;
    evidence: string[];
  }[];
  risk: {
    score: number;
    confidence: number;
    verdict: Verdict;
    rationale: string;
  };
  engine_version: string;
}
