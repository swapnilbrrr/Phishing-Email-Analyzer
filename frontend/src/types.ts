
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
    attachments: {
      filename?: string | null;
      content_type: string;
      disposition?: string | null;
      size_bytes?: number | null;
    }[];
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
    smtp_mail_from_claims: string[];
    source_headers: number;
    trusted: boolean;
    untrusted_header_count: number;
    trust_note: string;
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
  html_links: {
    href: string;
    text: string;
    href_hostname?: string | null;
    displayed_hostname?: string | null;
    destination_mismatch: boolean;
  }[];
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
