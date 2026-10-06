
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["info", "low", "medium", "high", "critical"]
Verdict = Literal["low_risk", "suspicious", "malicious"]


class AnalysisRequest(BaseModel):
    raw_email: str = Field(min_length=1, max_length=300_000)


class Address(BaseModel):
    raw: str | None = None
    address: str | None = None
    display_name: str | None = None
    domain: str | None = None


class AuthSignal(BaseModel):
    result: str = "none"
    domain: str | None = None
    aligned: bool | None = None


class Authentication(BaseModel):
    spf: AuthSignal = Field(default_factory=AuthSignal)
    dkim: AuthSignal = Field(default_factory=AuthSignal)
    dmarc: AuthSignal = Field(default_factory=AuthSignal)
    source_headers: int = 0


class ReceivedHop(BaseModel):
    index: int
    raw: str
    from_host: str | None = None
    by_host: str | None = None
    ips: list[str] = Field(default_factory=list)
    public_ips: list[str] = Field(default_factory=list)


class Delivery(BaseModel):
    hop_count: int = 0
    received: list[ReceivedHop] = Field(default_factory=list)
    earliest_public_ip: str | None = None


class UrlIndicator(BaseModel):
    url: str
    hostname: str | None = None
    scheme: str | None = None
    port: int | None = None
    path: str | None = None
    has_ip_host: bool = False
    is_punycode: bool = False
    has_userinfo: bool = False
    is_shortener: bool = False
    suspicious_path: bool = False
    sender_domain_match: bool | None = None


class Detection(BaseModel):
    id: str
    name: str
    category: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    score: int = Field(ge=0, le=100)
    evidence: list[str] = Field(min_length=1)


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    verdict: Verdict
    rationale: str


class EmailMetadata(BaseModel):
    subject: str | None = None
    date: str | None = None
    message_id: str | None = None
    content_types: list[str] = Field(default_factory=list)


class EmailAnalysis(BaseModel):
    metadata: EmailMetadata
    sender: Address
    reply_to: Address
    return_path: Address
    authentication: Authentication
    delivery: Delivery
    urls: list[UrlIndicator] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    detections: list[Detection] = Field(default_factory=list)
    risk: RiskAssessment
    engine_version: str = "0.1.0"


class HealthResponse(BaseModel):
    status: str
    engine_version: str
