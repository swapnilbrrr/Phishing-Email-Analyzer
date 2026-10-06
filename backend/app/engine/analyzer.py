
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from .domain import (
    SHORTENERS,
    display_claims_brand,
    find_brand_impersonation,
    normalize_domain,
    same_organization,
)
from .parser import extract_urls, parse_email
from ..models import Detection, EmailAnalysis, RiskAssessment, UrlIndicator


ENGINE_VERSION = "0.1.0"

URGENCY_TERMS = {
    "urgent", "immediately", "suspended", "verify your", "confirm your",
    "unusual activity", "security alert", "limited time", "act now",
    "action required", "account locked", "account disabled", "click here",
}

CREDENTIAL_TERMS = {
    "password", "passcode", "one-time code", "verification code",
    "login", "log in", "sign in", "credentials", "verify your account",
    "confirm your identity",
}

SUSPICIOUS_PATH_TERMS = {
    "login", "signin", "sign-in", "verify", "verification", "password",
    "secure", "account", "unlock", "confirm", "update-payment",
}


def make_detection(
    detection_id: str,
    name: str,
    category: str,
    severity: str,
    confidence: float,
    score: int,
    *evidence: str,
) -> Detection:
    return Detection(
        id=detection_id,
        name=name,
        category=category,
        severity=severity,
        confidence=confidence,
        score=score,
        evidence=[item for item in evidence if item],
    )


def analyze(raw_email: str) -> EmailAnalysis:
    (
        _message,
        body,
        metadata,
        sender,
        reply_to,
        return_path,
        authentication,
        delivery,
    ) = parse_email(raw_email)

    combined = " ".join(
        value for value in [metadata.subject or "", body] if value
    ).casefold()

    detections: list[Detection] = []

    if authentication.spf.result == "fail":
        detections.append(
            make_detection(
                "AUTH-001", "SPF failed", "authentication", "high", 0.94, 15,
                "Authentication-Results reports SPF=fail.",
                f"Envelope sender domain: {authentication.spf.domain}"
                if authentication.spf.domain else "",
            )
        )

    if authentication.dkim.result == "fail":
        detections.append(
            make_detection(
                "AUTH-002", "DKIM failed", "authentication", "high", 0.93, 15,
                "Authentication-Results reports DKIM=fail.",
            )
        )

    if authentication.dmarc.result == "fail":
        detections.append(
            make_detection(
                "AUTH-003", "DMARC failed", "authentication", "high", 0.97, 25,
                "Authentication-Results reports DMARC=fail.",
                "DMARC failure is a strong identity-integrity signal, not proof of phishing by itself.",
            )
        )

    if authentication.spf.aligned is False:
        detections.append(
            make_detection(
                "AUTH-004", "SPF identity is not aligned", "authentication",
                "medium", 0.88, 10,
                "The SMTP MAIL FROM organization differs from the visible From organization.",
            )
        )

    if authentication.dkim.aligned is False:
        detections.append(
            make_detection(
                "AUTH-005", "DKIM identity is not aligned", "authentication",
                "medium", 0.88, 10,
                "The DKIM signing domain differs from the visible From organization.",
            )
        )

    if sender.domain and reply_to.domain and sender.domain != reply_to.domain:
        detections.append(
            make_detection(
                "IDENTITY-001", "Reply-To domain mismatch", "identity",
                "high", 0.92, 20,
                f"From domain: {sender.domain}",
                f"Reply-To domain: {reply_to.domain}",
            )
        )

    if sender.domain and return_path.domain and not same_organization(
        sender.domain, return_path.domain
    ):
        detections.append(
            make_detection(
                "IDENTITY-002", "Return-Path organization mismatch", "identity",
                "medium", 0.82, 10,
                f"From domain: {sender.domain}",
                f"Return-Path domain: {return_path.domain}",
            )
        )

    brand = find_brand_impersonation(sender.domain)
    if brand:
        brand_name, distance = brand
        detections.append(
            make_detection(
                "IDENTITY-003",
                "Sender domain resembles a protected brand",
                "identity",
                "high",
                0.96,
                30,
                f"Sender domain: {sender.domain}",
                f"Closest protected brand: {brand_name}",
                f"Base-label edit distance: {distance}",
            )
        )

    claimed_brand = display_claims_brand(sender.display_name, sender.domain)
    if claimed_brand:
        detections.append(
            make_detection(
                "IDENTITY-004",
                "Display name claims a different brand",
                "identity",
                "high",
                0.90,
                20,
                f'Display name: "{sender.display_name}"',
                f"Sender domain: {sender.domain}",
                f"Brand claim: {claimed_brand}",
            )
        )

    urgency_hits = sorted(term for term in URGENCY_TERMS if term in combined)
    if urgency_hits:
        detections.append(
            make_detection(
                "CONTENT-001", "Urgency or pressure language", "content",
                "medium", 0.67, min(8 + len(urgency_hits), 12),
                f"Matched language: {', '.join(urgency_hits[:5])}",
            )
        )

    credential_hits = sorted(term for term in CREDENTIAL_TERMS if term in combined)
    if credential_hits:
        detections.append(
            make_detection(
                "CONTENT-002",
                "Credential or account-verification language",
                "content",
                "medium",
                0.78,
                min(15, 8 + len(credential_hits) * 2),
                f"Matched language: {', '.join(credential_hits[:5])}",
            )
        )

    url_indicators: list[UrlIndicator] = []
    url_values = extract_urls(raw_email + "\n" + body)

    for raw_url in url_values[:50]:
        try:
            parsed = urlsplit(raw_url)
            hostname = normalize_domain(parsed.hostname)
        except ValueError:
            continue

        if not hostname:
            continue

        try:
            port = parsed.port
        except ValueError:
            port = None

        has_ip_host = False
        try:
            ipaddress.ip_address(hostname)
            has_ip_host = True
        except ValueError:
            pass

        suspicious_path = any(
            token in (parsed.path or "").casefold()
            for token in SUSPICIOUS_PATH_TERMS
        )

        indicator = UrlIndicator(
            url=raw_url,
            hostname=hostname,
            scheme=parsed.scheme.lower() if parsed.scheme else None,
            port=port,
            path=parsed.path or None,
            has_ip_host=has_ip_host,
            is_punycode=any(
                label.startswith("xn--") for label in hostname.split(".")
            ),
            has_userinfo=bool(parsed.username or parsed.password),
            is_shortener=hostname in SHORTENERS,
            suspicious_path=suspicious_path,
            sender_domain_match=same_organization(hostname, sender.domain),
        )
        url_indicators.append(indicator)

        if has_ip_host:
            detections.append(
                make_detection(
                    "URL-001", "URL uses an IP address as host", "url",
                    "high", 0.95, 20, f"URL: {raw_url}",
                )
            )

        if indicator.is_punycode:
            detections.append(
                make_detection(
                    "URL-002", "URL uses punycode", "url",
                    "medium", 0.89, 15, f"Hostname: {hostname}",
                )
            )

        if indicator.has_userinfo:
            detections.append(
                make_detection(
                    "URL-003", "URL contains userinfo before the host", "url",
                    "high", 0.98, 22, f"URL: {raw_url}",
                )
            )

        if indicator.is_shortener:
            detections.append(
                make_detection(
                    "URL-004", "URL uses a known shortening service", "url",
                    "medium", 0.73, 10, f"Shortener: {hostname}",
                )
            )

        if suspicious_path:
            detections.append(
                make_detection(
                    "URL-005",
                    "URL path suggests account or credential collection",
                    "url",
                    "medium",
                    0.69,
                    8,
                    f"Path: {parsed.path}",
                )
            )

        url_brand = find_brand_impersonation(hostname)
        if url_brand:
            brand_name, distance = url_brand
            detections.append(
                make_detection(
                    "URL-006",
                    "URL domain resembles a protected brand",
                    "url",
                    "high",
                    0.94,
                    22,
                    f"URL hostname: {hostname}",
                    f"Closest protected brand: {brand_name}",
                    f"Base-label edit distance: {distance}",
                )
            )

    credential_hosts = [
        item.hostname
        for item in url_indicators
        if item.hostname
        and item.suspicious_path
        and item.sender_domain_match is False
    ]
    if credential_hosts:
        detections.append(
            make_detection(
                "URL-007",
                "Credential-oriented URL is outside the sender organization",
                "correlation",
                "medium",
                0.79,
                12,
                f"URL host: {credential_hosts[0]}",
                f"Sender domain: {sender.domain}" if sender.domain else "",
            )
        )

    detection_ids = {item.id for item in detections}

    if (
        "IDENTITY-001" in detection_ids
        and ("CONTENT-002" in detection_ids or "URL-005" in detection_ids)
        and (
            "IDENTITY-003" in detection_ids
            or "IDENTITY-004" in detection_ids
            or "AUTH-003" in detection_ids
        )
    ):
        detections.append(
            make_detection(
                "CORR-001",
                "Identity, content, and authentication signals reinforce each other",
                "correlation",
                "critical",
                0.95,
                18,
                "Reply-To differs from the sender identity.",
                "Credential/account-verification pressure or a credential-oriented URL is present.",
                "A separate brand-identity or authentication anomaly is also present.",
            )
        )

    if "IDENTITY-003" in detection_ids and (
        "URL-006" in detection_ids or "URL-005" in detection_ids
    ):
        detections.append(
            make_detection(
                "CORR-002",
                "Brand impersonation extends into the URL",
                "correlation",
                "critical",
                0.96,
                20,
                "The sender identity and a linked hostname both exhibit impersonation characteristics.",
            )
        )

    unique: dict[str, Detection] = {}
    for item in detections:
        existing = unique.get(item.id)
        if existing is None:
            unique[item.id] = item
            continue
        merged_evidence = existing.evidence + [
            evidence for evidence in item.evidence
            if evidence not in existing.evidence
        ]
        unique[item.id] = existing.model_copy(
            update={"evidence": merged_evidence[:5]}
        )

    detections = sorted(
        unique.values(),
        key=lambda item: (-item.score, -item.confidence, item.id),
    )

    score = min(100, sum(item.score for item in detections))

    if score >= 70:
        verdict = "malicious"
        rationale = (
            "Multiple independent signals indicate that the message should "
            "be treated as a phishing threat."
        )
    elif score >= 40:
        verdict = "suspicious"
        rationale = (
            "The message contains meaningful anomalies, but the available "
            "evidence is not sufficient to call it malicious."
        )
    else:
        verdict = "low_risk"
        rationale = (
            "No strong phishing indicators were established by the current "
            "offline analysis rules."
        )

    if detections:
        confidence_product = 1.0
        for item in detections[:8]:
            confidence_product *= 1 - (item.confidence * 0.45)
        confidence = round(1 - confidence_product, 3)
    else:
        confidence = 0.25

    domains = sorted(
        {
            value
            for value in [
                sender.domain,
                reply_to.domain,
                return_path.domain,
                authentication.spf.domain,
                authentication.dkim.domain,
            ] + [item.hostname for item in url_indicators]
            if value
        }
    )

    ips = sorted(
        {
            ip
            for hop in delivery.received
            for ip in hop.ips
        }
    )

    return EmailAnalysis(
        metadata=metadata,
        sender=sender,
        reply_to=reply_to,
        return_path=return_path,
        authentication=authentication,
        delivery=delivery,
        urls=url_indicators,
        domains=domains,
        ips=ips,
        detections=detections,
        risk=RiskAssessment(
            score=score,
            confidence=confidence,
            verdict=verdict,
            rationale=rationale,
        ),
        engine_version=ENGINE_VERSION,
    )
