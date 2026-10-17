
from backend.app.engine.analyzer import analyze


PHISHING = """From: "PayPal Security" <security@paypa1-example.com>
Reply-To: collect@evil.example
Return-Path: bounce@mailer.evil.example
Subject: URGENT: Verify your account immediately
Authentication-Results: mx.example; spf=fail smtp.mailfrom=paypa1-example.com; dkim=fail header.d=paypa1-example.com; dmarc=fail
Received: from mx.evil.example (198.51.100.23) by mx.example with ESMTP
Message-ID: <abc@example>

Verify your password and sign in here:
https://paypa1-example.com/login
"""


BENIGN = """From: GitHub <noreply@github.com>
Return-Path: bounces@github.com
Subject: Your issue was updated
Authentication-Results: mx.example; spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass
Received: from github.com (140.82.112.3) by mx.example with ESMTP
Message-ID: <xyz@github.com>

Your issue has been updated in the GitHub web interface.
"""


def test_phishing_email_gets_high_risk():
    result = analyze(PHISHING)
    assert result.risk.verdict in {"suspicious", "malicious"}
    assert result.risk.score >= 40
    assert any(item.id == "CORR-001" for item in result.detections)


def test_benign_email_does_not_use_a_trust_discount():
    result = analyze(BENIGN)
    assert result.risk.score < 40
    assert not any(item.id == "IDENTITY-003" for item in result.detections)



def test_html_visible_url_mismatch_creates_detection():
    raw = """From: notifications@example.org
Subject: Please review
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<p>Continue to <a href="https://attacker.example/login">https://paypal.com/signin</a></p>
"""
    result = analyze(raw)

    detection = next(item for item in result.detections if item.id == "URL-008")
    assert detection.severity == "high"
    assert any("paypal.com" in evidence for evidence in detection.evidence)
    assert any("attacker.example" in evidence for evidence in detection.evidence)
    assert result.html_links[0].destination_mismatch is True




def test_authentication_results_never_add_auth_detections_from_raw_email():
    forged = PHISHING.replace(
        "Authentication-Results: mx.example;",
        "Authentication-Results: mx.receiver;",
    )
    result = analyze(forged)
    auth_detection_ids = {"AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "AUTH-005"}

    assert result.authentication.trusted is False
    assert result.authentication.spf.result == "fail"
    assert not any(item.id in auth_detection_ids for item in result.detections)


def test_forged_matching_authserv_id_cannot_change_risk_score():
    forged = PHISHING.replace(
        "Authentication-Results: mx.example;",
        "Authentication-Results: trusted-gateway.example;",
    )
    result = analyze(forged)
    auth_detection_ids = {"AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "AUTH-005"}

    assert result.authentication.trusted is False
    assert not any(item.id in auth_detection_ids for item in result.detections)
