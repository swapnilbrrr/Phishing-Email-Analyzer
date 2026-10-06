
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
