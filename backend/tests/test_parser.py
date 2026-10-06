
from backend.app.engine.parser import parse_email


SAMPLE = """From: "PayPal Security" <security@paypa1-example.com>
Reply-To: collect@evil.example
Return-Path: bounce@mailer.evil.example
Subject: URGENT: Verify your account
Authentication-Results: mx.example; spf=fail smtp.mailfrom=paypa1-example.com; dkim=fail; dmarc=fail
Received: from mx.evil.example (198.51.100.23) by mx.example with ESMTP
Message-ID: <123@example>
Date: Tue, 6 Oct 2026 10:00:00 +0000

Please verify your account at https://paypa1-example.com/login
"""


def test_parser_extracts_identity_auth_and_delivery():
    (
        _message,
        body,
        metadata,
        sender,
        reply_to,
        return_path,
        auth,
        delivery,
    ) = parse_email(SAMPLE)

    assert metadata.subject == "URGENT: Verify your account"
    assert sender.address == "security@paypa1-example.com"
    assert sender.domain == "paypa1-example.com"
    assert reply_to.domain == "evil.example"
    assert return_path.domain == "mailer.evil.example"
    assert auth.spf.result == "fail"
    assert auth.dkim.result == "fail"
    assert auth.dmarc.result == "fail"
    assert delivery.hop_count == 1
    assert delivery.earliest_public_ip == "198.51.100.23"
    assert "https://paypa1-example.com/login" in body
