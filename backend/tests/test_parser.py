
from backend.app.engine.parser import parse_email


SAMPLE = """From: "PayPal Security" <security@paypa1-example.com>
Reply-To: collect@evil.example
Return-Path: bounce@mailer.evil.example
Subject: URGENT: Verify your account
Authentication-Results: mx.example; spf=fail smtp.mailfrom=paypa1-example.com; dkim=fail; dmarc=fail
Received: from mx.evil.example (8.8.8.8) by mx.example with ESMTP
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
    assert delivery.earliest_public_ip == "8.8.8.8"
    assert "https://paypa1-example.com/login" in body



def test_authentication_results_do_not_cross_contaminate_headers_or_clauses():
    raw = """From: sender@victim.example
Authentication-Results: mx.receiver; spf=fail; dkim=fail; dmarc=fail
Authentication-Results: legacy.receiver; spf=pass smtp.mailfrom=aligned.example; dkim=pass header.d=aligned.example; dmarc=pass header.from=aligned.example

Body text.
"""
    (
        _message,
        _body,
        _metadata,
        sender,
        _reply_to,
        _return_path,
        auth,
        _delivery,
    ) = parse_email(raw)

    assert sender.domain == "victim.example"
    assert auth.source_headers == 2
    assert auth.spf.result == "fail"
    assert auth.spf.domain is None
    assert auth.dkim.result == "fail"
    assert auth.dkim.domain is None
    assert auth.dmarc.result == "fail"


def test_authentication_domain_is_taken_from_the_matching_clause():
    raw = """From: sender@victim.example
Authentication-Results: mx.receiver; spf=pass smtp.mailfrom=mail.victim.example; dkim=pass header.d=signer.other.example; dmarc=pass header.from=victim.example

Body text.
"""
    (
        _message,
        _body,
        _metadata,
        _sender,
        _reply_to,
        _return_path,
        auth,
        _delivery,
    ) = parse_email(raw)

    assert auth.spf.result == "pass"
    assert auth.spf.domain == "mail.victim.example"
    assert auth.spf.aligned is True
    assert auth.dkim.result == "pass"
    assert auth.dkim.domain == "signer.other.example"
    assert auth.dkim.aligned is False
    assert auth.dmarc.result == "pass"
