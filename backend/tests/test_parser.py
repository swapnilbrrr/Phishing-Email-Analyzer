
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
        _html_links,
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
        _html_links,
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
        _html_links,
    ) = parse_email(raw)

    assert auth.spf.result == "pass"
    assert auth.spf.domain == "mail.victim.example"
    assert auth.spf.aligned is True
    assert auth.dkim.result == "pass"
    assert auth.dkim.domain == "signer.other.example"
    assert auth.dkim.aligned is False
    assert auth.dmarc.result == "pass"



def test_html_link_extraction_detects_visible_url_destination_mismatch():
    raw = """From: sender@example.org
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="alt"

--alt
Content-Type: text/plain; charset="utf-8"

Please review the notification.
--alt
Content-Type: text/html; charset="utf-8"

<p>Sign in at <a href="https://attacker.example/login">https://paypal.com/signin</a>.</p>
<p><a href="https://example.org/help">Help centre</a></p>
--alt--
"""
    links = parse_email(raw)[8]

    assert len(links) == 2
    assert links[0].href_hostname == "attacker.example"
    assert links[0].displayed_hostname == "paypal.com"
    assert links[0].destination_mismatch is True
    assert links[1].destination_mismatch is False


def test_text_attachment_is_reported_but_not_scanned_as_body_content():
    raw = """From: sender@example.org
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="mixed"

--mixed
Content-Type: text/plain; charset="utf-8"

Normal message body.
--mixed
Content-Type: text/plain; name="notes.txt"
Content-Disposition: attachment; filename="notes.txt"

Visit https://paypa1.example/login
--mixed--
"""
    _message, body, metadata, *_rest = parse_email(raw)

    assert "Normal message body." in body
    assert "paypa1.example" not in body
    assert len(metadata.attachments) == 1
    assert metadata.attachments[0].filename == "notes.txt"
    assert metadata.attachments[0].content_type == "text/plain"


def test_mime_part_limit_fails_with_controlled_error(monkeypatch):
    from backend.app.engine import parser
    from backend.app.engine.parser import EmailStructureError

    raw = """MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: text/plain

one
--b
Content-Type: text/plain

two
--b--
"""
    monkeypatch.setattr(parser, "MAX_MIME_PARTS", 2)
    try:
        parse_email(raw)
    except EmailStructureError as exc:
        assert "parts" in str(exc)
    else:
        raise AssertionError("Expected MIME part limit to reject the message")


def test_mime_depth_limit_fails_with_controlled_error(monkeypatch):
    from backend.app.engine import parser
    from backend.app.engine.parser import EmailStructureError

    raw = """MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: multipart/alternative; boundary="inner"

--inner
Content-Type: text/plain

nested body
--inner--
--outer--
"""
    monkeypatch.setattr(parser, "MAX_MIME_DEPTH", 1)
    try:
        parse_email(raw)
    except EmailStructureError as exc:
        assert "nesting" in str(exc)
    else:
        raise AssertionError("Expected MIME depth limit to reject the message")



def test_authentication_results_are_untrusted_by_default():
    raw = """From: sender@victim.example
Authentication-Results: mx.receiver; spf=fail; dkim=fail; dmarc=fail

Body text.
"""
    auth = parse_email(raw)[6]
    assert auth.trusted is False
    assert auth.trusted_authserv_ids == []
    assert auth.untrusted_header_count == 1
    assert auth.spf.result == "fail"


def test_authentication_results_only_trust_configured_authserv_id():
    raw = """From: sender@victim.example
Authentication-Results: attacker.example; spf=fail; dkim=fail; dmarc=fail
Authentication-Results: mx.receiver; spf=pass smtp.mailfrom=victim.example; dkim=pass header.d=victim.example; dmarc=pass header.from=victim.example

Body text.
"""
    auth = parse_email(raw, trusted_authserv_ids={"MX.RECEIVER"})[6]
    assert auth.trusted is True
    assert auth.trusted_authserv_ids == ["mx.receiver"]
    assert auth.untrusted_header_count == 1
    assert auth.spf.result == "pass"
    assert auth.dkim.result == "pass"
    assert auth.dmarc.result == "pass"
