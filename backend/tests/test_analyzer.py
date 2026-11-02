
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



def test_reported_smtp_mailfrom_is_separate_untrusted_context():
    raw = """From: display@example.org
Return-Path: <bounce@delivery.example>
Authentication-Results: mx.example; spf=pass smtp.mailfrom=<envelope@sender.example>
Authentication-Results: another.example; spf=pass smtp.mailfrom=second@sender.example

A routine message.
"""
    result = analyze(raw)

    assert result.sender.address == "display@example.org"
    assert result.return_path.address == "bounce@delivery.example"
    assert result.authentication.smtp_mail_from_claims == [
        "envelope@sender.example",
        "second@sender.example",
    ]
    assert result.authentication.trusted is False
    assert result.authentication.untrusted_header_count == 2


def test_reported_smtp_mailfrom_claim_does_not_change_risk_score():
    baseline = """From: sender@example.org
Subject: Routine update

Nothing unusual here.
"""
    claimed = baseline.replace(
        "\n\n",
        "\nAuthentication-Results: mx.example; "
        "spf=fail smtp.mailfrom=claimed@attacker.example\n\n",
        1,
    )

    baseline_result = analyze(baseline)
    claimed_result = analyze(claimed)

    assert claimed_result.authentication.smtp_mail_from_claims == [
        "claimed@attacker.example"
    ]
    assert claimed_result.risk.score == baseline_result.risk.score
    assert [item.id for item in claimed_result.detections] == [
        item.id for item in baseline_result.detections
    ]


def test_authentication_result_changes_do_not_change_risk_score():
    pass_claim = PHISHING.replace(
        "Authentication-Results: mx.example; spf=fail smtp.mailfrom=paypa1-example.com; dkim=fail header.d=paypa1-example.com; dmarc=fail",
        "Authentication-Results: mx.example; spf=pass smtp.mailfrom=paypa1-example.com; dkim=pass header.d=paypa1-example.com; dmarc=pass",
    )
    fail_result = analyze(PHISHING)
    pass_result = analyze(pass_claim)

    assert fail_result.authentication.spf.result == "fail"
    assert pass_result.authentication.spf.result == "pass"
    assert fail_result.authentication.trusted is False
    assert pass_result.authentication.trusted is False
    assert fail_result.risk.score == pass_result.risk.score
    assert [item.id for item in fail_result.detections] == [item.id for item in pass_result.detections]
