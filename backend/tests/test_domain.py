from backend.app.engine.domain import (
    base_label,
    find_brand_impersonation,
    normalize_domain,
    registrable_domain,
    same_organization,
)


def test_domain_normalization_handles_case_trailing_dot_and_idna():
    assert normalize_domain("  BÜCHER.example. ") == "xn--bcher-kva.example"
    assert normalize_domain("Example.COM.") == "example.com"
    assert normalize_domain("bad..example") is None
    assert normalize_domain("-invalid.example") is None


def test_registrable_domain_respects_multilabel_public_suffixes():
    assert registrable_domain("mail.example.co.uk") == "example.co.uk"
    assert registrable_domain("login.bank.com.np") == "bank.com.np"
    assert same_organization("mail.example.co.uk", "example.co.uk") is True
    assert same_organization("example.co.uk", "other.co.uk") is False


def test_private_suffixes_separate_hosted_tenants():
    assert registrable_domain("tenant-a.github.io") == "tenant-a.github.io"
    assert registrable_domain("tenant-b.github.io") == "tenant-b.github.io"
    assert same_organization("tenant-a.github.io", "tenant-b.github.io") is False


def test_brand_impersonation_uses_registrable_domain_not_substring():
    assert find_brand_impersonation("paypa1.com") == ("paypal", 1)
    assert find_brand_impersonation("login.paypal.com") is None
    assert find_brand_impersonation("paypal.com.attacker.example") is None
    assert base_label("paypal.com.attacker.example") == "attacker"


def test_ip_literals_are_not_treated_as_brand_domains():
    assert normalize_domain("2001:db8::1") == "2001:db8::1"
    assert base_label("2001:db8::1") is None
