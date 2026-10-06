
from __future__ import annotations

import re


KNOWN_BRANDS: dict[str, set[str]] = {
    "amazon": {"amazon.com", "amazon.co.uk"},
    "apple": {"apple.com", "icloud.com"},
    "cloudflare": {"cloudflare.com"},
    "dropbox": {"dropbox.com"},
    "facebook": {"facebook.com", "meta.com"},
    "github": {"github.com", "githubusercontent.com", "github.io"},
    "google": {"google.com", "googlemail.com", "gmail.com"},
    "linkedin": {"linkedin.com"},
    "microsoft": {"microsoft.com", "office.com", "outlook.com"},
    "netflix": {"netflix.com"},
    "paypal": {"paypal.com"},
    "spotify": {"spotify.com"},
    "stripe": {"stripe.com"},
    "zoom": {"zoom.us", "zoom.com"},
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "shorturl.at", "rebrand.ly",
}

PUBLIC_SUFFIX_OVERRIDES = {"co.uk", "com.au", "com.np", "co.jp", "co.in"}


def normalize_domain(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip().lower().rstrip(".")
    value = re.sub(r"^\.+", "", value)
    return value or None


def registrable_domain(domain: str | None) -> str | None:
    domain = normalize_domain(domain)
    if not domain:
        return None

    labels = domain.split(".")
    if len(labels) <= 2:
        return domain

    suffix = ".".join(labels[-2:])
    if suffix in PUBLIC_SUFFIX_OVERRIDES and len(labels) >= 3:
        return ".".join(labels[-3:])

    return ".".join(labels[-2:])


def same_organization(a: str | None, b: str | None) -> bool | None:
    if not a or not b:
        return None
    return registrable_domain(a) == registrable_domain(b)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            replace = previous[j - 1] + (ca != cb)
            current.append(min(insert, delete, replace))
        previous = current
    return previous[-1]


def base_label(domain: str | None) -> str | None:
    reg = registrable_domain(domain)
    if not reg:
        return None
    labels = reg.split(".")
    return labels[-2] if len(labels) >= 2 else labels[0]


def find_brand_impersonation(domain: str | None) -> tuple[str, int] | None:
    label = base_label(domain)
    if not label:
        return None

    for brand, official_domains in KNOWN_BRANDS.items():
        if normalize_domain(domain) in official_domains:
            continue
        distance = levenshtein(label, brand)
        if 1 <= distance <= 2 and abs(len(label) - len(brand)) <= 2:
            return brand, distance

    return None


def display_claims_brand(display_name: str | None, domain: str | None) -> str | None:
    if not display_name or not domain:
        return None
    lower = display_name.casefold()
    for brand, official_domains in KNOWN_BRANDS.items():
        if brand in lower and normalize_domain(domain) not in official_domains and brand not in (base_label(domain) or ""):
            return brand
    return None
