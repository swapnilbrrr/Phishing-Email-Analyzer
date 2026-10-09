from __future__ import annotations

import ipaddress
import re
from functools import lru_cache

import tldextract


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

# Use the Public Suffix List bundled with tldextract. Disable network fetching
# so email analysis stays deterministic and never makes implicit network calls.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


def normalize_domain(value: str | None) -> str | None:
    """Normalize a hostname to lowercase ASCII/IDNA form without resolving it."""
    if not value:
        return None

    value = value.strip().lower().rstrip(".")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]

    if not value or any(char.isspace() for char in value):
        return None

    # Keep IP literals recognizable; callers can classify them with ipaddress.
    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        pass

    try:
        ascii_value = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

    if len(ascii_value) > 253:
        return None

    labels = ascii_value.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not re.fullmatch(r"[a-z0-9-]+", label)
        for label in labels
    ):
        return None

    return ascii_value


@lru_cache(maxsize=4096)
def registrable_domain(domain: str | None) -> str | None:
    """Return eTLD+1 using the bundled Public Suffix List.

    Unknown/private intranet suffixes fall back to the final two labels. This
    fallback is intentionally conservative and should not be treated as an
    authoritative public-suffix determination.
    """
    normalized = normalize_domain(domain)
    if not normalized:
        return None

    try:
        ipaddress.ip_address(normalized)
        return normalized
    except ValueError:
        pass

    extracted = _EXTRACT(normalized)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"

    labels = normalized.split(".")
    if len(labels) == 1:
        return normalized

    # A known public suffix on its own has no registrable domain.
    if extracted.suffix and not extracted.domain:
        return None

    return ".".join(labels[-2:])


def same_organization(a: str | None, b: str | None) -> bool | None:
    if not a or not b:
        return None

    left = registrable_domain(a)
    right = registrable_domain(b)
    if not left or not right:
        return None
    return left == right


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
    normalized = normalize_domain(domain)
    if not normalized:
        return None

    try:
        ipaddress.ip_address(normalized)
        return None
    except ValueError:
        pass

    extracted = _EXTRACT(normalized)
    if extracted.domain and extracted.suffix:
        return extracted.domain

    reg = registrable_domain(normalized)
    if not reg:
        return None
    labels = reg.split(".")
    return labels[-2] if len(labels) >= 2 else labels[0]


def find_brand_impersonation(domain: str | None) -> tuple[str, int] | None:
    normalized = normalize_domain(domain)
    label = base_label(normalized)
    if not label:
        return None

    for brand, official_domains in KNOWN_BRANDS.items():
        if any(
            normalized == official or normalized.endswith("." + official)
            for official in official_domains
        ):
            continue
        distance = levenshtein(label, brand)
        if 1 <= distance <= 2 and abs(len(label) - len(brand)) <= 2:
            return brand, distance

    return None


def display_claims_brand(display_name: str | None, domain: str | None) -> str | None:
    normalized = normalize_domain(domain)
    if not display_name or not normalized:
        return None

    lower = display_name.casefold()
    label = base_label(normalized) or ""
    for brand, official_domains in KNOWN_BRANDS.items():
        is_official = any(
            normalized == official or normalized.endswith("." + official)
            for official in official_domains
        )
        if brand in lower and not is_official and brand not in label:
            return brand
    return None
