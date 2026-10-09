from __future__ import annotations

import ipaddress
import re
from email.header import decode_header, make_header
from email.message import Message
from email.parser import BytesParser
from email.policy import default
from email.utils import parseaddr

from .domain import normalize_domain, same_organization
from ..models import (
    Address,
    AuthSignal,
    Authentication,
    Delivery,
    EmailMetadata,
    ReceivedHop,
)


IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s<>'\"\]\[(){}]+", re.I)
AUTH_RESULT_RE = {
    "spf": re.compile(r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.I),
    "dkim": re.compile(r"\bdkim=(pass|fail|neutral|none|temperror|permerror)\b", re.I),
    "dmarc": re.compile(r"\bdmarc=(pass|fail|bestguesspass|none|temperror|permerror)\b", re.I),
}
SPF_DOMAIN_RE = re.compile(r"\bsmtp\.mailfrom=([^\s;]+)", re.I)
DKIM_DOMAIN_RE = re.compile(r"\bheader\.d=([^\s;]+)", re.I)


def safe_decode(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(make_header(decode_header(value))).strip()
    except (ValueError, UnicodeError):
        return value.strip()


def header_values(message: Message, name: str) -> list[str]:
    return [
        value
        for key, value in message.raw_items()
        if key.casefold() == name.casefold()
    ]


def single_header(message: Message, name: str) -> str | None:
    values = header_values(message, name)
    return safe_decode(values[0]) if values else None


def parse_address(raw: str | None) -> Address:
    if not raw:
        return Address()

    display_name, address = parseaddr(raw)
    domain = None
    if "@" in address:
        domain = normalize_domain(address.rsplit("@", 1)[1])

    return Address(
        raw=raw,
        address=address.lower() if address else None,
        display_name=display_name.strip() or None,
        domain=domain,
    )


def is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )
    except ValueError:
        return False


def extract_ipv4s(text: str) -> list[str]:
    found: list[str] = []
    for candidate in IPV4_RE.findall(text):
        parts = candidate.split(".")
        if len(parts) != 4 or any(int(part) > 255 for part in parts):
            continue
        if candidate not in found:
            found.append(candidate)
    return found


def parse_received(values: list[str]) -> Delivery:
    hops: list[ReceivedHop] = []

    for index, raw in enumerate(values, 1):
        from_match = re.search(r"\bfrom\s+([^\s(]+)", raw, re.I)
        by_match = re.search(r"\bby\s+([^\s;]+)", raw, re.I)
        ips = extract_ipv4s(raw)
        public = [ip for ip in ips if is_public_ip(ip)]

        hops.append(
            ReceivedHop(
                index=index,
                raw=raw,
                from_host=from_match.group(1) if from_match else None,
                by_host=by_match.group(1) if by_match else None,
                ips=ips,
                public_ips=public,
            )
        )

    earliest_public = None
    for hop in reversed(hops):
        if hop.public_ips:
            earliest_public = hop.public_ips[0]
            break

    return Delivery(
        hop_count=len(hops),
        received=hops,
        earliest_public_ip=earliest_public,
    )


def parse_authentication(message: Message, sender_domain: str | None) -> Authentication:
    values = header_values(message, "Authentication-Results")

    def parse_one(name: str) -> AuthSignal:
        # Keep each result and its method-specific properties in the same
        # semicolon-delimited clause. Joining headers before parsing can
        # accidentally pair a result with another header's domain.
        for header in values:
            for clause in header.split(";"):
                result_match = AUTH_RESULT_RE[name].search(clause)
                if not result_match:
                    continue

                auth_domain = None
                if name == "spf":
                    domain_match = SPF_DOMAIN_RE.search(clause)
                elif name == "dkim":
                    domain_match = DKIM_DOMAIN_RE.search(clause)
                else:
                    domain_match = None

                if domain_match:
                    candidate = domain_match.group(1).strip("()<>").strip(chr(34)).strip(chr(39))
                    auth_domain = normalize_domain(candidate)

                aligned = (
                    same_organization(auth_domain, sender_domain)
                    if auth_domain
                    else None
                )
                return AuthSignal(
                    result=result_match.group(1).lower(),
                    domain=auth_domain,
                    aligned=aligned,
                )

        return AuthSignal(result="none")

    return Authentication(
        spf=parse_one("spf"),
        dkim=parse_one("dkim"),
        dmarc=parse_one("dmarc"),
        source_headers=len(values),
    )


def extract_body_text(message: Message, limit: int = 120_000) -> str:
    chunks: list[str] = []

    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart():
                continue
            content_type = part.get_content_type()
            if content_type not in {"text/plain", "text/html"}:
                continue
            try:
                content = part.get_content()
            except (LookupError, UnicodeError):
                continue
            if isinstance(content, str):
                chunks.append(content)
    else:
        try:
            content = message.get_content()
        except (LookupError, UnicodeError):
            content = ""
        if isinstance(content, str):
            chunks.append(content)

    body = "\n".join(chunks)
    body = re.sub(r"(?is)<script.*?>.*?</script>", " ", body)
    body = re.sub(r"(?is)<style.*?>.*?</style>", " ", body)
    body = re.sub(r"(?s)<[^>]+>", " ", body)
    return re.sub(r"\s+", " ", body)[:limit]


def extract_urls(text: str) -> list[str]:
    found: list[str] = []
    for match in URL_RE.finditer(text):
        value = match.group(0).rstrip(".,;:!?")
        if value not in found:
            found.append(value)
    return found


def parse_email(raw_email: str):
    raw_bytes = raw_email.encode("utf-8", errors="replace")
    message = BytesParser(policy=default).parsebytes(raw_bytes)

    from_addr = parse_address(single_header(message, "From"))
    reply_to = parse_address(single_header(message, "Reply-To"))
    return_path = parse_address(single_header(message, "Return-Path"))

    metadata = EmailMetadata(
        subject=single_header(message, "Subject"),
        date=single_header(message, "Date"),
        message_id=single_header(message, "Message-ID"),
        content_types=sorted(
            {
                part.get_content_type()
                for part in message.walk()
                if not part.is_multipart()
            }
        ),
    )

    auth = parse_authentication(message, from_addr.domain)
    delivery = parse_received(header_values(message, "Received"))
    body = extract_body_text(message)

    return (
        message,
        body,
        metadata,
        from_addr,
        reply_to,
        return_path,
        auth,
        delivery,
    )
