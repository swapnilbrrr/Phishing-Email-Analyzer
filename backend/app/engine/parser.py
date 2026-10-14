from __future__ import annotations

import ipaddress
import re
from email.header import decode_header, make_header
from email.message import Message
from email.parser import BytesParser
from email.policy import default
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .domain import normalize_domain, same_organization
from ..models import (
    Address,
    AttachmentInfo,
    AuthSignal,
    Authentication,
    Delivery,
    EmailMetadata,
    HtmlLinkIndicator,
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

MAX_MIME_PARTS = 200
MAX_MIME_DEPTH = 20
MAX_BODY_CHARS = 120_000
MAX_HTML_LINKS = 100


class EmailStructureError(ValueError):
    """Raised when an email exceeds the parser's structural safety limits."""


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

    return Delivery(hop_count=len(hops), received=hops, earliest_public_ip=earliest_public)


def parse_authentication(message: Message, sender_domain: str | None) -> Authentication:
    values = header_values(message, "Authentication-Results")

    def parse_one(name: str) -> AuthSignal:
        # Keep result and method-specific properties within the same clause.
        for header in values:
            for clause in header.split(";"):
                result_match = AUTH_RESULT_RE[name].search(clause)
                if not result_match:
                    continue

                if name == "spf":
                    domain_match = SPF_DOMAIN_RE.search(clause)
                elif name == "dkim":
                    domain_match = DKIM_DOMAIN_RE.search(clause)
                else:
                    domain_match = None

                auth_domain = None
                if domain_match:
                    candidate = domain_match.group(1).strip("()<>").strip(chr(34)).strip(chr(39))
                    auth_domain = normalize_domain(candidate)

                aligned = same_organization(auth_domain, sender_domain) if auth_domain else None
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


def _is_attachment(part: Message) -> bool:
    return part.get_content_disposition() == "attachment" or bool(part.get_filename())


def _bounded_parts(message: Message) -> list[tuple[Message, int, bool, bool]]:
    """Return (part, depth, inside_attachment, is_attachment_root) tuples."""
    result: list[tuple[Message, int, bool, bool]] = []
    stack: list[tuple[Message, int, bool]] = [(message, 0, False)]

    while stack:
        part, depth, inside_attachment = stack.pop()
        if depth > MAX_MIME_DEPTH:
            raise EmailStructureError(
                f"Email MIME nesting exceeds the limit of {MAX_MIME_DEPTH} levels."
            )

        is_attachment_root = _is_attachment(part) and not inside_attachment
        now_inside_attachment = inside_attachment or _is_attachment(part)
        result.append((part, depth, now_inside_attachment, is_attachment_root))
        if len(result) > MAX_MIME_PARTS:
            raise EmailStructureError(
                f"Email MIME structure exceeds the limit of {MAX_MIME_PARTS} parts."
            )

        payload = part.get_payload()
        if isinstance(payload, list):
            for child in reversed(payload):
                stack.append((child, depth + 1, now_inside_attachment))

    return result


def _decoded_text(part: Message) -> str | None:
    try:
        content = part.get_content()
    except (LookupError, UnicodeError, TypeError, ValueError):
        return None
    return content if isinstance(content, str) else None


def _attachment_info(part: Message) -> AttachmentInfo:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw_payload = part.get_payload()
        size_bytes = len(raw_payload.encode("utf-8", errors="replace")) if isinstance(raw_payload, str) else None
    else:
        size_bytes = len(payload)
    return AttachmentInfo(
        filename=part.get_filename(),
        content_type=part.get_content_type(),
        disposition=part.get_content_disposition(),
        size_bytes=size_bytes,
    )


def extract_body_text(parts: list[tuple[Message, int, bool, bool]], limit: int = MAX_BODY_CHARS) -> str:
    chunks: list[str] = []
    for part, _depth, inside_attachment, _is_attachment_root in parts:
        if inside_attachment or part.is_multipart():
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        content = _decoded_text(part)
        if content is not None:
            chunks.append(content)

    body = "\n".join(chunks)
    body = re.sub(r"(?is)<script.*?>.*?</script>", " ", body)
    body = re.sub(r"(?is)<style.*?>.*?</style>", " ", body)
    body = re.sub(r"(?s)<[^>]+>", " ", body)
    return re.sub(r"\s+", " ", body)[:limit]


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def _finish_anchor(self) -> None:
        if self._href is not None and len(self.links) < MAX_HTML_LINKS:
            visible = re.sub(r"\s+", " ", "".join(self._text)).strip()
            self.links.append((self._href, visible))
        self._href = None
        self._text = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() != "a":
            return
        if self._href is not None:
            self._finish_anchor()
        self._href = next((value for key, value in attrs if key.casefold() == "href" and value is not None), None)
        self._text = []

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "a" and self._href is not None:
            self._finish_anchor()

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def finish(self) -> None:
        self.close()
        if self._href is not None:
            self._finish_anchor()


def extract_html_links(parts: list[tuple[Message, int, bool, bool]]) -> list[HtmlLinkIndicator]:
    links: list[HtmlLinkIndicator] = []
    for part, _depth, inside_attachment, _is_attachment_root in parts:
        if inside_attachment or part.is_multipart() or part.get_content_type() != "text/html":
            continue
        html = _decoded_text(part)
        if not html:
            continue

        parser = _AnchorParser()
        try:
            parser.feed(html)
            parser.finish()
        except (ValueError, AssertionError):
            continue

        for href, visible_text in parser.links:
            if len(links) >= MAX_HTML_LINKS:
                return links
            try:
                destination = urlsplit(href)
                if destination.scheme.casefold() not in {"http", "https"} and not href.startswith("//"):
                    destination_hostname = None
                else:
                    destination_hostname = normalize_domain(destination.hostname)
            except ValueError:
                destination_hostname = None

            displayed_hostname = None
            displayed_urls = extract_urls(visible_text)
            if displayed_urls:
                try:
                    displayed_hostname = normalize_domain(urlsplit(displayed_urls[0]).hostname)
                except ValueError:
                    displayed_hostname = None

            matches = (
                same_organization(displayed_hostname, destination_hostname)
                if displayed_hostname and destination_hostname
                else None
            )
            links.append(
                HtmlLinkIndicator(
                    href=href,
                    text=visible_text[:500],
                    href_hostname=destination_hostname,
                    displayed_hostname=displayed_hostname,
                    destination_mismatch=matches is False,
                )
            )
    return links


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
    parts = _bounded_parts(message)

    from_addr = parse_address(single_header(message, "From"))
    reply_to = parse_address(single_header(message, "Reply-To"))
    return_path = parse_address(single_header(message, "Return-Path"))

    metadata = EmailMetadata(
        subject=single_header(message, "Subject"),
        date=single_header(message, "Date"),
        message_id=single_header(message, "Message-ID"),
        content_types=sorted({
            part.get_content_type()
            for part, _depth, _inside_attachment, _attachment_root in parts
            if not part.is_multipart()
        }),
        attachments=[
            _attachment_info(part)
            for part, _depth, _inside_attachment, attachment_root in parts
            if attachment_root
        ],
    )

    auth = parse_authentication(message, from_addr.domain)
    delivery = parse_received(header_values(message, "Received"))
    body = extract_body_text(parts)
    html_links = extract_html_links(parts)

    return message, body, metadata, from_addr, reply_to, return_path, auth, delivery, html_links
