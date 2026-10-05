import ipaddress
import re
import socket
import ssl
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler, urlopen

MAX_BODY_BYTES = 256 * 1024
TIMEOUT_SECONDS = 4


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = []
        self.in_title = False
        self.forms = 0
        self.password_forms = 0

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag.lower() == "title":
            self.in_title = True
        if tag.lower() == "form":
            self.forms += 1
        if tag.lower() == "input" and attrs_dict.get("type", "").lower() == "password":
            self.password_forms += 1

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title.append(data.strip())


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _public_addresses(hostname: str) -> list[str]:
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None)})
    for address in addresses:
        parsed = ipaddress.ip_address(address)
        if not parsed.is_global:
            raise ValueError("The host resolves to a private or local network address")
    return addresses


def _certificate_info(hostname: str, port: int = 443) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=TIMEOUT_SECONDS) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
            certificate = tls_socket.getpeercert()
            return {
                "valid": True,
                "subject": dict(item[0] for item in certificate.get("subject", [])),
                "issuer": dict(item[0] for item in certificate.get("issuer", [])),
            }


def inspect_url(url: str) -> dict:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    result = {
        "reachable": False,
        "final_url": None,
        "redirects": [],
        "title": None,
        "forms": 0,
        "password_forms": 0,
        "dns": {"resolved": False, "addresses": [], "error": None},
        "certificate": None,
        "domain_age": {"available": False, "reason": "WHOIS lookup is not configured"},
        "reputation": {"available": False, "reason": "External reputation APIs are not configured"},
        "error": None,
    }

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        result["error"] = "Only valid HTTP and HTTPS URLs can be inspected"
        return result

    hostname = parsed.hostname.lower()
    try:
        addresses = _public_addresses(hostname)
        result["dns"] = {"resolved": True, "addresses": addresses, "error": None}
    except (OSError, ValueError) as error:
        result["dns"]["error"] = str(error)
        result["error"] = str(error)
        return result

    if parsed.scheme == "https":
        try:
            result["certificate"] = _certificate_info(hostname, parsed.port or 443)
        except (OSError, ssl.SSLError, ValueError) as error:
            result["certificate"] = {"valid": False, "error": str(error)}

    request = Request(url, headers={"User-Agent": "SignalScan/1.0 URL inspection"})
    opener = build_opener(_NoRedirectHandler())
    current_url = url
    try:
        for _ in range(5):
            request = Request(current_url, headers={"User-Agent": "SignalScan/1.0 URL inspection"})
            try:
                response = opener.open(request, timeout=TIMEOUT_SECONDS)
            except Exception as error:
                if hasattr(error, "headers") and error.headers.get("Location"):
                    location = urljoin(current_url, error.headers["Location"])
                    result["redirects"].append(location)
                    current_url = location
                    continue
                raise

            result["reachable"] = 200 <= response.status < 500
            result["final_url"] = current_url
            content_type = response.headers.get("Content-Type", "")
            body = response.read(MAX_BODY_BYTES) if "text/html" in content_type.lower() else b""
            parser = _PageParser()
            parser.feed(body.decode(response.headers.get_content_charset() or "utf-8", errors="replace"))
            result["title"] = re.sub(r"\s+", " ", " ".join(parser.title)).strip() or None
            result["forms"] = parser.forms
            result["password_forms"] = parser.password_forms
            break
    except Exception as error:
        result["error"] = str(error)

    return result
