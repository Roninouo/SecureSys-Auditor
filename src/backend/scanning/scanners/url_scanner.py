"""
URL/Website Security Scanner for SecureSys Auditor.

This scanner fetches URLs and inspects:
- HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
- SSL/TLS certificate details and validity
- Cookie security settings
- Server information disclosure

The scan is performed from the backend acting as a client,
so no agent installation is needed on the target website.
"""
import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


@dataclass
class SSLInfo:
    """SSL/TLS certificate information."""

    is_valid: bool = False
    issuer: str = ""
    subject: str = ""
    version: int = 0
    serial_number: str = ""
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    signature_algorithm: str = ""
    san_domains: List[str] = field(default_factory=list)
    protocol_version: str = ""
    cipher_suite: str = ""
    key_size: Optional[int] = None
    is_self_signed: bool = False
    certificate_chain_length: int = 0
    errors: List[str] = field(default_factory=list)


@dataclass
class SecurityHeaders:
    """HTTP security headers analysis."""

    strict_transport_security: Optional[str] = None
    content_security_policy: Optional[str] = None
    x_frame_options: Optional[str] = None
    x_content_type_options: Optional[str] = None
    x_xss_protection: Optional[str] = None
    referrer_policy: Optional[str] = None
    permissions_policy: Optional[str] = None
    cross_origin_opener_policy: Optional[str] = None
    cross_origin_resource_policy: Optional[str] = None
    cross_origin_embedder_policy: Optional[str] = None
    cache_control: Optional[str] = None
    pragma: Optional[str] = None
    server: Optional[str] = None
    x_powered_by: Optional[str] = None

    # Analysis results
    missing_headers: List[str] = field(default_factory=list)
    weak_headers: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class CookieInfo:
    """Cookie security analysis."""

    name: str
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None
    path: str = "/"
    domain: Optional[str] = None
    expires: Optional[str] = None
    issues: List[str] = field(default_factory=list)


@dataclass
class URLScanResult:
    """Complete URL scan result."""

    url: str
    final_url: str  # After redirects
    status_code: int
    response_time_ms: float
    ssl_info: Optional[SSLInfo] = None
    security_headers: Optional[SecurityHeaders] = None
    cookies: List[CookieInfo] = field(default_factory=list)
    redirects: List[str] = field(default_factory=list)
    server_info: Dict[str, Any] = field(default_factory=dict)
    scan_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "response_time_ms": self.response_time_ms,
            "ssl_info": self._ssl_to_dict() if self.ssl_info else None,
            "security_headers": self._headers_to_dict() if self.security_headers else None,
            "cookies": [self._cookie_to_dict(c) for c in self.cookies],
            "redirects": self.redirects,
            "server_info": self.server_info,
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "errors": self.errors,
        }

    def _ssl_to_dict(self) -> Dict[str, Any]:
        ssl_info = self.ssl_info
        if not ssl_info:
            return {}
        return {
            "is_valid": ssl_info.is_valid,
            "issuer": ssl_info.issuer,
            "subject": ssl_info.subject,
            "version": ssl_info.version,
            "serial_number": ssl_info.serial_number,
            "not_before": ssl_info.not_before.isoformat() if ssl_info.not_before else None,
            "not_after": ssl_info.not_after.isoformat() if ssl_info.not_after else None,
            "days_until_expiry": ssl_info.days_until_expiry,
            "signature_algorithm": ssl_info.signature_algorithm,
            "san_domains": ssl_info.san_domains,
            "protocol_version": ssl_info.protocol_version,
            "cipher_suite": ssl_info.cipher_suite,
            "key_size": ssl_info.key_size,
            "is_self_signed": ssl_info.is_self_signed,
            "certificate_chain_length": ssl_info.certificate_chain_length,
            "errors": ssl_info.errors,
        }

    def _headers_to_dict(self) -> Dict[str, Any]:
        headers = self.security_headers
        if not headers:
            return {}
        return {
            "strict_transport_security": headers.strict_transport_security,
            "content_security_policy": headers.content_security_policy,
            "x_frame_options": headers.x_frame_options,
            "x_content_type_options": headers.x_content_type_options,
            "x_xss_protection": headers.x_xss_protection,
            "referrer_policy": headers.referrer_policy,
            "permissions_policy": headers.permissions_policy,
            "cross_origin_opener_policy": headers.cross_origin_opener_policy,
            "cross_origin_resource_policy": headers.cross_origin_resource_policy,
            "cross_origin_embedder_policy": headers.cross_origin_embedder_policy,
            "cache_control": headers.cache_control,
            "pragma": headers.pragma,
            "server": headers.server,
            "x_powered_by": headers.x_powered_by,
            "missing_headers": headers.missing_headers,
            "weak_headers": headers.weak_headers,
        }

    def _cookie_to_dict(self, cookie: CookieInfo) -> Dict[str, Any]:
        return {
            "name": cookie.name,
            "secure": cookie.secure,
            "http_only": cookie.http_only,
            "same_site": cookie.same_site,
            "path": cookie.path,
            "domain": cookie.domain,
            "expires": cookie.expires,
            "issues": cookie.issues,
        }


class URLScanner:
    """
    URL/Website Security Scanner.

    Performs comprehensive security analysis of web URLs including:
    - SSL/TLS certificate validation and analysis
    - HTTP security headers inspection
    - Cookie security analysis
    - Server information disclosure detection
    """

    # Required security headers (header_name, description)
    REQUIRED_HEADERS = [
        ("Strict-Transport-Security", "HSTS - Enforces HTTPS connections"),
        ("Content-Security-Policy", "CSP - Prevents XSS and injection attacks"),
        ("X-Frame-Options", "Prevents clickjacking attacks"),
        ("X-Content-Type-Options", "Prevents MIME type sniffing"),
        ("Referrer-Policy", "Controls referrer information"),
    ]

    # Recommended security headers
    RECOMMENDED_HEADERS = [
        ("Permissions-Policy", "Controls browser features"),
        ("Cross-Origin-Opener-Policy", "COOP - Isolates browsing context"),
        ("Cross-Origin-Resource-Policy", "CORP - Controls resource loading"),
    ]

    # Headers that may leak server information
    INFO_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]

    DEFAULT_TIMEOUT = 30  # seconds
    DEFAULT_USER_AGENT = "SecureSys-Auditor/1.0 Security Scanner"

    def __init__(self, timeout: Optional[int] = None, verify_ssl: bool = True):
        """
        Initialize the URL scanner.

        Args:
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = timeout or self.DEFAULT_TIMEOUT
        self.verify_ssl = verify_ssl
        self._session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()

        # Configure retries
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set default headers
        session.headers.update(
            {
                "User-Agent": self.DEFAULT_USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }
        )

        return session

    def scan(self, url: str) -> URLScanResult:
        """
        Perform a comprehensive security scan of a URL.

        Args:
            url: The URL to scan (must be http:// or https://)

        Returns:
            URLScanResult with all scan findings
        """
        logger.info(f"Starting URL scan for: {url}")

        # Normalize URL
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        result = URLScanResult(
            url=url,
            final_url=url,
            status_code=0,
            response_time_ms=0,
        )

        try:
            # Perform HTTP request
            response = self._fetch_url(url, result)

            if response:
                result.status_code = response.status_code
                result.final_url = response.url

                # Analyze security headers
                result.security_headers = self._analyze_headers(response.headers)

                # Analyze cookies
                result.cookies = self._analyze_cookies(response.cookies)

                # Extract server info
                result.server_info = self._extract_server_info(response)

            # Analyze SSL/TLS (only for HTTPS)
            parsed = urlparse(result.final_url)
            if parsed.scheme == "https":
                result.ssl_info = self._analyze_ssl(parsed.hostname, parsed.port or 443)

        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}")
            result.errors.append(str(e))

        logger.info(f"URL scan completed for: {url}")
        return result

    def _fetch_url(self, url: str, result: URLScanResult) -> Optional[requests.Response]:
        """Fetch the URL and track redirects."""
        try:
            import time

            start_time = time.time()

            response = self._session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True,
            )

            result.response_time_ms = (time.time() - start_time) * 1000

            # Track redirect chain
            if response.history:
                result.redirects = [r.url for r in response.history]

            return response

        except requests.exceptions.SSLError as e:
            result.errors.append(f"SSL Error: {str(e)}")
            return None
        except requests.exceptions.ConnectionError as e:
            result.errors.append(f"Connection Error: {str(e)}")
            return None
        except requests.exceptions.Timeout as e:
            result.errors.append(f"Timeout: {str(e)}")
            return None
        except requests.exceptions.RequestException as e:
            result.errors.append(f"Request Error: {str(e)}")
            return None

    def _analyze_headers(self, headers: Dict[str, str]) -> SecurityHeaders:
        """Analyze HTTP security headers."""
        security_headers = SecurityHeaders()

        # Map response headers to our data structure
        header_mapping = {
            "Strict-Transport-Security": "strict_transport_security",
            "Content-Security-Policy": "content_security_policy",
            "X-Frame-Options": "x_frame_options",
            "X-Content-Type-Options": "x_content_type_options",
            "X-XSS-Protection": "x_xss_protection",
            "Referrer-Policy": "referrer_policy",
            "Permissions-Policy": "permissions_policy",
            "Cross-Origin-Opener-Policy": "cross_origin_opener_policy",
            "Cross-Origin-Resource-Policy": "cross_origin_resource_policy",
            "Cross-Origin-Embedder-Policy": "cross_origin_embedder_policy",
            "Cache-Control": "cache_control",
            "Pragma": "pragma",
            "Server": "server",
            "X-Powered-By": "x_powered_by",
        }

        # Extract header values
        for header_name, attr_name in header_mapping.items():
            value = headers.get(header_name)
            if value:
                setattr(security_headers, attr_name, value)

        # Check for missing required headers
        for header_name, _description in self.REQUIRED_HEADERS:
            if not headers.get(header_name):
                security_headers.missing_headers.append(header_name)

        # Check for weak header configurations
        self._check_weak_headers(headers, security_headers)

        return security_headers

    def _check_weak_headers(self, headers: Dict[str, str], security_headers: SecurityHeaders):
        """Check for weak or misconfigured security headers."""

        # Check HSTS
        hsts = headers.get("Strict-Transport-Security", "")
        if hsts:
            if "max-age" in hsts.lower():
                try:
                    max_age = int(hsts.lower().split("max-age=")[1].split(";")[0].strip())
                    if max_age < 31536000:  # Less than 1 year
                        security_headers.weak_headers.append(
                            {
                                "header": "Strict-Transport-Security",
                                "issue": f"max-age is only {max_age} seconds, should be at least 31536000 (1 year)",
                            }
                        )
                except (IndexError, ValueError):
                    pass
            if "includesubdomains" not in hsts.lower():
                security_headers.weak_headers.append(
                    {
                        "header": "Strict-Transport-Security",
                        "issue": "Missing includeSubDomains directive",
                    }
                )

        # Check X-Frame-Options
        xfo = headers.get("X-Frame-Options", "")
        if xfo and xfo.upper() not in ["DENY", "SAMEORIGIN"]:
            security_headers.weak_headers.append(
                {
                    "header": "X-Frame-Options",
                    "issue": f"Weak value: {xfo}. Should be DENY or SAMEORIGIN",
                }
            )

        # Check X-Content-Type-Options
        xcto = headers.get("X-Content-Type-Options", "")
        if xcto and xcto.lower() != "nosniff":
            security_headers.weak_headers.append(
                {
                    "header": "X-Content-Type-Options",
                    "issue": f'Value should be "nosniff", got: {xcto}',
                }
            )

        # Check for deprecated X-XSS-Protection
        if headers.get("X-XSS-Protection"):
            security_headers.weak_headers.append(
                {
                    "header": "X-XSS-Protection",
                    "issue": "This header is deprecated. Use Content-Security-Policy instead.",
                }
            )

    def _analyze_cookies(self, cookies: requests.cookies.RequestsCookieJar) -> List[CookieInfo]:
        """Analyze cookie security settings."""
        analyzed_cookies = []

        for cookie in cookies:
            cookie_info = CookieInfo(
                name=cookie.name,
                secure=cookie.secure,
                http_only=cookie.has_nonstandard_attr("HttpOnly") or "httponly" in str(cookie).lower(),
                path=cookie.path,
                domain=cookie.domain,
                expires=str(cookie.expires) if cookie.expires else None,
            )

            # Check for SameSite attribute
            cookie_str = str(cookie)
            if "samesite=strict" in cookie_str.lower():
                cookie_info.same_site = "Strict"
            elif "samesite=lax" in cookie_str.lower():
                cookie_info.same_site = "Lax"
            elif "samesite=none" in cookie_str.lower():
                cookie_info.same_site = "None"

            # Identify cookie security issues
            if not cookie_info.secure:
                cookie_info.issues.append("Missing Secure flag - cookie can be sent over unencrypted connections")
            if not cookie_info.http_only:
                cookie_info.issues.append("Missing HttpOnly flag - cookie accessible to JavaScript")
            if not cookie_info.same_site:
                cookie_info.issues.append("Missing SameSite attribute - vulnerable to CSRF")
            elif cookie_info.same_site == "None" and not cookie_info.secure:
                cookie_info.issues.append("SameSite=None requires Secure flag")

            analyzed_cookies.append(cookie_info)

        return analyzed_cookies

    def _analyze_ssl(self, hostname: str, port: int) -> SSLInfo:
        """Analyze SSL/TLS certificate and configuration."""
        ssl_info = SSLInfo()

        try:
            # Create SSL context
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate info
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    ssl_info.is_valid = True
                    ssl_info.protocol_version = version or ""

                    if cipher:
                        ssl_info.cipher_suite = cipher[0]
                        ssl_info.key_size = cipher[2] if len(cipher) > 2 else None

                    if cert:
                        # Parse certificate details
                        ssl_info.subject = self._parse_cert_name(cert.get("subject", ()))
                        ssl_info.issuer = self._parse_cert_name(cert.get("issuer", ()))
                        ssl_info.serial_number = str(cert.get("serialNumber", ""))

                        # Check if self-signed
                        ssl_info.is_self_signed = ssl_info.subject == ssl_info.issuer

                        # Parse dates
                        not_before = cert.get("notBefore")
                        not_after = cert.get("notAfter")

                        if not_before:
                            ssl_info.not_before = self._parse_ssl_date(not_before)
                        if not_after:
                            ssl_info.not_after = self._parse_ssl_date(not_after)
                            if ssl_info.not_after:
                                delta = ssl_info.not_after - datetime.now(timezone.utc)
                                ssl_info.days_until_expiry = delta.days

                        # Get SAN domains
                        san = cert.get("subjectAltName", ())
                        ssl_info.san_domains = [name for type_, name in san if type_ == "DNS"]

        except ssl.SSLCertVerificationError as e:
            ssl_info.is_valid = False
            ssl_info.errors.append(f"Certificate verification failed: {str(e)}")
        except ssl.SSLError as e:
            ssl_info.is_valid = False
            ssl_info.errors.append(f"SSL Error: {str(e)}")
        except socket.timeout:
            ssl_info.errors.append("Connection timed out while checking SSL")
        except socket.error as e:
            ssl_info.errors.append(f"Socket error: {str(e)}")
        except Exception as e:
            ssl_info.errors.append(f"Error analyzing SSL: {str(e)}")

        return ssl_info

    def _parse_cert_name(self, name_tuple: tuple) -> str:
        """Parse certificate subject/issuer tuple to string."""
        parts = []
        for rdn in name_tuple:
            for attr_type, attr_value in rdn:
                parts.append(f"{attr_type}={attr_value}")
        return ", ".join(parts)

    def _parse_ssl_date(self, date_str: str) -> Optional[datetime]:
        """Parse SSL certificate date string."""
        try:
            # Common SSL date format: 'Mar  1 12:00:00 2024 GMT'
            from datetime import datetime

            dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            try:
                # Alternative format
                dt = datetime.strptime(date_str, "%b  %d %H:%M:%S %Y %Z")
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                return None

    def _extract_server_info(self, response: requests.Response) -> Dict[str, Any]:
        """Extract server and technology information from response."""
        info = {}

        # Check common info disclosure headers
        for header in self.INFO_DISCLOSURE_HEADERS:
            value = response.headers.get(header)
            if value:
                info[header.lower().replace("-", "_")] = value

        # Check for common technology indicators in other headers
        for header, value in response.headers.items():
            if "version" in header.lower():
                info[header.lower().replace("-", "_")] = value

        return info
