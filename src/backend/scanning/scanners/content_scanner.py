"""
Website Content Security Scanner for SecureSys Auditor.

This scanner performs deep content analysis of websites including:
- HTML structure and content analysis
- JavaScript security analysis
- Form security inspection
- Link and resource analysis
- Sensitive data exposure detection
- Third-party resource security
- DOM-based vulnerability patterns
- Information leakage detection

The scanner fetches full page content and analyzes it for security issues.
"""
import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


@dataclass
class ScriptInfo:
    """Information about a script resource."""

    src: Optional[str] = None
    is_inline: bool = False
    is_external: bool = False
    has_integrity: bool = False
    integrity_value: Optional[str] = None
    crossorigin: Optional[str] = None
    content_hash: Optional[str] = None
    content_preview: Optional[str] = None
    security_issues: List[str] = field(default_factory=list)
    dangerous_patterns: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class FormInfo:
    """Information about a form element."""

    action: Optional[str] = None
    method: str = "GET"
    has_csrf_token: bool = False
    has_autocomplete_off: bool = False
    is_https_action: bool = True
    input_fields: List[Dict[str, Any]] = field(default_factory=list)
    password_fields: int = 0
    sensitive_fields: List[str] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)


@dataclass
class LinkInfo:
    """Information about links on the page."""

    total_links: int = 0
    internal_links: int = 0
    external_links: int = 0
    http_links: List[str] = field(default_factory=list)  # Insecure links
    javascript_links: List[str] = field(default_factory=list)
    data_links: List[str] = field(default_factory=list)
    suspicious_links: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class SensitiveDataExposure:
    """Information about exposed sensitive data."""

    emails: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    api_keys: List[Dict[str, str]] = field(default_factory=list)
    tokens: List[Dict[str, str]] = field(default_factory=list)
    passwords_in_source: List[str] = field(default_factory=list)
    private_keys: List[str] = field(default_factory=list)
    internal_paths: List[str] = field(default_factory=list)
    comments_with_secrets: List[Dict[str, str]] = field(default_factory=list)
    debug_info: List[str] = field(default_factory=list)


@dataclass
class MetaTagInfo:
    """Information about meta tags."""

    csp_meta: Optional[str] = None
    robots: Optional[str] = None
    generator: Optional[str] = None
    author: Optional[str] = None
    referrer: Optional[str] = None
    viewport: Optional[str] = None
    x_ua_compatible: Optional[str] = None
    refresh_redirect: Optional[str] = None
    sensitive_meta: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class ThirdPartyResource:
    """Information about third-party resources."""

    domain: str
    resource_type: str  # script, style, image, iframe, font
    url: str
    has_integrity: bool = False
    is_tracking: bool = False
    reputation: str = "unknown"  # unknown, trusted, suspicious, malicious


@dataclass
class ContentScanResult:
    """Complete content scan result."""

    url: str
    page_title: Optional[str] = None
    content_length: int = 0
    content_hash: Optional[str] = None

    # Content analysis results
    scripts: List[ScriptInfo] = field(default_factory=list)
    forms: List[FormInfo] = field(default_factory=list)
    links: Optional[LinkInfo] = None
    meta_tags: Optional[MetaTagInfo] = None
    sensitive_data: Optional[SensitiveDataExposure] = None
    third_party_resources: List[ThirdPartyResource] = field(default_factory=list)

    # Iframe analysis
    iframes: List[Dict[str, Any]] = field(default_factory=list)

    # Technology detection
    detected_technologies: List[Dict[str, str]] = field(default_factory=list)

    # Security indicators
    has_mixed_content: bool = False
    has_inline_event_handlers: int = 0
    has_document_write: bool = False
    has_eval_usage: bool = False

    # Analysis metadata
    scan_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_duration_ms: float = 0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "url": self.url,
            "page_title": self.page_title,
            "content_length": self.content_length,
            "content_hash": self.content_hash,
            "scripts": [self._script_to_dict(s) for s in self.scripts],
            "forms": [self._form_to_dict(f) for f in self.forms],
            "links": self._links_to_dict() if self.links else None,
            "meta_tags": self._meta_to_dict() if self.meta_tags else None,
            "sensitive_data": self._sensitive_to_dict() if self.sensitive_data else None,
            "third_party_resources": [
                {
                    "domain": r.domain,
                    "resource_type": r.resource_type,
                    "url": r.url,
                    "has_integrity": r.has_integrity,
                    "is_tracking": r.is_tracking,
                    "reputation": r.reputation,
                }
                for r in self.third_party_resources
            ],
            "iframes": self.iframes,
            "detected_technologies": self.detected_technologies,
            "has_mixed_content": self.has_mixed_content,
            "has_inline_event_handlers": self.has_inline_event_handlers,
            "has_document_write": self.has_document_write,
            "has_eval_usage": self.has_eval_usage,
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "scan_duration_ms": self.scan_duration_ms,
            "errors": self.errors,
        }

    def _script_to_dict(self, script: ScriptInfo) -> Dict[str, Any]:
        return {
            "src": script.src,
            "is_inline": script.is_inline,
            "is_external": script.is_external,
            "has_integrity": script.has_integrity,
            "integrity_value": script.integrity_value,
            "crossorigin": script.crossorigin,
            "content_hash": script.content_hash,
            "content_preview": script.content_preview,
            "security_issues": script.security_issues,
            "dangerous_patterns": script.dangerous_patterns,
        }

    def _form_to_dict(self, form: FormInfo) -> Dict[str, Any]:
        return {
            "action": form.action,
            "method": form.method,
            "has_csrf_token": form.has_csrf_token,
            "has_autocomplete_off": form.has_autocomplete_off,
            "is_https_action": form.is_https_action,
            "input_fields": form.input_fields,
            "password_fields": form.password_fields,
            "sensitive_fields": form.sensitive_fields,
            "security_issues": form.security_issues,
        }

    def _links_to_dict(self) -> Dict[str, Any]:
        links = self.links
        if not links:
            return {}
        return {
            "total_links": links.total_links,
            "internal_links": links.internal_links,
            "external_links": links.external_links,
            "http_links": links.http_links[:20],  # Limit
            "javascript_links": links.javascript_links[:10],
            "data_links": links.data_links[:10],
            "suspicious_links": links.suspicious_links[:10],
        }

    def _meta_to_dict(self) -> Dict[str, Any]:
        meta = self.meta_tags
        if not meta:
            return {}
        return {
            "csp_meta": meta.csp_meta,
            "robots": meta.robots,
            "generator": meta.generator,
            "author": meta.author,
            "referrer": meta.referrer,
            "viewport": meta.viewport,
            "x_ua_compatible": meta.x_ua_compatible,
            "refresh_redirect": meta.refresh_redirect,
            "sensitive_meta": meta.sensitive_meta,
        }

    def _sensitive_to_dict(self) -> Dict[str, Any]:
        sensitive = self.sensitive_data
        if not sensitive:
            return {}
        return {
            "emails_count": len(sensitive.emails),
            "emails_sample": sensitive.emails[:5],
            "phone_numbers_count": len(sensitive.phone_numbers),
            "ip_addresses": sensitive.ip_addresses[:10],
            "api_keys": sensitive.api_keys[:5],
            "tokens": sensitive.tokens[:5],
            "passwords_in_source": len(sensitive.passwords_in_source) > 0,
            "private_keys_found": len(sensitive.private_keys) > 0,
            "internal_paths": sensitive.internal_paths[:10],
            "comments_with_secrets": sensitive.comments_with_secrets[:5],
            "debug_info": sensitive.debug_info[:5],
        }


class HTMLContentParser(HTMLParser):
    """Custom HTML parser for security analysis."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc

        # Parsing state
        self.in_script = False
        self.in_style = False
        self.current_script_content = ""
        self.current_script_attrs = {}

        # Results
        self.title = None
        self.scripts: List[ScriptInfo] = []
        self.forms: List[FormInfo] = []
        self.current_form: Optional[FormInfo] = None
        self.links = LinkInfo()
        self.meta_tags = MetaTagInfo()
        self.iframes: List[Dict[str, Any]] = []
        self.third_party_resources: List[ThirdPartyResource] = []
        self.inline_event_handlers = 0
        self.all_text = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attrs_dict = {k: v for k, v in attrs if v is not None}

        # Check for inline event handlers
        event_handlers = [a for a in attrs_dict.keys() if a.startswith("on")]
        self.inline_event_handlers += len(event_handlers)

        if tag == "script":
            self.in_script = True
            self.current_script_content = ""
            self.current_script_attrs = attrs_dict

            if "src" in attrs_dict:
                script = ScriptInfo(
                    src=attrs_dict["src"],
                    is_inline=False,
                    is_external=self._is_external_url(attrs_dict["src"]),
                    has_integrity="integrity" in attrs_dict,
                    integrity_value=attrs_dict.get("integrity"),
                    crossorigin=attrs_dict.get("crossorigin"),
                )
                self.scripts.append(script)
                self._check_third_party(attrs_dict["src"], "script", "integrity" in attrs_dict)

        elif tag == "link":
            rel = attrs_dict.get("rel", "")
            href = attrs_dict.get("href", "")
            if "stylesheet" in rel and href:
                self._check_third_party(href, "style", "integrity" in attrs_dict)

        elif tag == "img":
            src = attrs_dict.get("src", "")
            if src:
                self._check_third_party(src, "image", False)

        elif tag == "iframe":
            iframe_info = {
                "src": attrs_dict.get("src"),
                "sandbox": attrs_dict.get("sandbox"),
                "allow": attrs_dict.get("allow"),
                "is_external": self._is_external_url(attrs_dict.get("src", "")),
            }
            self.iframes.append(iframe_info)
            if attrs_dict.get("src"):
                self._check_third_party(attrs_dict["src"], "iframe", False)

        elif tag == "form":
            action = attrs_dict.get("action", "")
            full_action = urljoin(self.base_url, action) if action else self.base_url

            self.current_form = FormInfo(
                action=full_action,
                method=attrs_dict.get("method", "GET").upper(),
                is_https_action=full_action.startswith("https://") or not full_action.startswith("http"),
                has_autocomplete_off=attrs_dict.get("autocomplete", "").lower() == "off",
            )

        elif tag == "input" and self.current_form:
            input_type = attrs_dict.get("type", "text").lower()
            input_name = attrs_dict.get("name", "")

            self.current_form.input_fields.append(
                {
                    "type": input_type,
                    "name": input_name,
                    "autocomplete": attrs_dict.get("autocomplete"),
                }
            )

            if input_type == "password":
                self.current_form.password_fields += 1

            # Check for CSRF token
            if input_type == "hidden" and any(
                csrf in input_name.lower() for csrf in ["csrf", "token", "_token", "authenticity"]
            ):
                self.current_form.has_csrf_token = True

            # Check for sensitive fields
            sensitive_patterns = ["ssn", "social", "credit", "card", "cvv", "ccv", "passport", "license"]
            if any(p in input_name.lower() for p in sensitive_patterns):
                self.current_form.sensitive_fields.append(input_name)

        elif tag == "a":
            href = attrs_dict.get("href", "")
            self._analyze_link(href)

        elif tag == "meta":
            name = attrs_dict.get("name", "").lower()
            http_equiv = attrs_dict.get("http-equiv", "").lower()
            content = attrs_dict.get("content", "")

            if http_equiv == "content-security-policy":
                self.meta_tags.csp_meta = content
            elif http_equiv == "refresh":
                self.meta_tags.refresh_redirect = content
            elif name == "robots":
                self.meta_tags.robots = content
            elif name == "generator":
                self.meta_tags.generator = content
            elif name == "author":
                self.meta_tags.author = content
            elif name == "referrer":
                self.meta_tags.referrer = content
            elif name == "viewport":
                self.meta_tags.viewport = content

        elif tag == "title":
            pass  # Will be handled in handle_data

    def handle_endtag(self, tag: str):
        if tag == "script":
            if self.in_script and self.current_script_content:
                script = ScriptInfo(
                    is_inline=True,
                    is_external=False,
                    content_hash=hashlib.md5(self.current_script_content.encode(), usedforsecurity=False).hexdigest()[
                        :16
                    ],
                    content_preview=self.current_script_content[:200]
                    if len(self.current_script_content) > 200
                    else self.current_script_content,
                )
                self._analyze_inline_script(script, self.current_script_content)
                self.scripts.append(script)
            self.in_script = False
            self.current_script_content = ""

        elif tag == "form" and self.current_form:
            self._analyze_form_security(self.current_form)
            self.forms.append(self.current_form)
            self.current_form = None

    def handle_data(self, data: str):
        if self.in_script:
            self.current_script_content += data
        else:
            self.all_text.append(data)

    def _is_external_url(self, url: str) -> bool:
        """Check if URL points to external domain."""
        if not url:
            return False
        if url.startswith("//"):
            url = "https:" + url
        parsed = urlparse(url)
        if not parsed.netloc:
            return False
        return parsed.netloc != self.base_domain

    def _check_third_party(self, url: str, resource_type: str, has_integrity: bool):
        """Check and record third-party resource."""
        if not url:
            return
        if url.startswith("//"):
            url = "https:" + url
        parsed = urlparse(url)
        if not parsed.netloc or parsed.netloc == self.base_domain:
            return

        # Known tracking domains
        tracking_domains = [
            "google-analytics.com",
            "googletagmanager.com",
            "facebook.net",
            "doubleclick.net",
            "googlesyndication.com",
            "analytics.",
            "tracking.",
            "pixel.",
            "beacon.",
            "hotjar.com",
            "mixpanel.com",
        ]

        is_tracking = any(td in parsed.netloc.lower() for td in tracking_domains)

        self.third_party_resources.append(
            ThirdPartyResource(
                domain=parsed.netloc,
                resource_type=resource_type,
                url=url,
                has_integrity=has_integrity,
                is_tracking=is_tracking,
            )
        )

    def _analyze_link(self, href: str):
        """Analyze a link for security issues."""
        if not href:
            return

        self.links.total_links += 1

        if href.startswith("javascript:"):
            self.links.javascript_links.append(href[:100])
        elif href.startswith("data:"):
            self.links.data_links.append(href[:100])
        elif href.startswith("http://"):
            self.links.http_links.append(href)
            self.links.external_links += 1
        elif href.startswith("https://") or href.startswith("//"):
            if self._is_external_url(href):
                self.links.external_links += 1
            else:
                self.links.internal_links += 1
        else:
            self.links.internal_links += 1

        # Check for suspicious patterns
        suspicious_patterns = [
            (r"\.exe\b", "Executable file link"),
            (r"\.bat\b", "Batch file link"),
            (r"\.cmd\b", "Command file link"),
            (r"\.scr\b", "Screensaver file link"),
            (r"\.msi\b", "Installer file link"),
        ]
        for pattern, desc in suspicious_patterns:
            if re.search(pattern, href, re.I):
                self.links.suspicious_links.append({"url": href[:200], "reason": desc})

    def _analyze_inline_script(self, script: ScriptInfo, content: str):
        """Analyze inline script for security issues."""
        dangerous_patterns = [
            (r"\beval\s*\(", "eval() usage detected"),
            (r"\bdocument\.write\s*\(", "document.write() usage detected"),
            (r"\binnerHTML\s*=", "innerHTML assignment detected"),
            (r"\bouterHTML\s*=", "outerHTML assignment detected"),
            (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML usage detected"),
            (r"\bFunction\s*\(", "Function constructor usage detected"),
            (r'\bsetTimeout\s*\(\s*[\'"]', "setTimeout with string argument"),
            (r'\bsetInterval\s*\(\s*[\'"]', "setInterval with string argument"),
            (r"location\s*=", "Location assignment detected"),
            (r"location\.href\s*=", "Location.href assignment detected"),
            (r"window\.open\s*\(", "window.open usage detected"),
        ]

        for pattern, description in dangerous_patterns:
            if re.search(pattern, content):
                script.dangerous_patterns.append(
                    {
                        "pattern": pattern,
                        "description": description,
                    }
                )

        # Check for hardcoded secrets
        secret_patterns = [
            (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9_-]{16,}["\']', "Hardcoded API key"),
            (r'["\']?secret["\']?\s*[:=]\s*["\'][a-zA-Z0-9_-]{16,}["\']', "Hardcoded secret"),
            (r'["\']?password["\']?\s*[:=]\s*["\'][^"\']+["\']', "Hardcoded password"),
            (r'["\']?token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_-]{16,}["\']', "Hardcoded token"),
        ]

        for pattern, description in secret_patterns:
            if re.search(pattern, content, re.I):
                script.security_issues.append(description)

    def _analyze_form_security(self, form: FormInfo):
        """Analyze form for security issues."""
        if form.password_fields > 0 and form.method == "GET":
            form.security_issues.append("Password submitted via GET method")

        if form.password_fields > 0 and not form.is_https_action:
            form.security_issues.append("Password form submits to non-HTTPS URL")

        if form.method == "POST" and not form.has_csrf_token:
            form.security_issues.append("POST form missing CSRF token")

        if form.sensitive_fields and not form.is_https_action:
            form.security_issues.append("Sensitive data submitted to non-HTTPS URL")

        # Check for autocomplete on sensitive fields
        for input_field in form.input_fields:
            if input_field["type"] == "password" and input_field.get("autocomplete") != "off":
                form.security_issues.append("Password field allows autocomplete")
                break


class ContentScanner:
    """
    Website Content Security Scanner.

    Performs deep analysis of website content including:
    - HTML structure analysis
    - JavaScript security inspection
    - Form security analysis
    - Sensitive data exposure detection
    - Third-party resource analysis
    """

    DEFAULT_TIMEOUT = 30
    DEFAULT_USER_AGENT = "SecureSys-Auditor/1.0 Security Scanner"
    MAX_CONTENT_SIZE = 10 * 1024 * 1024  # 10MB max

    # Patterns for sensitive data detection
    EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    PHONE_PATTERN = re.compile(r"(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}")
    IP_PATTERN = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    # API key patterns
    API_KEY_PATTERNS = [
        (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "Google API Key"),
        (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key"),
        (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "Stripe Secret Key"),
        (re.compile(r"pk_live_[0-9a-zA-Z]{24,}"), "Stripe Publishable Key"),
        (re.compile(r"sq0atp-[0-9A-Za-z_-]{22}"), "Square Access Token"),
        (re.compile(r"ghp_[0-9a-zA-Z]{36}"), "GitHub Personal Token"),
        (re.compile(r"gho_[0-9a-zA-Z]{36}"), "GitHub OAuth Token"),
        (re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,}"), "Slack Token"),
    ]

    # Private key patterns
    PRIVATE_KEY_PATTERNS = [
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PR" + "IVATE KEY-----"),  # pragma: allowlist secret
        re.compile(r"-----BEGIN PGP " + "PR" + "IVATE KEY BLOCK-----"),  # pragma: allowlist secret
    ]

    def __init__(self, timeout: Optional[int] = None):
        """Initialize the content scanner."""
        self.timeout = timeout or self.DEFAULT_TIMEOUT
        self._session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()

        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        session.headers.update(
            {
                "User-Agent": self.DEFAULT_USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }
        )

        return session

    def scan(self, url: str, html_content: Optional[str] = None) -> ContentScanResult:
        """
        Perform comprehensive content security scan.

        Args:
            url: The URL to scan
            html_content: Optional pre-fetched HTML content

        Returns:
            ContentScanResult with all findings
        """
        import time

        start_time = time.time()

        logger.info(f"Starting content scan for: {url}")

        result = ContentScanResult(url=url)

        try:
            # Fetch content if not provided
            if html_content is None:
                html_content = self._fetch_content(url, result)

            if html_content:
                result.content_length = len(html_content)
                result.content_hash = hashlib.sha256(html_content.encode()).hexdigest()[:32]

                # Parse HTML and analyze structure
                self._parse_html(url, html_content, result)

                # Detect sensitive data exposure
                self._detect_sensitive_data(html_content, result)

                # Detect technologies
                self._detect_technologies(html_content, result)

                # Check for mixed content
                self._check_mixed_content(url, html_content, result)

        except Exception as e:
            logger.error(f"Error during content scan: {e}")
            result.errors.append(str(e))

        result.scan_duration_ms = (time.time() - start_time) * 1000
        logger.info(f"Content scan completed for: {url} in {result.scan_duration_ms:.0f}ms")

        return result

    def _fetch_content(self, url: str, result: ContentScanResult) -> Optional[str]:
        """Fetch HTML content from URL."""
        try:
            response = self._session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
            )

            # Check content size
            content_length = int(response.headers.get("Content-Length", 0))
            if content_length > self.MAX_CONTENT_SIZE:
                result.errors.append(f"Content too large: {content_length} bytes")
                return None

            return response.text

        except requests.exceptions.RequestException as e:
            result.errors.append(f"Failed to fetch content: {str(e)}")
            return None

    def _parse_html(self, url: str, content: str, result: ContentScanResult):
        """Parse HTML content and extract security-relevant information."""
        try:
            parser = HTMLContentParser(url)
            parser.feed(content)

            result.page_title = parser.title
            result.scripts = parser.scripts
            result.forms = parser.forms
            result.links = parser.links
            result.meta_tags = parser.meta_tags
            result.iframes = parser.iframes
            result.third_party_resources = parser.third_party_resources
            result.has_inline_event_handlers = parser.inline_event_handlers

            # Check for document.write and eval in scripts
            for script in result.scripts:
                if script.dangerous_patterns:
                    for pattern in script.dangerous_patterns:
                        if "document.write" in pattern.get("description", ""):
                            result.has_document_write = True
                        if "eval" in pattern.get("description", ""):
                            result.has_eval_usage = True

        except Exception as e:
            result.errors.append(f"HTML parsing error: {str(e)}")

    def _detect_sensitive_data(self, content: str, result: ContentScanResult):
        """Detect sensitive data exposure in content."""
        sensitive = SensitiveDataExposure()

        # Find emails (limit to prevent DoS on large pages)
        emails = self.EMAIL_PATTERN.findall(content)
        sensitive.emails = list(set(emails))[:50]

        # Find phone numbers
        phones = self.PHONE_PATTERN.findall(content)
        sensitive.phone_numbers = list(set(phones))[:20]

        # Find IP addresses (exclude common ones)
        ips = self.IP_PATTERN.findall(content)
        filtered_ips = [ip for ip in ips if not ip.startswith(("127.", "0.", "192.168.", "10.", "172."))]
        sensitive.ip_addresses = list(set(filtered_ips))[:20]

        # Find API keys
        for pattern, key_type in self.API_KEY_PATTERNS:
            matches = pattern.findall(content)
            for match in matches[:5]:
                sensitive.api_keys.append(
                    {
                        "type": key_type,
                        "value_preview": match[:8] + "..." if len(match) > 8 else match,
                    }
                )

        # Check for private keys
        for pattern in self.PRIVATE_KEY_PATTERNS:
            if pattern.search(content):
                sensitive.private_keys.append("Private key detected in page source")

        # Find internal paths
        path_pattern = re.compile(r'["\']/?(?:home|var|usr|etc|opt|tmp|www|htdocs|public_html)/[^\s"\'<>]{5,}["\']')
        paths = path_pattern.findall(content)
        sensitive.internal_paths = list(set(paths))[:10]

        # Find debug info
        debug_patterns = [
            (r"stack\s*trace", "Stack trace detected"),
            (r"debug\s*=\s*(?:true|1|on)", "Debug mode enabled"),
            (r"console\s*\.\s*(?:log|debug|error)\s*\(", "Console logging detected"),
            (r"<\!--.*(?:TODO|FIXME|HACK|XXX).*-->", "Development comments found"),
        ]
        for pattern, desc in debug_patterns:
            if re.search(pattern, content, re.I):
                sensitive.debug_info.append(desc)

        # Find secrets in HTML comments
        comment_pattern = re.compile(r"<!--(.*?)-->", re.DOTALL)
        comments = comment_pattern.findall(content)
        secret_keywords = ["password", "secret", "api_key", "apikey", "token", "credential", "private"]
        for comment in comments:
            if any(kw in comment.lower() for kw in secret_keywords):
                sensitive.comments_with_secrets.append(
                    {
                        "preview": comment[:100] + "..." if len(comment) > 100 else comment,
                    }
                )

        result.sensitive_data = sensitive

    def _detect_technologies(self, content: str, result: ContentScanResult):
        """Detect technologies used on the page."""
        technologies = []

        tech_signatures = [
            # JavaScript frameworks
            (r"react", "React"),
            (r"angular", "Angular"),
            (r"vue\.?js|Vue\.", "Vue.js"),
            (r"jquery", "jQuery"),
            (r"backbone", "Backbone.js"),
            (r"ember", "Ember.js"),
            (r"svelte", "Svelte"),
            # CSS frameworks
            (r"bootstrap", "Bootstrap"),
            (r"tailwind", "Tailwind CSS"),
            (r"bulma", "Bulma"),
            (r"foundation", "Foundation"),
            (r"materialize", "Materialize"),
            # CMS/Platforms
            (r"wp-content|wordpress", "WordPress"),
            (r"drupal", "Drupal"),
            (r"joomla", "Joomla"),
            (r"shopify", "Shopify"),
            (r"magento", "Magento"),
            (r"wix\.com", "Wix"),
            (r"squarespace", "Squarespace"),
            # Analytics/Tracking
            (r"google-analytics|gtag|ga\.js", "Google Analytics"),
            (r"googletagmanager", "Google Tag Manager"),
            (r"facebook.*pixel|fbq\(", "Facebook Pixel"),
            (r"hotjar", "Hotjar"),
            (r"mixpanel", "Mixpanel"),
            # Server technologies (from comments/meta)
            (r"php|\.php", "PHP"),
            (r"asp\.net|aspx", "ASP.NET"),
            (r"node\.?js|express", "Node.js"),
            (r"django", "Django"),
            (r"laravel", "Laravel"),
            (r"ruby on rails|rails", "Ruby on Rails"),
        ]

        content_lower = content.lower()
        detected = set()

        for pattern, tech_name in tech_signatures:
            if re.search(pattern, content_lower):
                if tech_name not in detected:
                    detected.add(tech_name)
                    technologies.append(
                        {
                            "name": tech_name,
                            "confidence": "high" if tech_name in content else "medium",
                        }
                    )

        # Check generator meta tag
        if result.meta_tags and result.meta_tags.generator:
            technologies.append(
                {
                    "name": result.meta_tags.generator,
                    "confidence": "confirmed",
                    "source": "meta generator",
                }
            )

        result.detected_technologies = technologies

    def _check_mixed_content(self, url: str, content: str, result: ContentScanResult):
        """Check for mixed content issues."""
        if not url.startswith("https://"):
            return

        # Look for http:// URLs in content
        http_pattern = re.compile(r'(?:src|href|action)\s*=\s*["\']http://[^"\']+["\']', re.I)
        if http_pattern.search(content):
            result.has_mixed_content = True
