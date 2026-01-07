"""
URL Security Analysis Rules for SecureSys Auditor.

This module defines security rules that analyze URL scan results
to identify vulnerabilities and generate findings with remediation guidance.

Rules follow the same pattern as core.analysis.SecurityRule but are
specialized for URL/website security issues.
"""
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class URLSecurityRule:
    """Base class for URL security rules."""

    rule_id: str
    category: str
    severity: str

    def evaluate(self, scan_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluate the rule against the scan result.

        Args:
            scan_result: Dictionary from URLScanResult.to_dict()

        Returns:
            Finding dict if rule triggers, None otherwise
        """
        raise NotImplementedError


class MissingHSTSRule(URLSecurityRule):
    """Check for missing or weak HSTS header."""

    def __init__(self):
        super().__init__("URL-HSTS-001", "http_headers", "high")

    def evaluate(self, scan_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        headers = scan_result.get("security_headers", {})
        if not headers:
            return None

        hsts = headers.get("strict_transport_security")
        missing_headers = headers.get("missing_headers", [])

        if "Strict-Transport-Security" in missing_headers or not hsts:
            return {
                "category": self.category,
                "severity": self.severity,
                "title": "Missing HSTS Header",
                "description": "The website does not implement HTTP Strict Transport Security (HSTS). "
                "This leaves users vulnerable to protocol downgrade attacks and cookie hijacking.",
                "evidence": {
                    "url": scan_result.get("url"),
                    "header": "Strict-Transport-Security",
                    "status": "missing",
                },
                "recommendations": [
                    {
                        "title": "Implement HSTS Header",
                        "description": "Add the Strict-Transport-Security header to enforce HTTPS connections.",
                        "priority": "high",
                        "effort": "low",
                        "steps": [
                            "Add header to your web server configuration",
                            (
                                'For Apache: Header always set Strict-Transport-Security "max-age=31536000; '
                                'includeSubDomains; preload"'
                            ),
                            (
                                'For Nginx: add_header Strict-Transport-Security "max-age=31536000; '
                                'includeSubDomains; preload" always;'
                            ),
                            "Test with browser developer tools to verify header is present",
                            "Consider submitting to HSTS preload list at hstspreload.org",
                        ],
                    }
                ],
            }
        return None


class WeakHSTSRule(URLSecurityRule):
    """Check for weak HSTS configuration."""

    def __init__(self):
        super().__init__("URL-HSTS-002", "http_headers", "medium")

    def evaluate(self, scan_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        headers = scan_result.get("security_headers", {})
        if not headers:
            return None

        weak_headers = headers.get("weak_headers", [])
        hsts_issues = [h for h in weak_headers if h.get("header") == "Strict-Transport-Security"]

        if hsts_issues:
            return {
                "category": self.category,
                "severity": self.severity,
                "title": "Weak HSTS Configuration",
                "description": (
                    "The HSTS header is present but has configuration weaknesses that reduce its effectiveness."
                ),
                "evidence": {
                    "url": scan_result.get("url"),
                    "header": "Strict-Transport-Security",
                    "value": headers.get("strict_transport_security"),
                    "issues": [h.get("issue") for h in hsts_issues],
                },
                "recommendations": [
                    {
                        "title": "Strengthen HSTS Configuration",
                        "description": "Update HSTS header with stronger settings.",
                        "priority": "medium",
                        "effort": "low",
                        "steps": [
                            "Set max-age to at least 31536000 (1 year)",
                            "Add includeSubDomains directive",
                            "Consider adding preload directive for HSTS preload list submission",
                            'Recommended value: "max-age=31536000; includeSubDomains; preload"',
                        ],
                    }
                ],
            }
        return None


class MissingCSPRule(URLSecurityRule):
    """Check for missing Content-Security-Policy header."""

    def __init__(self):
        super().__init__("URL-CSP-001", "http_headers", "high")

    def evaluate(self, scan_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        headers = scan_result.get("security_headers", {})
        if not headers:
            return None

        csp = headers.get("content_security_policy")
        missing_headers = headers.get("missing_headers", [])

        if "Content-Security-Policy" in missing_headers or not csp:
            return {
                "category": self.category,
                "severity": self.severity,
                "title": "Missing Content Security Policy",
                "description": "The website does not implement a Content-Security-Policy header. "
                "CSP helps prevent XSS attacks, clickjacking, and other code injection attacks.",
                "evidence": {
                    "url": scan_result.get("url"),
                    "header": "Content-Security-Policy",
                    "status": "missing",
                },
                "recommendations": [
                    {
                        "title": "Implement Content Security Policy",
                        "description": "Add a Content-Security-Policy header to control resource loading.",
                        "priority": "high",
                        "effort": "high",
                        "steps": [
                            "Audit your website for all resource sources (scripts, styles, images, etc.)",
                            "Start with a report-only policy: Content-Security-Policy-Report-Only",
                            "Define allowed sources for each directive (script-src, style-src, img-src, etc.)",
                            (
                                "Example starter policy: \"default-src 'self'; script-src 'self'; style-src 'self' "
                                "'unsafe-inline'\""
                            ),
                            "Monitor CSP violation reports and refine policy",
                            "Switch from report-only to enforcing mode once policy is tuned",
                        ],
                    }
                ],
            }
        return None


class MissingXFrameOptionsRule(URLSecurityRule):
    """Check for missing X-Frame-Options header."""

    def __init__(self):
        super().__init__("URL-XFO-001", "http_headers", "medium")

    def evaluate(self, scan_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        headers = scan_result.get("security_headers", {})
        if not headers:
            return None

        xfo = headers.get("x_frame_options")
        missing_headers = headers.get("missing_headers", [])

        if "X-Frame-Options" in missing_headers or not xfo:
            return {
                "category": self.category,
                "severity": self.severity,
                "title": "Missing X-Frame-Options Header",
                "description": "The website does not set the X-Frame-Options header, making it potentially "
                "vulnerable to clickjacking attacks where attackers embed your site in an iframe.",
                "evidence": {
                    "url": scan_result.get("url"),
                    "header": "X-Frame-Options",
                    "status": "missing",
                },
                "recommendations": [
                    {
                        "title": "Add X-Frame-Options Header",
                        "description": "Implement X-Frame-Options to prevent clickjacking.",
                        "priority": "medium",
                        "effort": "low",
                        "steps": [
                            "Determine if your site needs to be embedded in iframes",
                            "If no embedding needed: Set X-Frame-Options: DENY",
                            "If same-origin embedding needed: Set X-Frame-Options: SAMEORIGIN",
                            'For Apache: Header always set X-Frame-Options "DENY"',
                            'For Nginx: add_header X-Frame-Options "DENY" always;',
                            "Note: CSP frame-ancestors directive is preferred over X-Frame-Options",
                        ],
                    }
                ],
            }
        return None


class MissingXContentTypeOptionsRule(URLSecurityRule):
    """Check for missing X-Content-Type-Options header."""

    def __init__(self):
        super().__init__("URL-XCTO-001", "http_headers", "low")

    def evaluate(self, scan_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        headers = scan_result.get("security_headers", {})
        if not headers:
            return None

        xcto = headers.get("x_content_type_options")
        missing_headers = headers.get("missing_headers", [])

        if "X-Content-Type-Options" in missing_headers or not xcto:
            return {
                "category": self.category,
                "severity": self.severity,
                "title": "Missing X-Content-Type-Options Header",
                "description": "The website does not set X-Content-Type-Options: nosniff. "
                "This allows browsers to MIME-sniff content, potentially executing malicious files.",
                "evidence": {
                    "url": scan_result.get("url"),
                    "header": "X-Content-Type-Options",
                    "status": "missing",
                },
                "recommendations": [
                    {
                        "title": "Add X-Content-Type-Options Header",
                        "description": "Prevent MIME type sniffing with nosniff directive.",
                        "priority": "low",
                        "effort": "low",
                        "steps": [
                            "Add header: X-Content-Type-Options: nosniff",
                            'For Apache: Header always set X-Content-Type-Options "nosniff"',
                            'For Nginx: add_header X-Content-Type-Options "nosniff" always;',
                            "Ensure all resources are served with correct Content-Type headers",
                        ],
                    }
                ],
            }
        return None


class MissingReferrerPolicyRule(URLSecurityRule):
    """Check for missing Referrer-Policy header."""

    def __init__(self):
        super().__init__("URL-RP-001", "http_headers", "low")

    def evaluate(self, scan_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        headers = scan_result.get("security_headers", {})
        if not headers:
            return None

        rp = headers.get("referrer_policy")
        missing_headers = headers.get("missing_headers", [])

        if "Referrer-Policy" in missing_headers or not rp:
            return {
                "category": self.category,
                "severity": self.severity,
                "title": "Missing Referrer-Policy Header",
                "description": "The website does not set a Referrer-Policy header. "
                "This may leak sensitive URL information to third-party sites.",
                "evidence": {
                    "url": scan_result.get("url"),
                    "header": "Referrer-Policy",
                    "status": "missing",
                },
                "recommendations": [
                    {
                        "title": "Add Referrer-Policy Header",
                        "description": "Control referrer information sent to external sites.",
                        "priority": "low",
                        "effort": "low",
                        "steps": [
                            "Choose appropriate policy based on your needs:",
                            '- "strict-origin-when-cross-origin" (recommended default)',
                            '- "no-referrer" (maximum privacy)',
                            '- "same-origin" (only send to same origin)',
                            'For Apache: Header always set Referrer-Policy "strict-origin-when-cross-origin"',
                            'For Nginx: add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
                        ],
                    }
                ],
            }
        return None


class ServerInfoDisclosureRule(URLSecurityRule):
    """Check for server information disclosure."""

    def __init__(self):
        super().__init__("URL-INFO-001", "configuration", "low")

    def evaluate(self, scan_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        headers = scan_result.get("security_headers", {})
        server_info = scan_result.get("server_info", {})

        disclosed = []

        if headers:
            if headers.get("server"):
                disclosed.append(("Server", headers.get("server")))
            if headers.get("x_powered_by"):
                disclosed.append(("X-Powered-By", headers.get("x_powered_by")))

        for key, value in server_info.items():
            if key not in ["server", "x_powered_by"]:
                disclosed.append((key, value))

        if disclosed:
            return {
                "category": self.category,
                "severity": self.severity,
                "title": "Server Information Disclosure",
                "description": "The server reveals technology and version information in HTTP headers. "
                "This information could help attackers identify known vulnerabilities.",
                "evidence": {
                    "url": scan_result.get("url"),
                    "disclosed_headers": [{"header": h, "value": v} for h, v in disclosed],
                },
                "recommendations": [
                    {
                        "title": "Hide Server Information",
                        "description": "Remove or obscure server version headers.",
                        "priority": "low",
                        "effort": "low",
                        "steps": [
                            "For Apache: ServerTokens Prod and ServerSignature Off",
                            "For Nginx: server_tokens off;",
                            "Remove X-Powered-By header in application config",
                            "For PHP: expose_php = Off in php.ini",
                            'For Express.js: app.disable("x-powered-by")',
                            "Consider using a WAF or reverse proxy to strip headers",
                        ],
                    }
                ],
            }
        return None


class SSLCertificateExpiryRule(URLSecurityRule):
    """Check for SSL certificate near expiry or expired."""

    def __init__(self):
        super().__init__("URL-SSL-001", "ssl_tls", "critical")

    def evaluate(self, scan_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ssl_info = scan_result.get("ssl_info")
        if not ssl_info:
            return None

        days_until_expiry = ssl_info.get("days_until_expiry")

        if days_until_expiry is not None:
            if days_until_expiry <= 0:
                return {
                    "category": self.category,
                    "severity": "critical",
                    "title": "SSL Certificate Expired",
                    "description": "The SSL certificate has expired! Users will see security warnings and "
                    "connections may be rejected by browsers.",
                    "evidence": {
                        "url": scan_result.get("url"),
                        "days_until_expiry": days_until_expiry,
                        "not_after": ssl_info.get("not_after"),
                        "issuer": ssl_info.get("issuer"),
                    },
                    "recommendations": [
                        {
                            "title": "Renew SSL Certificate Immediately",
                            "description": "The certificate has expired and needs immediate renewal.",
                            "priority": "critical",
                            "effort": "medium",
                            "steps": [
                                "Generate a new certificate signing request (CSR)",
                                "Submit CSR to your certificate authority",
                                "Or use Let's Encrypt: certbot renew --force-renewal",
                                "Install the new certificate on your web server",
                                "Restart your web server",
                                "Set up automated renewal to prevent future expiration",
                            ],
                        }
                    ],
                }
            elif days_until_expiry <= 30:
                severity = "high" if days_until_expiry <= 7 else "medium"
                return {
                    "category": self.category,
                    "severity": severity,
                    "title": f"SSL Certificate Expiring Soon ({days_until_expiry} days)",
                    "description": f"The SSL certificate will expire in {days_until_expiry} days. "
                    "Plan renewal to avoid service disruption.",
                    "evidence": {
                        "url": scan_result.get("url"),
                        "days_until_expiry": days_until_expiry,
                        "not_after": ssl_info.get("not_after"),
                        "issuer": ssl_info.get("issuer"),
                    },
                    "recommendations": [
                        {
                            "title": "Renew SSL Certificate",
                            "description": "Plan certificate renewal before expiration.",
                            "priority": severity,
                            "effort": "medium",
                            "steps": [
                                "Check certificate expiration date and set reminder",
                                "For Let's Encrypt: certbot renew",
                                "For other CAs: Submit renewal request through your provider",
                                "Test renewal in staging first if possible",
                                "Set up automated certificate renewal",
                                "Consider using certbot with auto-renewal cronjob",
                            ],
                        }
                    ],
                }
        return None


class SSLCertificateInvalidRule(URLSecurityRule):
    """Check for SSL certificate validation errors."""

    def __init__(self):
        super().__init__("URL-SSL-002", "ssl_tls", "critical")

    def evaluate(self, scan_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ssl_info = scan_result.get("ssl_info")
        if not ssl_info:
            return None

        if not ssl_info.get("is_valid", True):
            errors = ssl_info.get("errors", [])
            return {
                "category": self.category,
                "severity": self.severity,
                "title": "SSL Certificate Validation Failed",
                "description": "The SSL certificate could not be validated. This may indicate an "
                "untrusted, self-signed, or misconfigured certificate.",
                "evidence": {
                    "url": scan_result.get("url"),
                    "errors": errors,
                    "issuer": ssl_info.get("issuer"),
                },
                "recommendations": [
                    {
                        "title": "Fix SSL Certificate Issues",
                        "description": "Resolve SSL certificate validation problems.",
                        "priority": "critical",
                        "effort": "medium",
                        "steps": [
                            "Check if the certificate is issued by a trusted CA",
                            "Verify the certificate chain is complete",
                            "Ensure intermediate certificates are installed",
                            "Check that the certificate matches the domain name",
                            "If self-signed, obtain a certificate from a trusted CA",
                            "Test with: openssl s_client -connect domain.com:443 -servername domain.com",
                        ],
                    }
                ],
            }
        return None


class SelfSignedCertificateRule(URLSecurityRule):
    """Check for self-signed SSL certificates."""

    def __init__(self):
        super().__init__("URL-SSL-003", "ssl_tls", "high")

    def evaluate(self, scan_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ssl_info = scan_result.get("ssl_info")
        if not ssl_info:
            return None

        if ssl_info.get("is_self_signed"):
            return {
                "category": self.category,
                "severity": self.severity,
                "title": "Self-Signed SSL Certificate Detected",
                "description": "The website uses a self-signed certificate. Browsers will show "
                "security warnings and users may be unable to verify site authenticity.",
                "evidence": {
                    "url": scan_result.get("url"),
                    "subject": ssl_info.get("subject"),
                    "issuer": ssl_info.get("issuer"),
                },
                "recommendations": [
                    {
                        "title": "Use Trusted CA Certificate",
                        "description": "Replace self-signed certificate with one from a trusted CA.",
                        "priority": "high",
                        "effort": "medium",
                        "steps": [
                            "Obtain a certificate from a trusted Certificate Authority",
                            "Free option: Use Let's Encrypt (certbot)",
                            "Generate CSR: openssl req -new -key private.key -out domain.csr",
                            "Submit CSR to your chosen CA",
                            "Install the issued certificate and any intermediate certs",
                            "Verify with SSL Labs: ssllabs.com/ssltest/",
                        ],
                    }
                ],
            }
        return None


class InsecureCookiesRule(URLSecurityRule):
    """Check for cookies without security flags."""

    def __init__(self):
        super().__init__("URL-COOKIE-001", "web_security", "medium")

    def evaluate(self, scan_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        cookies = scan_result.get("cookies", [])

        insecure_cookies = []
        for cookie in cookies:
            if cookie.get("issues"):
                insecure_cookies.append(
                    {
                        "name": cookie.get("name"),
                        "issues": cookie.get("issues"),
                        "secure": cookie.get("secure"),
                        "http_only": cookie.get("http_only"),
                        "same_site": cookie.get("same_site"),
                    }
                )

        if insecure_cookies:
            return {
                "category": self.category,
                "severity": self.severity,
                "title": f"Insecure Cookie Configuration ({len(insecure_cookies)} cookies)",
                "description": "One or more cookies are missing security attributes, making them "
                "vulnerable to theft or cross-site attacks.",
                "evidence": {
                    "url": scan_result.get("url"),
                    "insecure_cookies": insecure_cookies,
                },
                "recommendations": [
                    {
                        "title": "Secure Cookie Configuration",
                        "description": "Add security attributes to all cookies.",
                        "priority": "medium",
                        "effort": "medium",
                        "steps": [
                            "Add Secure flag to ensure HTTPS-only transmission",
                            "Add HttpOnly flag to prevent JavaScript access",
                            "Add SameSite=Strict or SameSite=Lax to prevent CSRF",
                            "Example: Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict",
                            "For session cookies, always use all three attributes",
                            "Test cookie settings with browser developer tools",
                        ],
                    }
                ],
            }
        return None


class NoHTTPSRedirectRule(URLSecurityRule):
    """Check if HTTP redirects to HTTPS."""

    def __init__(self):
        super().__init__("URL-HTTPS-001", "encryption", "medium")

    def evaluate(self, scan_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        url = scan_result.get("url", "")
        final_url = scan_result.get("final_url", "")

        # If we started with HTTP and ended with HTTP, flag it
        if url.startswith("http://") and final_url.startswith("http://"):
            return {
                "category": self.category,
                "severity": self.severity,
                "title": "No HTTPS Redirect",
                "description": "HTTP requests are not automatically redirected to HTTPS. "
                "Users accessing the site via HTTP are exposed to man-in-the-middle attacks.",
                "evidence": {
                    "original_url": url,
                    "final_url": final_url,
                    "redirects": scan_result.get("redirects", []),
                },
                "recommendations": [
                    {
                        "title": "Implement HTTP to HTTPS Redirect",
                        "description": "Configure automatic redirect from HTTP to HTTPS.",
                        "priority": "medium",
                        "effort": "low",
                        "steps": [
                            "For Apache (.htaccess):",
                            "  RewriteEngine On",
                            "  RewriteCond %{HTTPS} off",
                            "  RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
                            "For Nginx:",
                            "  server { listen 80; return 301 https://$host$request_uri; }",
                            "Use 301 (permanent) redirect for SEO benefits",
                            "Test redirect chain to ensure no redirect loops",
                        ],
                    }
                ],
            }
        return None


class URLSecurityAnalyzer:
    """
    Analyzer that runs all URL security rules against scan results.
    """

    # Risk weights by severity
    SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3}

    # Maturity level thresholds (lower score = more mature)
    MATURITY_THRESHOLDS = {"optimized": 20, "managed": 40, "basic": 60, "reactive": 100}

    def __init__(self):
        self.rules = self._load_rules()

    def _load_rules(self) -> List[URLSecurityRule]:
        """Load all URL security rules."""
        return [
            MissingHSTSRule(),
            WeakHSTSRule(),
            MissingCSPRule(),
            MissingXFrameOptionsRule(),
            MissingXContentTypeOptionsRule(),
            MissingReferrerPolicyRule(),
            ServerInfoDisclosureRule(),
            SSLCertificateExpiryRule(),
            SSLCertificateInvalidRule(),
            SelfSignedCertificateRule(),
            InsecureCookiesRule(),
            NoHTTPSRedirectRule(),
        ]

    def analyze(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run all security rules and calculate risk score.

        Args:
            scan_result: Dictionary from URLScanResult.to_dict()

        Returns:
            Dict with findings, risk_score, maturity_level, and score_breakdown
        """
        if not scan_result:
            return {
                "findings": [],
                "risk_score": 0,
                "maturity_level": "optimized",
                "score_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            }

        findings = []
        score_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        # Evaluate all rules
        for rule in self.rules:
            try:
                result = rule.evaluate(scan_result)
                if result:
                    findings.append(result)
                    score_breakdown[result["severity"]] += 1
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.rule_id}: {str(e)}")

        # Calculate risk score
        risk_score = self._calculate_risk_score(score_breakdown)

        # Determine maturity level
        maturity_level = self._determine_maturity(risk_score)

        return {
            "findings": findings,
            "risk_score": risk_score,
            "maturity_level": maturity_level,
            "score_breakdown": score_breakdown,
        }

    def _calculate_risk_score(self, breakdown: Dict[str, int]) -> int:
        """Calculate overall risk score from findings breakdown."""
        score = 0
        for severity, count in breakdown.items():
            score += count * self.SEVERITY_WEIGHTS.get(severity, 0)
        return min(100, score)

    def _determine_maturity(self, risk_score: int) -> str:
        """Determine security maturity level based on risk score."""
        for level, threshold in self.MATURITY_THRESHOLDS.items():
            if risk_score <= threshold:
                return level
        return "reactive"
