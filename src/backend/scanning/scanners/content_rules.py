"""
Content Security Analysis Rules for SecureSys Auditor.

This module defines security rules that analyze website content
to identify vulnerabilities and generate detailed findings with
comprehensive remediation guidance.

Categories covered:
- JavaScript Security (XSS, DOM-based vulnerabilities)
- Form Security (CSRF, data exposure)
- Sensitive Data Exposure (credentials, PII, secrets)
- Third-Party Resource Security (SRI, tracking)
- Information Disclosure (technology, debug info)
- Mixed Content Issues
"""
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ContentSecurityRule:
    """Base class for content security rules."""

    rule_id: str
    category: str
    severity: str

    def evaluate(self, content_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluate the rule against the content scan result.

        Args:
            content_result: Dictionary from ContentScanResult.to_dict()

        Returns:
            Finding dict if rule triggers, None otherwise
        """
        raise NotImplementedError


class DangerousJavaScriptRule(ContentSecurityRule):
    """Check for dangerous JavaScript patterns."""

    def __init__(self):
        super().__init__("CONTENT-JS-001", "javascript_security", "high")

    def evaluate(self, content_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        scripts = content_result.get("scripts", [])
        dangerous_scripts = []

        for script in scripts:
            if script.get("dangerous_patterns"):
                dangerous_scripts.append(
                    {
                        "is_inline": script.get("is_inline"),
                        "patterns": script.get("dangerous_patterns"),
                        "content_preview": script.get("content_preview", "")[:100],
                    }
                )

        if dangerous_scripts:
            pattern_types = set()
            for s in dangerous_scripts:
                for p in s.get("patterns", []):
                    pattern_types.add(p.get("description", ""))

            return {
                "category": self.category,
                "severity": self.severity,
                "title": f"Dangerous JavaScript Patterns Detected ({len(dangerous_scripts)} scripts)",
                "description": (
                    "The website contains JavaScript code with potentially dangerous patterns "
                    "that can lead to XSS vulnerabilities, DOM manipulation attacks, or code injection. "
                    f"Detected patterns: {', '.join(list(pattern_types)[:5])}"
                ),
                "evidence": {
                    "url": content_result.get("url"),
                    "dangerous_scripts_count": len(dangerous_scripts),
                    "pattern_types": list(pattern_types),
                    "scripts_preview": dangerous_scripts[:3],
                },
                "recommendations": [
                    {
                        "title": "Eliminate Dangerous JavaScript Patterns",
                        "description": "Replace dangerous JavaScript patterns with secure alternatives.",
                        "priority": "high",
                        "effort": "high",
                        "steps": [
                            "Avoid eval(): Use JSON.parse() for JSON data,",
                            "or Function constructors with caution",
                            "Replace document.write(): Use DOM manipulation (createElement, appendChild)",
                            "Use textContent instead of innerHTML when inserting user data",
                            "Sanitize all user input before DOM insertion using a library like DOMPurify",
                            "Implement Content Security Policy (CSP) to prevent inline script execution",
                            "Use setTimeout/setInterval with function references, not strings",
                            "Audit all third-party scripts for similar dangerous patterns",
                        ],
                        "references": [
                            "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
                            (
                                "https://developer.mozilla.org/en-US/docs/Web/Security/"
                                "Types_of_attacks#cross-site_scripting_xss"
                            ),
                        ],
                    }
                ],
            }
        return None


class InlineEventHandlersRule(ContentSecurityRule):
    """Check for excessive inline event handlers."""

    def __init__(self):
        super().__init__("CONTENT-JS-002", "javascript_security", "medium")

    def evaluate(self, content_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        inline_handlers = content_result.get("has_inline_event_handlers", 0)

        if inline_handlers > 5:
            severity = "high" if inline_handlers > 20 else self.severity
            return {
                "category": self.category,
                "severity": severity,
                "title": f"Inline Event Handlers Detected ({inline_handlers} found)",
                "description": (
                    f"The page contains {inline_handlers} inline event handlers (onclick, onload, etc.). "
                    "Inline event handlers violate Content Security Policy best practices, make XSS "
                    "attacks easier to execute, and indicate poor separation of concerns."
                ),
                "evidence": {
                    "url": content_result.get("url"),
                    "inline_handlers_count": inline_handlers,
                },
                "recommendations": [
                    {
                        "title": "Remove Inline Event Handlers",
                        "description": "Replace inline event handlers with JavaScript event listeners.",
                        "priority": "medium",
                        "effort": "medium",
                        "steps": [
                            "Replace onclick='handler()' with element.addEventListener('click', handler)",
                            "Move all JavaScript to external files or script blocks",
                            "Use data attributes for dynamic values: data-action='submit'",
                            "Implement event delegation for dynamic elements",
                            "Enable CSP directive: script-src 'self' (no 'unsafe-inline')",
                            "Consider using a framework that handles event binding securely",
                        ],
                        "references": [
                            "https://developer.mozilla.org/en-US/docs/Learn/JavaScript/Building_blocks/Events",
                            "https://content-security-policy.com/unsafe-inline/",
                        ],
                    }
                ],
            }
        return None


class HardcodedSecretsRule(ContentSecurityRule):
    """Check for hardcoded secrets in JavaScript."""

    def __init__(self):
        super().__init__("CONTENT-SECRET-001", "sensitive_data", "critical")

    def evaluate(self, content_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        scripts = content_result.get("scripts", [])
        secrets_found = []

        for script in scripts:
            if script.get("security_issues"):
                for issue in script.get("security_issues"):
                    secrets_found.append(
                        {
                            "issue": issue,
                            "script_type": "inline" if script.get("is_inline") else "external",
                        }
                    )

        if secrets_found:
            return {
                "category": self.category,
                "severity": "critical",
                "title": f"Hardcoded Secrets in JavaScript ({len(secrets_found)} found)",
                "description": (
                    "Hardcoded credentials, API keys, or secrets were detected in JavaScript code. "
                    "This is a critical vulnerability as client-side code is fully visible to users "
                    "and attackers. Exposed credentials can lead to account compromise, data breaches, "
                    "and unauthorized access to APIs and services."
                ),
                "evidence": {
                    "url": content_result.get("url"),
                    "secrets_count": len(secrets_found),
                    "secrets_preview": secrets_found[:5],
                },
                "recommendations": [
                    {
                        "title": "Remove All Hardcoded Secrets Immediately",
                        "description": "Secrets must never be exposed in client-side code.",
                        "priority": "critical",
                        "effort": "high",
                        "steps": [
                            "IMMEDIATE: Rotate all exposed credentials and API keys",
                            "Move sensitive operations to backend APIs",
                            "Use environment variables on the server side",
                            "Implement a secrets management solution (HashiCorp Vault, AWS Secrets Manager)",
                            "For public APIs requiring keys, use a backend proxy",
                            "Add pre-commit hooks to detect secrets before commit",
                            "Scan git history for previously committed secrets",
                            "Review access logs for potential misuse of exposed credentials",
                        ],
                        "references": [
                            "https://owasp.org/www-project-web-security-testing-guide/csrf-testing",
                            "https://docs.github.com/en/code-security/secret-scanning",
                        ],
                    }
                ],
            }
        return None


class InsecureFormRule(ContentSecurityRule):
    """Check for forms with security issues."""

    def __init__(self):
        super().__init__("CONTENT-FORM-001", "form_security", "high")

    def evaluate(self, content_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        forms = content_result.get("forms", [])
        insecure_forms = []

        for form in forms:
            issues = form.get("security_issues", [])
            if issues:
                insecure_forms.append(
                    {
                        "action": form.get("action"),
                        "method": form.get("method"),
                        "issues": issues,
                        "password_fields": form.get("password_fields", 0),
                        "sensitive_fields": form.get("sensitive_fields", []),
                    }
                )

        if insecure_forms:
            all_issues = []
            for f in insecure_forms:
                all_issues.extend(f.get("issues", []))

            has_password_issues = any(f.get("password_fields", 0) > 0 for f in insecure_forms)
            severity = "critical" if has_password_issues else self.severity

            return {
                "category": self.category,
                "severity": severity,
                "title": f"Insecure Forms Detected ({len(insecure_forms)} forms)",
                "description": (
                    f"The website contains {len(insecure_forms)} forms with security vulnerabilities. "
                    f"Issues found: {', '.join(list(set(all_issues))[:5])}. "
                    "These vulnerabilities can lead to credential theft, CSRF attacks, and data exposure."
                ),
                "evidence": {
                    "url": content_result.get("url"),
                    "insecure_forms_count": len(insecure_forms),
                    "forms_detail": insecure_forms[:5],
                    "unique_issues": list(set(all_issues)),
                },
                "recommendations": [
                    {
                        "title": "Secure All Forms",
                        "description": "Implement proper security controls on all forms.",
                        "priority": "high" if has_password_issues else "medium",
                        "effort": "medium",
                        "steps": [
                            "Ensure all forms submit to HTTPS URLs only",
                            "Use POST method for forms handling sensitive data",
                            "Implement CSRF tokens on all forms",
                            "(Django: {% csrf_token %})",
                            "Add autocomplete='off' or",
                            "autocomplete='new-password' for password fields",
                            "Disable autocomplete on forms with sensitive financial data",
                            "Validate form submission on both client and server side",
                            "Implement rate limiting on form submissions",
                            "Use CAPTCHA or similar for public-facing forms",
                        ],
                        "references": [
                            "https://cheatsheetseries.owasp.org/csrf-prevention",
                            (
                                "https://developer.mozilla.org/en-US/docs/Web/Security/"
                                "Securing_your_site/Turning_off_form_autocompletion"
                            ),
                        ],
                    }
                ],
            }
        return None


class MissingCSRFTokenRule(ContentSecurityRule):
    """Check for POST forms missing CSRF protection."""

    def __init__(self):
        super().__init__("CONTENT-FORM-002", "form_security", "high")

    def evaluate(self, content_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        forms = content_result.get("forms", [])
        forms_without_csrf = []

        for form in forms:
            if form.get("method", "").upper() == "POST" and not form.get("has_csrf_token"):
                forms_without_csrf.append(
                    {
                        "action": form.get("action"),
                        "has_password": form.get("password_fields", 0) > 0,
                        "sensitive_fields": form.get("sensitive_fields", []),
                    }
                )

        if forms_without_csrf:
            has_sensitive = any(f.get("has_password") or f.get("sensitive_fields") for f in forms_without_csrf)
            severity = "critical" if has_sensitive else self.severity

            return {
                "category": self.category,
                "severity": severity,
                "title": f"Forms Without CSRF Protection ({len(forms_without_csrf)} forms)",
                "description": (
                    f"{len(forms_without_csrf)} POST forms were found without CSRF token protection. "
                    "Cross-Site Request Forgery (CSRF) allows attackers to trick users into performing "
                    "unintended actions. Without CSRF protection, attackers can submit forms on behalf "
                    "of authenticated users."
                ),
                "evidence": {
                    "url": content_result.get("url"),
                    "forms_without_csrf": len(forms_without_csrf),
                    "forms_detail": forms_without_csrf[:5],
                },
                "recommendations": [
                    {
                        "title": "Implement CSRF Protection",
                        "description": "Add CSRF tokens to all state-changing forms.",
                        "priority": "high",
                        "effort": "medium",
                        "steps": [
                            "Use framework-provided CSRF protection:",
                            "  - Django: {% csrf_token %} in forms,",
                            "    CsrfViewMiddleware",
                            "  - Rails: protect_from_forgery with: :exception",
                            "  - Express: csurf middleware",
                            "Generate unique tokens per session or per request",
                            "Validate tokens on the server side for all POST requests",
                            "Use SameSite=Strict or Lax for session cookies",
                            "Implement double-submit cookie pattern as additional protection",
                            "Consider using custom request headers for AJAX requests",
                        ],
                        "references": [
                            "https://cheatsheetseries.owasp.org/csrf-prevention",
                            "https://portswigger.net/web-security/csrf",
                        ],
                    }
                ],
            }
        return None


class APIKeyExposureRule(ContentSecurityRule):
    """Check for exposed API keys in page content."""

    def __init__(self):
        super().__init__("CONTENT-SECRET-002", "sensitive_data", "critical")

    def evaluate(self, content_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        sensitive = content_result.get("sensitive_data", {})
        api_keys = sensitive.get("api_keys", [])
        tokens = sensitive.get("tokens", [])

        all_secrets = api_keys + tokens

        if all_secrets:
            secret_types = list({s.get("type", "Unknown") for s in all_secrets})

            return {
                "category": self.category,
                "severity": "critical",
                "title": f"API Keys/Tokens Exposed ({len(all_secrets)} found)",
                "description": (
                    f"Exposed API keys or tokens were found in the page source code. "
                    f"Types detected: {', '.join(secret_types)}. "
                    "These credentials provide direct access to external services and must be "
                    "rotated immediately. Attackers can use exposed keys for unauthorized access, "
                    "data theft, or to incur charges on your accounts."
                ),
                "evidence": {
                    "url": content_result.get("url"),
                    "secrets_count": len(all_secrets),
                    "secret_types": secret_types,
                    "secrets_preview": all_secrets[:5],
                },
                "recommendations": [
                    {
                        "title": "Rotate and Secure API Credentials",
                        "description": (
                            "Immediately rotate all exposed credentials " "and implement proper secrets management."
                        ),
                        "priority": "critical",
                        "effort": "high",
                        "steps": [
                            "IMMEDIATE ACTIONS:",
                            "1. Identify all services using the exposed keys",
                            "2. Rotate/regenerate all exposed API keys and tokens",
                            "3. Review API usage logs for unauthorized access",
                            "4. Remove keys from client-side code",
                            "",
                            "LONG-TERM SOLUTIONS:",
                            "- Move API calls to backend services",
                            "- Use environment variables for secrets",
                            "- Implement a secrets management solution",
                            "- Set up API key rotation policies",
                            "- Use scoped/limited API keys where possible",
                            "- Implement IP allowlisting for API keys",
                            "- Set up alerts for unusual API usage patterns",
                        ],
                        "references": [
                            "https://cloud.google.com/docs/authentication/api-keys#securing_an_api_key",
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
                        ],
                    }
                ],
            }
        return None


class PrivateKeyExposureRule(ContentSecurityRule):
    """Check for exposed private keys."""

    def __init__(self):
        super().__init__("CONTENT-SECRET-003", "sensitive_data", "critical")

    def evaluate(self, content_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        sensitive = content_result.get("sensitive_data", {})

        if sensitive.get("private_keys_found"):
            return {
                "category": self.category,
                "severity": "critical",
                "title": "Private Keys Exposed in Page Source",
                "description": (
                    "Private cryptographic keys were found in the page source code. "
                    "This is an extremely critical vulnerability. Private keys provide the ability to "
                    "impersonate servers, decrypt sensitive communications, sign malicious code, or "
                    "access protected resources. This requires immediate incident response."
                ),
                "evidence": {
                    "url": content_result.get("url"),
                    "private_keys_detected": True,
                },
                "recommendations": [
                    {
                        "title": "CRITICAL: Private Key Compromise Response",
                        "description": "Treat this as a security incident requiring immediate response.",
                        "priority": "critical",
                        "effort": "high",
                        "steps": [
                            "IMMEDIATE INCIDENT RESPONSE:",
                            "1. Revoke/rotate all exposed private keys immediately",
                            "2. If SSL/TLS key: Reissue certificates from your CA",
                            "3. If code signing key: Revoke and reissue certificates",
                            "4. If SSH key: Remove from all authorized_keys files",
                            "5. Audit all systems that used the compromised keys",
                            "6. Check logs for unauthorized access",
                            "",
                            "REMEDIATION:",
                            "- Remove private keys from web-accessible locations",
                            "- Store keys in secure key management systems (HSM, Vault)",
                            "- Implement proper file permissions (600 for private keys)",
                            "- Use .gitignore to prevent accidental commits",
                            "- Scan code repositories for committed secrets",
                            "- Implement pre-commit hooks to detect key patterns",
                        ],
                        "references": [
                            "https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final",
                            "https://www.ssl.com/faqs/what-to-do-if-your-private-key-is-compromised/",
                        ],
                    }
                ],
            }
        return None


class SensitiveDataExposureRule(ContentSecurityRule):
    """Check for exposed sensitive data like emails, IPs, paths."""

    def __init__(self):
        super().__init__("CONTENT-PII-001", "sensitive_data", "medium")

    def evaluate(self, content_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        sensitive = content_result.get("sensitive_data", {})

        issues = []
        email_count = sensitive.get("emails_count", 0)
        if email_count > 10:
            issues.append(f"{email_count} email addresses exposed")

        internal_paths = sensitive.get("internal_paths", [])
        if internal_paths:
            issues.append(f"{len(internal_paths)} internal server paths exposed")

        debug_info = sensitive.get("debug_info", [])
        if debug_info:
            issues.append("Debug/development information exposed")

        comments = sensitive.get("comments_with_secrets", [])
        if comments:
            issues.append(f"{len(comments)} HTML comments contain sensitive information")

        if issues:
            severity = "high" if internal_paths or comments else self.severity

            return {
                "category": self.category,
                "severity": severity,
                "title": f"Sensitive Information Exposure ({len(issues)} issues)",
                "description": (
                    f"The page exposes sensitive information that could aid attackers. "
                    f"Issues found: {'; '.join(issues)}. "
                    "This information can be used for reconnaissance, social engineering, "
                    "or identifying attack vectors."
                ),
                "evidence": {
                    "url": content_result.get("url"),
                    "emails_exposed": email_count,
                    "internal_paths": internal_paths[:5],
                    "debug_info": debug_info,
                    "sensitive_comments": len(comments),
                },
                "recommendations": [
                    {
                        "title": "Remove Sensitive Information from Public Pages",
                        "description": "Audit and remove all unnecessary sensitive data exposure.",
                        "priority": "medium",
                        "effort": "medium",
                        "steps": [
                            "Review and remove unnecessary email addresses from pages",
                            "Use contact forms instead of displaying email addresses",
                            "Remove or obfuscate internal server paths",
                            "Disable debug mode in production environments",
                            "Remove development comments from production code",
                            "Implement proper error handling that doesn't expose internals",
                            "Use build tools to strip comments in production",
                            "Regularly audit pages for information leakage",
                        ],
                        "references": [
                            (
                                # pragma: allowlist secret
                                "https://owasp.org/www-project-web-security-testing-guide/latest/"
                                "4-Web_Application_Security_TestING/01-Information_"  # pragma: allowlist secret
                                "Gathering/"
                            ),
                        ],
                    }
                ],
            }
        return None


class ThirdPartyScriptIntegrityRule(ContentSecurityRule):
    """Check for third-party scripts without integrity checks."""

    def __init__(self):
        super().__init__("CONTENT-3P-001", "third_party_security", "medium")

    def evaluate(self, content_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        third_party = content_result.get("third_party_resources", [])
        scripts_without_sri = []

        for resource in third_party:
            if resource.get("resource_type") == "script" and not resource.get("has_integrity"):
                scripts_without_sri.append(
                    {
                        "domain": resource.get("domain"),
                        "url": resource.get("url", "")[:100],
                    }
                )

        if len(scripts_without_sri) > 0:
            severity = "high" if len(scripts_without_sri) > 3 else self.severity

            return {
                "category": self.category,
                "severity": severity,
                "title": f"Third-Party Scripts Without Integrity Verification ({len(scripts_without_sri)} scripts)",
                "description": (
                    f"The website loads {len(scripts_without_sri)} external JavaScript files without "
                    "Subresource Integrity (SRI) verification. If a CDN or third-party host is "
                    "compromised, attackers could inject malicious code that would execute on your site, "
                    "affecting all visitors."
                ),
                "evidence": {
                    "url": content_result.get("url"),
                    "scripts_without_sri": scripts_without_sri[:10],
                    "domains_affected": list({s.get("domain") for s in scripts_without_sri}),
                },
                "recommendations": [
                    {
                        "title": "Implement Subresource Integrity (SRI)",
                        "description": "Add integrity attributes to all external scripts and stylesheets.",
                        "priority": "high",
                        "effort": "medium",
                        "steps": [
                            "Generate SRI hashes for each external resource:",
                            "  openssl dgst -sha384 -binary file.js | openssl base64 -A",
                            "Or use: https://www.srihash.org/",
                            "",
                            "Add integrity and crossorigin attributes:",
                            '  <script src="https://cdn.example.com/lib.js"',
                            '          integrity="sha384-hash..."',
                            '          crossorigin="anonymous"></script>',
                            "",
                            "For CSS files, use the same approach",
                            "Update SRI hashes when libraries are updated",
                            "Consider self-hosting critical third-party scripts",
                            "Implement CSP with require-sri-for directive",
                        ],
                        "references": [
                            "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                            "https://www.w3.org/TR/SRI/",
                        ],
                    }
                ],
            }
        return None


class ExcessiveTrackingRule(ContentSecurityRule):
    """Check for excessive tracking scripts."""

    def __init__(self):
        super().__init__("CONTENT-3P-002", "third_party_security", "low")

    def evaluate(self, content_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        third_party = content_result.get("third_party_resources", [])
        tracking_resources = [r for r in third_party if r.get("is_tracking")]

        if len(tracking_resources) > 3:
            domains = list({r.get("domain") for r in tracking_resources})

            return {
                "category": self.category,
                "severity": "low",
                "title": f"Multiple Tracking Services Detected ({len(tracking_resources)} trackers)",
                "description": (
                    f"The website loads resources from {len(tracking_resources)} tracking/analytics services "
                    f"across {len(domains)} domains. While tracking is common, excessive tracking can: "
                    "impact page performance, raise privacy concerns, increase attack surface through "
                    "third-party code, and may require explicit consent under privacy regulations."
                ),
                "evidence": {
                    "url": content_result.get("url"),
                    "tracking_count": len(tracking_resources),
                    "tracking_domains": domains,
                },
                "recommendations": [
                    {
                        "title": "Audit and Minimize Tracking",
                        "description": "Review tracking services and minimize unnecessary data collection.",
                        "priority": "low",
                        "effort": "medium",
                        "steps": [
                            "Audit all tracking scripts and document their purpose",
                            "Remove tracking services that are not actively used",
                            "Consider privacy-focused alternatives (Plausible, Fathom)",
                            "Implement proper cookie consent mechanisms (GDPR/CCPA)",
                            "Use tag management to control tracking script loading",
                            "Implement Content Security Policy to control third-party scripts",
                            "Consider server-side analytics for privacy-sensitive data",
                            "Document data flows for privacy compliance",
                        ],
                        "references": [
                            "https://gdpr.eu/cookies/",
                            "https://www.privacypolicies.com/blog/gdpr-tracking-scripts/",
                        ],
                    }
                ],
            }
        return None


class MixedContentRule(ContentSecurityRule):
    """Check for mixed content issues."""

    def __init__(self):
        super().__init__("CONTENT-MIX-001", "mixed_content", "high")

    def evaluate(self, content_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if content_result.get("has_mixed_content"):
            return {
                "category": self.category,
                "severity": self.severity,
                "title": "Mixed Content Detected",
                "description": (
                    "The HTTPS page loads resources over insecure HTTP connections. "
                    "Mixed content weakens the security of HTTPS by allowing attackers to "
                    "intercept and modify insecure resources. Modern browsers may block mixed "
                    "content entirely, breaking page functionality."
                ),
                "evidence": {
                    "url": content_result.get("url"),
                    "has_mixed_content": True,
                },
                "recommendations": [
                    {
                        "title": "Eliminate Mixed Content",
                        "description": "Ensure all resources are loaded over HTTPS.",
                        "priority": "high",
                        "effort": "medium",
                        "steps": [
                            "Use browser DevTools Console to identify mixed content warnings",
                            "Update all resource URLs from http:// to https://",
                            "Use protocol-relative URLs (//example.com) where appropriate",
                            "Update Content-Security-Policy: upgrade-insecure-requests",
                            "Ensure all third-party services support HTTPS",
                            "Check embedded iframes for mixed content",
                            "Update hardcoded URLs in JavaScript and CSS",
                            "Test thoroughly after changes",
                        ],
                        "references": [
                            "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
                            (
                                "https://developers.google.com/web/fundamentals/security/prevent-mixed-content/"
                                "what-is-mixed-content"
                            ),
                        ],
                    }
                ],
            }
        return None


class InsecureIframeRule(ContentSecurityRule):
    """Check for iframes without sandbox attribute."""

    def __init__(self):
        super().__init__("CONTENT-IFRAME-001", "iframe_security", "medium")

    def evaluate(self, content_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        iframes = content_result.get("iframes", [])
        external_unsandboxed = []

        for iframe in iframes:
            if iframe.get("is_external") and not iframe.get("sandbox"):
                external_unsandboxed.append(
                    {
                        "src": iframe.get("src", "")[:100],
                    }
                )

        if external_unsandboxed:
            return {
                "category": self.category,
                "severity": self.severity,
                "title": f"External Iframes Without Sandbox ({len(external_unsandboxed)} found)",
                "description": (
                    f"The page contains {len(external_unsandboxed)} external iframes without sandbox "
                    "restrictions. Unsandboxed iframes from external sources can access the parent "
                    "page's DOM, navigate the top-level browsing context, and potentially execute "
                    "malicious scripts with full privileges."
                ),
                "evidence": {
                    "url": content_result.get("url"),
                    "unsandboxed_iframes": external_unsandboxed,
                },
                "recommendations": [
                    {
                        "title": "Sandbox External Iframes",
                        "description": "Apply sandbox attribute to restrict iframe capabilities.",
                        "priority": "medium",
                        "effort": "low",
                        "steps": [
                            "Add sandbox attribute to external iframes:",
                            '  <iframe src="..." sandbox="allow-scripts allow-same-origin">',
                            "",
                            "Common sandbox permissions:",
                            "- allow-scripts: Allow JavaScript execution",
                            "- allow-same-origin: Treat content as same origin",
                            "- allow-forms: Allow form submission",
                            "- allow-popups: Allow popups",
                            "",
                            "Start with empty sandbox and add only required permissions",
                            "Avoid allow-same-origin with allow-scripts for untrusted content",
                            "Consider using CSP frame-ancestors on the embedded page",
                            "Use X-Frame-Options on your pages to prevent framing",
                        ],
                        "references": [
                            "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#attr-sandbox",
                            "https://www.html5rocks.com/en/tutorials/security/sandboxed-iframes/",
                        ],
                    }
                ],
            }
        return None


class TechnologyDisclosureRule(ContentSecurityRule):
    """Check for technology/framework disclosure."""

    def __init__(self):
        super().__init__("CONTENT-TECH-001", "information_disclosure", "low")

    def evaluate(self, content_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        technologies = content_result.get("detected_technologies", [])
        meta_tags = content_result.get("meta_tags", {})

        disclosed = []

        # Check generator meta tag
        if meta_tags and meta_tags.get("generator"):
            disclosed.append(
                {
                    "technology": meta_tags.get("generator"),
                    "source": "meta generator tag",
                    "confidence": "confirmed",
                }
            )

        # Check high-confidence detections
        for tech in technologies:
            if tech.get("confidence") in ["confirmed", "high"]:
                disclosed.append(
                    {
                        "technology": tech.get("name"),
                        "source": tech.get("source", "content analysis"),
                        "confidence": tech.get("confidence"),
                    }
                )

        if len(disclosed) > 2:
            return {
                "category": self.category,
                "severity": "low",
                "title": f"Technology Stack Disclosure ({len(disclosed)} technologies)",
                "description": (
                    "The website reveals multiple technologies and frameworks in use. "
                    "While not immediately exploitable, this information helps attackers profile "
                    "the stack to identify known vulnerabilities in specific versions."
                ),
                "evidence": {
                    "url": content_result.get("url"),
                    "technologies": disclosed,
                },
                "recommendations": [
                    {
                        "title": "Minimize Technology Disclosure",
                        "description": "Reduce the amount of technology information exposed.",
                        "priority": "low",
                        "effort": "low",
                        "steps": [
                            "Remove generator meta tags",
                            "Anonymize or remove version information",
                            "Use generic error pages that don't reveal technology",
                            "Configure frameworks to minimize fingerprinting",
                            "Keep all components updated regardless of disclosure",
                            "The primary defense is keeping software updated, not hiding versions",
                        ],
                        "references": [
                            "https://owasp.org/www-project-web-security-testing-guide/fingerprint-web-server",
                        ],
                    }
                ],
            }
        return None


class ContentSecurityAnalyzer:
    """
    Analyzer that runs all content security rules against scan results.
    """

    SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3}
    MATURITY_THRESHOLDS = {"optimized": 15, "managed": 35, "basic": 55, "reactive": 100}

    def __init__(self):
        self.rules = self._load_rules()

    def _load_rules(self) -> List[ContentSecurityRule]:
        """Load all content security rules."""
        return [
            DangerousJavaScriptRule(),
            InlineEventHandlersRule(),
            HardcodedSecretsRule(),
            InsecureFormRule(),
            MissingCSRFTokenRule(),
            APIKeyExposureRule(),
            PrivateKeyExposureRule(),
            SensitiveDataExposureRule(),
            ThirdPartyScriptIntegrityRule(),
            ExcessiveTrackingRule(),
            MixedContentRule(),
            InsecureIframeRule(),
            TechnologyDisclosureRule(),
        ]

    def analyze(self, content_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run all content security rules and calculate risk score.

        Args:
            content_result: Dictionary from ContentScanResult.to_dict()

        Returns:
            Dict with findings, risk_score, maturity_level, and score_breakdown
        """
        if not content_result:
            return {
                "findings": [],
                "risk_score": 0,
                "maturity_level": "optimized",
                "score_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            }

        findings = []
        score_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for rule in self.rules:
            try:
                result = rule.evaluate(content_result)
                if result:
                    findings.append(result)
                    score_breakdown[result["severity"]] += 1
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.rule_id}: {str(e)}")

        risk_score = self._calculate_risk_score(score_breakdown)
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
