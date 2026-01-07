"""
Security Analysis Engine for SecureSys Auditor.

This module provides rule-based security analysis of scan payloads
to identify vulnerabilities and calculate risk scores.

Features:
- Rule-based vulnerability detection
- Security Maturity Model (Levels 1-4)
- NIST CSF and ISO 27001 control mapping
- Risk scoring with weighted severity
"""
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List

logger = logging.getLogger("core")


class MaturityLevel(Enum):
    """Security Maturity Model Levels (1-4)."""

    INITIAL = 1  # Ad hoc, reactive security
    DEVELOPING = 2  # Basic security practices emerging
    DEFINED = 3  # Documented and standardized processes
    MANAGED = 4  # Optimized and continuously improved


@dataclass
class ControlMapping:
    """NIST/ISO control mapping for a finding category."""

    nist_id: str
    nist_function: str  # Identify, Protect, Detect, Respond, Recover
    nist_category: str
    iso_control: str
    description: str


# Comprehensive NIST CSF and ISO 27001 Control Mappings
CONTROL_MAPPINGS = {
    "access_control": ControlMapping(
        nist_id="PR.AC",
        nist_function="Protect",
        nist_category="Identity Management and Access Control",
        iso_control="A.9 Access Control",
        description="Limit access to authorized users, processes, and devices",
    ),
    "authentication": ControlMapping(
        nist_id="PR.AC-1",
        nist_function="Protect",
        nist_category="Identities and Credentials Management",
        iso_control="A.9.2 User Access Management",
        description="Identities and credentials are managed and verified",
    ),
    "network": ControlMapping(
        nist_id="PR.AC-5",
        nist_function="Protect",
        nist_category="Network Integrity",
        iso_control="A.13.1 Network Security Management",
        description="Network integrity is protected with segregation",
    ),
    "patch_management": ControlMapping(
        nist_id="ID.RA-1",
        nist_function="Identify",
        nist_category="Risk Assessment",
        iso_control="A.12.6 Technical Vulnerability Management",
        description="Asset vulnerabilities are identified and documented",
    ),
    "configuration": ControlMapping(
        nist_id="PR.IP-1",
        nist_function="Protect",
        nist_category="Security Configuration",
        iso_control="A.12.5 Control of Operational Software",
        description="Baseline configuration is established and maintained",
    ),
    "encryption": ControlMapping(
        nist_id="PR.DS-1",
        nist_function="Protect",
        nist_category="Data Security",
        iso_control="A.10 Cryptography",
        description="Data at rest and in transit is protected",
    ),
    "logging": ControlMapping(
        nist_id="DE.CM-3",
        nist_function="Detect",
        nist_category="Security Continuous Monitoring",
        iso_control="A.12.4 Logging and Monitoring",
        description="Personnel activity is monitored for security events",
    ),
    "backup": ControlMapping(
        nist_id="PR.IP-4",
        nist_function="Protect",
        nist_category="Information Protection Processes",
        iso_control="A.12.3 Information Backup",
        description="Backups are conducted and tested",
    ),
    "incident_response": ControlMapping(
        nist_id="RS.RP-1",
        nist_function="Respond",
        nist_category="Response Planning",
        iso_control="A.16 Information Security Incident Management",
        description="Response plan is executed during incidents",
    ),
    "asset_management": ControlMapping(
        nist_id="ID.AM-1",
        nist_function="Identify",
        nist_category="Asset Management",
        iso_control="A.8 Asset Management",
        description="Physical devices and systems are inventoried",
    ),
}


class SecurityRule:
    """Base class for security rules."""

    def __init__(self, rule_id: str, category: str, severity: str):
        self.rule_id = rule_id
        self.category = category
        self.severity = severity

    def evaluate(self, payload: Dict) -> Dict | None:
        """
        Evaluate the rule against the payload.
        Returns finding dict if rule triggers, None otherwise.
        """
        raise NotImplementedError


class RootSSHRule(SecurityRule):
    """Check for root SSH login enabled."""

    def __init__(self):
        super().__init__("SSH-001", "access_control", "high")

    def evaluate(self, payload: Dict) -> Dict | None:
        ssh_config = payload.get("ssh_config", {})
        if ssh_config.get("permit_root_login", False):
            return {
                "category": self.category,
                "severity": self.severity,
                "title": "Root SSH Login Enabled",
                "description": "SSH configuration allows direct root login, which is a security risk.",
                "evidence": {"config_file": "/etc/ssh/sshd_config", "setting": "PermitRootLogin yes"},
                "recommendations": [
                    {
                        "title": "Disable Root SSH Login",
                        "description": "Disable direct root login via SSH to improve security.",
                        "priority": "high",
                        "effort": "low",
                        "steps": [
                            "Edit /etc/ssh/sshd_config",
                            "Set PermitRootLogin to no",
                            "Restart SSH service: systemctl restart sshd",
                        ],
                    }
                ],
            }
        return None


class FirewallDisabledRule(SecurityRule):
    """Check if firewall is disabled."""

    def __init__(self):
        super().__init__("FW-001", "network", "critical")

    def evaluate(self, payload: Dict) -> Dict | None:
        firewall = payload.get("firewall", {})
        if not firewall.get("enabled", True):
            return {
                "category": self.category,
                "severity": self.severity,
                "title": "Firewall Disabled",
                "description": "System firewall is disabled, leaving the system exposed to network attacks.",
                "evidence": {"firewall_status": "disabled"},
                "recommendations": [
                    {
                        "title": "Enable System Firewall",
                        "description": "Enable and configure the system firewall.",
                        "priority": "critical",
                        "effort": "medium",
                        "steps": [
                            "Enable firewall: ufw enable (Ubuntu) or firewall-cmd --state (CentOS)",
                            "Configure default deny incoming: ufw default deny incoming",
                            "Allow required services: ufw allow ssh",
                            "Verify status: ufw status verbose",
                        ],
                    }
                ],
            }
        return None


class OutdatedPackagesRule(SecurityRule):
    """Check for outdated packages with known vulnerabilities."""

    def __init__(self):
        super().__init__("PKG-001", "patch_management", "medium")

    def evaluate(self, payload: Dict) -> Dict | None:
        packages = payload.get("packages", {})
        outdated = packages.get("outdated", [])

        if outdated:
            return {
                "category": self.category,
                "severity": "high" if len(outdated) > 10 else self.severity,
                "title": f"{len(outdated)} Outdated Packages Found",
                "description": f"System has {len(outdated)} packages that need updates.",
                "evidence": {"outdated_packages": outdated[:20]},  # Limit to first 20
                "recommendations": [
                    {
                        "title": "Update System Packages",
                        "description": "Update all outdated packages to their latest versions.",
                        "priority": "high" if len(outdated) > 10 else "medium",
                        "effort": "medium",
                        "steps": [
                            "Backup current system state",
                            "Update package lists: apt update (Debian) or yum check-update (RHEL)",
                            "Upgrade packages: apt upgrade -y or yum update -y",
                            "Reboot if kernel was updated",
                        ],
                    }
                ],
            }
        return None


class WeakPasswordPolicyRule(SecurityRule):
    """Check for weak password policy."""

    def __init__(self):
        super().__init__("AUTH-001", "authentication", "high")

    def evaluate(self, payload: Dict) -> Dict | None:
        password_policy = payload.get("password_policy", {})

        issues = []
        if password_policy.get("min_length", 0) < 12:
            issues.append("Minimum password length is less than 12 characters")
        if not password_policy.get("require_special", True):
            issues.append("Special characters not required")
        if not password_policy.get("require_numbers", True):
            issues.append("Numbers not required")

        if issues:
            return {
                "category": self.category,
                "severity": self.severity,
                "title": "Weak Password Policy",
                "description": "Password policy does not meet security best practices.",
                "evidence": {"issues": issues, "current_policy": password_policy},
                "recommendations": [
                    {
                        "title": "Strengthen Password Policy",
                        "description": "Configure a stronger password policy.",
                        "priority": "high",
                        "effort": "low",
                        "steps": [
                            "Edit /etc/security/pwquality.conf",
                            "Set minlen = 12",
                            "Set minclass = 4",
                            "Enable password history checks",
                        ],
                    }
                ],
            }
        return None


class AdminUsersRule(SecurityRule):
    """Check for excessive admin/sudo users."""

    def __init__(self):
        super().__init__("ACC-001", "access_control", "medium")

    def evaluate(self, payload: Dict) -> Dict | None:
        users = payload.get("users", {})
        admin_users = users.get("admin_users", [])

        if len(admin_users) > 3:
            return {
                "category": self.category,
                "severity": self.severity,
                "title": "Excessive Administrative Users",
                "description": f"System has {len(admin_users)} users with administrative privileges.",
                "evidence": {"admin_users": admin_users, "count": len(admin_users)},
                "recommendations": [
                    {
                        "title": "Review Administrative Access",
                        "description": "Review and reduce the number of administrative users.",
                        "priority": "medium",
                        "effort": "low",
                        "steps": [
                            "Review list of sudo/admin users",
                            "Remove unnecessary admin privileges",
                            "Implement principle of least privilege",
                            "Document admin access requirements",
                        ],
                    }
                ],
            }
        return None


class OpenPortsRule(SecurityRule):
    """Check for unnecessary open ports."""

    def __init__(self):
        super().__init__("NET-001", "network", "medium")

    def evaluate(self, payload: Dict) -> Dict | None:
        network = payload.get("network", {})
        open_ports = network.get("open_ports", [])

        # Define commonly risky ports
        risky_ports = {21: "FTP", 23: "Telnet", 25: "SMTP", 3389: "RDP", 5900: "VNC"}
        found_risky = []

        for port in open_ports:
            port_num = port.get("port") if isinstance(port, dict) else port
            if port_num in risky_ports:
                found_risky.append({"port": port_num, "service": risky_ports[port_num]})

        if found_risky:
            return {
                "category": self.category,
                "severity": "high" if any(p["port"] == 23 for p in found_risky) else self.severity,
                "title": "Potentially Risky Ports Open",
                "description": f"Found {len(found_risky)} potentially risky open ports.",
                "evidence": {"risky_ports": found_risky, "all_open_ports": open_ports[:20]},
                "recommendations": [
                    {
                        "title": "Review Open Ports",
                        "description": "Close unnecessary ports and secure required services.",
                        "priority": "high",
                        "effort": "medium",
                        "steps": [
                            "Identify services bound to risky ports",
                            "Disable unnecessary services",
                            "Use firewall to restrict access",
                            "Consider using secure alternatives (SSH instead of Telnet)",
                        ],
                    }
                ],
            }
        return None


class SecurityAnalyzer:
    """
    Main security analyzer that processes scan payloads.
    """

    # Risk weights by severity
    SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3}

    # Maturity level thresholds (lower score = more mature)
    MATURITY_THRESHOLDS = {"optimized": 20, "managed": 40, "basic": 60, "reactive": 100}

    def __init__(self, payload: Dict):
        self.payload = payload
        self.rules = self._load_rules()

    def _load_rules(self) -> List[SecurityRule]:
        """Load all security rules."""
        return [
            RootSSHRule(),
            FirewallDisabledRule(),
            OutdatedPackagesRule(),
            WeakPasswordPolicyRule(),
            AdminUsersRule(),
            OpenPortsRule(),
        ]

    def analyze(self) -> Dict[str, Any]:
        """
        Run all security rules and calculate risk score.

        Returns:
            Dict with findings, risk_score, maturity_level, and score_breakdown
        """
        # If there's no scan data at all, do not emit findings.
        # This keeps analysis resilient to partial/empty agent payloads.
        if not self.payload:
            score_breakdown = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }
            return {
                "findings": [],
                "risk_score": 0,
                "maturity_level": self._determine_maturity(0),
                "score_breakdown": score_breakdown,
            }

        findings = []
        score_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        # Evaluate all rules
        for rule in self.rules:
            try:
                result = rule.evaluate(self.payload)
                if result:
                    findings.append(result)
                    score_breakdown[result["severity"]] += 1
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.rule_id}: {str(e)}")

        # Calculate risk score (0-100, higher = more risk)
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

        # Normalize to 0-100 scale
        return min(100, score)

    def _determine_maturity(self, risk_score: int) -> str:
        """Determine security maturity level based on risk score."""
        for level, threshold in self.MATURITY_THRESHOLDS.items():
            if risk_score <= threshold:
                return level
        return "reactive"


class EnhancedSecurityAnalyzer(SecurityAnalyzer):
    """
    Enhanced security analyzer with Security Maturity Model support.

    Provides:
    - Detailed maturity assessment (Levels 1-4)
    - NIST CSF function scoring
    - Domain-specific maturity scoring
    - Control gap identification
    - Improvement roadmap generation
    """

    # Domain weights for maturity calculation
    DOMAIN_WEIGHTS = {
        "identity_access": 0.15,
        "asset_management": 0.10,
        "data_security": 0.15,
        "vulnerability_mgmt": 0.15,
        "configuration_mgmt": 0.10,
        "incident_response": 0.10,
        "monitoring_logging": 0.15,
        "network_security": 0.10,
    }

    # Category to domain mapping
    CATEGORY_TO_DOMAIN = {
        "access_control": "identity_access",
        "authentication": "identity_access",
        "network": "network_security",
        "patch_management": "vulnerability_mgmt",
        "configuration": "configuration_mgmt",
        "encryption": "data_security",
        "logging": "monitoring_logging",
        "backup": "data_security",
        "incident_response": "incident_response",
        "asset_management": "asset_management",
        "other": "configuration_mgmt",
    }

    # Category to NIST CSF function mapping
    CATEGORY_TO_NIST_FUNCTION = {
        "access_control": "protect",
        "authentication": "protect",
        "network": "protect",
        "patch_management": "identify",
        "configuration": "protect",
        "encryption": "protect",
        "logging": "detect",
        "backup": "recover",
        "incident_response": "respond",
        "asset_management": "identify",
        "other": "protect",
    }

    def __init__(self, payload: Dict):
        super().__init__(payload)
        self.control_mappings = CONTROL_MAPPINGS

    def analyze_with_maturity(self) -> Dict[str, Any]:
        """
        Perform comprehensive analysis including maturity assessment.

        Returns:
            Dict with findings, risk_score, maturity assessment, and control gaps
        """
        # Get base analysis results
        base_result = self.analyze()

        # Calculate domain scores
        domain_scores = self._calculate_domain_scores(base_result["findings"])

        # Calculate NIST CSF function scores
        nist_scores = self._calculate_nist_scores(base_result["findings"])

        # Determine overall maturity level (1-4)
        overall_maturity = self._calculate_overall_maturity(domain_scores)

        # Identify control gaps
        control_gaps = self._identify_control_gaps(base_result["findings"])

        # Generate improvement roadmap
        roadmap = self._generate_improvement_roadmap(domain_scores, nist_scores, base_result["findings"])

        return {
            **base_result,
            "maturity_assessment": {
                "overall_level": overall_maturity,
                "overall_label": self._get_maturity_label(overall_maturity),
                "domain_scores": domain_scores,
                "nist_csf_scores": nist_scores,
            },
            "control_gaps": control_gaps,
            "improvement_roadmap": roadmap,
            "compliance_mapping": self._map_findings_to_controls(base_result["findings"]),
        }

    def _calculate_domain_scores(self, findings: List[Dict]) -> Dict[str, int]:
        """Calculate maturity scores for each security domain."""
        # Start with maximum score (4) and deduct based on findings
        domain_scores = dict.fromkeys(self.DOMAIN_WEIGHTS, 4)

        # Deduction per severity
        severity_deductions = {"critical": 2, "high": 1.5, "medium": 0.75, "low": 0.25}

        for finding in findings:
            category = finding.get("category", "other")
            domain = self.CATEGORY_TO_DOMAIN.get(category, "configuration_mgmt")
            severity = finding.get("severity", "medium")

            deduction = severity_deductions.get(severity, 0.5)
            domain_scores[domain] = max(1, domain_scores[domain] - deduction)

        # Round scores to integers
        return {domain: max(1, min(4, round(score))) for domain, score in domain_scores.items()}

    def _calculate_nist_scores(self, findings: List[Dict]) -> Dict[str, int]:
        """Calculate NIST CSF function scores."""
        # Start with maximum score (4)
        nist_scores = {
            "identify": 4,
            "protect": 4,
            "detect": 4,
            "respond": 4,
            "recover": 4,
        }

        severity_deductions = {"critical": 1.5, "high": 1.0, "medium": 0.5, "low": 0.2}

        for finding in findings:
            category = finding.get("category", "other")
            nist_function = self.CATEGORY_TO_NIST_FUNCTION.get(category, "protect")
            severity = finding.get("severity", "medium")

            deduction = severity_deductions.get(severity, 0.3)
            nist_scores[nist_function] = max(1, nist_scores[nist_function] - deduction)

        return {func: max(1, min(4, round(score))) for func, score in nist_scores.items()}

    def _calculate_overall_maturity(self, domain_scores: Dict[str, int]) -> int:
        """Calculate weighted overall maturity level."""
        weighted_sum = sum(domain_scores[domain] * weight for domain, weight in self.DOMAIN_WEIGHTS.items())
        return max(1, min(4, round(weighted_sum)))

    def _get_maturity_label(self, level: int) -> str:
        """Get descriptive label for maturity level."""
        labels = {
            1: "Initial/Ad Hoc",
            2: "Developing",
            3: "Defined",
            4: "Managed/Optimized",
        }
        return labels.get(level, "Unknown")

    def _identify_control_gaps(self, findings: List[Dict]) -> List[Dict]:
        """Identify control gaps based on findings."""
        gaps = []
        affected_controls = set()

        for finding in findings:
            category = finding.get("category", "other")
            if category in self.control_mappings:
                mapping = self.control_mappings[category]

                if mapping.nist_id not in affected_controls:
                    affected_controls.add(mapping.nist_id)
                    gaps.append(
                        {
                            "control_id": mapping.nist_id,
                            "nist_function": mapping.nist_function,
                            "nist_category": mapping.nist_category,
                            "iso_control": mapping.iso_control,
                            "description": mapping.description,
                            "finding_count": sum(1 for f in findings if f.get("category") == category),
                            "highest_severity": max(
                                (f.get("severity", "low") for f in findings if f.get("category") == category),
                                key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0),
                            ),
                        }
                    )

        return sorted(
            gaps, key=lambda g: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(g["highest_severity"], 4)
        )

    def _generate_improvement_roadmap(
        self, domain_scores: Dict[str, int], nist_scores: Dict[str, int], findings: List[Dict]
    ) -> List[Dict]:
        """Generate prioritized improvement roadmap."""
        roadmap = []

        # Identify lowest scoring domains
        low_domains = [(domain, score) for domain, score in domain_scores.items() if score < 3]
        low_domains.sort(key=lambda x: x[1])

        # Priority 1: Critical findings
        critical_findings = [f for f in findings if f.get("severity") == "critical"]
        if critical_findings:
            roadmap.append(
                {
                    "priority": 1,
                    "phase": "Immediate (0-30 days)",
                    "title": "Address Critical Vulnerabilities",
                    "description": f"Remediate {len(critical_findings)} critical severity findings",
                    "effort": "High",
                    "impact": "Critical risk reduction",
                    "domains_improved": list(
                        {self.CATEGORY_TO_DOMAIN.get(f.get("category", "other"), "other") for f in critical_findings}
                    ),
                }
            )

        # Priority 2: High findings
        high_findings = [f for f in findings if f.get("severity") == "high"]
        if high_findings:
            roadmap.append(
                {
                    "priority": 2,
                    "phase": "Short-term (30-90 days)",
                    "title": "Remediate High-Risk Issues",
                    "description": f"Address {len(high_findings)} high severity findings",
                    "effort": "Medium-High",
                    "impact": "Significant risk reduction",
                    "domains_improved": list(
                        {self.CATEGORY_TO_DOMAIN.get(f.get("category", "other"), "other") for f in high_findings}
                    ),
                }
            )

        # Priority 3: Domain improvements
        for domain, score in low_domains[:3]:  # Top 3 lowest domains
            domain_name = domain.replace("_", " ").title()
            roadmap.append(
                {
                    "priority": 3,
                    "phase": "Medium-term (90-180 days)",
                    "title": f"Improve {domain_name} Capabilities",
                    "description": f"Enhance {domain_name} from Level {score} to Level {min(4, score + 1)}",
                    "effort": "Medium",
                    "impact": "Domain maturity improvement",
                    "target_level": min(4, score + 1),
                    "current_level": score,
                }
            )

        # Priority 4: NIST function improvements
        low_nist = [(func, score) for func, score in nist_scores.items() if score < 3]
        for func, score in low_nist:
            func_name = func.title()
            roadmap.append(
                {
                    "priority": 4,
                    "phase": "Long-term (180+ days)",
                    "title": f"Strengthen NIST {func_name} Capabilities",
                    "description": f"Improve {func_name} function from Level {score} to Level {min(4, score + 1)}",
                    "effort": "Medium-High",
                    "impact": "Framework alignment",
                    "nist_function": func,
                }
            )

        return roadmap

    def _map_findings_to_controls(self, findings: List[Dict]) -> List[Dict]:
        """Map each finding to its control framework references."""
        mapped_findings = []

        for finding in findings:
            category = finding.get("category", "other")
            mapping = self.control_mappings.get(category)

            mapped_finding = {
                **finding,
                "nist_control": {
                    "id": mapping.nist_id if mapping else "N/A",
                    "function": mapping.nist_function if mapping else "N/A",
                    "category": mapping.nist_category if mapping else "N/A",
                },
                "iso_control": mapping.iso_control if mapping else "N/A",
            }
            mapped_findings.append(mapped_finding)

        return mapped_findings
