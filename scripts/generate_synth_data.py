#!/usr/bin/env python3
"""
Synthetic Data Generator for SecureSys Auditor

This script generates comprehensive synthetic data for exploring and testing
all features of the SecureSys Auditor application.

Usage:
    python scripts/generate_synth_data.py

    # With custom settings:
    python scripts/generate_synth_data.py --num-systems 10 --num-scans 50

    # Using Django management command (alternative):
    python src/backend/manage.py shell < scripts/generate_synth_data.py
"""

import os
import sys
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path

# Add the backend directory to path for Django imports
backend_dir = Path(__file__).resolve().parent.parent / "src" / "backend"
sys.path.insert(0, str(backend_dir))

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.settings")

import django
django.setup()

# Now import Django models
from django.utils import timezone
from django.contrib.auth import get_user_model
from scanning.models import System, Scan, Finding, Recommendation

User = get_user_model()

# =============================================================================
# Data Pools for Synthetic Generation
# =============================================================================

HOSTNAMES = [
    "web-server-prod-{}", "api-gateway-{}", "database-master-{}", "database-replica-{}",
    "cache-server-{}", "load-balancer-{}", "monitoring-server-{}", "ci-cd-runner-{}",
    "file-storage-{}", "auth-server-{}", "email-server-{}", "backup-server-{}",
    "logging-server-{}", "analytics-server-{}", "worker-node-{}", "scheduler-{}",
    "proxy-server-{}", "vpn-gateway-{}", "dns-server-{}", "container-host-{}"
]

OPERATING_SYSTEMS = [
    ("Ubuntu Server", ["20.04 LTS", "22.04 LTS", "24.04 LTS"]),
    ("CentOS Stream", ["8", "9"]),
    ("Rocky Linux", ["8.9", "9.3"]),
    ("Debian", ["11 Bullseye", "12 Bookworm"]),
    ("Windows Server", ["2019", "2022"]),
    ("Amazon Linux", ["2", "2023"]),
    ("Red Hat Enterprise Linux", ["8.9", "9.3"]),
]

ENVIRONMENTS = ["development", "staging", "production", "testing"]

IP_PREFIXES = [
    "10.0.1.", "10.0.2.", "10.0.3.", "192.168.1.", "192.168.10.", 
    "172.16.0.", "172.16.1.", "172.17.0."
]

SCAN_TYPES = ["full", "quick", "compliance", "vulnerability"]

# Finding data for realistic security issues
FINDING_TEMPLATES = {
    "critical": [
        {
            "title": "Remote Code Execution Vulnerability (CVE-2024-1234)",
            "description": "A critical remote code execution vulnerability was found in the Apache Struts framework. An attacker can execute arbitrary code remotely without authentication.",
            "category": "patch_management",
            "cwe_id": "CWE-94",
            "cvss_score": 9.8,
        },
        {
            "title": "SQL Injection in Authentication Module",
            "description": "The login endpoint is vulnerable to SQL injection attacks, allowing attackers to bypass authentication and access sensitive data.",
            "category": "authentication",
            "cwe_id": "CWE-89",
            "cvss_score": 9.1,
        },
        {
            "title": "Hardcoded Credentials in Configuration",
            "description": "Database credentials are hardcoded in the application configuration files with world-readable permissions.",
            "category": "configuration",
            "cwe_id": "CWE-798",
            "cvss_score": 9.0,
        },
        {
            "title": "Unauthenticated Admin Panel Access",
            "description": "The administrative panel is accessible without authentication due to misconfigured access controls.",
            "category": "access_control",
            "cwe_id": "CWE-306",
            "cvss_score": 9.5,
        },
    ],
    "high": [
        {
            "title": "Outdated OpenSSL Library (CVE-2024-0567)",
            "description": "The system is running OpenSSL 1.0.2 which contains multiple known high-severity vulnerabilities including buffer overflows.",
            "category": "patch_management",
            "cwe_id": "CWE-327",
            "cvss_score": 8.1,
        },
        {
            "title": "SSH Root Login Enabled",
            "description": "SSH is configured to allow direct root login, which increases the risk of brute-force attacks gaining full system access.",
            "category": "configuration",
            "cwe_id": "CWE-250",
            "cvss_score": 7.5,
        },
        {
            "title": "Missing HTTP Security Headers",
            "description": "Critical security headers (CSP, X-Frame-Options, HSTS) are not configured, leaving the application vulnerable to XSS and clickjacking.",
            "category": "configuration",
            "cwe_id": "CWE-693",
            "cvss_score": 7.2,
        },
        {
            "title": "Weak Password Policy",
            "description": "The password policy allows passwords shorter than 8 characters without complexity requirements.",
            "category": "authentication",
            "cwe_id": "CWE-521",
            "cvss_score": 7.8,
        },
        {
            "title": "Exposed Debug Endpoints",
            "description": "Debug endpoints are accessible in production, exposing internal application state and potential attack vectors.",
            "category": "configuration",
            "cwe_id": "CWE-489",
            "cvss_score": 8.2,
        },
    ],
    "medium": [
        {
            "title": "TLS 1.0/1.1 Supported",
            "description": "The server supports deprecated TLS 1.0 and TLS 1.1 protocols which have known security weaknesses.",
            "category": "encryption",
            "cwe_id": "CWE-326",
            "cvss_score": 5.3,
        },
        {
            "title": "Insufficient Logging Configuration",
            "description": "Security-relevant events are not being logged, making incident investigation and forensics difficult.",
            "category": "logging",
            "cwe_id": "CWE-778",
            "cvss_score": 5.1,
        },
        {
            "title": "Missing Brute-Force Protection",
            "description": "No rate limiting or account lockout mechanism is in place to prevent brute-force attacks on login endpoints.",
            "category": "authentication",
            "cwe_id": "CWE-307",
            "cvss_score": 6.5,
        },
        {
            "title": "Session Timeout Too Long",
            "description": "User sessions do not expire for 24 hours, increasing the window for session hijacking attacks.",
            "category": "authentication",
            "cwe_id": "CWE-613",
            "cvss_score": 5.4,
        },
        {
            "title": "Unencrypted Database Connections",
            "description": "Database connections are not using SSL/TLS encryption, exposing sensitive data in transit.",
            "category": "encryption",
            "cwe_id": "CWE-319",
            "cvss_score": 6.1,
        },
        {
            "title": "Missing File Integrity Monitoring",
            "description": "No file integrity monitoring is configured on critical system files and configuration directories.",
            "category": "configuration",
            "cwe_id": "CWE-693",
            "cvss_score": 5.5,
        },
    ],
    "low": [
        {
            "title": "Information Disclosure in Error Messages",
            "description": "Detailed error messages expose internal paths and stack traces to users.",
            "category": "configuration",
            "cwe_id": "CWE-209",
            "cvss_score": 3.1,
        },
        {
            "title": "Banner Grabbing Vulnerability",
            "description": "Server version information is disclosed in HTTP headers and SSH banners.",
            "category": "configuration",
            "cwe_id": "CWE-200",
            "cvss_score": 3.5,
        },
        {
            "title": "Missing DNS CAA Records",
            "description": "CAA DNS records are not configured, allowing any CA to issue certificates for this domain.",
            "category": "network",
            "cwe_id": "CWE-295",
            "cvss_score": 3.7,
        },
        {
            "title": "Cookie Without Secure Flag",
            "description": "Session cookies are missing the Secure flag, allowing transmission over unencrypted connections.",
            "category": "configuration",
            "cwe_id": "CWE-614",
            "cvss_score": 3.1,
        },
        {
            "title": "Directory Listing Enabled",
            "description": "Web server directory listing is enabled on some paths, potentially exposing file structure.",
            "category": "configuration",
            "cwe_id": "CWE-548",
            "cvss_score": 3.3,
        },
    ],
}

RECOMMENDATION_TEMPLATES = {
    "patch_management": {
        "title": "Apply Security Patches",
        "description": "Update the affected software to the latest patched version and implement a regular patch management schedule.",
        "steps": [
            "Backup the current system state",
            "Review the patch release notes for compatibility",
            "Apply patches in a staging environment first",
            "Run automated tests to verify functionality",
            "Schedule maintenance window for production deployment",
            "Apply patches to production systems",
            "Verify successful patching and restart affected services",
            "Document the changes in change management system"
        ],
        "script_bash": "#!/bin/bash\nsudo apt update && sudo apt upgrade -y\nsudo systemctl restart affected-service",
        "script_powershell": "# Windows Update\nInstall-WindowsUpdate -AcceptAll -AutoReboot",
    },
    "configuration": {
        "title": "Harden System Configuration",
        "description": "Apply security hardening measures according to CIS benchmarks and industry best practices.",
        "steps": [
            "Review current configuration against security baseline",
            "Identify deviations from security standards",
            "Create remediation plan for each finding",
            "Test configuration changes in non-production",
            "Apply hardening configurations",
            "Verify system functionality after changes",
            "Update configuration documentation"
        ],
        "script_bash": "#!/bin/bash\n# Disable unnecessary services\nsudo systemctl disable cups\nsudo systemctl stop cups",
        "script_powershell": "# Disable unnecessary Windows features\nDisable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
    },
    "authentication": {
        "title": "Strengthen Authentication Controls",
        "description": "Implement multi-factor authentication and enforce strong password policies across all systems.",
        "steps": [
            "Review current authentication mechanisms",
            "Define password complexity requirements",
            "Configure account lockout policies",
            "Implement MFA for privileged accounts",
            "Enable audit logging for authentication events",
            "Test authentication flows",
            "Communicate password policy changes to users"
        ],
        "script_bash": "#!/bin/bash\n# Configure PAM password requirements\nsudo apt install libpam-pwquality -y",
        "script_powershell": "# Set password policy\nSet-ADDefaultDomainPasswordPolicy -MinPasswordLength 14 -ComplexityEnabled $true",
    },
    "encryption": {
        "title": "Implement Strong Encryption",
        "description": "Upgrade encryption protocols and ensure all data in transit and at rest is properly encrypted.",
        "steps": [
            "Audit current encryption usage",
            "Disable weak ciphers and protocols",
            "Generate new certificates if needed",
            "Configure TLS 1.3 or TLS 1.2 minimum",
            "Enable encryption for database connections",
            "Implement disk encryption for sensitive data",
            "Verify encryption configuration"
        ],
        "script_bash": "#!/bin/bash\n# Disable TLS 1.0/1.1 in nginx\n# ssl_protocols TLSv1.2 TLSv1.3;",
        "script_powershell": "# Disable old TLS versions\nNew-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Name 'Enabled' -Value 0 -PropertyType DWORD",
    },
    "access_control": {
        "title": "Implement Least Privilege Access",
        "description": "Review and restrict access permissions following the principle of least privilege.",
        "steps": [
            "Inventory all user accounts and permissions",
            "Identify excessive privileges",
            "Define role-based access control model",
            "Remove unnecessary access rights",
            "Implement regular access reviews",
            "Document access control policies",
            "Enable access logging"
        ],
        "script_bash": "#!/bin/bash\n# Remove world-readable permissions\nfind /etc -type f -perm -o+r -exec chmod o-r {} \\;",
        "script_powershell": "# Audit local admin group\nGet-LocalGroupMember -Group 'Administrators'",
    },
    "logging": {
        "title": "Enable Comprehensive Logging",
        "description": "Configure centralized logging for all security-relevant events with proper retention policies.",
        "steps": [
            "Define logging requirements",
            "Configure system audit policies",
            "Set up centralized log collection",
            "Implement log rotation and retention",
            "Configure alerting for critical events",
            "Test log collection and parsing",
            "Document logging architecture"
        ],
        "script_bash": "#!/bin/bash\n# Enable auditd logging\nsudo systemctl enable auditd\nsudo systemctl start auditd",
        "script_powershell": "# Enable Windows Security Auditing\nauditpol /set /subcategory:\"Logon\" /success:enable /failure:enable",
    },
    "network": {
        "title": "Secure Network Configuration",
        "description": "Implement network segmentation and firewall rules to restrict unauthorized access.",
        "steps": [
            "Document current network topology",
            "Identify required network flows",
            "Configure firewall rules (deny by default)",
            "Implement network segmentation",
            "Enable network monitoring",
            "Test connectivity after changes",
            "Document firewall rules"
        ],
        "script_bash": "#!/bin/bash\n# Configure UFW firewall\nsudo ufw default deny incoming\nsudo ufw default allow outgoing\nsudo ufw enable",
        "script_powershell": "# Enable Windows Firewall\nSet-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
    },
    "other": {
        "title": "Address Security Finding",
        "description": "Review and remediate the identified security issue following security best practices.",
        "steps": [
            "Review the finding details",
            "Research remediation options",
            "Plan remediation approach",
            "Implement fix in test environment",
            "Validate the fix",
            "Deploy to production",
            "Document changes"
        ],
        "script_bash": "#!/bin/bash\n# Custom remediation script\necho 'Implement specific fix here'",
        "script_powershell": "# Custom remediation script\nWrite-Host 'Implement specific fix here'",
    },
}


# =============================================================================
# Helper Functions
# =============================================================================

def random_ip(prefix: str = None) -> str:
    """Generate a random IP address."""
    if prefix is None:
        prefix = random.choice(IP_PREFIXES)
    return f"{prefix}{random.randint(1, 254)}"


def random_date_in_range(days_back: int = 30) -> datetime:
    """Generate a random datetime within the past N days."""
    now = timezone.now()
    random_days = random.uniform(0, days_back)
    return now - timedelta(days=random_days)


def calculate_risk_score(findings: list) -> int:
    """Calculate risk score based on findings."""
    if not findings:
        return random.randint(0, 15)  # Low risk for no findings
    
    severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
    total_weight = sum(severity_weights.get(f.severity, 0) for f in findings)
    
    # Normalize to 0-100 scale with some randomness
    score = min(100, total_weight + random.randint(-5, 10))
    return max(0, score)


def determine_maturity_level(risk_score: int) -> str:
    """Determine maturity level based on risk score."""
    if risk_score >= 75:
        return "reactive"
    elif risk_score >= 50:
        return "basic"
    elif risk_score >= 25:
        return "managed"
    else:
        return "optimized"


def generate_score_breakdown(findings: list) -> dict:
    """Generate detailed score breakdown."""
    breakdown = {
        "access_control": {"score": random.randint(60, 100), "weight": 15},
        "configuration": {"score": random.randint(50, 100), "weight": 20},
        "patch_management": {"score": random.randint(40, 100), "weight": 20},
        "network": {"score": random.randint(55, 100), "weight": 15},
        "authentication": {"score": random.randint(50, 100), "weight": 15},
        "encryption": {"score": random.randint(60, 100), "weight": 10},
        "logging": {"score": random.randint(50, 100), "weight": 5},
    }
    
    # Adjust scores based on findings
    for finding in findings:
        category = finding.category
        if category in breakdown:
            penalty = {"critical": 30, "high": 20, "medium": 10, "low": 5}.get(finding.severity, 5)
            breakdown[category]["score"] = max(0, breakdown[category]["score"] - penalty)
    
    return breakdown


def generate_scan_payload(system: System) -> dict:
    """Generate realistic scan payload data."""
    return {
        "agent_version": f"1.{random.randint(0, 5)}.{random.randint(0, 20)}",
        "scan_start": timezone.now().isoformat(),
        "system_info": {
            "hostname": system.hostname,
            "os": system.os,
            "os_version": system.os_version,
            "kernel": f"{random.randint(4, 6)}.{random.randint(0, 20)}.{random.randint(0, 100)}-generic",
            "cpu_cores": random.choice([2, 4, 8, 16, 32]),
            "memory_gb": random.choice([4, 8, 16, 32, 64, 128]),
            "disk_gb": random.choice([100, 250, 500, 1000, 2000]),
        },
        "collectors": {
            "packages": {"status": "completed", "items_checked": random.randint(200, 1500)},
            "services": {"status": "completed", "items_checked": random.randint(50, 200)},
            "users": {"status": "completed", "items_checked": random.randint(5, 50)},
            "ports": {"status": "completed", "items_checked": random.randint(10, 100)},
            "processes": {"status": "completed", "items_checked": random.randint(50, 300)},
            "configurations": {"status": "completed", "items_checked": random.randint(100, 500)},
        },
        "compliance_checks": {
            "cis_benchmark": random.randint(60, 100),
            "nist_800_53": random.randint(55, 95),
            "pci_dss": random.randint(50, 90),
        },
    }


# =============================================================================
# Data Generation Functions
# =============================================================================

def create_test_users() -> list:
    """Create test users with different roles."""
    users = []
    
    # Admin user (main test account)
    admin, created = User.objects.get_or_create(
        email="test@test.com",
        defaults={
            "first_name": "Test",
            "last_name": "Admin",
            "role": "admin",
            "is_active": True,
            "is_staff": True,
            "is_superuser": True,
        }
    )
    if created:
        admin.set_password("test123")
        admin.save()
        print(f"✓ Created admin user: {admin.email}")
    else:
        print(f"• Admin user exists: {admin.email}")
    users.append(admin)
    
    # Additional users
    test_users = [
        ("auditor@securesys.local", "Sarah", "Chen", "auditor"),
        ("analyst@securesys.local", "James", "Wilson", "auditor"),
        ("viewer@securesys.local", "Maria", "Garcia", "viewer"),
        ("operations@securesys.local", "Alex", "Johnson", "viewer"),
    ]
    
    for email, first_name, last_name, role in test_users:
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                "first_name": first_name,
                "last_name": last_name,
                "role": role,
                "is_active": True,
            }
        )
        if created:
            user.set_password("SecureSys2024!")
            user.save()
            print(f"✓ Created {role} user: {email}")
        users.append(user)
    
    return users


def create_systems(num_systems: int = 15) -> list:
    """Create diverse system records."""
    systems = []
    
    print(f"\n📦 Creating {num_systems} systems...")
    
    for i in range(num_systems):
        hostname_template = random.choice(HOSTNAMES)
        hostname = hostname_template.format(str(i + 1).zfill(2))
        
        os_name, os_versions = random.choice(OPERATING_SYSTEMS)
        os_version = random.choice(os_versions)
        
        environment = random.choices(
            ENVIRONMENTS,
            weights=[15, 20, 45, 20],  # More production systems
            k=1
        )[0]
        
        # Use consistent IP prefix for environment
        ip_prefix = {
            "production": "10.0.1.",
            "staging": "10.0.2.",
            "development": "192.168.1.",
            "testing": "192.168.10.",
        }.get(environment, random.choice(IP_PREFIXES))
        
        system, created = System.objects.get_or_create(
            hostname=hostname,
            defaults={
                "os": os_name,
                "os_version": os_version,
                "environment": environment,
                "ip_address": random_ip(ip_prefix),
                "description": f"Auto-generated {environment} {os_name} system for testing",
                "is_active": True,
                "last_seen": random_date_in_range(7),
            }
        )
        
        if created:
            print(f"  ✓ {hostname} ({os_name} {os_version}) - {environment}")
        else:
            print(f"  • {hostname} already exists")
        
        systems.append(system)
    
    return systems


def create_scans_and_findings(systems: list, scans_per_system: int = 3) -> tuple:
    """Create scans with associated findings and recommendations."""
    all_scans = []
    all_findings = []
    all_recommendations = []
    
    print(f"\n🔍 Creating scans for {len(systems)} systems...")
    
    for system in systems:
        num_scans = random.randint(1, scans_per_system)
        
        for scan_num in range(num_scans):
            # Determine scan type and characteristics
            scan_type = random.choice(SCAN_TYPES)
            scan_date = random_date_in_range(30)
            
            # 85% completed, 10% processing, 5% failed
            status_choice = random.choices(
                ["completed", "processing", "failed"],
                weights=[85, 10, 5],
                k=1
            )[0]
            
            scan = Scan.objects.create(
                system=system,
                scan_type=scan_type,
                status=status_choice,
                scan_payload=generate_scan_payload(system) if status_choice == "completed" else {},
                started_at=scan_date,
            )
            
            # Only create findings for completed scans
            if status_choice == "completed":
                # Generate findings based on environment (production = more scrutiny)
                num_findings_base = {
                    "production": random.randint(3, 12),
                    "staging": random.randint(2, 8),
                    "development": random.randint(1, 6),
                    "testing": random.randint(0, 4),
                }.get(system.environment, random.randint(1, 5))
                
                scan_findings = []
                
                # Distribute findings across severities
                for severity in ["critical", "high", "medium", "low"]:
                    severity_weights = {
                        "critical": 0.05,
                        "high": 0.15,
                        "medium": 0.35,
                        "low": 0.45,
                    }
                    
                    num_of_severity = int(num_findings_base * severity_weights[severity])
                    if severity in ["critical", "high"] and random.random() > 0.7:
                        num_of_severity += 1  # Sometimes add extra critical/high
                    
                    templates = FINDING_TEMPLATES[severity]
                    for _ in range(num_of_severity):
                        template = random.choice(templates)
                        
                        # Determine if finding is resolved (older findings more likely resolved)
                        days_old = (timezone.now() - scan_date).days
                        is_resolved = random.random() < (days_old / 60)  # More likely resolved if older
                        
                        finding = Finding.objects.create(
                            scan=scan,
                            category=template["category"],
                            severity=severity,
                            title=template["title"],
                            description=template["description"],
                            cwe_id=template.get("cwe_id", ""),
                            cvss_score=template.get("cvss_score"),
                            evidence={
                                "affected_paths": [f"/etc/{random.choice(['apache2', 'nginx', 'ssh', 'mysql'])}/config"],
                                "detection_method": random.choice(["signature", "heuristic", "policy"]),
                                "first_detected": scan_date.isoformat(),
                            },
                            is_resolved=is_resolved,
                            resolved_at=timezone.now() if is_resolved else None,
                        )
                        
                        scan_findings.append(finding)
                        all_findings.append(finding)
                        
                        # Create recommendation for each finding
                        rec_template = RECOMMENDATION_TEMPLATES.get(
                            template["category"],
                            RECOMMENDATION_TEMPLATES["other"]
                        )
                        
                        recommendation = Recommendation.objects.create(
                            finding=finding,
                            priority=severity,
                            effort=random.choice(["low", "medium", "high"]),
                            title=rec_template["title"],
                            description=rec_template["description"],
                            steps=rec_template["steps"],
                            script_bash=rec_template.get("script_bash", ""),
                            script_powershell=rec_template.get("script_powershell", ""),
                            references=[
                                f"https://nvd.nist.gov/vuln/detail/{template.get('cwe_id', 'CWE-000')}",
                                "https://cwe.mitre.org/data/definitions/",
                                "https://owasp.org/www-project-top-ten/",
                            ]
                        )
                        all_recommendations.append(recommendation)
                
                # Update scan with calculated scores
                risk_score = calculate_risk_score(scan_findings)
                maturity_level = determine_maturity_level(risk_score)
                score_breakdown = generate_score_breakdown(scan_findings)
                
                scan.risk_score = risk_score
                scan.maturity_level = maturity_level
                scan.score_breakdown = score_breakdown
                scan.completed_at = scan_date + timedelta(minutes=random.randint(2, 30))
                scan.save()
                
                # Update system's latest scan data
                if not system.latest_risk_score or scan_date > (system.last_seen or timezone.now()):
                    system.latest_risk_score = risk_score
                    system.latest_maturity_level = maturity_level
                    system.last_seen = scan_date
                    system.save()
                
            elif status_choice == "failed":
                scan.error_message = random.choice([
                    "Connection timeout - unable to reach agent",
                    "Agent authentication failed",
                    "Insufficient permissions to complete scan",
                    "Scan interrupted by system restart",
                    "Memory limit exceeded during analysis",
                ])
                scan.completed_at = scan_date + timedelta(minutes=random.randint(1, 5))
                scan.save()
            
            all_scans.append(scan)
    
    return all_scans, all_findings, all_recommendations


def print_summary(users: list, systems: list, scans: list, findings: list, recommendations: list):
    """Print a summary of generated data."""
    
    print("\n" + "=" * 60)
    print("📊 SYNTHETIC DATA GENERATION COMPLETE")
    print("=" * 60)
    
    print(f"\n👥 Users: {len(users)}")
    for user in users:
        print(f"   • {user.email} ({user.role})")
    
    print(f"\n🖥️  Systems: {len(systems)}")
    env_counts = {}
    for system in systems:
        env_counts[system.environment] = env_counts.get(system.environment, 0) + 1
    for env, count in sorted(env_counts.items()):
        print(f"   • {env.capitalize()}: {count}")
    
    print(f"\n🔍 Scans: {len(scans)}")
    status_counts = {}
    for scan in scans:
        status_counts[scan.status] = status_counts.get(scan.status, 0) + 1
    for status, count in sorted(status_counts.items()):
        print(f"   • {status.capitalize()}: {count}")
    
    print(f"\n⚠️  Findings: {len(findings)}")
    severity_counts = {}
    resolved_count = 0
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        if finding.is_resolved:
            resolved_count += 1
    
    severity_order = ["critical", "high", "medium", "low"]
    for severity in severity_order:
        count = severity_counts.get(severity, 0)
        indicator = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
        print(f"   {indicator} {severity.capitalize()}: {count}")
    print(f"   ✓ Resolved: {resolved_count} ({resolved_count/len(findings)*100:.1f}%)" if findings else "")
    
    print(f"\n💡 Recommendations: {len(recommendations)}")
    
    print("\n" + "=" * 60)
    print("🚀 Ready to explore! Login credentials:")
    print("=" * 60)
    print("   Email:    test@test.com")
    print("   Password: test123")
    print("\n   Access the dashboard at: http://127.0.0.1:5173/dashboard")
    print("=" * 60 + "\n")


# =============================================================================
# Main Entry Point
# =============================================================================

def main(num_systems: int = 15, scans_per_system: int = 3):
    """Main function to generate all synthetic data."""
    
    print("\n" + "=" * 60)
    print("🔐 SecureSys Auditor - Synthetic Data Generator")
    print("=" * 60)
    
    try:
        # Create test users
        print("\n👥 Creating test users...")
        users = create_test_users()
        
        # Create systems
        systems = create_systems(num_systems)
        
        # Create scans, findings, and recommendations
        scans, findings, recommendations = create_scans_and_findings(
            systems, scans_per_system
        )
        
        # Print summary
        print_summary(users, systems, scans, findings, recommendations)
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error generating data: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate synthetic data for SecureSys Auditor")
    parser.add_argument("--num-systems", type=int, default=15, help="Number of systems to create")
    parser.add_argument("--scans-per-system", type=int, default=3, help="Max scans per system")
    
    args = parser.parse_args()
    
    success = main(num_systems=args.num_systems, scans_per_system=args.scans_per_system)
    sys.exit(0 if success else 1)
