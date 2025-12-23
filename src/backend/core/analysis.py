"""
Security Analysis Engine for SecureSys Auditor.

This module provides rule-based security analysis of scan payloads
to identify vulnerabilities and calculate risk scores.
"""
import logging
from typing import Dict, List, Any

logger = logging.getLogger('core')


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
        super().__init__('SSH-001', 'access_control', 'high')
    
    def evaluate(self, payload: Dict) -> Dict | None:
        ssh_config = payload.get('ssh_config', {})
        if ssh_config.get('permit_root_login', False):
            return {
                'category': self.category,
                'severity': self.severity,
                'title': 'Root SSH Login Enabled',
                'description': 'SSH configuration allows direct root login, which is a security risk.',
                'evidence': {
                    'config_file': '/etc/ssh/sshd_config',
                    'setting': 'PermitRootLogin yes'
                },
                'recommendations': [{
                    'title': 'Disable Root SSH Login',
                    'description': 'Disable direct root login via SSH to improve security.',
                    'priority': 'high',
                    'effort': 'low',
                    'steps': [
                        'Edit /etc/ssh/sshd_config',
                        'Set PermitRootLogin to no',
                        'Restart SSH service: systemctl restart sshd'
                    ]
                }]
            }
        return None


class FirewallDisabledRule(SecurityRule):
    """Check if firewall is disabled."""
    
    def __init__(self):
        super().__init__('FW-001', 'network', 'critical')
    
    def evaluate(self, payload: Dict) -> Dict | None:
        firewall = payload.get('firewall', {})
        if not firewall.get('enabled', True):
            return {
                'category': self.category,
                'severity': self.severity,
                'title': 'Firewall Disabled',
                'description': 'System firewall is disabled, leaving the system exposed to network attacks.',
                'evidence': {
                    'firewall_status': 'disabled'
                },
                'recommendations': [{
                    'title': 'Enable System Firewall',
                    'description': 'Enable and configure the system firewall.',
                    'priority': 'critical',
                    'effort': 'medium',
                    'steps': [
                        'Enable firewall: ufw enable (Ubuntu) or firewall-cmd --state (CentOS)',
                        'Configure default deny incoming: ufw default deny incoming',
                        'Allow required services: ufw allow ssh',
                        'Verify status: ufw status verbose'
                    ]
                }]
            }
        return None


class OutdatedPackagesRule(SecurityRule):
    """Check for outdated packages with known vulnerabilities."""
    
    def __init__(self):
        super().__init__('PKG-001', 'patch_management', 'medium')
    
    def evaluate(self, payload: Dict) -> Dict | None:
        packages = payload.get('packages', {})
        outdated = packages.get('outdated', [])
        
        if outdated:
            return {
                'category': self.category,
                'severity': 'high' if len(outdated) > 10 else self.severity,
                'title': f'{len(outdated)} Outdated Packages Found',
                'description': f'System has {len(outdated)} packages that need updates.',
                'evidence': {
                    'outdated_packages': outdated[:20]  # Limit to first 20
                },
                'recommendations': [{
                    'title': 'Update System Packages',
                    'description': 'Update all outdated packages to their latest versions.',
                    'priority': 'high' if len(outdated) > 10 else 'medium',
                    'effort': 'medium',
                    'steps': [
                        'Backup current system state',
                        'Update package lists: apt update (Debian) or yum check-update (RHEL)',
                        'Upgrade packages: apt upgrade -y or yum update -y',
                        'Reboot if kernel was updated'
                    ]
                }]
            }
        return None


class WeakPasswordPolicyRule(SecurityRule):
    """Check for weak password policy."""
    
    def __init__(self):
        super().__init__('AUTH-001', 'authentication', 'high')
    
    def evaluate(self, payload: Dict) -> Dict | None:
        password_policy = payload.get('password_policy', {})
        
        issues = []
        if password_policy.get('min_length', 0) < 12:
            issues.append('Minimum password length is less than 12 characters')
        if not password_policy.get('require_special', True):
            issues.append('Special characters not required')
        if not password_policy.get('require_numbers', True):
            issues.append('Numbers not required')
        
        if issues:
            return {
                'category': self.category,
                'severity': self.severity,
                'title': 'Weak Password Policy',
                'description': 'Password policy does not meet security best practices.',
                'evidence': {
                    'issues': issues,
                    'current_policy': password_policy
                },
                'recommendations': [{
                    'title': 'Strengthen Password Policy',
                    'description': 'Configure a stronger password policy.',
                    'priority': 'high',
                    'effort': 'low',
                    'steps': [
                        'Edit /etc/security/pwquality.conf',
                        'Set minlen = 12',
                        'Set minclass = 4',
                        'Enable password history checks'
                    ]
                }]
            }
        return None


class AdminUsersRule(SecurityRule):
    """Check for excessive admin/sudo users."""
    
    def __init__(self):
        super().__init__('ACC-001', 'access_control', 'medium')
    
    def evaluate(self, payload: Dict) -> Dict | None:
        users = payload.get('users', {})
        admin_users = users.get('admin_users', [])
        
        if len(admin_users) > 3:
            return {
                'category': self.category,
                'severity': self.severity,
                'title': 'Excessive Administrative Users',
                'description': f'System has {len(admin_users)} users with administrative privileges.',
                'evidence': {
                    'admin_users': admin_users,
                    'count': len(admin_users)
                },
                'recommendations': [{
                    'title': 'Review Administrative Access',
                    'description': 'Review and reduce the number of administrative users.',
                    'priority': 'medium',
                    'effort': 'low',
                    'steps': [
                        'Review list of sudo/admin users',
                        'Remove unnecessary admin privileges',
                        'Implement principle of least privilege',
                        'Document admin access requirements'
                    ]
                }]
            }
        return None


class OpenPortsRule(SecurityRule):
    """Check for unnecessary open ports."""
    
    def __init__(self):
        super().__init__('NET-001', 'network', 'medium')
    
    def evaluate(self, payload: Dict) -> Dict | None:
        network = payload.get('network', {})
        open_ports = network.get('open_ports', [])
        
        # Define commonly risky ports
        risky_ports = {21: 'FTP', 23: 'Telnet', 25: 'SMTP', 3389: 'RDP', 5900: 'VNC'}
        found_risky = []
        
        for port in open_ports:
            port_num = port.get('port') if isinstance(port, dict) else port
            if port_num in risky_ports:
                found_risky.append({'port': port_num, 'service': risky_ports[port_num]})
        
        if found_risky:
            return {
                'category': self.category,
                'severity': 'high' if any(p['port'] == 23 for p in found_risky) else self.severity,
                'title': 'Potentially Risky Ports Open',
                'description': f'Found {len(found_risky)} potentially risky open ports.',
                'evidence': {
                    'risky_ports': found_risky,
                    'all_open_ports': open_ports[:20]
                },
                'recommendations': [{
                    'title': 'Review Open Ports',
                    'description': 'Close unnecessary ports and secure required services.',
                    'priority': 'high',
                    'effort': 'medium',
                    'steps': [
                        'Identify services bound to risky ports',
                        'Disable unnecessary services',
                        'Use firewall to restrict access',
                        'Consider using secure alternatives (SSH instead of Telnet)'
                    ]
                }]
            }
        return None


class SecurityAnalyzer:
    """
    Main security analyzer that processes scan payloads.
    """
    
    # Risk weights by severity
    SEVERITY_WEIGHTS = {
        'critical': 25,
        'high': 15,
        'medium': 8,
        'low': 3
    }
    
    # Maturity level thresholds (lower score = more mature)
    MATURITY_THRESHOLDS = {
        'optimized': 20,
        'managed': 40,
        'basic': 60,
        'reactive': 100
    }
    
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
        findings = []
        score_breakdown = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        # Evaluate all rules
        for rule in self.rules:
            try:
                result = rule.evaluate(self.payload)
                if result:
                    findings.append(result)
                    score_breakdown[result['severity']] += 1
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.rule_id}: {str(e)}")
        
        # Calculate risk score (0-100, higher = more risk)
        risk_score = self._calculate_risk_score(score_breakdown)
        
        # Determine maturity level
        maturity_level = self._determine_maturity(risk_score)
        
        return {
            'findings': findings,
            'risk_score': risk_score,
            'maturity_level': maturity_level,
            'score_breakdown': score_breakdown
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
        return 'reactive'
