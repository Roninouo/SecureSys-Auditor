"""
Unit tests for the security analysis engine.

Tests coverage for:
- Individual security rules (RootSSHRule, FirewallDisabledRule, etc.)
- SecurityAnalyzer integration
- Risk score calculation
- Maturity level determination
"""
import pytest


class TestSecurityRules:
    """Test individual security rules."""

    def test_root_ssh_rule_triggers_on_permit_root(self, sample_scan_payload):
        """Test RootSSHRule triggers when root login is enabled."""
        from core.analysis import RootSSHRule

        rule = RootSSHRule()
        result = rule.evaluate(sample_scan_payload)

        assert result is not None
        assert result["category"] == "access_control"
        assert result["severity"] == "high"
        assert "Root SSH Login Enabled" in result["title"]
        assert len(result["recommendations"]) > 0

    def test_root_ssh_rule_passes_when_disabled(self, secure_scan_payload):
        """Test RootSSHRule passes when root login is disabled."""
        from core.analysis import RootSSHRule

        rule = RootSSHRule()
        result = rule.evaluate(secure_scan_payload)

        assert result is None

    def test_firewall_disabled_rule_triggers(self, sample_scan_payload):
        """Test FirewallDisabledRule triggers when firewall is disabled."""
        from core.analysis import FirewallDisabledRule

        rule = FirewallDisabledRule()
        result = rule.evaluate(sample_scan_payload)

        assert result is not None
        assert result["category"] == "network"
        assert result["severity"] == "critical"
        assert "Firewall Disabled" in result["title"]

    def test_firewall_disabled_rule_passes_when_enabled(self, secure_scan_payload):
        """Test FirewallDisabledRule passes when firewall is enabled."""
        from core.analysis import FirewallDisabledRule

        rule = FirewallDisabledRule()
        result = rule.evaluate(secure_scan_payload)

        assert result is None

    def test_outdated_packages_rule_triggers(self, sample_scan_payload):
        """Test OutdatedPackagesRule triggers with outdated packages."""
        from core.analysis import OutdatedPackagesRule

        rule = OutdatedPackagesRule()
        result = rule.evaluate(sample_scan_payload)

        assert result is not None
        assert result["category"] == "patch_management"
        assert "Outdated Packages" in result["title"]

    def test_outdated_packages_rule_passes_when_current(self, secure_scan_payload):
        """Test OutdatedPackagesRule passes when all packages are current."""
        from core.analysis import OutdatedPackagesRule

        rule = OutdatedPackagesRule()
        result = rule.evaluate(secure_scan_payload)

        assert result is None

    def test_weak_password_policy_rule_triggers(self, sample_scan_payload):
        """Test WeakPasswordPolicyRule triggers with weak policy."""
        from core.analysis import WeakPasswordPolicyRule

        rule = WeakPasswordPolicyRule()
        result = rule.evaluate(sample_scan_payload)

        assert result is not None
        assert result["category"] == "authentication"
        assert result["severity"] == "high"
        assert "Weak Password Policy" in result["title"]

    def test_weak_password_policy_rule_passes_with_strong_policy(self, secure_scan_payload):
        """Test WeakPasswordPolicyRule passes with strong policy."""
        from core.analysis import WeakPasswordPolicyRule

        rule = WeakPasswordPolicyRule()
        result = rule.evaluate(secure_scan_payload)

        assert result is None

    def test_admin_users_rule_triggers_with_excess_admins(self, sample_scan_payload):
        """Test AdminUsersRule triggers with too many admin users."""
        from core.analysis import AdminUsersRule

        rule = AdminUsersRule()
        result = rule.evaluate(sample_scan_payload)

        assert result is not None
        assert result["category"] == "access_control"
        assert "Excessive Administrative Users" in result["title"]

    def test_admin_users_rule_passes_with_few_admins(self, secure_scan_payload):
        """Test AdminUsersRule passes with acceptable number of admins."""
        from core.analysis import AdminUsersRule

        rule = AdminUsersRule()
        result = rule.evaluate(secure_scan_payload)

        assert result is None

    def test_open_ports_rule_triggers_with_risky_ports(self, sample_scan_payload):
        """Test OpenPortsRule triggers with risky open ports."""
        from core.analysis import OpenPortsRule

        rule = OpenPortsRule()
        result = rule.evaluate(sample_scan_payload)

        assert result is not None
        assert result["category"] == "network"
        assert "Risky Ports" in result["title"]
        # Telnet (port 23) should make it high severity
        assert result["severity"] == "high"

    def test_open_ports_rule_passes_with_safe_ports(self, secure_scan_payload):
        """Test OpenPortsRule passes with only safe ports."""
        from core.analysis import OpenPortsRule

        rule = OpenPortsRule()
        result = rule.evaluate(secure_scan_payload)

        assert result is None


class TestSecurityAnalyzer:
    """Test SecurityAnalyzer integration."""

    def test_analyzer_finds_all_issues(self, sample_scan_payload):
        """Test analyzer identifies all security issues in payload."""
        from core.analysis import SecurityAnalyzer

        analyzer = SecurityAnalyzer(sample_scan_payload)
        result = analyzer.analyze()

        assert "findings" in result
        assert "risk_score" in result
        assert "maturity_level" in result
        assert "score_breakdown" in result

        # Should find multiple issues
        assert len(result["findings"]) >= 4

    def test_analyzer_secure_system_has_no_findings(self, secure_scan_payload):
        """Test analyzer finds no issues in secure system."""
        from core.analysis import SecurityAnalyzer

        analyzer = SecurityAnalyzer(secure_scan_payload)
        result = analyzer.analyze()

        assert len(result["findings"]) == 0
        assert result["risk_score"] == 0
        assert result["maturity_level"] == "optimized"

    def test_risk_score_calculation(self, sample_scan_payload):
        """Test risk score is calculated correctly."""
        from core.analysis import SecurityAnalyzer

        analyzer = SecurityAnalyzer(sample_scan_payload)
        result = analyzer.analyze()

        # Risk score should be > 0 for insecure payload
        assert result["risk_score"] > 0
        # Should be capped at 100
        assert result["risk_score"] <= 100

    def test_maturity_level_reactive_for_high_risk(self, sample_scan_payload):
        """Test maturity level is reactive for high-risk systems."""
        from core.analysis import SecurityAnalyzer

        analyzer = SecurityAnalyzer(sample_scan_payload)
        result = analyzer.analyze()

        # With multiple issues, should not be optimized
        assert result["maturity_level"] in ["reactive", "basic", "managed"]

    def test_score_breakdown_has_all_severities(self, sample_scan_payload):
        """Test score breakdown includes all severity levels."""
        from core.analysis import SecurityAnalyzer

        analyzer = SecurityAnalyzer(sample_scan_payload)
        result = analyzer.analyze()

        breakdown = result["score_breakdown"]
        assert "critical" in breakdown
        assert "high" in breakdown
        assert "medium" in breakdown
        assert "low" in breakdown

    def test_analyzer_handles_empty_payload(self):
        """Test analyzer handles empty payload gracefully."""
        from core.analysis import SecurityAnalyzer

        analyzer = SecurityAnalyzer({})
        result = analyzer.analyze()

        assert result["findings"] == []
        assert result["risk_score"] == 0
        assert result["maturity_level"] == "optimized"

    def test_analyzer_handles_partial_payload(self):
        """Test analyzer handles payload with missing sections."""
        from core.analysis import SecurityAnalyzer

        partial_payload = {
            "hostname": "partial-server",
            "ssh_config": {"permit_root_login": True},
        }

        analyzer = SecurityAnalyzer(partial_payload)
        result = analyzer.analyze()

        # Should find SSH issue but handle missing sections
        assert len(result["findings"]) >= 1
        ssh_finding = next((f for f in result["findings"] if "SSH" in f["title"]), None)
        assert ssh_finding is not None
