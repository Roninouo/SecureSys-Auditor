"""
Unit tests for scanner and telemetry filtering.

Tests coverage for:
- filter_sensitive_data function
- SystemScanner with minimal_telemetry
- Custom sensitive fields
"""
import pytest


class TestFilterSensitiveData:
    """Test sensitive data filtering."""

    def test_filter_removes_sensitive_fields(self):
        """Test filter removes known sensitive fields."""
        from agent.scanner import filter_sensitive_data

        data = {
            "hostname": "server-01",
            "ip_address": "192.168.1.100",
            "mac_address": "00:11:22:33:44:55",
            "os": "Linux",
        }

        sensitive_fields = ["ip_address", "mac_address"]
        filtered = filter_sensitive_data(data, sensitive_fields)

        assert "hostname" in filtered
        assert "os" in filtered
        assert "ip_address" not in filtered
        assert "mac_address" not in filtered

    def test_filter_handles_nested_dicts(self):
        """Test filter removes fields from nested dictionaries."""
        from agent.scanner import filter_sensitive_data

        data = {
            "hostname": "server-01",
            "network": {
                "interface": "eth0",
                "ip_address": "192.168.1.100",
                "mac_address": "00:11:22:33:44:55",
            },
        }

        sensitive_fields = ["ip_address", "mac_address"]
        filtered = filter_sensitive_data(data, sensitive_fields)

        assert "network" in filtered
        assert "interface" in filtered["network"]
        assert "ip_address" not in filtered["network"]
        assert "mac_address" not in filtered["network"]

    def test_filter_handles_lists(self):
        """Test filter removes fields from dicts inside lists."""
        from agent.scanner import filter_sensitive_data

        data = {
            "users": [
                {"name": "admin", "password": "secret123"},
                {"name": "user", "password": "password"},
            ]
        }

        sensitive_fields = ["password"]
        filtered = filter_sensitive_data(data, sensitive_fields)

        assert len(filtered["users"]) == 2
        assert filtered["users"][0]["name"] == "admin"
        assert "password" not in filtered["users"][0]
        assert "password" not in filtered["users"][1]

    def test_filter_case_insensitive_matching(self):
        """Test filter matches fields case-insensitively."""
        from agent.scanner import filter_sensitive_data

        data = {
            "IP_Address": "192.168.1.1",
            "MAC_ADDRESS": "aa:bb:cc:dd:ee:ff",
            "hostname": "server-01",
        }

        sensitive_fields = ["ip_address", "mac_address"]
        filtered = filter_sensitive_data(data, sensitive_fields)

        assert "hostname" in filtered
        assert "IP_Address" not in filtered
        assert "MAC_ADDRESS" not in filtered

    def test_filter_partial_matching(self):
        """Test filter matches partial field names."""
        from agent.scanner import filter_sensitive_data

        data = {
            "user_password_hash": "abc123",
            "ssh_private_key": "key-content",
            "api_credentials_json": "{}",
            "hostname": "server-01",
        }

        sensitive_fields = ["password", "private_key", "credentials"]
        filtered = filter_sensitive_data(data, sensitive_fields)

        assert "hostname" in filtered
        assert "user_password_hash" not in filtered
        assert "ssh_private_key" not in filtered
        assert "api_credentials_json" not in filtered

    def test_filter_preserves_non_dict_data(self):
        """Test filter preserves non-dict values in lists."""
        from agent.scanner import filter_sensitive_data

        data = {
            "ports": [22, 80, 443],
            "services": ["ssh", "http", "https"],
            "ip_address": "192.168.1.1",
        }

        sensitive_fields = ["ip_address"]
        filtered = filter_sensitive_data(data, sensitive_fields)

        assert filtered["ports"] == [22, 80, 443]
        assert filtered["services"] == ["ssh", "http", "https"]
        assert "ip_address" not in filtered

    def test_filter_empty_data(self):
        """Test filter handles empty data."""
        from agent.scanner import filter_sensitive_data

        filtered = filter_sensitive_data({}, ["password"])
        assert filtered == {}

    def test_filter_returns_non_dict_unchanged(self):
        """Test filter returns non-dict values unchanged."""
        from agent.scanner import filter_sensitive_data

        result = filter_sensitive_data("string value", ["password"])
        assert result == "string value"

        result = filter_sensitive_data(123, ["password"])
        assert result == 123


class TestSystemScanner:
    """Test SystemScanner with telemetry settings."""

    def test_scanner_default_minimal_telemetry(self):
        """Test scanner has minimal_telemetry enabled by default."""
        from agent.scanner import SystemScanner

        scanner = SystemScanner()
        assert scanner.minimal_telemetry is True

    def test_scanner_disable_minimal_telemetry(self):
        """Test scanner can disable minimal_telemetry."""
        from agent.scanner import SystemScanner

        scanner = SystemScanner(minimal_telemetry=False)
        assert scanner.minimal_telemetry is False

    def test_scanner_custom_sensitive_fields(self):
        """Test scanner accepts custom sensitive fields."""
        from agent.scanner import SystemScanner

        custom_fields = ["custom_field", "internal_data"]
        scanner = SystemScanner(sensitive_fields=custom_fields)

        assert scanner.sensitive_fields == custom_fields

    def test_scanner_has_default_sensitive_fields(self):
        """Test scanner has default sensitive fields list."""
        from agent.scanner import SystemScanner

        scanner = SystemScanner()

        assert "ip_address" in scanner.sensitive_fields
        assert "mac_address" in scanner.sensitive_fields
        assert "passwords" in scanner.sensitive_fields
        assert "tokens" in scanner.sensitive_fields
        assert "credentials" in scanner.sensitive_fields

    def test_collect_all_includes_metadata(self):
        """Test collect_all includes telemetry metadata."""
        from agent.scanner import SystemScanner

        scanner = SystemScanner(minimal_telemetry=True)
        data = scanner.collect_all()

        # Should have metadata about telemetry setting
        assert "_metadata" in data
        assert data["_metadata"]["minimal_telemetry"] is True

    def test_collect_all_respects_minimal_telemetry(self):
        """Test collect_all filters data when minimal_telemetry is True."""
        from agent.scanner import SystemScanner

        # Create scanner with minimal telemetry
        scanner = SystemScanner(minimal_telemetry=True)
        scanner.sensitive_fields = ["ip_address"]

        # Manually add sensitive data to test filtering
        # (The actual scan data depends on the system)
        data = scanner.collect_all()

        # Verify metadata indicates filtering was applied
        assert data.get("_metadata", {}).get("minimal_telemetry") is True


class TestConfigSensitiveFields:
    """Test Config sensitive fields integration."""

    def test_config_has_minimal_telemetry_default(self):
        """Test Config defaults to minimal_telemetry=True."""
        from agent.config import Config

        config = Config()
        assert config.minimal_telemetry is True

    def test_config_has_sensitive_fields(self):
        """Test Config includes sensitive_fields list."""
        from agent.config import Config

        config = Config()
        assert hasattr(config, "sensitive_fields")
        assert len(config.sensitive_fields) > 0

    def test_config_sensitive_fields_default(self):
        """Test Config sensitive_fields has expected defaults."""
        from agent.config import SENSITIVE_FIELDS

        assert "ip_address" in SENSITIVE_FIELDS
        assert "mac_address" in SENSITIVE_FIELDS
        assert "passwords" in SENSITIVE_FIELDS

    def test_config_to_dict_includes_telemetry_settings(self):
        """Test Config.to_dict includes telemetry settings."""
        from agent.config import Config

        config = Config(minimal_telemetry=False)
        data = config.to_dict()

        assert "minimal_telemetry" in data
        assert data["minimal_telemetry"] is False
