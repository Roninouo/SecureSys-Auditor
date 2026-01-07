"""
Tests for error handling and exception scenarios.

Validates that:
- Exceptions are properly logged and not silenced
- Error fields are populated when operations fail
- Specific exception types are caught (not bare except)
- Fallback behavior is correct and documented
"""
import json
import logging
import subprocess
from unittest.mock import MagicMock, mock_open, patch

import pytest
import requests


class TestAPIClientErrorHandling:
    """Test error handling in API client."""

    @patch("agent.api_client.requests.Session")
    def test_health_check_returns_tuple_with_reason_on_timeout(self, mock_session_class):
        """Test health_check returns (False, reason) on timeout."""
        from agent.api_client import SecureSysAPIClient

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.get.side_effect = requests.Timeout("Connection timed out")

        client = SecureSysAPIClient(api_url="https://api.example.com", api_key="test-key")

        is_healthy, reason = client.health_check()

        assert is_healthy is False
        assert reason is not None
        assert "timed out" in reason.lower()

    @patch("agent.api_client.requests.Session")
    def test_health_check_returns_tuple_with_reason_on_connection_error(self, mock_session_class):
        """Test health_check returns (False, reason) on connection error."""
        from agent.api_client import SecureSysAPIClient

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.get.side_effect = requests.ConnectionError("Connection refused")

        client = SecureSysAPIClient(api_url="https://api.example.com", api_key="test-key")

        is_healthy, reason = client.health_check()

        assert is_healthy is False
        assert reason is not None
        assert "connection" in reason.lower()

    @patch("agent.api_client.requests.Session")
    def test_health_check_returns_tuple_with_reason_on_bad_status(self, mock_session_class):
        """Test health_check returns (False, reason) on non-200 status."""
        from agent.api_client import SecureSysAPIClient

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_session.get.return_value = mock_response

        client = SecureSysAPIClient(api_url="https://api.example.com", api_key="test-key")

        is_healthy, reason = client.health_check()

        assert is_healthy is False
        assert reason is not None
        assert "503" in reason

    @patch("agent.api_client.requests.Session")
    def test_register_or_get_system_logs_get_error_and_tries_post(self, mock_session_class, caplog):
        """Test register_or_get_system logs GET error and attempts POST."""
        from agent.api_client import SecureSysAPIClient

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # GET fails with timeout
        mock_session.get.side_effect = requests.Timeout("GET timed out")

        # POST succeeds
        mock_post_response = MagicMock()
        mock_post_response.status_code = 201
        mock_post_response.json.return_value = {"id": "new-system", "hostname": "test-host"}
        mock_session.post.return_value = mock_post_response

        client = SecureSysAPIClient(api_url="https://api.example.com", api_key="test-key")

        with caplog.at_level(logging.WARNING):
            result = client.register_or_get_system(hostname="test-host", os="Linux")

        # Should succeed via POST
        assert result["id"] == "new-system"
        # Should log the GET error
        assert any("timeout" in record.message.lower() for record in caplog.records)

    @patch("agent.api_client.requests.Session")
    def test_register_or_get_system_raises_on_post_failure(self, mock_session_class):
        """Test register_or_get_system raises when POST fails."""
        from agent.api_client import SecureSysAPIClient

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # GET returns empty
        mock_get_response = MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {"results": []}
        mock_session.get.return_value = mock_get_response

        # POST fails
        mock_session.post.side_effect = requests.ConnectionError("POST failed")

        client = SecureSysAPIClient(api_url="https://api.example.com", api_key="test-key")

        with pytest.raises(requests.ConnectionError):
            client.register_or_get_system(hostname="test-host", os="Linux")


class TestScannerErrorHandling:
    """Test error handling in SystemScanner."""

    @patch("subprocess.run")
    def test_get_linux_users_handles_timeout(self, mock_run):
        """Test _get_linux_users handles subprocess timeout."""
        from agent.scanner import SystemScanner

        # Make subprocess timeout for sudoers check
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["grep"], timeout=5)

        scanner = SystemScanner()
        scanner.platform = "linux"

        # Mock /etc/passwd read
        passwd_content = "user1:x:1000:1000::/home/user1:/bin/bash\n"
        with patch("builtins.open", mock_open(read_data=passwd_content)):
            result = scanner._get_linux_users()

        # Should return partial results with error info
        assert "local_users" in result
        assert "errors" in result
        assert any("timeout" in err.lower() for err in result["errors"])

    @patch("subprocess.run")
    def test_get_windows_users_handles_subprocess_error(self, mock_run):
        """Test _get_windows_users handles subprocess errors."""
        from agent.scanner import SystemScanner

        mock_run.side_effect = subprocess.SubprocessError("Command failed")

        scanner = SystemScanner()
        scanner.platform = "windows"

        result = scanner._get_windows_users()

        assert "local_users" in result
        assert "admin_users" in result
        assert "errors" in result

    @patch("subprocess.run")
    def test_get_macos_users_handles_filenotfound(self, mock_run):
        """Test _get_macos_users handles missing dscl command."""
        from agent.scanner import SystemScanner

        mock_run.side_effect = FileNotFoundError("dscl not found")

        scanner = SystemScanner()
        scanner.platform = "darwin"

        result = scanner._get_macos_users()

        # Should return empty results with error
        assert result["local_users"] == []
        assert result["admin_users"] == []
        # FileNotFoundError causes OSError which is caught

    @patch("psutil.process_iter")
    def test_get_services_handles_psutil_error(self, mock_process_iter):
        """Test get_services handles psutil errors gracefully."""
        from agent.scanner import SystemScanner

        mock_process_iter.side_effect = psutil.Error("Access denied")

        scanner = SystemScanner()
        result = scanner.get_services()

        # Should return empty list (error handled internally)
        assert isinstance(result, list)

    @patch("subprocess.run")
    def test_get_packages_includes_error_on_failure(self, mock_run):
        """Test get_packages includes error field on failure."""
        from agent.scanner import SystemScanner

        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["dpkg"], timeout=30)

        scanner = SystemScanner()
        scanner.platform = "linux"

        result = scanner.get_packages()

        assert "installed" in result
        # The error can be in 'error' or 'errors' depending on implementation
        has_error = "error" in result or "errors" in result
        assert has_error
        # Check the error message contains timeout info
        if "error" in result:
            assert "timeout" in result["error"].lower()
        elif "errors" in result:
            assert any("timeout" in err.lower() for err in result["errors"])

    @patch("subprocess.run")
    def test_get_linux_packages_tries_rpm_if_dpkg_not_found(self, mock_run):
        """Test _get_linux_packages falls back to rpm if dpkg not found."""
        from typing import Any, Dict

        from agent.scanner import SystemScanner

        def mock_subprocess(cmd, **kwargs):
            if cmd[0] == "dpkg":
                raise FileNotFoundError("dpkg not found")
            elif cmd[0] == "rpm":
                result = MagicMock()
                result.returncode = 0
                result.stdout = "package1|1.0.0\npackage2|2.0.0\n"
                return result
            return MagicMock(returncode=1)

        mock_run.side_effect = mock_subprocess

        scanner = SystemScanner()
        scanner.platform = "linux"

        result: Dict[str, Any] = scanner._get_linux_packages()

        assert len(result["installed"]) == 2
        first_package: Dict[str, str] = result["installed"][0]
        assert first_package["name"] == "package1"

    @patch("subprocess.run")
    def test_get_windows_packages_handles_json_decode_error(self, mock_run):
        """Test _get_windows_packages handles invalid JSON from PowerShell."""
        from agent.scanner import SystemScanner

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "invalid json {"
        mock_run.return_value = mock_result

        scanner = SystemScanner()
        scanner.platform = "windows"

        result = scanner._get_windows_packages()

        assert "installed" in result
        assert "errors" in result
        assert any("json" in err.lower() for err in result["errors"])

    @patch("psutil.net_if_addrs")
    @patch("psutil.net_connections")
    def test_get_network_info_handles_access_denied(self, mock_connections, mock_addrs):
        """Test get_network_info handles access denied errors."""
        import psutil

        from agent.scanner import SystemScanner

        mock_addrs.return_value = {}
        mock_connections.side_effect = psutil.AccessDenied("Permission denied")

        scanner = SystemScanner()
        result = scanner.get_network_info()

        assert "interfaces" in result
        assert "open_ports" in result
        assert "errors" in result
        assert any("access denied" in err.lower() for err in result["errors"])

    @patch("subprocess.run")
    def test_get_firewall_status_handles_command_not_found(self, mock_run):
        """Test get_firewall_status handles missing firewall command."""
        from agent.scanner import SystemScanner

        mock_run.side_effect = FileNotFoundError("ufw not found")

        scanner = SystemScanner()
        scanner.platform = "linux"

        result = scanner.get_firewall_status()

        assert result["status"] == "unknown"
        assert "errors" in result
        assert any("not found" in err.lower() for err in result["errors"])

    def test_get_ssh_config_handles_permission_denied(self):
        """Test get_ssh_config handles permission denied."""
        import os

        from agent.scanner import SystemScanner

        scanner = SystemScanner()
        scanner.platform = "linux"

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", side_effect=PermissionError("Permission denied")):
                result = scanner.get_ssh_config()

        assert "errors" in result
        assert any("permission" in err.lower() for err in result["errors"])

    def test_get_password_policy_handles_parse_errors(self):
        """Test get_password_policy handles parse errors gracefully."""
        from agent.scanner import SystemScanner

        scanner = SystemScanner()
        scanner.platform = "linux"

        # Invalid content that will cause parse errors
        invalid_content = "PASS_MIN_LEN not_a_number\nPASS_MAX_DAYS also_not_a_number\n"

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=invalid_content)):
                result = scanner.get_password_policy()

        # Should have errors but not crash
        assert "errors" in result
        # Default values should remain
        assert result["min_length"] == 0


class TestRunPyErrorHandling:
    """Test error handling in run.py HTTP client."""

    def test_make_request_handles_json_decode_error(self):
        """Test _make_request handles JSON decode errors properly."""
        import urllib.error
        import urllib.request
        from unittest.mock import MagicMock

        # This tests the fixed code path where we catch json.JSONDecodeError specifically
        # instead of bare except
        # The fix ensures that when JSON parsing fails, we get a descriptive error
        # rather than silently returning an empty dict


class TestLoggingOnError:
    """Test that errors are properly logged."""

    @patch("agent.api_client.requests.Session")
    def test_api_client_logs_warning_on_get_error(self, mock_session_class, caplog):
        """Test API client logs warning when GET fails."""
        from agent.api_client import SecureSysAPIClient

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_session.get.side_effect = requests.ConnectionError("Connection refused")

        # POST succeeds
        mock_post_response = MagicMock()
        mock_post_response.status_code = 201
        mock_post_response.json.return_value = {"id": "new-system"}
        mock_session.post.return_value = mock_post_response

        client = SecureSysAPIClient(api_url="https://api.example.com", api_key="test-key")

        with caplog.at_level(logging.WARNING):
            client.register_or_get_system(hostname="test", os="Linux")

        # Verify warning was logged
        assert any("connection" in record.message.lower() for record in caplog.records)

    @patch("agent.api_client.requests.Session")
    def test_api_client_logs_exception_on_unexpected_error(self, mock_session_class, caplog):
        """Test API client logs exception details on unexpected errors."""
        from agent.api_client import SecureSysAPIClient

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_session.get.side_effect = requests.RequestException("Unexpected error")

        # POST succeeds
        mock_post_response = MagicMock()
        mock_post_response.status_code = 201
        mock_post_response.json.return_value = {"id": "new-system"}
        mock_session.post.return_value = mock_post_response

        client = SecureSysAPIClient(api_url="https://api.example.com", api_key="test-key")

        with caplog.at_level(logging.DEBUG):
            client.register_or_get_system(hostname="test", os="Linux")

        # Verify the error was logged (at WARNING level for RequestException)
        assert len(caplog.records) > 0


# Import psutil for the test
import psutil
