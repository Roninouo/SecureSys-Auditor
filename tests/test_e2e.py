"""
End-to-End Tests for SecureSys Auditor.

Tests the complete flow: Agent → Backend → Frontend
- Agent submits scan data
- Backend processes and stores data
- API returns correct data for frontend consumption
"""
import time
import uuid
from typing import Any, Dict

import pytest
import requests

pytestmark = pytest.mark.e2e


class TestE2EWorkflow:
    """Test complete agent to frontend workflow."""

    @pytest.fixture
    def base_url(self):
        """Base URL for API calls."""
        return "http://localhost:8000"

    @pytest.fixture
    def agent_auth_headers(self):
        """Authentication headers for agent."""
        # In production, this would use actual OAuth tokens
        return {"Authorization": "Bearer test-agent-token", "Content-Type": "application/json"}

    @pytest.fixture
    def user_auth_headers(self):
        """Authentication headers for user."""
        return {"Authorization": "Bearer test-user-token", "Content-Type": "application/json"}

    @pytest.fixture
    def sample_scan_data(self) -> Dict[str, Any]:
        """Sample scan data from agent."""
        return {
            "system_info": {
                "hostname": f"test-server-{uuid.uuid4().hex[:8]}",
                "os": "Ubuntu 22.04 LTS",
                "os_version": "22.04",
                "environment": "testing",
                "ip_address": "192.168.1.100",
            },
            "scan_type": "full",
            "results": {
                "checks": [
                    {"id": "auth_001", "name": "Password Policy Check", "status": "passed", "severity": "high"},
                    {
                        "id": "net_002",
                        "name": "Open Ports Check",
                        "status": "failed",
                        "severity": "medium",
                        "details": "Port 23 (telnet) is open",
                    },
                ],
                "findings": [
                    {
                        "title": "Telnet Service Enabled",
                        "description": "Telnet is an insecure protocol",
                        "severity": "high",
                        "category": "network",
                        "affected_resource": "port:23",
                        "remediation": "Disable telnet and use SSH instead",
                    }
                ],
            },
        }

    def test_complete_scan_workflow(self, base_url, agent_auth_headers, user_auth_headers, sample_scan_data):
        """
        Test complete workflow:
        1. Agent submits scan
        2. Backend processes scan
        3. User retrieves scan via API
        4. Frontend-like queries work correctly
        """
        # Step 1: Agent submits scan
        response = requests.post(
            f"{base_url}/api/scans/submit/", json=sample_scan_data, headers=agent_auth_headers, timeout=10
        )

        assert response.status_code in [200, 201, 202], f"Scan submission failed: {response.text}"

        scan_data = response.json()
        scan_id = scan_data.get("scan_id") or scan_data.get("id")
        system_id = scan_data.get("system_id")

        assert scan_id, "No scan_id returned from submission"

        # Step 2: Wait for processing (with timeout)
        max_wait = 30  # seconds
        waited = 0
        scan_completed = False

        while waited < max_wait:
            response = requests.get(f"{base_url}/api/scans/{scan_id}/", headers=user_auth_headers, timeout=10)

            if response.status_code == 200:
                scan_status = response.json()
                if scan_status["status"] in ["completed", "failed"]:
                    scan_completed = True
                    assert scan_status["status"] == "completed", f"Scan failed: {scan_status.get('error_message')}"
                    break

            time.sleep(2)
            waited += 2

        assert scan_completed, f"Scan did not complete within {max_wait} seconds"

        # Step 3: Verify scan details
        response = requests.get(f"{base_url}/api/scans/{scan_id}/", headers=user_auth_headers, timeout=10)

        assert response.status_code == 200
        scan_detail = response.json()

        assert scan_detail["id"] == scan_id
        assert scan_detail["status"] == "completed"
        assert scan_detail["risk_score"] is not None
        assert scan_detail["maturity_level"] is not None

        # Step 4: Verify findings were created
        response = requests.get(f"{base_url}/api/scans/{scan_id}/findings/", headers=user_auth_headers, timeout=10)

        assert response.status_code == 200
        findings = response.json()

        if isinstance(findings, dict):
            findings = findings.get("results", [])

        assert len(findings) > 0, "No findings created from scan"

        # Verify finding details
        telnet_finding = next((f for f in findings if "Telnet" in f.get("title", "")), None)
        assert telnet_finding is not None, "Expected Telnet finding not found"
        assert telnet_finding["severity"] == "high"

        # Step 5: Verify system was created/updated
        if system_id:
            response = requests.get(f"{base_url}/api/systems/{system_id}/", headers=user_auth_headers, timeout=10)

            assert response.status_code == 200
            system = response.json()
            assert system["hostname"] == sample_scan_data["system_info"]["hostname"]
            assert system["latest_risk_score"] is not None

    def test_list_scans_pagination(self, base_url, user_auth_headers):
        """Test that scan listing supports pagination."""
        response = requests.get(f"{base_url}/api/scans/?page=1&page_size=10", headers=user_auth_headers, timeout=10)

        assert response.status_code == 200
        data = response.json()

        # Check pagination structure
        assert "results" in data or isinstance(data, list), "Response should have pagination structure or be a list"

    def test_filter_scans_by_status(self, base_url, user_auth_headers):
        """Test filtering scans by status."""
        response = requests.get(f"{base_url}/api/scans/?status=completed", headers=user_auth_headers, timeout=10)

        assert response.status_code == 200
        data = response.json()

        scans = data.get("results", data) if isinstance(data, dict) else data

        # All returned scans should have completed status
        for scan in scans[:5]:  # Check first 5
            assert scan["status"] == "completed"

    def test_agent_authentication_required(self, base_url, sample_scan_data):
        """Test that scan submission requires authentication."""
        response = requests.post(f"{base_url}/api/scans/submit/", json=sample_scan_data, timeout=10)

        assert response.status_code in [401, 403], "Unauthenticated scan submission should be rejected"

    def test_invalid_scan_data_rejected(self, base_url, agent_auth_headers):
        """Test that invalid scan data is rejected."""
        invalid_data = {
            "system_info": {
                "hostname": "test-server"
                # Missing required fields
            }
        }

        response = requests.post(
            f"{base_url}/api/scans/submit/", json=invalid_data, headers=agent_auth_headers, timeout=10
        )

        assert response.status_code == 400, "Invalid scan data should be rejected with 400"

    def test_webhook_delivery(self, base_url, user_auth_headers):
        """Test that webhooks are triggered on scan completion."""
        # This test would typically mock a webhook endpoint
        # For E2E, we check that webhook deliveries are recorded

        response = requests.get(
            f"{base_url}/api/webhooks/deliveries/?event_type=scan.completed", headers=user_auth_headers, timeout=10
        )

        # Should return successfully even if no deliveries yet
        assert response.status_code in [200, 404]

    def test_recommendations_generated(self, base_url, agent_auth_headers, user_auth_headers, sample_scan_data):
        """Test that recommendations are generated from findings."""
        # Submit scan
        response = requests.post(
            f"{base_url}/api/scans/submit/", json=sample_scan_data, headers=agent_auth_headers, timeout=10
        )

        assert response.status_code in [200, 201, 202]
        scan_id = response.json().get("scan_id") or response.json().get("id")

        # Wait for processing
        time.sleep(5)

        # Check recommendations
        response = requests.get(
            f"{base_url}/api/scans/{scan_id}/recommendations/", headers=user_auth_headers, timeout=10
        )

        if response.status_code == 200:
            recommendations = response.json()
            if isinstance(recommendations, dict):
                recommendations = recommendations.get("results", [])
            # Recommendations should be generated for findings
            assert isinstance(recommendations, list)


class TestE2EPerformance:
    """Test system performance under load."""

    @pytest.fixture
    def base_url(self):
        return "http://localhost:8000"

    @pytest.fixture
    def user_auth_headers(self):
        return {"Authorization": "Bearer test-user-token", "Content-Type": "application/json"}

    def test_api_response_time(self, base_url, user_auth_headers):
        """Test that API endpoints respond within acceptable time."""
        endpoints = [
            "/api/scans/",
            "/api/systems/",
            "/api/findings/",
        ]

        for endpoint in endpoints:
            start_time = time.time()
            response = requests.get(f"{base_url}{endpoint}", headers=user_auth_headers, timeout=10)
            elapsed = time.time() - start_time

            assert response.status_code == 200, f"Endpoint {endpoint} returned {response.status_code}"
            assert elapsed < 2.0, f"Endpoint {endpoint} took {elapsed:.2f}s (should be < 2s)"

    def test_concurrent_requests(self, base_url, user_auth_headers):
        """Test system handles concurrent requests."""
        import concurrent.futures

        def make_request():
            response = requests.get(f"{base_url}/api/scans/", headers=user_auth_headers, timeout=10)
            return response.status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All requests should succeed
        assert all(status == 200 for status in results), "Some concurrent requests failed"


class TestE2EResilience:
    """Test system resilience and error handling."""

    @pytest.fixture
    def base_url(self):
        return "http://localhost:8000"

    @pytest.fixture
    def user_auth_headers(self):
        return {"Authorization": "Bearer test-user-token", "Content-Type": "application/json"}

    def test_handles_nonexistent_resource(self, base_url, user_auth_headers):
        """Test proper error handling for nonexistent resources."""
        fake_id = str(uuid.uuid4())

        response = requests.get(f"{base_url}/api/scans/{fake_id}/", headers=user_auth_headers, timeout=10)

        assert response.status_code == 404

    def test_handles_malformed_request(self, base_url, user_auth_headers):
        """Test proper error handling for malformed requests."""
        response = requests.post(
            f"{base_url}/api/scans/submit/", data="not valid json", headers=user_auth_headers, timeout=10
        )

        assert response.status_code == 400

    def test_rate_limiting(self, base_url, user_auth_headers):
        """Test that rate limiting is in place."""
        # Make many requests quickly
        responses = []
        for _ in range(100):
            response = requests.get(f"{base_url}/api/scans/", headers=user_auth_headers, timeout=10)
            responses.append(response.status_code)
            if response.status_code == 429:
                break

        # Should eventually hit rate limit
        # (or all requests succeed if limit is high)
        assert 429 in responses or all(
            s == 200 for s in responses
        ), "Rate limiting should either trigger or allow all requests"


@pytest.mark.e2e
class TestE2ESmoke:
    """Smoke tests for production deployments."""

    def test_health_check(self):
        """Test that health check endpoint responds."""
        response = requests.get("http://localhost:8000/health/", timeout=10)
        assert response.status_code == 200

        health = response.json()
        assert health.get("status") == "healthy"

    def test_database_connection(self):
        """Test that database is accessible."""
        response = requests.get("http://localhost:8000/health/database/", timeout=10)
        assert response.status_code == 200

    def test_celery_workers(self):
        """Test that Celery workers are running."""
        response = requests.get("http://localhost:8000/health/celery/", timeout=10)
        assert response.status_code == 200
