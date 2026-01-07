#!/usr/bin/env python3
"""
API Testing Script for SecureSys Auditor

This script tests all available API endpoints with the synthetic data.
Run this after generating synthetic data to verify all functions work.

Usage:
    python scripts/test_all_apis.py
"""

from datetime import datetime

import requests

# Configuration
BASE_URL = "http://127.0.0.1:8000/api/v1"
SCANNING_URL = f"{BASE_URL}/scanning"

# Test credentials
TEST_EMAIL = "test@test.com"
TEST_PASSWORD = "test123"

# Global session for authenticated requests
session = requests.Session()
token = None


def print_header(title: str):
    """Print a formatted header."""
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print("=" * 60)


def print_result(name: str, success: bool, details: str = ""):
    """Print test result."""
    icon = "✅" if success else "❌"
    print(f"  {icon} {name}")
    if details:
        print(f"     └─ {details}")


def authenticate():
    """Get JWT token for authenticated requests."""
    global token

    print_header("🔐 AUTHENTICATION")

    try:
        response = session.post(f"{BASE_URL}/auth/login/", json={"email": TEST_EMAIL, "password": TEST_PASSWORD})

        if response.status_code == 200:
            data = response.json()
            token = data.get("access")
            session.headers.update({"Authorization": f"Bearer {token}"})
            print_result("Login", True, f"Token obtained for {TEST_EMAIL}")
            return True
        else:
            print_result("Login", False, f"Status: {response.status_code}")
            return False
    except Exception as e:
        print_result("Login", False, str(e))
        return False


def test_health_check():
    """Test health check endpoints."""
    print_header("🏥 HEALTH CHECKS")

    endpoints = [
        (f"{BASE_URL}/health/", "Core Health"),
        (f"{SCANNING_URL}/health/", "Scanning Health"),
    ]

    for url, name in endpoints:
        try:
            response = session.get(url)
            success = response.status_code == 200
            print_result(name, success, f"Status: {response.status_code}")
        except Exception as e:
            print_result(name, False, str(e))


def test_user_endpoints():
    """Test user-related endpoints."""
    print_header("👥 USER ENDPOINTS")

    # Get current user
    try:
        response = session.get(f"{BASE_URL}/users/me/")
        success = response.status_code == 200
        if success:
            user = response.json()
            print_result("Get Current User", True, f"User: {user.get('email')}")
        else:
            print_result("Get Current User", False, f"Status: {response.status_code}")
    except Exception as e:
        print_result("Get Current User", False, str(e))

    # List users
    try:
        response = session.get(f"{BASE_URL}/users/")
        success = response.status_code == 200
        if success:
            users = response.json()
            count = len(users.get("results", users)) if isinstance(users, dict) else len(users)
            print_result("List Users", True, f"Found {count} users")
        else:
            print_result("List Users", False, f"Status: {response.status_code}")
    except Exception as e:
        print_result("List Users", False, str(e))


def test_system_endpoints():
    """Test system management endpoints."""
    print_header("🖥️  SYSTEM ENDPOINTS")

    systems = []

    # List systems
    try:
        response = session.get(f"{SCANNING_URL}/systems/")
        success = response.status_code == 200
        if success:
            data = response.json()
            systems = data.get("results", data) if isinstance(data, dict) else data
            print_result("List Systems", True, f"Found {len(systems)} systems")
        else:
            print_result("List Systems", False, f"Status: {response.status_code}")
    except Exception as e:
        print_result("List Systems", False, str(e))

    # Get single system
    if systems:
        try:
            system_id = systems[0].get("id")
            response = session.get(f"{SCANNING_URL}/systems/{system_id}/")
            success = response.status_code == 200
            if success:
                system = response.json()
                print_result("Get System Detail", True, f"Hostname: {system.get('hostname')}")
            else:
                print_result("Get System Detail", False, f"Status: {response.status_code}")
        except Exception as e:
            print_result("Get System Detail", False, str(e))

        # Get system scans
        try:
            response = session.get(f"{SCANNING_URL}/systems/{system_id}/scans/")
            success = response.status_code == 200
            if success:
                scans = response.json()
                print_result("Get System Scans", True, f"Found {len(scans)} scans")
            else:
                print_result("Get System Scans", False, f"Status: {response.status_code}")
        except Exception as e:
            print_result("Get System Scans", False, str(e))

    # Filter systems by environment
    try:
        response = session.get(f"{SCANNING_URL}/systems/", params={"environment": "production"})
        success = response.status_code == 200
        if success:
            data = response.json()
            count = len(data.get("results", data)) if isinstance(data, dict) else len(data)
            print_result("Filter by Environment", True, f"Found {count} production systems")
        else:
            print_result("Filter by Environment", False, f"Status: {response.status_code}")
    except Exception as e:
        print_result("Filter by Environment", False, str(e))

    return systems


def test_scan_endpoints(systems):
    """Test scan management endpoints."""
    print_header("🔍 SCAN ENDPOINTS")

    scans = []

    # List scans
    try:
        response = session.get(f"{SCANNING_URL}/scans/")
        success = response.status_code == 200
        if success:
            data = response.json()
            scans = data.get("results", data) if isinstance(data, dict) else data
            print_result("List Scans", True, f"Found {len(scans)} scans")
        else:
            print_result("List Scans", False, f"Status: {response.status_code}")
    except Exception as e:
        print_result("List Scans", False, str(e))

    # Get single scan
    if scans:
        try:
            scan_id = scans[0].get("id")
            response = session.get(f"{SCANNING_URL}/scans/{scan_id}/")
            success = response.status_code == 200
            if success:
                scan = response.json()
                print_result("Get Scan Detail", True, f"Status: {scan.get('status')}")
            else:
                print_result("Get Scan Detail", False, f"Status: {response.status_code}")
        except Exception as e:
            print_result("Get Scan Detail", False, str(e))

        # Get scan findings
        try:
            response = session.get(f"{SCANNING_URL}/scans/{scan_id}/findings/")
            success = response.status_code == 200
            if success:
                findings = response.json()
                print_result("Get Scan Findings", True, f"Found {len(findings)} findings")
            else:
                print_result("Get Scan Findings", False, f"Status: {response.status_code}")
        except Exception as e:
            print_result("Get Scan Findings", False, str(e))

        # Get scan summary
        try:
            response = session.get(f"{SCANNING_URL}/scans/{scan_id}/summary/")
            success = response.status_code == 200
            if success:
                summary = response.json()
                print_result("Get Scan Summary", True, f"Risk Score: {summary.get('risk_score')}")
            else:
                print_result("Get Scan Summary", False, f"Status: {response.status_code}")
        except Exception as e:
            print_result("Get Scan Summary", False, str(e))

    # Filter scans by status
    try:
        response = session.get(f"{SCANNING_URL}/scans/", params={"status": "completed"})
        success = response.status_code == 200
        if success:
            data = response.json()
            count = len(data.get("results", data)) if isinstance(data, dict) else len(data)
            print_result("Filter by Status", True, f"Found {count} completed scans")
        else:
            print_result("Filter by Status", False, f"Status: {response.status_code}")
    except Exception as e:
        print_result("Filter by Status", False, str(e))

    return scans


def test_finding_endpoints():
    """Test finding management endpoints."""
    print_header("⚠️  FINDING ENDPOINTS")

    findings = []

    # List findings
    try:
        response = session.get(f"{SCANNING_URL}/findings/")
        success = response.status_code == 200
        if success:
            data = response.json()
            findings = data.get("results", data) if isinstance(data, dict) else data
            print_result("List Findings", True, f"Found {len(findings)} findings")
        else:
            print_result("List Findings", False, f"Status: {response.status_code}")
    except Exception as e:
        print_result("List Findings", False, str(e))

    # Get single finding
    if findings:
        try:
            finding_id = findings[0].get("id")
            response = session.get(f"{SCANNING_URL}/findings/{finding_id}/")
            success = response.status_code == 200
            if success:
                finding = response.json()
                print_result("Get Finding Detail", True, f"Title: {finding.get('title')[:50]}...")
            else:
                print_result("Get Finding Detail", False, f"Status: {response.status_code}")
        except Exception as e:
            print_result("Get Finding Detail", False, str(e))

        # Get recommendations for finding
        try:
            response = session.get(f"{SCANNING_URL}/findings/{finding_id}/recommendations/")
            if response.status_code == 200:
                recs = response.json()
                count = len(recs) if isinstance(recs, list) else 1
                print_result("Get Recommendations", True, f"Found {count} recommendations")
            else:
                # Endpoint might be different
                print_result("Get Recommendations", False, f"Status: {response.status_code}")
        except Exception as e:
            print_result("Get Recommendations", False, str(e))

    # Filter findings by severity
    try:
        response = session.get(f"{SCANNING_URL}/findings/", params={"severity": "high"})
        success = response.status_code == 200
        if success:
            data = response.json()
            count = len(data.get("results", data)) if isinstance(data, dict) else len(data)
            print_result("Filter by Severity", True, f"Found {count} high severity findings")
        else:
            print_result("Filter by Severity", False, f"Status: {response.status_code}")
    except Exception as e:
        print_result("Filter by Severity", False, str(e))

    # Filter unresolved findings
    try:
        response = session.get(f"{SCANNING_URL}/findings/", params={"is_resolved": "false"})
        success = response.status_code == 200
        if success:
            data = response.json()
            count = len(data.get("results", data)) if isinstance(data, dict) else len(data)
            print_result("Filter Unresolved", True, f"Found {count} unresolved findings")
        else:
            print_result("Filter Unresolved", False, f"Status: {response.status_code}")
    except Exception as e:
        print_result("Filter Unresolved", False, str(e))

    return findings


def test_recommendation_endpoints():
    """Test recommendation endpoints."""
    print_header("💡 RECOMMENDATION ENDPOINTS")

    # List recommendations
    try:
        response = session.get(f"{SCANNING_URL}/recommendations/")
        success = response.status_code == 200
        if success:
            data = response.json()
            recs = data.get("results", data) if isinstance(data, dict) else data
            print_result("List Recommendations", True, f"Found {len(recs)} recommendations")

            # Get single recommendation
            if recs:
                rec_id = recs[0].get("id")
                response = session.get(f"{SCANNING_URL}/recommendations/{rec_id}/")
                success = response.status_code == 200
                if success:
                    rec = response.json()
                    print_result("Get Recommendation", True, f"Title: {rec.get('title')[:50]}...")
                else:
                    print_result("Get Recommendation", False, f"Status: {response.status_code}")
        else:
            print_result("List Recommendations", False, f"Status: {response.status_code}")
    except Exception as e:
        print_result("List Recommendations", False, str(e))


def test_dashboard_endpoints():
    """Test dashboard statistics endpoints."""
    print_header("📊 DASHBOARD ENDPOINTS")

    # Try scanning dashboard stats
    try:
        response = session.get(f"{SCANNING_URL}/dashboard/stats/")
        success = response.status_code == 200
        if success:
            stats = response.json()
            print_result("Dashboard Stats", True, f"Total Systems: {stats.get('total_systems', 'N/A')}")

            # Print detailed stats if available
            if "findings_by_severity" in stats:
                print(f"     └─ Findings by severity: {stats['findings_by_severity']}")
        else:
            print_result("Dashboard Stats", False, f"Status: {response.status_code}")
    except Exception as e:
        print_result("Dashboard Stats", False, str(e))

    # Try core dashboard stats
    try:
        response = session.get(f"{BASE_URL}/dashboard/stats/")
        success = response.status_code == 200
        if success:
            stats = response.json()
            print_result("Core Dashboard Stats", True, "Data retrieved")
        else:
            print_result("Core Dashboard Stats", False, f"Status: {response.status_code}")
    except Exception as e:
        print_result("Core Dashboard Stats", False, str(e))


def test_report_endpoints(scans):
    """Test report generation endpoints."""
    print_header("📄 REPORT ENDPOINTS")

    # Find a completed scan
    completed_scan = None
    for scan in scans:
        if scan.get("status") == "completed":
            completed_scan = scan
            break

    if not completed_scan:
        print_result("Report Generation", False, "No completed scans available")
        return

    scan_id = completed_scan.get("id")

    # Request report generation (async)
    try:
        response = session.post(
            f"{BASE_URL}/reports/generate/",
            json={
                "scan_id": scan_id,
                "report_type": "executive",
                "async": False,  # Synchronous for testing
                "company_name": "Test Organization",
            },
        )

        if response.status_code in [200, 201, 202]:
            print_result("Generate Report", True, f"Report requested for scan {scan_id[:8]}...")
        else:
            print_result("Generate Report", False, f"Status: {response.status_code}")
    except Exception as e:
        print_result("Generate Report", False, str(e))


def test_webhook_endpoints():
    """Test webhook management endpoints."""
    print_header("🔗 WEBHOOK ENDPOINTS")

    # List webhooks
    try:
        response = session.get(f"{BASE_URL}/webhooks/")
        success = response.status_code == 200
        if success:
            data = response.json()
            webhooks = data.get("results", data) if isinstance(data, dict) else data
            print_result("List Webhooks", True, f"Found {len(webhooks)} webhooks")
        else:
            print_result("List Webhooks", False, f"Status: {response.status_code}")
    except Exception as e:
        print_result("List Webhooks", False, str(e))


def test_submit_scan(systems):
    """Test submitting a new scan."""
    print_header("📤 SCAN SUBMISSION")

    if not systems:
        print_result("Submit Scan", False, "No systems available")
        return

    system_id = systems[0].get("id")

    # Submit a new scan
    try:
        scan_payload = {
            "system_id": system_id,
            "scan_type": "quick",
            "scan_payload": {
                "agent_version": "1.5.0",
                "system_info": {
                    "hostname": systems[0].get("hostname"),
                    "uptime_hours": 720,
                },
                "collectors": {
                    "packages": {"status": "completed", "items_checked": 500},
                    "services": {"status": "completed", "items_checked": 100},
                },
            },
        }

        response = session.post(f"{SCANNING_URL}/scans/submit/", json=scan_payload)

        if response.status_code in [200, 201, 202]:
            result = response.json()
            print_result("Submit Scan", True, f"Scan ID: {result.get('scan_id', 'N/A')[:8]}...")
        else:
            print_result("Submit Scan", False, f"Status: {response.status_code} - {response.text[:100]}")
    except Exception as e:
        print_result("Submit Scan", False, str(e))


def print_summary():
    """Print final summary."""
    print_header("📋 API TEST SUMMARY")
    print(
        """
  All major API endpoints have been tested!

  Available Features:
  • User management and authentication
  • System CRUD operations
  • Scan submission and retrieval
  • Finding management with filtering
  • Recommendations for remediation
  • Dashboard statistics
  • Report generation
  • Webhook management

  To explore the data visually:
  → Dashboard: http://127.0.0.1:5173/dashboard
  → API Docs:  http://127.0.0.1:8000/api/docs/

  Login credentials:
  → Email:    test@test.com
  → Password: test123
"""
    )


def main():
    """Main test runner."""
    print("\n" + "=" * 60)
    print("  🔐 SecureSys Auditor - API Test Suite")
    print("=" * 60)
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Base URL: {BASE_URL}")

    # Authenticate first
    if not authenticate():
        print("\n❌ Authentication failed. Cannot proceed with tests.")
        return

    # Run all tests
    test_health_check()
    test_user_endpoints()
    systems = test_system_endpoints()
    scans = test_scan_endpoints(systems)
    test_finding_endpoints()
    test_recommendation_endpoints()
    test_dashboard_endpoints()
    test_report_endpoints(scans)
    test_webhook_endpoints()
    test_submit_scan(systems)

    print_summary()


if __name__ == "__main__":
    main()
