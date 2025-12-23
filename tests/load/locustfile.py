"""
SecureSys Auditor - Load Testing with Locust
Run with: locust -f locustfile.py --host=https://api.securesys.io
"""

import json
import random
import time
from datetime import datetime, timedelta
from typing import Dict, List

from locust import HttpUser, TaskSet, task, between, events
from locust.runners import MasterRunner


class ScanSubmissionTasks(TaskSet):
    """Tasks related to scan submission and retrieval."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.scan_ids: List[str] = []
        self.system_hosts = [
            'webserver-01.example.com',
            'database-01.example.com',
            'cache-01.example.com',
            'worker-01.example.com',
            'api-01.example.com',
        ]
    
    def on_start(self):
        """Called when a simulated user starts executing this TaskSet."""
        # Authenticate if needed
        pass
    
    def generate_scan_payload(self) -> Dict:
        """Generate a realistic scan payload."""
        hostname = random.choice(self.system_hosts)
        num_findings = random.randint(5, 50)
        
        findings = []
        for i in range(num_findings):
            findings.append({
                'title': f'Finding {i + 1}: {random.choice(["CVE-2023-1234", "CWE-79", "OWASP-A01", "Missing patch"])}',
                'severity': random.choice(['critical', 'high', 'medium', 'low', 'info']),
                'description': 'Detailed description of the security finding.',
                'recommendation': 'Recommended remediation steps.',
                'affected_component': f'/usr/local/bin/app-{random.randint(1, 10)}',
            })
        
        return {
            'hostname': hostname,
            'scan_type': random.choice(['vulnerability', 'compliance', 'configuration']),
            'agent_version': '2.0.0',
            'started_at': (datetime.utcnow() - timedelta(minutes=random.randint(1, 5))).isoformat() + 'Z',
            'completed_at': datetime.utcnow().isoformat() + 'Z',
            'findings': findings,
            'metadata': {
                'os': 'Ubuntu 22.04',
                'kernel': '5.15.0-generic',
                'agent_id': f'agent-{random.randint(1, 100)}',
            },
        }
    
    @task(3)
    def submit_scan(self):
        """Submit a new security scan."""
        payload = self.generate_scan_payload()
        
        with self.client.post(
            '/api/v1/scans/',
            json=payload,
            headers={'Content-Type': 'application/json'},
            catch_response=True,
            name='/api/v1/scans/ [POST]'
        ) as response:
            if response.status_code == 201:
                try:
                    scan_id = response.json().get('id')
                    if scan_id:
                        self.scan_ids.append(scan_id)
                        # Keep only last 100 scan IDs
                        if len(self.scan_ids) > 100:
                            self.scan_ids = self.scan_ids[-100:]
                    response.success()
                except json.JSONDecodeError:
                    response.failure('Invalid JSON response')
            else:
                response.failure(f'Status code: {response.status_code}')
    
    @task(5)
    def list_scans(self):
        """List scans with pagination."""
        page = random.randint(1, 5)
        page_size = random.choice([10, 20, 50])
        
        self.client.get(
            f'/api/v1/scans/?page={page}&page_size={page_size}',
            name='/api/v1/scans/ [GET]'
        )
    
    @task(2)
    def get_scan_detail(self):
        """Get details of a specific scan."""
        if not self.scan_ids:
            return
        
        scan_id = random.choice(self.scan_ids)
        self.client.get(
            f'/api/v1/scans/{scan_id}/',
            name='/api/v1/scans/{id}/ [GET]'
        )
    
    @task(1)
    def get_scan_findings(self):
        """Get findings for a specific scan."""
        if not self.scan_ids:
            return
        
        scan_id = random.choice(self.scan_ids)
        self.client.get(
            f'/api/v1/scans/{scan_id}/findings/',
            name='/api/v1/scans/{id}/findings/ [GET]'
        )


class DashboardTasks(TaskSet):
    """Tasks related to dashboard and reporting."""
    
    @task(3)
    def get_dashboard_stats(self):
        """Fetch dashboard statistics."""
        self.client.get(
            '/api/v1/dashboard/stats/',
            name='/api/v1/dashboard/stats/'
        )
    
    @task(1)
    def get_severity_breakdown(self):
        """Get severity breakdown."""
        self.client.get(
            '/api/v1/dashboard/severity-breakdown/',
            name='/api/v1/dashboard/severity-breakdown/'
        )
    
    @task(1)
    def get_recent_activity(self):
        """Get recent activity."""
        self.client.get(
            '/api/v1/dashboard/recent-activity/',
            name='/api/v1/dashboard/recent-activity/'
        )


class WebhookTasks(TaskSet):
    """Tasks to simulate webhook processing load."""
    
    @task(1)
    def list_webhooks(self):
        """List webhook endpoints."""
        self.client.get(
            '/api/v1/webhooks/',
            name='/api/v1/webhooks/'
        )
    
    @task(1)
    def get_webhook_stats(self):
        """Get webhook delivery statistics."""
        self.client.get(
            '/api/v1/webhooks/stats/',
            name='/api/v1/webhooks/stats/'
        )


class SecureSysUser(HttpUser):
    """
    Simulated SecureSys user.
    
    Represents a typical API consumer (agent or dashboard user).
    """
    
    # Wait time between tasks (1-5 seconds)
    wait_time = between(1, 5)
    
    # Task weights
    tasks = {
        ScanSubmissionTasks: 3,
        DashboardTasks: 2,
        WebhookTasks: 1,
    }
    
    def on_start(self):
        """Called when a simulated user starts."""
        # Set authentication headers
        self.client.headers['Authorization'] = f'Bearer {self.environment.parsed_options.api_key or "test-key"}'
        self.client.headers['User-Agent'] = 'SecureSys-LoadTest/1.0'
    
    @task(1)
    def health_check(self):
        """Periodic health check."""
        self.client.get('/api/v1/health/')


class AgentUser(HttpUser):
    """
    Simulated SecureSys Agent.
    
    Agents submit scans at regular intervals.
    """
    
    # Agents submit scans every 30-60 seconds
    wait_time = between(30, 60)
    
    def on_start(self):
        """Called when a simulated agent starts."""
        self.client.headers['Authorization'] = f'Bearer {self.environment.parsed_options.api_key or "test-key"}'
        self.client.headers['User-Agent'] = 'SecureSys-Agent/2.0'
        self.client.headers['X-Agent-ID'] = f'agent-{random.randint(1, 1000)}'
    
    @task
    def submit_scan(self):
        """Submit a security scan."""
        payload = self._generate_scan_payload()
        
        self.client.post(
            '/api/v1/scans/',
            json=payload,
            name='/api/v1/scans/ [Agent]'
        )
    
    def _generate_scan_payload(self) -> Dict:
        """Generate agent scan payload."""
        return {
            'hostname': f'host-{random.randint(1, 100)}.example.com',
            'scan_type': 'vulnerability',
            'agent_version': '2.0.0',
            'started_at': (datetime.utcnow() - timedelta(minutes=2)).isoformat() + 'Z',
            'completed_at': datetime.utcnow().isoformat() + 'Z',
            'findings': [
                {
                    'title': f'CVE-2023-{random.randint(1000, 9999)}',
                    'severity': random.choice(['critical', 'high', 'medium']),
                    'description': 'Security vulnerability detected.',
                    'recommendation': 'Update to latest version.',
                }
                for _ in range(random.randint(1, 20))
            ],
        }


# Event hooks for custom reporting
@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Called when the load test starts."""
    print("=" * 60)
    print("SecureSys Auditor Load Test Starting")
    print("=" * 60)


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Called when the load test stops."""
    print("=" * 60)
    print("SecureSys Auditor Load Test Complete")
    print("=" * 60)


@events.request.add_listener
def on_request(request_type, name, response_time, response_length, response, context, exception, **kwargs):
    """Called on every request."""
    if exception:
        print(f"Request failed: {name} - {exception}")


# Custom command line arguments
@events.init_command_line_parser.add_listener
def add_custom_arguments(parser):
    """Add custom command line arguments."""
    parser.add_argument(
        '--api-key',
        type=str,
        default='',
        help='API key for authentication'
    )
    parser.add_argument(
        '--scenario',
        type=str,
        choices=['normal', 'spike', 'stress', 'soak'],
        default='normal',
        help='Load test scenario to run'
    )


# Scenario-based configuration
@events.init.add_listener
def on_locust_init(environment, **kwargs):
    """Configure test based on scenario."""
    if isinstance(environment.runner, MasterRunner):
        scenario = environment.parsed_options.scenario
        
        if scenario == 'spike':
            print("Running SPIKE test scenario")
            # Spike: sudden traffic surge
            environment.runner.target_user_count = 200
            
        elif scenario == 'stress':
            print("Running STRESS test scenario")
            # Stress: find breaking point
            environment.runner.target_user_count = 500
            
        elif scenario == 'soak':
            print("Running SOAK test scenario")
            # Soak: sustained load over time
            environment.runner.target_user_count = 100
            
        else:
            print("Running NORMAL load test scenario")
            environment.runner.target_user_count = 50
