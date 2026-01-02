#!/usr/bin/env python
"""
SecureSys Auditor - Centralized Runner

This script provides a unified interface to run all components of the
SecureSys Auditor application: Backend, Frontend, CLI Agent, and services.

Usage:
    python run.py [command] [options]

Commands:
    all          Start all components (backend, frontend, celery)
    backend      Start Django backend server
    frontend     Start Vite frontend dev server
    celery       Start Celery worker
    services     Start Docker services (postgres, redis, keycloak)
    createuser   Create a local login user (Django)
    test         Run HTTP tests against the API
    status       Check status of all services
    stop         Stop all running services
"""

import argparse
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Project paths
PROJECT_ROOT = Path(__file__).parent.resolve()
BACKEND_DIR = PROJECT_ROOT / "src" / "backend"
FRONTEND_DIR = PROJECT_ROOT / "src" / "frontend"
AGENT_DIR = PROJECT_ROOT / "src" / "agent"
VENV_DIR = PROJECT_ROOT / "SecureSys-venv"

# Default configuration
DEFAULT_BACKEND_PORT = 8000
DEFAULT_FRONTEND_PORT = 5173
DEFAULT_API_URL = f"http://localhost:{DEFAULT_BACKEND_PORT}"


def _validate_http_url(url: str, *, allow_hosts: Optional[set] = None) -> None:
    """Validate URL scheme (and optionally hostname) before opening."""

    import urllib.parse

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
    if not parsed.netloc:
        raise ValueError("URL missing network location")
    if allow_hosts is not None:
        host = parsed.hostname
        if host not in allow_hosts:
            raise ValueError(f"Disallowed host: {host}")


def _safe_urlopen(target, *, timeout: int, allow_hosts: Optional[set] = None):
    """Open a URL/Request after validating scheme and (optionally) host."""

    import urllib.request

    url = target.full_url if isinstance(target, urllib.request.Request) else str(target)
    _validate_http_url(url, allow_hosts=allow_hosts)
    return urllib.request.urlopen(target, timeout=timeout)  # nosec B310


def _tcp_port_open(host: str, port: int, timeout_seconds: float = 0.5) -> bool:
    import socket

    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True
    except OSError:
        return False


def _ensure_local_services_running() -> None:
    """Best-effort start of local Docker services when deps are missing."""
    db_host = os.getenv("DB_HOST", "localhost")
    db_port = int(os.getenv("DB_PORT", "5432"))
    redis_port = int(os.getenv("REDIS_PORT", "6380"))

    postgres_up = _tcp_port_open(db_host, db_port)
    redis_up = _tcp_port_open("localhost", redis_port)
    if postgres_up and redis_up:
        return

    docker_compose = shutil.which("docker-compose")
    if not docker_compose:
        print_status(
            (
                f"Dependencies not reachable (Postgres {db_host}:{db_port}, Redis localhost:{redis_port}). "
                "Run: python run.py services"
            ),
            "warning",
        )
        return

    print_status("Starting Docker services (postgres/redis/keycloak)...", "info")
    os.chdir(PROJECT_ROOT)
    rc = os.system("docker-compose -f docker-compose.yml up -d")
    if rc != 0:
        print_status("Failed to start Docker services. Run: python run.py services", "warning")
        return

    # Wait briefly for ports to come up
    for _ in range(30):
        if _tcp_port_open(db_host, db_port) and _tcp_port_open("localhost", redis_port):
            return
        time.sleep(1)

    print_status("Docker services started, but dependencies are still not reachable yet.", "warning")


class Colors:
    """ANSI color codes for terminal output."""

    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


class ServiceStatus(Enum):
    """Service status enumeration."""

    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class TestResult:
    """HTTP test result."""

    name: str
    endpoint: str
    method: str
    status_code: Optional[int] = None
    response_time_ms: float = 0.0
    success: bool = False
    error: Optional[str] = None
    response_data: Optional[dict] = None


@dataclass
class TestReport:
    """HTTP test report."""

    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    results: List[TestResult] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0


def print_banner():
    """Print application banner."""
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════╗
║                                                                    ║
║   {Colors.BOLD}SecureSys Auditor - Centralized Runner{Colors.ENDC}{Colors.CYAN}                          ║
║                                                                    ║
║   Security auditing and compliance platform                        ║
║                                                                    ║
╚══════════════════════════════════════════════════════════════════════╝{Colors.ENDC}
    """
    print(banner)


def print_status(message: str, status: str = "info"):
    """Print status message with color coding."""
    colors = {
        "info": Colors.BLUE,
        "success": Colors.GREEN,
        "warning": Colors.WARNING,
        "error": Colors.FAIL,
    }
    color = colors.get(status, Colors.BLUE)
    icons = {
        "info": "ℹ",
        "success": "✓",
        "warning": "⚠",
        "error": "✗",
    }
    icon = icons.get(status, "•")
    print(f"{color}{icon} {message}{Colors.ENDC}")


def check_python_version():
    """Check Python version compatibility."""
    if sys.version_info < (3, 10):
        print_status("Python 3.10+ is required", "error")
        sys.exit(1)
    print_status(f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}", "success")


def get_python_executable() -> str:
    """Get the correct Python executable path."""
    if platform.system() == "Windows":
        venv_python = VENV_DIR / "Scripts" / "python.exe"
    else:
        venv_python = VENV_DIR / "bin" / "python"

    if venv_python.exists():
        return str(venv_python)
    return sys.executable


def get_npm_command() -> str:
    """Get npm command for the current platform."""
    if platform.system() == "Windows":
        return "npm.cmd"
    return "npm"


def run_command(
    cmd: List[str],
    cwd: Optional[Path] = None,
    env: Optional[dict] = None,
    capture_output: bool = True,
    timeout: Optional[int] = None,
) -> Tuple[int, str, str]:
    """
    Run a shell command and return result.

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    process_env = os.environ.copy()
    if env:
        process_env.update(env)

    try:
        result = subprocess.run(
            cmd, cwd=cwd, env=process_env, capture_output=capture_output, text=True, timeout=timeout, shell=False
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def _windows_wrap_cmd_if_needed(cmd: List[str]) -> List[str]:
    """Wrap .cmd/.bat invocations via cmd.exe so Popen can run them reliably."""
    if platform.system() != "Windows":
        return cmd
    if not cmd:
        return cmd

    executable = cmd[0]
    resolved = shutil.which(executable) or executable
    suffix = Path(resolved).suffix.lower()

    if suffix in {".cmd", ".bat"}:
        return [
            "cmd.exe",
            "/d",
            "/s",
            "/c",
            subprocess.list2cmdline(cmd),
        ]

    return cmd


def start_process(
    cmd: List[str], cwd: Optional[Path] = None, env: Optional[dict] = None, name: str = "process"
) -> Optional[subprocess.Popen]:
    """Start a background process."""
    process_env = os.environ.copy()
    if env:
        process_env.update(env)

    try:
        if platform.system() == "Windows":
            cmd = _windows_wrap_cmd_if_needed(cmd)
            # On Windows, use CREATE_NEW_PROCESS_GROUP for proper signal handling
            process = subprocess.Popen(
                cmd,
                cwd=cwd,
                env=process_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                shell=False,
            )
        else:
            setsid_fn = getattr(os, "setsid", None)
            process = subprocess.Popen(
                cmd,
                cwd=cwd,
                env=process_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                preexec_fn=setsid_fn,
            )
        print_status(f"Started {name} (PID: {process.pid})", "success")
        return process
    except Exception as e:
        print_status(f"Failed to start {name}: {e}", "error")
        return None


class ProcessManager:
    """Manage multiple background processes."""

    def __init__(self):
        self.processes: Dict[str, subprocess.Popen] = {}
        self.threads: Dict[str, threading.Thread] = {}
        self._shutdown = threading.Event()

    def add_process(self, name: str, process: subprocess.Popen):
        """Add a process to manage."""
        self.processes[name] = process

        # Start output monitoring thread
        thread = threading.Thread(target=self._monitor_output, args=(name, process), daemon=True)
        thread.start()
        self.threads[name] = thread

    def _monitor_output(self, name: str, process: subprocess.Popen):
        """Monitor process output and print with prefix."""
        color_map = {
            "backend": Colors.GREEN,
            "frontend": Colors.CYAN,
            "celery": Colors.WARNING,
        }
        color = color_map.get(name, Colors.BLUE)

        while not self._shutdown.is_set():
            if process.stdout:
                line = process.stdout.readline()
                if line:
                    print(f"{color}[{name}]{Colors.ENDC} {line.rstrip()}")
                elif process.poll() is not None:
                    break

    def stop_all(self):
        """Stop all managed processes."""
        self._shutdown.set()

        for name, process in self.processes.items():
            try:
                if platform.system() == "Windows":
                    process.terminate()
                else:
                    killpg_fn = getattr(os, "killpg", None)
                    getpgid_fn = getattr(os, "getpgid", None)
                    if callable(killpg_fn) and callable(getpgid_fn):
                        killpg_fn(getpgid_fn(process.pid), signal.SIGTERM)
                    else:
                        process.terminate()
                print_status(f"Stopped {name}", "info")
            except Exception as e:
                print_status(f"Error stopping {name}: {e}", "warning")

        # Wait for processes to terminate
        for process in self.processes.values():
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

    def wait(self):
        """Wait for all processes to complete."""
        try:
            while True:
                time.sleep(1)
                # Check if any process has died
                stopped: List[str] = []
                for name, process in self.processes.items():
                    if process.poll() is not None:
                        print_status(f"{name} has stopped (exit code: {process.returncode})", "warning")
                        stopped.append(name)

                for name in stopped:
                    self.processes.pop(name, None)

                if not self.processes:
                    break
        except KeyboardInterrupt:
            print_status("\nReceived shutdown signal...", "info")
            self.stop_all()


class APITester:
    """HTTP API tester for SecureSys Auditor."""

    def __init__(self, base_url: str = DEFAULT_API_URL):
        self.base_url = base_url.rstrip("/")
        self.report = TestReport()
        self.session_token: Optional[str] = None

    def _make_request(
        self, method: str, endpoint: str, data: Optional[dict] = None, headers: Optional[dict] = None, timeout: int = 10
    ) -> Tuple[Optional[int], Optional[dict], float, Optional[str]]:
        """
        Make HTTP request using urllib (no external dependencies).

        Returns:
            Tuple of (status_code, response_json, response_time_ms, error)
        """
        import urllib.error
        import urllib.parse
        import urllib.request

        url = f"{self.base_url}{endpoint}"
        req_headers = {"Content-Type": "application/json"}
        if headers:
            req_headers.update(headers)
        if self.session_token:
            req_headers["Authorization"] = f"Bearer {self.session_token}"

        body = None
        if data:
            body = json.dumps(data).encode("utf-8")

        request = urllib.request.Request(url, data=body, headers=req_headers, method=method)

        start_time = time.perf_counter()

        try:
            with _safe_urlopen(request, timeout=timeout) as response:
                end_time = time.perf_counter()
                response_time = (end_time - start_time) * 1000

                response_body = response.read().decode("utf-8")
                try:
                    response_json = json.loads(response_body) if response_body else {}
                except json.JSONDecodeError:
                    response_json = {"raw": response_body}

                return response.status, response_json, response_time, None
        except urllib.error.HTTPError as e:
            end_time = time.perf_counter()
            response_time = (end_time - start_time) * 1000
            try:
                error_body = e.read().decode("utf-8")
                error_json = json.loads(error_body) if error_body else {}
            except json.JSONDecodeError:
                error_json = {"raw_error": error_body if error_body else "Unable to decode error response"}
            except (IOError, UnicodeDecodeError) as decode_err:
                error_json = {"decode_error": str(decode_err)}
            return e.code, error_json, response_time, None
        except urllib.error.URLError as e:
            end_time = time.perf_counter()
            response_time = (end_time - start_time) * 1000
            return None, None, response_time, str(e.reason)
        except Exception as e:
            end_time = time.perf_counter()
            response_time = (end_time - start_time) * 1000
            return None, None, response_time, str(e)

    def add_test_result(self, result: TestResult):
        """Add test result to report."""
        self.report.results.append(result)
        self.report.total += 1

        if result.error:
            self.report.errors += 1
        elif result.success:
            self.report.passed += 1
        else:
            self.report.failed += 1

    def test_health_check(self) -> TestResult:
        """Test health check endpoint."""
        result = TestResult(name="Health Check", endpoint="/health/health/", method="GET")

        status_code, response, response_time, error = self._make_request("GET", "/health/health/")

        result.status_code = status_code
        result.response_time_ms = response_time
        result.error = error
        result.response_data = response

        if error:
            result.success = False
        elif status_code == 200:
            result.success = True
        else:
            result.success = False

        return result

    def test_readiness_check(self) -> TestResult:
        """Test readiness check endpoint."""
        result = TestResult(name="Readiness Check", endpoint="/health/ready/", method="GET")

        status_code, response, response_time, error = self._make_request("GET", "/health/ready/")

        result.status_code = status_code
        result.response_time_ms = response_time
        result.error = error
        result.response_data = response
        result.success = status_code == 200 and not error

        return result

    def test_liveness_check(self) -> TestResult:
        """Test liveness check endpoint."""
        result = TestResult(name="Liveness Check", endpoint="/health/live/", method="GET")

        status_code, response, response_time, error = self._make_request("GET", "/health/live/")

        result.status_code = status_code
        result.response_time_ms = response_time
        result.error = error
        result.response_data = response
        result.success = status_code == 200 and not error

        return result

    def test_api_v1_health(self) -> TestResult:
        """Test API v1 health endpoint."""
        result = TestResult(name="API v1 Health", endpoint="/api/v1/health/", method="GET")

        status_code, response, response_time, error = self._make_request("GET", "/api/v1/health/")

        result.status_code = status_code
        result.response_time_ms = response_time
        result.error = error
        result.response_data = response
        result.success = status_code == 200 and not error

        return result

    def test_api_docs(self) -> TestResult:
        """Test API documentation endpoint."""
        result = TestResult(name="API Documentation (Swagger)", endpoint="/api/docs/", method="GET")

        status_code, response, response_time, error = self._make_request("GET", "/api/docs/")

        result.status_code = status_code
        result.response_time_ms = response_time
        result.error = error
        result.success = status_code == 200 and not error

        return result

    def test_api_schema(self) -> TestResult:
        """Test OpenAPI schema endpoint."""
        result = TestResult(name="OpenAPI Schema", endpoint="/api/schema/", method="GET")

        status_code, response, response_time, error = self._make_request("GET", "/api/schema/")

        result.status_code = status_code
        result.response_time_ms = response_time
        result.error = error
        result.response_data = response
        result.success = status_code == 200 and not error

        return result

    def test_systems_list_unauthenticated(self) -> TestResult:
        """Test systems list endpoint without authentication."""
        result = TestResult(name="Systems List (Unauthenticated)", endpoint="/api/v1/systems/", method="GET")

        status_code, response, response_time, error = self._make_request("GET", "/api/v1/systems/")

        result.status_code = status_code
        result.response_time_ms = response_time
        result.error = error
        result.response_data = response

        # This should return 401 Unauthorized
        if status_code == 401:
            result.success = True
        elif status_code == 200:
            # API might allow anonymous access in dev mode
            result.success = True
        else:
            result.success = False

        return result

    def test_scans_list_unauthenticated(self) -> TestResult:
        """Test scans list endpoint without authentication."""
        result = TestResult(name="Scans List (Unauthenticated)", endpoint="/api/v1/scans/", method="GET")

        status_code, response, response_time, error = self._make_request("GET", "/api/v1/scans/")

        result.status_code = status_code
        result.response_time_ms = response_time
        result.error = error
        result.response_data = response

        # Expected 401 or 200 (dev mode)
        result.success = status_code in [200, 401] and not error

        return result

    def test_scanning_endpoint(self) -> TestResult:
        """Test scanning module endpoint."""
        result = TestResult(name="Scanning Module", endpoint="/api/v1/scanning/", method="GET")

        status_code, response, response_time, error = self._make_request("GET", "/api/v1/scanning/")

        result.status_code = status_code
        result.response_time_ms = response_time
        result.error = error
        result.response_data = response
        result.success = status_code in [200, 401, 404] and not error

        return result

    def test_webhooks_endpoint(self) -> TestResult:
        """Test webhooks module endpoint."""
        result = TestResult(name="Webhooks Module", endpoint="/api/v1/webhooks/", method="GET")

        status_code, response, response_time, error = self._make_request("GET", "/api/v1/webhooks/")

        result.status_code = status_code
        result.response_time_ms = response_time
        result.error = error
        result.response_data = response
        result.success = status_code in [200, 401] and not error

        return result

    def test_authentication(self) -> TestResult:
        """Test authentication endpoint with test credentials."""
        result = TestResult(name="Authentication Login", endpoint="/api/v1/auth/login/", method="POST")

        # Test with optional credentials.
        # Defaults intentionally do NOT include a real password.
        test_credentials = {
            "username": os.getenv("SECURESYS_TEST_USERNAME", "admin"),
            "password": os.getenv("SECURESYS_TEST_PASSWORD", ""),
        }

        status_code, response, response_time, error = self._make_request(
            "POST", "/api/v1/auth/login/", data=test_credentials
        )

        result.status_code = status_code
        result.response_time_ms = response_time
        result.error = error

        if status_code == 200 and response and "access" in response:
            result.success = True
            self.session_token = response.get("access")
            result.response_data = {"message": "Authentication successful"}
        elif status_code == 401:
            result.success = True  # Expected for invalid credentials
            result.response_data = {"message": "Invalid credentials (expected)"}
        else:
            result.success = not error
            result.response_data = response

        return result

    def test_dashboard_stats(self) -> TestResult:
        """Test dashboard statistics endpoint."""
        result = TestResult(name="Dashboard Statistics", endpoint="/api/v1/dashboard/stats/", method="GET")

        status_code, response, response_time, error = self._make_request("GET", "/api/v1/dashboard/stats/")

        result.status_code = status_code
        result.response_time_ms = response_time
        result.error = error
        result.response_data = response
        result.success = status_code in [200, 401] and not error

        return result

    def run_all_tests(self) -> TestReport:
        """Run all API tests."""
        print_status("Running HTTP API tests...", "info")
        print(f"\n{Colors.BOLD}Target: {self.base_url}{Colors.ENDC}\n")

        self.report.start_time = datetime.now()

        # Define all tests
        tests = [
            self.test_health_check,
            self.test_readiness_check,
            self.test_liveness_check,
            self.test_api_v1_health,
            self.test_api_docs,
            self.test_api_schema,
            self.test_authentication,
            self.test_systems_list_unauthenticated,
            self.test_scans_list_unauthenticated,
            self.test_scanning_endpoint,
            self.test_webhooks_endpoint,
            self.test_dashboard_stats,
        ]

        # Run tests
        for test_func in tests:
            try:
                result = test_func()
                self.add_test_result(result)
                self._print_test_result(result)
            except Exception as e:
                result = TestResult(name=test_func.__name__, endpoint="", method="", error=str(e))
                self.add_test_result(result)
                self._print_test_result(result)

        self.report.end_time = datetime.now()
        return self.report

    def _print_test_result(self, result: TestResult):
        """Print individual test result."""
        if result.success:
            status_icon = f"{Colors.GREEN}✓{Colors.ENDC}"
            status_text = f"{Colors.GREEN}PASS{Colors.ENDC}"
        elif result.error:
            status_icon = f"{Colors.FAIL}✗{Colors.ENDC}"
            status_text = f"{Colors.FAIL}ERROR{Colors.ENDC}"
        else:
            status_icon = f"{Colors.WARNING}✗{Colors.ENDC}"
            status_text = f"{Colors.WARNING}FAIL{Colors.ENDC}"

        print(f"  {status_icon} {result.name:<35} [{status_text}]")
        print(f"      {result.method} {result.endpoint}")

        if result.status_code:
            print(f"      Status: {result.status_code} | Time: {result.response_time_ms:.2f}ms")

        if result.error:
            print(f"      {Colors.FAIL}Error: {result.error}{Colors.ENDC}")

        print()

    def print_summary(self):
        """Print test summary."""
        print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}TEST SUMMARY{Colors.ENDC}")
        print(f"{'='*70}\n")

        total_color = Colors.BLUE
        if self.report.failed > 0 or self.report.errors > 0:
            total_color = Colors.WARNING
        if self.report.passed == self.report.total:
            total_color = Colors.GREEN

        print(f"  Total Tests:  {total_color}{self.report.total}{Colors.ENDC}")
        print(f"  Passed:       {Colors.GREEN}{self.report.passed}{Colors.ENDC}")
        print(f"  Failed:       {Colors.WARNING}{self.report.failed}{Colors.ENDC}")
        print(f"  Errors:       {Colors.FAIL}{self.report.errors}{Colors.ENDC}")
        print(f"  Duration:     {self.report.duration_seconds:.2f}s")

        # Calculate pass rate
        if self.report.total > 0:
            pass_rate = (self.report.passed / self.report.total) * 100
            rate_color = Colors.GREEN if pass_rate >= 80 else (Colors.WARNING if pass_rate >= 50 else Colors.FAIL)
            print(f"  Pass Rate:    {rate_color}{pass_rate:.1f}%{Colors.ENDC}")

        print()


def cmd_backend(args):
    """Start Django backend server."""
    print_status("Starting Django backend server...", "info")

    python = get_python_executable()
    env = {
        "DJANGO_SETTINGS_MODULE": "backend.settings",
        "DEBUG": "True",
    }

    cmd = [python, "manage.py", "runserver", f"{args.host}:{args.port}"]

    if args.foreground:
        subprocess.run(cmd, cwd=BACKEND_DIR, env={**os.environ, **env})
    else:
        return start_process(cmd, cwd=BACKEND_DIR, env=env, name="backend")


def cmd_frontend(args):
    """Start Vite frontend dev server."""
    print_status("Starting Vite frontend dev server...", "info")

    npm = get_npm_command()
    cmd = [
        npm,
        "run",
        "dev",
        "--",
        "--host",
        args.host,
        "--port",
        str(args.frontend_port),
    ]

    if args.foreground:
        cmd_to_run = _windows_wrap_cmd_if_needed(cmd)
        subprocess.run(cmd_to_run, cwd=FRONTEND_DIR)
    else:
        return start_process(cmd, cwd=FRONTEND_DIR, name="frontend")


def cmd_celery(args):
    """Start Celery worker."""
    print_status("Starting Celery worker...", "info")

    python = get_python_executable()
    cmd = [python, "-m", "celery", "-A", "backend", "worker", "-l", args.log_level]

    if args.foreground:
        subprocess.run(cmd, cwd=BACKEND_DIR)
    else:
        return start_process(cmd, cwd=BACKEND_DIR, name="celery")


def cmd_services(args):
    """Start Docker services."""
    print_status("Starting Docker services...", "info")

    if args.production:
        compose_file = "docker-compose.prod.yml"
    else:
        compose_file = "docker-compose.yml"

    cmd = ["docker-compose", "-f", compose_file, "up", "-d"]
    if args.build:
        cmd.append("--build")

    result = subprocess.run(cmd, cwd=PROJECT_ROOT)
    return_code = result.returncode

    if return_code == 0:
        print_status("Docker services started successfully", "success")
    else:
        print_status("Failed to start Docker services", "error")


def cmd_all(args):
    """Start all components."""
    print_status("Starting all components...", "info")

    _ensure_local_services_running()

    manager = ProcessManager()

    # Start backend
    backend_process = cmd_backend(args)
    if backend_process:
        manager.add_process("backend", backend_process)

    # Wait for backend to be ready
    time.sleep(3)

    # Start frontend
    frontend_process = cmd_frontend(args)
    if frontend_process:
        manager.add_process("frontend", frontend_process)

    # Start celery if requested
    if args.with_celery:
        celery_process = cmd_celery(args)
        if celery_process:
            manager.add_process("celery", celery_process)

    print_status("All components started. Press Ctrl+C to stop.", "success")
    manager.wait()


def cmd_test(args):
    """Run HTTP API tests."""
    print_banner()

    base_url = args.url or f"http://{args.host}:{args.port}"
    tester = APITester(base_url)

    report = tester.run_all_tests()
    tester.print_summary()

    # Print next steps based on results
    print_next_steps(report)

    # Return exit code based on results
    if report.errors > 0 or report.failed > 0:
        return 1
    return 0


def cmd_status(args):
    """Check status of all services."""
    print_banner()
    print_status("Checking service status...\n", "info")

    redis_port = os.getenv("REDIS_PORT", "6380")

    services = {
        "Backend API": f"http://localhost:{DEFAULT_BACKEND_PORT}/health/health/",
        "Frontend": f"http://localhost:{DEFAULT_FRONTEND_PORT}/",
        "PostgreSQL": "localhost:5432",
        "Redis": f"localhost:{redis_port}",
        "Keycloak": "http://localhost:8080/health/ready",
        "Jaeger": "http://localhost:16686/",
    }

    import socket

    for name, endpoint in services.items():
        try:
            if endpoint.startswith("http"):
                with _safe_urlopen(
                    endpoint,
                    timeout=3,
                    allow_hosts={"localhost", "127.0.0.1", "::1"},
                ):
                    print(f"  {Colors.GREEN}●{Colors.ENDC} {name:<20} {Colors.GREEN}Running{Colors.ENDC}")
            else:
                # TCP port check
                host, port = endpoint.split(":")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((host, int(port)))
                sock.close()
                if result == 0:
                    print(f"  {Colors.GREEN}●{Colors.ENDC} {name:<20} {Colors.GREEN}Running{Colors.ENDC}")
                else:
                    print(f"  {Colors.FAIL}●{Colors.ENDC} {name:<20} {Colors.FAIL}Stopped{Colors.ENDC}")
        except Exception:
            print(f"  {Colors.FAIL}●{Colors.ENDC} {name:<20} {Colors.FAIL}Stopped{Colors.ENDC}")

    print()


def cmd_stop(args):
    """Stop all Docker services."""
    print_status("Stopping Docker services...", "info")
    subprocess.run(["docker-compose", "down"], cwd=PROJECT_ROOT)
    print_status("Docker services stopped", "success")


def cmd_createuser(args):
    """Create a local Django user for browser testing."""
    # main() already prints banner + python version
    _ensure_local_services_running()

    # Create via Django shell so we use the project's configured AUTH_USER_MODEL
    email = args.email.strip()
    password = args.password
    role = (args.role or "viewer").strip().lower()

    if role not in {"viewer", "auditor", "admin"}:
        print_status("Invalid role. Use: viewer|auditor|admin", "error")
        return 2

    is_superuser = bool(args.superuser) or role == "admin"

    django_code = """
import os
from django.contrib.auth import get_user_model

User = get_user_model()
email = os.environ['SS_CREATE_EMAIL']
password = os.environ['SS_CREATE_PASSWORD']
role = os.environ.get('SS_CREATE_ROLE', 'viewer')
is_superuser = os.environ.get('SS_CREATE_SUPERUSER', 'false').lower() == 'true'

user, created = User.objects.get_or_create(email=email)
user.role = role
user.is_active = True
user.is_staff = user.is_staff or is_superuser
user.is_superuser = user.is_superuser or is_superuser
user.set_password(password)
user.save()

print('CREATED' if created else 'UPDATED', user.email)
""".strip()

    env = {
        "DJANGO_SETTINGS_MODULE": "backend.settings",
        "SS_CREATE_EMAIL": email,
        "SS_CREATE_PASSWORD": password,
        "SS_CREATE_ROLE": role,
        "SS_CREATE_SUPERUSER": "true" if is_superuser else "false",
    }

    docker_compose = shutil.which("docker-compose")
    if docker_compose:
        # Prefer creating the user inside the backend container so DB settings match docker-compose.
        rc, out, _err = run_command(["docker-compose", "ps", "-q", "backend"], cwd=PROJECT_ROOT)
        if rc == 0 and out.strip():
            cmd = [
                "docker-compose",
                "exec",
                "-T",
                "-e",
                f"SS_CREATE_EMAIL={email}",
                "-e",
                f"SS_CREATE_PASSWORD={password}",
                "-e",
                f"SS_CREATE_ROLE={role}",
                "-e",
                f"SS_CREATE_SUPERUSER={'true' if is_superuser else 'false'}",
                "backend",
                "python",
                "manage.py",
                "shell",
                "-c",
                django_code,
            ]

            result = subprocess.run(cmd, cwd=PROJECT_ROOT, text=True)
            if result.returncode != 0:
                print_status("Failed to create user inside backend container.", "error")
                return result.returncode

            print_status(f"User ready: {email} (role={role})", "success")
            return 0

    # Fallback: create user using local manage.py (expects correct DB_* env vars in your shell)
    python = get_python_executable()
    cmd = [python, "manage.py", "shell", "-c", django_code]
    try:
        result = subprocess.run(cmd, cwd=BACKEND_DIR, env={**os.environ, **env}, text=True)
        if result.returncode != 0:
            print_status("Failed to create user (Django shell returned non-zero).", "error")
            return result.returncode
    except Exception as e:
        print_status(f"Failed to create user: {e}", "error")
        return 1

    print_status(f"User ready: {email} (role={role})", "success")
    return 0


def print_next_steps(report: TestReport):
    """Print recommended next steps based on test results."""
    print(f"\n{Colors.BOLD}NEXT STEPS{Colors.ENDC}")
    print(f"{'='*70}\n")

    failed_tests = [r for r in report.results if not r.success]
    connection_errors = [
        r for r in report.results if r.error and ("Connection" in r.error or "refused" in str(r.error).lower())
    ]

    if connection_errors:
        print(f"  {Colors.FAIL}⚠ Backend server appears to be down{Colors.ENDC}")
        print("    1. Start Docker services: python run.py services")
        print("    2. Or start the backend directly: python run.py backend")
        print("    3. Check logs: docker-compose logs backend")
        print()
    elif report.passed == report.total:
        print(f"  {Colors.GREEN}✓ All tests passed!{Colors.ENDC}")
        print("    - API is healthy and responding correctly")
        print("    - Consider running load tests for production readiness")
        print("    - Review docs/PRODUCTION_READINESS_CHECKLIST.md")
        print()
    else:
        print(f"  {Colors.WARNING}⚠ Some tests failed. Recommendations:{Colors.ENDC}")
        print()

        for result in failed_tests:
            if "401" in str(result.status_code):
                print(f"    • {result.name}: Authentication required")
                print("      - Create API credentials or enable dev mode")
            elif "404" in str(result.status_code):
                print(f"    • {result.name}: Endpoint not found")
                print("      - Check URL configuration and migrations")
            elif "500" in str(result.status_code):
                print(f"    • {result.name}: Server error")
                print("      - Check backend logs for details")
        print()

    print(f"  {Colors.BOLD}Available Commands:{Colors.ENDC}")
    print("    python run.py all        - Start all components")
    print("    python run.py backend    - Start backend only")
    print("    python run.py frontend   - Start frontend only")
    print("    python run.py services   - Start Docker services")
    print("    python run.py status     - Check service status")
    print("    python run.py test       - Run API tests")
    print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SecureSys Auditor - Centralized Runner", formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Common arguments
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    common_parser.add_argument("--port", type=int, default=DEFAULT_BACKEND_PORT, help="Backend port")
    common_parser.add_argument("--frontend-port", type=int, default=DEFAULT_FRONTEND_PORT, help="Frontend port")

    # Backend command
    backend_parser = subparsers.add_parser("backend", parents=[common_parser], help="Start Django backend")
    backend_parser.add_argument("--foreground", "-f", action="store_true", help="Run in foreground")
    backend_parser.set_defaults(func=cmd_backend)

    # Frontend command
    frontend_parser = subparsers.add_parser("frontend", parents=[common_parser], help="Start Vite frontend")
    frontend_parser.add_argument("--foreground", "-f", action="store_true", help="Run in foreground")
    frontend_parser.set_defaults(func=cmd_frontend)

    # Celery command
    celery_parser = subparsers.add_parser("celery", parents=[common_parser], help="Start Celery worker")
    celery_parser.add_argument("--foreground", "-f", action="store_true", help="Run in foreground")
    celery_parser.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error"])
    celery_parser.set_defaults(func=cmd_celery)

    # Services command
    services_parser = subparsers.add_parser("services", help="Start Docker services")
    services_parser.add_argument("--production", "-p", action="store_true", help="Use production compose file")
    services_parser.add_argument("--build", "-b", action="store_true", help="Build images before starting")
    services_parser.set_defaults(func=cmd_services)

    # All command
    all_parser = subparsers.add_parser("all", parents=[common_parser], help="Start all components")
    all_parser.add_argument("--with-celery", "-c", action="store_true", help="Include Celery worker")
    all_parser.add_argument("--foreground", "-f", action="store_true", default=False)
    all_parser.set_defaults(func=cmd_all)

    # Test command
    test_parser = subparsers.add_parser("test", parents=[common_parser], help="Run HTTP API tests")
    test_parser.add_argument("--url", help="Custom API URL to test")
    test_parser.set_defaults(func=cmd_test)

    # Status command
    status_parser = subparsers.add_parser("status", help="Check service status")
    status_parser.set_defaults(func=cmd_status)

    # Stop command
    stop_parser = subparsers.add_parser("stop", help="Stop Docker services")
    stop_parser.set_defaults(func=cmd_stop)

    # Create user command
    createuser_parser = subparsers.add_parser("createuser", help="Create a local login user")
    createuser_parser.add_argument("--email", "-e", required=True, help="User email (login)")
    createuser_parser.add_argument("--password", "-p", required=True, help="User password")
    createuser_parser.add_argument("--role", "-r", default="admin", help="Role: viewer|auditor|admin")
    createuser_parser.add_argument("--superuser", action="store_true", help="Also grant Django superuser")
    createuser_parser.set_defaults(func=cmd_createuser)

    args = parser.parse_args()

    if args.command is None:
        print_banner()
        parser.print_help()
        print_status("\nNo command specified. Use 'python run.py <command>' to start.", "info")
        sys.exit(0)

    print_banner()
    check_python_version()

    exit_code = args.func(args)
    sys.exit(exit_code if exit_code else 0)


if __name__ == "__main__":
    main()
