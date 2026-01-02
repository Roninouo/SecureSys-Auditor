"""
System Scanner Module

Collects security-relevant information from the local system including:
- System information (OS, hostname, etc.)
- User accounts and privileges
- Running services
- Installed packages
- Network configuration
- Firewall status
- SSH configuration (if applicable)

Supports minimal telemetry mode to filter sensitive data.
"""

import json
import logging
import os
import platform
import socket
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional

import psutil

logger = logging.getLogger(__name__)


def filter_sensitive_data(data: Dict[str, Any], sensitive_fields: List[str]) -> Dict[str, Any]:
    """
    Recursively filter sensitive fields from scan data.

    Args:
        data: The data dictionary to filter
        sensitive_fields: List of field names to remove

    Returns:
        Filtered data dictionary
    """
    if not isinstance(data, dict):
        return data

    filtered = {}
    for key, value in data.items():
        # Skip sensitive fields
        key_lower = key.lower()
        if any(sf.lower() in key_lower for sf in sensitive_fields):
            continue

        # Recursively filter nested dicts
        if isinstance(value, dict):
            filtered[key] = filter_sensitive_data(value, sensitive_fields)
        elif isinstance(value, list):
            filtered[key] = [
                filter_sensitive_data(item, sensitive_fields) if isinstance(item, dict) else item for item in value
            ]
        else:
            filtered[key] = value

    return filtered


class SystemScanner:
    """
    Main scanner class that collects system security data.

    Args:
        minimal_telemetry: When True, filters sensitive data from results
        sensitive_fields: List of field names to filter (used with minimal_telemetry)
    """

    # Default sensitive fields to filter in minimal telemetry mode
    DEFAULT_SENSITIVE_FIELDS = [
        "ip_address",
        "mac_address",
        "user_home_paths",
        "environment_variables",
        "command_history",
        "ssh_keys",
        "private_keys",
        "passwords",
        "tokens",
        "credentials",
    ]

    def __init__(self, minimal_telemetry: bool = True, sensitive_fields: Optional[List[str]] = None):
        self.platform = platform.system().lower()
        self.scan_time = datetime.utcnow().isoformat()
        self.minimal_telemetry = minimal_telemetry
        self.sensitive_fields = sensitive_fields or self.DEFAULT_SENSITIVE_FIELDS

    def collect_all(self) -> Dict[str, Any]:
        """
        Collect all available system information.

        Returns:
            Dictionary containing all scan data, filtered if minimal_telemetry is enabled
        """
        data = {
            "hostname": self.get_hostname(),
            "os": self.get_os_info(),
            "scan_time": self.scan_time,
            "users": self.get_users(),
            "services": self.get_services(),
            "packages": self.get_packages(),
            "network": self.get_network_info(),
            "firewall": self.get_firewall_status(),
            "ssh_config": self.get_ssh_config(),
            "password_policy": self.get_password_policy(),
            "_metadata": {
                "minimal_telemetry": self.minimal_telemetry,
                "scanner_version": "1.0.0",
            },
        }

        if self.minimal_telemetry:
            data = filter_sensitive_data(data, self.sensitive_fields)

        return data

    def get_hostname(self) -> str:
        """Get system hostname."""
        return socket.gethostname()

    def get_os_info(self) -> Dict[str, str]:
        """Get operating system information."""
        return {
            "name": platform.system(),
            "version": platform.version(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
        }

    def get_users(self) -> Dict[str, Any]:
        """Get user account information."""
        users_info = {
            "local_users": [],
            "admin_users": [],
            "logged_in_users": [],
        }

        try:
            # Get logged-in users
            logged_in = psutil.users()
            users_info["logged_in_users"] = [
                {"name": u.name, "terminal": u.terminal, "host": u.host} for u in logged_in
            ]

            if self.platform == "linux":
                users_info.update(self._get_linux_users())
            elif self.platform == "windows":
                users_info.update(self._get_windows_users())
            elif self.platform == "darwin":
                users_info.update(self._get_macos_users())

        except Exception as e:
            users_info["error"] = str(e)

        return users_info

    def _get_linux_users(self) -> Dict[str, List[str]]:
        """Get Linux user information."""
        local_users = []
        admin_users = []
        errors = []

        try:
            # Read /etc/passwd for users
            with open("/etc/passwd", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        username = parts[0]
                        uid = int(parts[2])
                        shell = parts[6]

                        # Filter system users (typically UID >= 1000)
                        if uid >= 1000 and "/nologin" not in shell and "/false" not in shell:
                            local_users.append(username)

            # Check sudo/wheel group for admins
            try:
                with open("/etc/group", "r") as f:
                    for line in f:
                        if line.startswith("sudo:") or line.startswith("wheel:"):
                            parts = line.strip().split(":")
                            if len(parts) >= 4:
                                admin_users.extend(parts[3].split(","))
            except OSError as e:
                errors.append(f"Could not read /etc/group: {e}")
                logger.debug("Could not read /etc/group: %s", e)

            # Also check /etc/sudoers.d
            try:
                result = subprocess.run(
                    ["grep", "-r", "ALL=(ALL)", "/etc/sudoers", "/etc/sudoers.d/"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                # Parse output for additional admin users
            except subprocess.TimeoutExpired as e:
                errors.append(f"Timeout checking sudoers: {e}")
                logger.debug("Timeout checking sudoers files: %s", e)
            except subprocess.SubprocessError as e:
                errors.append(f"Error checking sudoers: {e}")
                logger.debug("Error checking sudoers files: %s", e)
            except OSError as e:
                errors.append(f"OS error checking sudoers: {e}")
                logger.debug("OS error checking sudoers: %s", e)

        except OSError as e:
            errors.append(f"Could not read /etc/passwd: {e}")
            logger.warning("Could not read /etc/passwd: %s", e)

        result = {"local_users": local_users, "admin_users": list(set(admin_users))}
        if errors:
            result["errors"] = errors
        return result

    def _get_windows_users(self) -> Dict[str, List[str]]:
        """Get Windows user information."""
        local_users = []
        admin_users = []
        errors = []

        try:
            # Use net user command
            result = subprocess.run(["net", "user"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split("\n")
                for line in lines:
                    # Skip header lines
                    if "---" in line or not line.strip():
                        continue
                    users = line.split()
                    local_users.extend(users)

            # Get admin users
            result = subprocess.run(["net", "localgroup", "Administrators"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split("\n")
                in_members = False
                for line in lines:
                    if "---" in line:
                        in_members = True
                        continue
                    if in_members and line.strip():
                        admin_users.append(line.strip())

        except subprocess.TimeoutExpired as e:
            errors.append(f"Timeout getting Windows users: {e}")
            logger.debug("Timeout getting Windows users: %s", e)
        except subprocess.SubprocessError as e:
            errors.append(f"Error getting Windows users: {e}")
            logger.debug("Error getting Windows users: %s", e)
        except OSError as e:
            errors.append(f"OS error getting Windows users: {e}")
            logger.debug("OS error getting Windows users: %s", e)

        result = {"local_users": local_users, "admin_users": admin_users}
        if errors:
            result["errors"] = errors
        return result

    def _get_macos_users(self) -> Dict[str, List[str]]:
        """Get macOS user information."""
        local_users = []
        admin_users = []
        errors = []

        try:
            result = subprocess.run(["dscl", ".", "-list", "/Users"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for user in result.stdout.split("\n"):
                    user = user.strip()
                    if user and not user.startswith("_"):
                        local_users.append(user)

            # Get admin users
            result = subprocess.run(
                ["dscl", ".", "-read", "/Groups/admin", "GroupMembership"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                parts = result.stdout.replace("GroupMembership:", "").split()
                admin_users.extend(parts)

        except subprocess.TimeoutExpired as e:
            errors.append(f"Timeout getting macOS users: {e}")
            logger.debug("Timeout getting macOS users: %s", e)
        except subprocess.SubprocessError as e:
            errors.append(f"Error getting macOS users: {e}")
            logger.debug("Error getting macOS users: %s", e)
        except OSError as e:
            errors.append(f"OS error getting macOS users: {e}")
            logger.debug("OS error getting macOS users: %s", e)

        result = {"local_users": local_users, "admin_users": admin_users}
        if errors:
            result["errors"] = errors
        return result

    def get_services(self) -> List[Dict[str, Any]]:
        """Get running services information."""
        services = []
        errors = []

        try:
            for proc in psutil.process_iter(["pid", "name", "username", "status"]):
                try:
                    info = proc.info
                    services.append(
                        {
                            "pid": info["pid"],
                            "name": info["name"],
                            "user": info["username"],
                            "status": info["status"],
                        }
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except psutil.Error as e:
            errors.append(f"Error enumerating processes: {e}")
            logger.debug("Error enumerating processes: %s", e)
        except OSError as e:
            errors.append(f"OS error getting services: {e}")
            logger.debug("OS error getting services: %s", e)

        result = services[:100]  # Limit to top 100
        return result

    def get_packages(self) -> Dict[str, Any]:
        """Get installed packages information."""
        packages = {
            "installed": [],
            "outdated": [],
        }

        try:
            if self.platform == "linux":
                packages.update(self._get_linux_packages())
            elif self.platform == "windows":
                packages.update(self._get_windows_packages())
            elif self.platform == "darwin":
                packages.update(self._get_macos_packages())
        except subprocess.TimeoutExpired as e:
            packages["error"] = f"Timeout getting packages: {e}"
            logger.debug("Timeout getting packages: %s", e)
        except subprocess.SubprocessError as e:
            packages["error"] = f"Error getting packages: {e}"
            logger.debug("Error getting packages: %s", e)
        except OSError as e:
            packages["error"] = f"OS error getting packages: {e}"
            logger.debug("OS error getting packages: %s", e)

        return packages

    def _get_linux_packages(self) -> Dict[str, List[str]]:
        """Get Linux packages using apt or yum."""
        installed = []
        errors = []

        # Try apt
        try:
            result = subprocess.run(["dpkg", "-l"], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.startswith("ii"):
                        parts = line.split()
                        if len(parts) >= 3:
                            installed.append({"name": parts[1], "version": parts[2]})
                return {"installed": installed[:200]}  # Limit
        except subprocess.TimeoutExpired as e:
            errors.append(f"Timeout running dpkg: {e}")
            logger.debug("Timeout running dpkg: %s", e)
        except FileNotFoundError:
            # dpkg not available, try rpm
            pass
        except subprocess.SubprocessError as e:
            errors.append(f"Error running dpkg: {e}")
            logger.debug("Error running dpkg: %s", e)

        # Try rpm
        try:
            result = subprocess.run(
                ["rpm", "-qa", "--qf", "%{NAME}|%{VERSION}\n"], capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "|" in line:
                        name, version = line.split("|", 1)
                        installed.append({"name": name, "version": version})
                return {"installed": installed[:200]}
        except subprocess.TimeoutExpired as e:
            errors.append(f"Timeout running rpm: {e}")
            logger.debug("Timeout running rpm: %s", e)
        except FileNotFoundError:
            errors.append("Neither dpkg nor rpm found")
            logger.debug("Neither dpkg nor rpm package manager found")
        except subprocess.SubprocessError as e:
            errors.append(f"Error running rpm: {e}")
            logger.debug("Error running rpm: %s", e)

        result = {"installed": installed}
        if errors:
            result["errors"] = errors
        return result

    def _get_windows_packages(self) -> Dict[str, List[str]]:
        """Get Windows installed programs."""
        installed = []
        errors = []

        try:
            # Query installed programs via PowerShell
            cmd = (
                "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
                "| Select-Object DisplayName, DisplayVersion | ConvertTo-Json"
            )
            result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                try:
                    programs = json.loads(result.stdout)
                    if isinstance(programs, list):
                        for prog in programs:
                            if prog.get("DisplayName"):
                                installed.append(
                                    {"name": prog["DisplayName"], "version": prog.get("DisplayVersion", "unknown")}
                                )
                except json.JSONDecodeError as e:
                    errors.append(f"JSON decode error parsing Windows packages: {e}")
                    logger.debug("JSON decode error parsing Windows packages: %s", e)
        except subprocess.TimeoutExpired as e:
            errors.append(f"Timeout getting Windows packages: {e}")
            logger.debug("Timeout getting Windows packages: %s", e)
        except subprocess.SubprocessError as e:
            errors.append(f"Error getting Windows packages: {e}")
            logger.debug("Error getting Windows packages: %s", e)
        except OSError as e:
            errors.append(f"OS error getting Windows packages: {e}")
            logger.debug("OS error getting Windows packages: %s", e)

        result = {"installed": installed[:200]}
        if errors:
            result["errors"] = errors
        return result

    def _get_macos_packages(self) -> Dict[str, List[str]]:
        """Get macOS installed packages (Homebrew)."""
        installed = []
        errors = []

        try:
            result = subprocess.run(["brew", "list", "--versions"], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    parts = line.split()
                    if len(parts) >= 2:
                        installed.append({"name": parts[0], "version": parts[-1]})
        except subprocess.TimeoutExpired as e:
            errors.append(f"Timeout getting Homebrew packages: {e}")
            logger.debug("Timeout getting Homebrew packages: %s", e)
        except FileNotFoundError:
            errors.append("Homebrew not installed")
            logger.debug("Homebrew not found on this macOS system")
        except subprocess.SubprocessError as e:
            errors.append(f"Error getting Homebrew packages: {e}")
            logger.debug("Error getting Homebrew packages: %s", e)

        result = {"installed": installed}
        if errors:
            result["errors"] = errors
        return result

    def get_network_info(self) -> Dict[str, Any]:
        """Get network configuration information."""
        network = {
            "interfaces": [],
            "open_ports": [],
        }
        errors = []

        try:
            # Get network interfaces
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        network["interfaces"].append(
                            {
                                "name": iface,
                                "ip": addr.address,
                                "netmask": addr.netmask,
                            }
                        )

            # Get open ports (listening connections)
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN":
                    network["open_ports"].append(
                        {
                            "port": conn.laddr.port,
                            "address": conn.laddr.ip,
                            "pid": conn.pid,
                        }
                    )

        except psutil.AccessDenied as e:
            errors.append(f"Access denied getting network info: {e}")
            logger.debug("Access denied getting network info: %s", e)
        except psutil.Error as e:
            errors.append(f"Error getting network info: {e}")
            logger.debug("Error getting network info: %s", e)
        except OSError as e:
            errors.append(f"OS error getting network info: {e}")
            logger.debug("OS error getting network info: %s", e)

        if errors:
            network["errors"] = errors
        return network

    def get_firewall_status(self) -> Dict[str, Any]:
        """Get firewall status."""
        firewall = {
            "enabled": False,
            "status": "unknown",
        }
        errors = []

        try:
            if self.platform == "linux":
                # Check ufw
                result = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
                if "Status: active" in result.stdout:
                    firewall["enabled"] = True
                    firewall["status"] = "active"
                elif "Status: inactive" in result.stdout:
                    firewall["status"] = "inactive"

            elif self.platform == "windows":
                result = subprocess.run(
                    ["netsh", "advfirewall", "show", "allprofiles", "state"], capture_output=True, text=True, timeout=10
                )
                if "ON" in result.stdout.upper():
                    firewall["enabled"] = True
                    firewall["status"] = "active"

            elif self.platform == "darwin":
                result = subprocess.run(
                    ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.stdout.strip() in ["1", "2"]:
                    firewall["enabled"] = True
                    firewall["status"] = "active"

        except subprocess.TimeoutExpired as e:
            errors.append(f"Timeout checking firewall status: {e}")
            logger.debug("Timeout checking firewall status: %s", e)
        except FileNotFoundError as e:
            errors.append(f"Firewall command not found: {e}")
            logger.debug("Firewall command not found: %s", e)
        except subprocess.SubprocessError as e:
            errors.append(f"Error checking firewall status: {e}")
            logger.debug("Error checking firewall status: %s", e)
        except OSError as e:
            errors.append(f"OS error checking firewall: {e}")
            logger.debug("OS error checking firewall: %s", e)

        if errors:
            firewall["errors"] = errors
        return firewall

    def get_ssh_config(self) -> Dict[str, Any]:
        """Get SSH configuration (Linux/macOS only)."""
        ssh_config = {
            "permit_root_login": False,
            "password_authentication": True,
            "port": 22,
        }
        errors = []

        if self.platform not in ["linux", "darwin"]:
            return ssh_config

        try:
            sshd_config_path = "/etc/ssh/sshd_config"
            if os.path.exists(sshd_config_path):
                with open(sshd_config_path, "r") as f:
                    for line in f:
                        line = line.strip().lower()
                        if line.startswith("permitrootlogin"):
                            if "yes" in line:
                                ssh_config["permit_root_login"] = True
                        elif line.startswith("passwordauthentication"):
                            if "no" in line:
                                ssh_config["password_authentication"] = False
                        elif line.startswith("port"):
                            try:
                                ssh_config["port"] = int(line.split()[1])
                            except (ValueError, IndexError) as e:
                                errors.append(f"Could not parse SSH port: {e}")
                                logger.debug("Could not parse SSH port: %s", e)
        except OSError as e:
            errors.append(f"Could not read SSH config: {e}")
            logger.debug("Could not read SSH config: %s", e)

        if errors:
            ssh_config["errors"] = errors
        return ssh_config

    def get_password_policy(self) -> Dict[str, Any]:
        """Get password policy configuration."""
        policy = {
            "min_length": 0,
            "require_special": False,
            "require_numbers": False,
            "max_age_days": 0,
        }
        errors = []

        try:
            if self.platform == "linux":
                # Check /etc/login.defs
                if os.path.exists("/etc/login.defs"):
                    with open("/etc/login.defs", "r") as f:
                        for line in f:
                            if line.startswith("PASS_MIN_LEN"):
                                try:
                                    policy["min_length"] = int(line.split()[1])
                                except (ValueError, IndexError) as e:
                                    errors.append(f"Could not parse PASS_MIN_LEN: {e}")
                                    logger.debug("Could not parse PASS_MIN_LEN: %s", e)
                            elif line.startswith("PASS_MAX_DAYS"):
                                try:
                                    policy["max_age_days"] = int(line.split()[1])
                                except (ValueError, IndexError) as e:
                                    errors.append(f"Could not parse PASS_MAX_DAYS: {e}")
                                    logger.debug("Could not parse PASS_MAX_DAYS: %s", e)

                # Check PAM configuration
                pam_files = ["/etc/pam.d/common-password", "/etc/security/pwquality.conf"]
                for pf in pam_files:
                    if os.path.exists(pf):
                        try:
                            with open(pf, "r") as f:
                                content = f.read().lower()
                                if "minlen" in content or "min_length" in content:
                                    policy["require_special"] = "special" in content or "ocredit" in content
                                    policy["require_numbers"] = "dcredit" in content
                        except OSError as e:
                            errors.append(f"Could not read {pf}: {e}")
                            logger.debug("Could not read PAM file %s: %s", pf, e)

        except OSError as e:
            errors.append(f"Error reading password policy: {e}")
            logger.debug("Error reading password policy: %s", e)

        if errors:
            policy["errors"] = errors
        return policy
