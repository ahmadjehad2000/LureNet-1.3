#!/usr/bin/env python3
"""
LureNet Startup Validation Script
Comprehensive pre-flight checks before starting services

Usage:
    python startup_check.py                # Run all checks
    python startup_check.py --fix          # Auto-fix issues
    python startup_check.py --service http # Check specific service
"""

import sys
import os
import argparse
import subprocess
import socket
import sqlite3
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import json

class Colors:
    """ANSI color codes"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class StartupChecker:
    """Comprehensive startup validation"""

    def __init__(self, fix_mode: bool = False):
        self.fix_mode = fix_mode
        self.project_root = Path(__file__).parent
        self.issues_found = []
        self.checks_passed = 0
        self.checks_failed = 0

    def print_header(self, text: str):
        """Print section header"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}{text:^80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.RESET}\n")

    def print_check(self, name: str, status: bool, message: str = ""):
        """Print check result"""
        if status:
            symbol = f"{Colors.GREEN}✓{Colors.RESET}"
            self.checks_passed += 1
        else:
            symbol = f"{Colors.RED}✗{Colors.RESET}"
            self.checks_failed += 1
            self.issues_found.append(f"{name}: {message}")

        print(f"  {symbol} {name:50s} {message}")

    def check_python_version(self) -> bool:
        """Check Python version"""
        print(f"\n{Colors.BOLD}Checking Python Version...{Colors.RESET}")

        version = sys.version_info
        required_major, required_minor = 3, 8

        compatible = version.major >= required_major and version.minor >= required_minor
        version_str = f"{version.major}.{version.minor}.{version.micro}"

        if compatible:
            self.print_check(
                "Python Version",
                True,
                f"{version_str} (required: {required_major}.{required_minor}+)"
            )
        else:
            self.print_check(
                "Python Version",
                False,
                f"{version_str} - Requires Python {required_major}.{required_minor}+"
            )

        return compatible

    def check_dependencies(self) -> bool:
        """Check required dependencies"""
        print(f"\n{Colors.BOLD}Checking Dependencies...{Colors.RESET}")

        requirements_file = self.project_root / "requirements.txt"

        if not requirements_file.exists():
            self.print_check("requirements.txt", False, "File not found")
            return False

        self.print_check("requirements.txt", True, "Found")

        # Critical dependencies
        critical_deps = [
            "fastapi", "uvicorn", "pydantic", "python-jose",
            "passlib", "bcrypt", "pyyaml", "click", "psutil"
        ]

        all_installed = True
        for dep in critical_deps:
            try:
                __import__(dep.replace("-", "_"))
                self.print_check(f"  {dep}", True, "Installed")
            except ImportError:
                self.print_check(f"  {dep}", False, "Not installed")
                all_installed = False

                if self.fix_mode:
                    print(f"    {Colors.YELLOW}Attempting to install {dep}...{Colors.RESET}")
                    try:
                        subprocess.check_call([
                            sys.executable, "-m", "pip", "install", dep, "-q"
                        ])
                        print(f"    {Colors.GREEN}✓ Installed {dep}{Colors.RESET}")
                    except subprocess.CalledProcessError:
                        print(f"    {Colors.RED}✗ Failed to install {dep}{Colors.RESET}")

        return all_installed

    def check_directory_structure(self) -> bool:
        """Check project directory structure"""
        print(f"\n{Colors.BOLD}Checking Directory Structure...{Colors.RESET}")

        required_dirs = [
            "Protocols",
            "Protocols/http_protocol",
            "Protocols/http_protocol/auth",
            "Protocols/http_protocol/intelligence",
            "config",
            "data",
            "logs",
        ]

        all_exist = True
        for dir_path in required_dirs:
            full_path = self.project_root / dir_path
            exists = full_path.exists() and full_path.is_dir()

            if exists:
                self.print_check(f"  {dir_path}", True, "")
            else:
                self.print_check(f"  {dir_path}", False, "Missing")
                all_exist = False

                if self.fix_mode:
                    print(f"    {Colors.YELLOW}Creating directory...{Colors.RESET}")
                    full_path.mkdir(parents=True, exist_ok=True)
                    print(f"    {Colors.GREEN}✓ Created {dir_path}{Colors.RESET}")

        return all_exist

    def check_file_permissions(self) -> bool:
        """Check file permissions"""
        print(f"\n{Colors.BOLD}Checking File Permissions...{Colors.RESET}")

        executable_files = [
            "service_manager.py",
            "health_monitor.py",
            "fix_bugs.py",
            "validate_integration.py",
            "startup_check.py",
        ]

        all_ok = True
        for file_path in executable_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                is_executable = os.access(full_path, os.X_OK)

                if is_executable:
                    self.print_check(f"  {file_path}", True, "Executable")
                else:
                    self.print_check(f"  {file_path}", False, "Not executable")
                    all_ok = False

                    if self.fix_mode:
                        print(f"    {Colors.YELLOW}Setting executable permission...{Colors.RESET}")
                        os.chmod(full_path, 0o755)
                        print(f"    {Colors.GREEN}✓ Made executable{Colors.RESET}")

        return all_ok

    def check_database_connectivity(self) -> bool:
        """Check database connectivity"""
        print(f"\n{Colors.BOLD}Checking Database Connectivity...{Colors.RESET}")

        databases = [
            ("data/threat_intelligence.db", "Threat Intelligence"),
            ("data/auth.db", "Authentication"),
        ]

        all_ok = True
        for db_path, db_name in databases:
            full_path = self.project_root / db_path
            full_path.parent.mkdir(parents=True, exist_ok=True)

            try:
                conn = sqlite3.connect(str(full_path), timeout=5.0)
                cursor = conn.cursor()

                # Test write
                cursor.execute("CREATE TABLE IF NOT EXISTS startup_test (id INTEGER PRIMARY KEY)")
                cursor.execute("INSERT INTO startup_test DEFAULT VALUES")
                cursor.execute("DELETE FROM startup_test")
                conn.commit()
                conn.close()

                self.print_check(f"  {db_name}", True, "Read/Write OK")
            except Exception as e:
                self.print_check(f"  {db_name}", False, str(e))
                all_ok = False

        return all_ok

    def check_port_availability(self) -> bool:
        """Check if required ports are available"""
        print(f"\n{Colors.BOLD}Checking Port Availability...{Colors.RESET}")

        required_ports = [
            (8080, "HTTP Honeypot"),
            (8888, "Dashboard"),
        ]

        optional_ports = [
            (2222, "SSH Honeypot"),
            (2121, "FTP Honeypot"),
            (2525, "SMTP Honeypot"),
            (5353, "DNS Honeypot"),
            (4445, "SMB Honeypot"),
            (3389, "LDAP/AD Honeypot"),
        ]

        all_available = True

        # Check required ports
        for port, service in required_ports:
            available = self._check_port(port)
            if available:
                self.print_check(f"  Port {port} ({service})", True, "Available")
            else:
                self.print_check(f"  Port {port} ({service})", False, "In use")
                all_available = False

        # Check optional ports (warnings only)
        for port, service in optional_ports:
            available = self._check_port(port)
            status_text = "Available" if available else "In use (will use default)"
            if available:
                self.print_check(f"  Port {port} ({service})", True, status_text)
            else:
                print(f"  {Colors.YELLOW}⚠{Colors.RESET} Port {port} ({service}):50s {status_text}")

        return all_available

    def _check_port(self, port: int) -> bool:
        """Check if port is available"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.bind(('127.0.0.1', port))
            sock.close()
            return True
        except OSError:
            return False

    def check_configuration_files(self) -> bool:
        """Check configuration files"""
        print(f"\n{Colors.BOLD}Checking Configuration Files...{Colors.RESET}")

        config_files = [
            ("config/services.yaml", True),
            ("config/intelligence.yaml", False),
            ("config/vulnerabilities.yaml", False),
        ]

        all_ok = True
        for config_path, required in config_files:
            full_path = self.project_root / config_path
            exists = full_path.exists()

            if exists:
                # Validate YAML
                try:
                    import yaml
                    with open(full_path, 'r') as f:
                        yaml.safe_load(f)
                    self.print_check(f"  {config_path}", True, "Valid YAML")
                except Exception as e:
                    self.print_check(f"  {config_path}", False, f"Invalid YAML: {str(e)}")
                    all_ok = False
            elif required:
                self.print_check(f"  {config_path}", False, "Missing (required)")
                all_ok = False

                if self.fix_mode:
                    print(f"    {Colors.YELLOW}Creating default configuration...{Colors.RESET}")
                    self._create_default_config(config_path)
            else:
                print(f"  {Colors.YELLOW}⚠{Colors.RESET} {config_path:50s} Missing (optional)")

        return all_ok

    def _create_default_config(self, config_path: str):
        """Create default configuration file"""
        import yaml

        full_path = self.project_root / config_path
        full_path.parent.mkdir(parents=True, exist_ok=True)

        if "services" in config_path:
            config = {
                'services': {
                    'http': {'protocol': 'http', 'enabled': True, 'host': '0.0.0.0',
                            'port': 8080, 'module_path': 'Protocols/http_protocol/main.py'},
                },
                'global': {
                    'data_directory': 'data',
                    'log_directory': 'logs',
                    'max_retention_days': 90,
                }
            }
        else:
            config = {}

        with open(full_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)

        print(f"    {Colors.GREEN}✓ Created {config_path}{Colors.RESET}")

    def check_system_resources(self) -> bool:
        """Check system resources"""
        print(f"\n{Colors.BOLD}Checking System Resources...{Colors.RESET}")

        try:
            import psutil

            # Memory
            memory = psutil.virtual_memory()
            memory_gb = memory.total / (1024**3)
            memory_available_gb = memory.available / (1024**3)

            if memory_gb >= 2:
                self.print_check("Memory", True, f"{memory_gb:.1f} GB total, {memory_available_gb:.1f} GB available")
            else:
                self.print_check("Memory", False, f"{memory_gb:.1f} GB (recommend 2GB+)")

            # Disk
            disk = psutil.disk_usage('/')
            disk_free_gb = disk.free / (1024**3)

            if disk_free_gb >= 5:
                self.print_check("Disk Space", True, f"{disk_free_gb:.1f} GB free")
            else:
                self.print_check("Disk Space", False, f"{disk_free_gb:.1f} GB (recommend 5GB+)")

            # CPU
            cpu_count = psutil.cpu_count()
            self.print_check("CPU Cores", True, f"{cpu_count} cores")

            return True
        except ImportError:
            print(f"  {Colors.YELLOW}⚠{Colors.RESET} psutil not installed - skipping resource checks")
            return True

    def print_summary(self):
        """Print summary"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'STARTUP CHECK SUMMARY':^80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.RESET}\n")

        total = self.checks_passed + self.checks_failed
        success_rate = (self.checks_passed / total * 100) if total > 0 else 0

        print(f"  {Colors.GREEN}✓{Colors.RESET} Passed: {self.checks_passed}")
        print(f"  {Colors.RED}✗{Colors.RESET} Failed: {self.checks_failed}")
        print(f"  {Colors.BOLD}Success Rate: {success_rate:.1f}%{Colors.RESET}\n")

        if self.issues_found:
            print(f"{Colors.RED}{Colors.BOLD}Issues Found:{Colors.RESET}")
            for issue in self.issues_found:
                print(f"  • {issue}")
            print()

        if self.checks_failed == 0:
            print(f"{Colors.GREEN}{Colors.BOLD}✅ All startup checks passed!{Colors.RESET}")
            print(f"{Colors.GREEN}System is ready to start LureNet services.{Colors.RESET}\n")
            return 0
        else:
            print(f"{Colors.RED}{Colors.BOLD}❌ Startup checks failed!{Colors.RESET}")
            print(f"{Colors.RED}Please fix the issues above before starting services.{Colors.RESET}")
            if not self.fix_mode:
                print(f"{Colors.YELLOW}Run with --fix flag to automatically fix some issues.{Colors.RESET}")
            print()
            return 1

    def run_all_checks(self) -> int:
        """Run all startup checks"""
        self.print_header("LureNet Startup Validation")

        if self.fix_mode:
            print(f"{Colors.YELLOW}{Colors.BOLD}Running in FIX mode - will attempt to fix issues{Colors.RESET}\n")

        # Run all checks
        self.check_python_version()
        self.check_dependencies()
        self.check_directory_structure()
        self.check_file_permissions()
        self.check_configuration_files()
        self.check_database_connectivity()
        self.check_port_availability()
        self.check_system_resources()

        # Print summary
        return self.print_summary()


def main():
    parser = argparse.ArgumentParser(
        description='LureNet Startup Validation Tool'
    )
    parser.add_argument('--fix', action='store_true', help='Auto-fix issues')
    parser.add_argument('--service', help='Check specific service only')

    args = parser.parse_args()

    checker = StartupChecker(fix_mode=args.fix)
    exit_code = checker.run_all_checks()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
