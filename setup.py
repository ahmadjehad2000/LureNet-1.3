#!/usr/bin/env python3
"""
LureNet Setup and Installation Script
Interactive configuration wizard with system requirements checking
"""

import os
import sys
import platform
import shutil
import subprocess
import json
import sqlite3
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import getpass


class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class SystemRequirements:
    """Check system requirements"""

    REQUIRED_PYTHON_VERSION = (3, 8)
    RECOMMENDED_RAM_GB = 2
    REQUIRED_DISK_GB = 10
    REQUIRED_PORTS = [8080, 8888, 2222, 2121, 2525, 5353, 4445, 3389]

    @staticmethod
    def check_python_version() -> Tuple[bool, str]:
        """Check Python version"""
        current_version = sys.version_info[:2]
        required = SystemRequirements.REQUIRED_PYTHON_VERSION

        if current_version >= required:
            return True, f"Python {current_version[0]}.{current_version[1]} (OK)"
        else:
            return False, f"Python {current_version[0]}.{current_version[1]} (Required: {required[0]}.{required[1]}+)"

    @staticmethod
    def check_disk_space() -> Tuple[bool, str]:
        """Check available disk space"""
        try:
            stat = shutil.disk_usage('/')
            free_gb = stat.free / (1024 ** 3)

            if free_gb >= SystemRequirements.REQUIRED_DISK_GB:
                return True, f"{free_gb:.1f} GB available (OK)"
            else:
                return False, f"{free_gb:.1f} GB available (Required: {SystemRequirements.REQUIRED_DISK_GB} GB+)"
        except Exception as e:
            return False, f"Error checking disk space: {e}"

    @staticmethod
    def check_ram() -> Tuple[bool, str]:
        """Check available RAM"""
        try:
            import psutil
            total_ram_gb = psutil.virtual_memory().total / (1024 ** 3)

            if total_ram_gb >= SystemRequirements.RECOMMENDED_RAM_GB:
                return True, f"{total_ram_gb:.1f} GB (OK)"
            else:
                return False, f"{total_ram_gb:.1f} GB (Recommended: {SystemRequirements.RECOMMENDED_RAM_GB} GB+)"
        except ImportError:
            return False, "psutil not installed (cannot check)"

    @staticmethod
    def check_port_availability(port: int) -> bool:
        """Check if a port is available"""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result != 0  # Port is available if connection failed
        except Exception:
            return True

    @staticmethod
    def check_ports() -> Tuple[bool, str]:
        """Check if required ports are available"""
        unavailable_ports = []

        for port in SystemRequirements.REQUIRED_PORTS:
            if not SystemRequirements.check_port_availability(port):
                unavailable_ports.append(port)

        if not unavailable_ports:
            return True, "All ports available (OK)"
        else:
            return False, f"Ports in use: {', '.join(map(str, unavailable_ports))}"

    @staticmethod
    def check_commands() -> Tuple[bool, str]:
        """Check if required commands are available"""
        required_commands = ['python3', 'pip3']
        missing_commands = []

        for cmd in required_commands:
            if not shutil.which(cmd):
                missing_commands.append(cmd)

        if not missing_commands:
            return True, "All required commands found (OK)"
        else:
            return False, f"Missing commands: {', '.join(missing_commands)}"

    @staticmethod
    def check_user_permissions() -> Tuple[bool, str]:
        """Check if user has necessary permissions"""
        if os.geteuid() == 0:
            return True, "Running as root (OK - but not recommended for production)"
        else:
            return True, "Running as regular user (OK)"

    @classmethod
    def run_all_checks(cls) -> Dict[str, Tuple[bool, str]]:
        """Run all system requirement checks"""
        return {
            'Python Version': cls.check_python_version(),
            'Disk Space': cls.check_disk_space(),
            'RAM': cls.check_ram(),
            'Ports': cls.check_ports(),
            'Commands': cls.check_commands(),
            'Permissions': cls.check_user_permissions()
        }


class ConfigurationWizard:
    """Interactive configuration wizard"""

    def __init__(self):
        self.config = {}

    def print_header(self, text: str):
        """Print section header"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 70}")
        print(f"  {text}")
        print(f"{'=' * 70}{Colors.ENDC}\n")

    def prompt(self, message: str, default: Optional[str] = None) -> str:
        """Prompt user for input"""
        if default:
            prompt_text = f"{Colors.CYAN}{message} [{default}]{Colors.ENDC}: "
        else:
            prompt_text = f"{Colors.CYAN}{message}{Colors.ENDC}: "

        value = input(prompt_text).strip()
        return value if value else (default or '')

    def prompt_yes_no(self, message: str, default: bool = True) -> bool:
        """Prompt for yes/no answer"""
        default_str = 'Y/n' if default else 'y/N'
        value = self.prompt(message, default_str).lower()

        if not value:
            return default

        return value.startswith('y')

    def prompt_choice(self, message: str, choices: List[str], default: int = 0) -> str:
        """Prompt for choice from list"""
        print(f"\n{Colors.CYAN}{message}{Colors.ENDC}")
        for i, choice in enumerate(choices, 1):
            marker = " (default)" if i - 1 == default else ""
            print(f"  {i}. {choice}{marker}")

        while True:
            value = input(f"{Colors.CYAN}Enter choice [1-{len(choices)}]{Colors.ENDC}: ").strip()

            if not value:
                return choices[default]

            try:
                idx = int(value) - 1
                if 0 <= idx < len(choices):
                    return choices[idx]
            except ValueError:
                pass

            print(f"{Colors.RED}Invalid choice. Please enter a number between 1 and {len(choices)}{Colors.ENDC}")

    def configure_basic(self):
        """Configure basic settings"""
        self.print_header("Basic Configuration")

        self.config['installation'] = {
            'directory': self.prompt("Installation directory", "/opt/lurenet"),
            'data_directory': self.prompt("Data directory", "/opt/lurenet/data"),
            'log_directory': self.prompt("Log directory", "/var/log/lurenet")
        }

        self.config['deployment'] = {
            'mode': self.prompt_choice(
                "Deployment mode",
                ["Docker", "Systemd", "Supervisor", "Standalone"],
                1
            ).lower()
        }

    def configure_services(self):
        """Configure honeypot services"""
        self.print_header("Service Configuration")

        services = {
            'http': {'port': 8080, 'name': 'HTTP'},
            'ssh': {'port': 2222, 'name': 'SSH'},
            'ftp': {'port': 2121, 'name': 'FTP'},
            'smtp': {'port': 2525, 'name': 'SMTP'},
            'dns': {'port': 5353, 'name': 'DNS'},
            'smb': {'port': 4445, 'name': 'SMB'},
            'ldap': {'port': 3389, 'name': 'LDAP'}
        }

        self.config['services'] = {}

        for service_id, service_info in services.items():
            enabled = self.prompt_yes_no(
                f"Enable {service_info['name']} honeypot (port {service_info['port']})?",
                default=True
            )

            if enabled:
                port = int(self.prompt(
                    f"  Port for {service_info['name']}",
                    str(service_info['port'])
                ))
                self.config['services'][service_id] = {
                    'enabled': True,
                    'port': port
                }
            else:
                self.config['services'][service_id] = {'enabled': False}

    def configure_database(self):
        """Configure database"""
        self.print_header("Database Configuration")

        db_type = self.prompt_choice(
            "Database type",
            ["SQLite (file-based, simple)", "PostgreSQL (production, scalable)"],
            0
        )

        if "SQLite" in db_type:
            self.config['database'] = {
                'type': 'sqlite',
                'path': self.prompt(
                    "Database file path",
                    f"{self.config['installation']['data_directory']}/lurenet.db"
                )
            }
        else:
            self.config['database'] = {
                'type': 'postgresql',
                'host': self.prompt("PostgreSQL host", "localhost"),
                'port': int(self.prompt("PostgreSQL port", "5432")),
                'database': self.prompt("Database name", "lurenet"),
                'username': self.prompt("Username", "lurenet"),
                'password': getpass.getpass(f"{Colors.CYAN}Password{Colors.ENDC}: ")
            }

    def configure_monitoring(self):
        """Configure monitoring and alerts"""
        self.print_header("Monitoring & Alerts Configuration")

        # Health monitoring
        self.config['monitoring'] = {
            'enabled': self.prompt_yes_no("Enable health monitoring?", True),
            'check_interval': int(self.prompt("Health check interval (seconds)", "30")),
            'resource_monitoring': self.prompt_yes_no("Enable resource monitoring?", True)
        }

        # Alerts
        self.config['alerts'] = {}

        # Email alerts
        if self.prompt_yes_no("Configure email alerts?", False):
            self.config['alerts']['email'] = {
                'enabled': True,
                'smtp_host': self.prompt("SMTP host", "smtp.gmail.com"),
                'smtp_port': int(self.prompt("SMTP port", "587")),
                'smtp_use_tls': self.prompt_yes_no("Use TLS?", True),
                'from_address': self.prompt("From address", "lurenet@example.com"),
                'to_addresses': self.prompt("To addresses (comma-separated)", "admin@example.com").split(','),
                'username': self.prompt("SMTP username (leave empty if none)", ""),
                'password': getpass.getpass(f"{Colors.CYAN}SMTP password (leave empty if none){Colors.ENDC}: ")
            }
        else:
            self.config['alerts']['email'] = {'enabled': False}

        # Webhook alerts
        if self.prompt_yes_no("Configure webhook alerts (Slack, Discord, etc)?", False):
            self.config['alerts']['webhook'] = {
                'enabled': True,
                'url': self.prompt("Webhook URL", "")
            }
        else:
            self.config['alerts']['webhook'] = {'enabled': False}

    def configure_dashboard(self):
        """Configure dashboard"""
        self.print_header("Dashboard Configuration")

        self.config['dashboard'] = {
            'enabled': self.prompt_yes_no("Enable web dashboard?", True),
            'port': int(self.prompt("Dashboard port", "8888")),
            'host': self.prompt("Dashboard host", "0.0.0.0"),
            'enhanced': self.prompt_yes_no("Use enhanced dashboard with advanced features?", True)
        }

    def configure_security(self):
        """Configure security settings"""
        self.print_header("Security Configuration")

        self.config['security'] = {
            'rate_limiting': self.prompt_yes_no("Enable rate limiting?", True),
            'ip_blacklist': self.prompt_yes_no("Enable IP blacklisting?", True),
            'geo_blocking': self.prompt_yes_no("Enable geographic blocking?", False),
            'ssl_enabled': self.prompt_yes_no("Enable SSL/TLS for dashboard?", False)
        }

        if self.config['security']['ssl_enabled']:
            self.config['security']['ssl'] = {
                'cert_path': self.prompt("SSL certificate path", "/etc/lurenet/ssl/cert.pem"),
                'key_path': self.prompt("SSL key path", "/etc/lurenet/ssl/key.pem")
            }

    def run(self) -> Dict[str, Any]:
        """Run configuration wizard"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}")
        print("╔════════════════════════════════════════════════════════════════════╗")
        print("║                                                                    ║")
        print("║              LureNet Configuration Wizard                          ║")
        print("║              Version 2.0.0                                         ║")
        print("║                                                                    ║")
        print("╚════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.ENDC}\n")

        self.configure_basic()
        self.configure_services()
        self.configure_database()
        self.configure_monitoring()
        self.configure_dashboard()
        self.configure_security()

        return self.config


class Setup:
    """Main setup class"""

    def __init__(self):
        self.config = {}
        self.install_dir = None

    def print_status(self, message: str, status: str):
        """Print status message"""
        if status == 'OK':
            icon = f"{Colors.GREEN}✓{Colors.ENDC}"
        elif status == 'WARNING':
            icon = f"{Colors.YELLOW}⚠{Colors.ENDC}"
        elif status == 'ERROR':
            icon = f"{Colors.RED}✗{Colors.ENDC}"
        else:
            icon = f"{Colors.BLUE}ℹ{Colors.ENDC}"

        print(f"{icon} {message}")

    def check_requirements(self) -> bool:
        """Check system requirements"""
        print(f"\n{Colors.BOLD}Checking system requirements...{Colors.ENDC}\n")

        results = SystemRequirements.run_all_checks()
        all_passed = True

        for check_name, (passed, message) in results.items():
            status = 'OK' if passed else 'ERROR'
            self.print_status(f"{check_name}: {message}", status)

            if not passed and check_name not in ['RAM']:  # RAM is recommended but not required
                all_passed = False

        if not all_passed:
            print(f"\n{Colors.RED}Some requirements are not met. Please fix them before continuing.{Colors.ENDC}")
            return False

        print(f"\n{Colors.GREEN}All requirements met!{Colors.ENDC}")
        return True

    def create_directories(self):
        """Create necessary directories"""
        print(f"\n{Colors.BOLD}Creating directories...{Colors.ENDC}\n")

        directories = [
            self.config['installation']['directory'],
            self.config['installation']['data_directory'],
            self.config['installation']['log_directory'],
            f"{self.config['installation']['directory']}/config"
        ]

        for directory in directories:
            try:
                Path(directory).mkdir(parents=True, exist_ok=True)
                self.print_status(f"Created {directory}", 'OK')
            except Exception as e:
                self.print_status(f"Failed to create {directory}: {e}", 'ERROR')
                raise

    def install_dependencies(self):
        """Install Python dependencies"""
        print(f"\n{Colors.BOLD}Installing Python dependencies...{Colors.ENDC}\n")

        try:
            # Create virtual environment
            venv_path = f"{self.config['installation']['directory']}/venv"
            self.print_status("Creating virtual environment...", 'INFO')
            subprocess.run(
                [sys.executable, '-m', 'venv', venv_path],
                check=True,
                capture_output=True
            )
            self.print_status("Virtual environment created", 'OK')

            # Install requirements
            pip_path = f"{venv_path}/bin/pip"
            requirements_path = Path(__file__).parent / 'requirements.txt'

            if requirements_path.exists():
                self.print_status("Installing requirements...", 'INFO')
                subprocess.run(
                    [pip_path, 'install', '--upgrade', 'pip', 'setuptools', 'wheel'],
                    check=True,
                    capture_output=True
                )
                subprocess.run(
                    [pip_path, 'install', '-r', str(requirements_path)],
                    check=True,
                    capture_output=True
                )
                self.print_status("Dependencies installed", 'OK')
            else:
                self.print_status("requirements.txt not found", 'WARNING')

        except subprocess.CalledProcessError as e:
            self.print_status(f"Failed to install dependencies: {e}", 'ERROR')
            raise

    def initialize_database(self):
        """Initialize database"""
        print(f"\n{Colors.BOLD}Initializing database...{Colors.ENDC}\n")

        try:
            if self.config['database']['type'] == 'sqlite':
                db_path = self.config['database']['path']
                Path(db_path).parent.mkdir(parents=True, exist_ok=True)

                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()

                # Create basic tables
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        client_ip TEXT NOT NULL,
                        protocol TEXT NOT NULL,
                        attack_type TEXT,
                        threat_level TEXT,
                        threat_score REAL,
                        data TEXT
                    )
                """)

                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)
                """)

                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_events_client_ip ON events(client_ip)
                """)

                conn.commit()
                conn.close()

                self.print_status(f"SQLite database initialized at {db_path}", 'OK')

            elif self.config['database']['type'] == 'postgresql':
                self.print_status("PostgreSQL database configuration saved (manual initialization required)", 'OK')

        except Exception as e:
            self.print_status(f"Failed to initialize database: {e}", 'ERROR')
            raise

    def save_configuration(self):
        """Save configuration to file"""
        print(f"\n{Colors.BOLD}Saving configuration...{Colors.ENDC}\n")

        try:
            config_dir = f"{self.config['installation']['directory']}/config"
            config_path = f"{config_dir}/lurenet_config.json"

            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=2)

            self.print_status(f"Configuration saved to {config_path}", 'OK')

            # Also save health monitor config if monitoring is enabled
            if self.config.get('monitoring', {}).get('enabled'):
                health_config = {
                    'services': self.config['services'],
                    'database': self.config['database'],
                    'alerts': self.config['alerts'],
                    'resource_thresholds': {
                        'cpu_percent': 90,
                        'memory_percent': 90,
                        'disk_percent': 90,
                        'disk_free_gb_min': 1
                    }
                }

                health_config_path = f"{config_dir}/health_config.json"
                with open(health_config_path, 'w') as f:
                    json.dump(health_config, f, indent=2)

                self.print_status(f"Health monitor config saved to {health_config_path}", 'OK')

        except Exception as e:
            self.print_status(f"Failed to save configuration: {e}", 'ERROR')
            raise

    def print_summary(self):
        """Print installation summary"""
        print(f"\n{Colors.GREEN}{Colors.BOLD}")
        print("╔════════════════════════════════════════════════════════════════════╗")
        print("║                                                                    ║")
        print("║              LureNet Installation Complete!                        ║")
        print("║                                                                    ║")
        print("╚════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.ENDC}\n")

        print(f"{Colors.BOLD}Installation Details:{Colors.ENDC}")
        print(f"  Installation Directory: {self.config['installation']['directory']}")
        print(f"  Data Directory: {self.config['installation']['data_directory']}")
        print(f"  Log Directory: {self.config['installation']['log_directory']}")
        print(f"  Deployment Mode: {self.config['deployment']['mode']}")

        print(f"\n{Colors.BOLD}Enabled Services:{Colors.ENDC}")
        for service_name, service_config in self.config['services'].items():
            if service_config.get('enabled'):
                print(f"  ✓ {service_name.upper()}: port {service_config.get('port')}")

        print(f"\n{Colors.BOLD}Next Steps:{Colors.ENDC}")
        print(f"  1. Review configuration: {self.config['installation']['directory']}/config/lurenet_config.json")
        print(f"  2. Deploy using: ./deploy/deploy.sh --mode {self.config['deployment']['mode']}")

        if self.config.get('dashboard', {}).get('enabled'):
            dashboard_port = self.config['dashboard'].get('port', 8888)
            print(f"  3. Access dashboard: http://localhost:{dashboard_port}")

        print(f"\n{Colors.YELLOW}Security Note:{Colors.ENDC}")
        print(f"  This is a honeypot system. Ensure it's properly isolated and monitored.")

    def run(self):
        """Run setup process"""
        try:
            # Check requirements
            if not self.check_requirements():
                sys.exit(1)

            # Run configuration wizard
            wizard = ConfigurationWizard()
            self.config = wizard.run()

            print(f"\n{Colors.BOLD}Starting installation...{Colors.ENDC}")

            # Execute setup steps
            self.create_directories()
            self.install_dependencies()
            self.initialize_database()
            self.save_configuration()

            # Print summary
            self.print_summary()

        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}Setup interrupted by user{Colors.ENDC}")
            sys.exit(1)
        except Exception as e:
            print(f"\n{Colors.RED}Setup failed: {e}{Colors.ENDC}")
            sys.exit(1)


def main():
    """Main entry point"""
    setup = Setup()
    setup.run()


if __name__ == "__main__":
    main()
