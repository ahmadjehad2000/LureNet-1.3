#!/usr/bin/env python3
"""
LureNet Integration Validation Script
Tests all system integrations, imports, database connectivity, and service health

Usage:
    python validate_integration.py                  # Run all tests
    python validate_integration.py --quick          # Quick validation only
    python validate_integration.py --verbose        # Detailed output
    python validate_integration.py --fix            # Attempt to fix issues
"""

import sys
import asyncio
import argparse
import importlib
import sqlite3
import socket
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
import time

@dataclass
class ValidationResult:
    """Result of a validation test"""
    category: str
    test_name: str
    status: str  # passed, failed, warning, skipped
    message: str
    details: Dict[str, Any]
    duration: float


class IntegrationValidator:
    """Comprehensive integration validation"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results: List[ValidationResult] = []
        self.project_root = Path(__file__).parent

    def log(self, message: str, level: str = "INFO"):
        """Log message"""
        if self.verbose or level in ["ERROR", "WARNING"]:
            prefix = {"INFO": "ℹ️", "ERROR": "❌", "WARNING": "⚠️", "SUCCESS": "✅"}
            print(f"{prefix.get(level, 'ℹ️')} {message}")

    async def validate_imports(self) -> List[ValidationResult]:
        """Validate all critical imports"""
        self.log("Testing Python imports...", "INFO")
        results = []

        # Critical imports to test
        critical_imports = [
            ("fastapi", "FastAPI web framework"),
            ("uvicorn", "ASGI server"),
            ("pydantic", "Data validation"),
            ("sqlite3", "Database (built-in)"),
            ("jwt", "JWT authentication"),
            ("bcrypt", "Password hashing"),
            ("yaml", "Configuration files"),
            ("click", "CLI interface"),
        ]

        optional_imports = [
            ("dnslib", "DNS protocol"),
            ("asyncssh", "SSH protocol"),
            ("aiosmtpd", "SMTP protocol"),
            ("psutil", "System monitoring"),
        ]

        # Test critical imports
        for module_name, description in critical_imports:
            start_time = time.time()
            try:
                if module_name == "jwt":
                    importlib.import_module("jose.jwt")
                else:
                    importlib.import_module(module_name)

                results.append(ValidationResult(
                    category="imports",
                    test_name=f"Import {module_name}",
                    status="passed",
                    message=f"{description} imported successfully",
                    details={"module": module_name},
                    duration=time.time() - start_time
                ))
                self.log(f"✓ {module_name}: {description}", "SUCCESS")
            except ImportError as e:
                results.append(ValidationResult(
                    category="imports",
                    test_name=f"Import {module_name}",
                    status="failed",
                    message=f"Failed to import {module_name}: {str(e)}",
                    details={"module": module_name, "error": str(e)},
                    duration=time.time() - start_time
                ))
                self.log(f"✗ {module_name}: Missing ({description})", "ERROR")

        # Test optional imports
        for module_name, description in optional_imports:
            start_time = time.time()
            try:
                importlib.import_module(module_name)
                results.append(ValidationResult(
                    category="imports",
                    test_name=f"Import {module_name}",
                    status="passed",
                    message=f"{description} available",
                    details={"module": module_name, "optional": True},
                    duration=time.time() - start_time
                ))
                self.log(f"✓ {module_name}: {description} (optional)", "SUCCESS")
            except ImportError:
                results.append(ValidationResult(
                    category="imports",
                    test_name=f"Import {module_name}",
                    status="warning",
                    message=f"{description} not available (optional)",
                    details={"module": module_name, "optional": True},
                    duration=time.time() - start_time
                ))
                self.log(f"⊘ {module_name}: Not installed (optional)", "WARNING")

        return results

    async def validate_project_structure(self) -> List[ValidationResult]:
        """Validate project structure"""
        self.log("Validating project structure...", "INFO")
        results = []

        # Required directories
        required_dirs = [
            ("Protocols", "Protocol honeypots"),
            ("Protocols/http_protocol", "HTTP honeypot"),
            ("Protocols/http_protocol/auth", "Authentication system"),
            ("Protocols/http_protocol/intelligence", "Intelligence system"),
            ("config", "Configuration files"),
            ("data", "Data storage"),
        ]

        for dir_path, description in required_dirs:
            start_time = time.time()
            full_path = self.project_root / dir_path
            if full_path.exists() and full_path.is_dir():
                results.append(ValidationResult(
                    category="structure",
                    test_name=f"Directory {dir_path}",
                    status="passed",
                    message=f"{description} exists",
                    details={"path": str(full_path)},
                    duration=time.time() - start_time
                ))
                self.log(f"✓ {dir_path}", "SUCCESS")
            else:
                results.append(ValidationResult(
                    category="structure",
                    test_name=f"Directory {dir_path}",
                    status="failed",
                    message=f"{description} missing",
                    details={"path": str(full_path)},
                    duration=time.time() - start_time
                ))
                self.log(f"✗ {dir_path}: Missing", "ERROR")

        # Required files
        required_files = [
            ("requirements.txt", "Dependencies"),
            ("service_manager.py", "Service manager"),
            ("health_monitor.py", "Health monitor"),
        ]

        for file_path, description in required_files:
            start_time = time.time()
            full_path = self.project_root / file_path
            if full_path.exists() and full_path.is_file():
                results.append(ValidationResult(
                    category="structure",
                    test_name=f"File {file_path}",
                    status="passed",
                    message=f"{description} exists",
                    details={"path": str(full_path), "size": full_path.stat().st_size},
                    duration=time.time() - start_time
                ))
                self.log(f"✓ {file_path}", "SUCCESS")
            else:
                results.append(ValidationResult(
                    category="structure",
                    test_name=f"File {file_path}",
                    status="failed",
                    message=f"{description} missing",
                    details={"path": str(full_path)},
                    duration=time.time() - start_time
                ))
                self.log(f"✗ {file_path}: Missing", "ERROR")

        return results

    async def validate_database(self) -> List[ValidationResult]:
        """Validate database schemas and connectivity"""
        self.log("Testing database connectivity...", "INFO")
        results = []

        # Test databases
        databases = [
            ("data/threat_intelligence.db", "Threat intelligence"),
            ("data/auth.db", "Authentication"),
        ]

        for db_path, description in databases:
            start_time = time.time()
            full_path = self.project_root / db_path

            # Create parent directory if needed
            full_path.parent.mkdir(parents=True, exist_ok=True)

            try:
                # Test connection
                conn = sqlite3.connect(str(full_path), timeout=5.0)
                cursor = conn.cursor()

                # Get table count
                cursor.execute("SELECT count(*) FROM sqlite_master WHERE type='table'")
                table_count = cursor.fetchone()[0]

                # Test write
                cursor.execute("CREATE TABLE IF NOT EXISTS validation_test (id INTEGER PRIMARY KEY, ts REAL)")
                cursor.execute("INSERT INTO validation_test (ts) VALUES (?)", (time.time(),))
                cursor.execute("SELECT COUNT(*) FROM validation_test")
                record_count = cursor.fetchone()[0]
                cursor.execute("DELETE FROM validation_test WHERE ts < ?", (time.time(),))
                conn.commit()
                conn.close()

                results.append(ValidationResult(
                    category="database",
                    test_name=f"Database {db_path}",
                    status="passed",
                    message=f"{description} database accessible",
                    details={
                        "path": str(full_path),
                        "tables": table_count,
                        "test_records": record_count
                    },
                    duration=time.time() - start_time
                ))
                self.log(f"✓ {db_path}: {table_count} tables", "SUCCESS")
            except Exception as e:
                results.append(ValidationResult(
                    category="database",
                    test_name=f"Database {db_path}",
                    status="failed",
                    message=f"Database error: {str(e)}",
                    details={"path": str(full_path), "error": str(e)},
                    duration=time.time() - start_time
                ))
                self.log(f"✗ {db_path}: {str(e)}", "ERROR")

        return results

    async def validate_ports(self) -> List[ValidationResult]:
        """Validate port availability"""
        self.log("Checking port availability...", "INFO")
        results = []

        # Default ports
        ports = [
            (8080, "HTTP Honeypot"),
            (2222, "SSH Honeypot"),
            (2121, "FTP Honeypot"),
            (2525, "SMTP Honeypot"),
            (5353, "DNS Honeypot"),
            (4445, "SMB Honeypot"),
            (3389, "LDAP/AD Honeypot"),
            (8888, "Dashboard"),
        ]

        for port, service in ports:
            start_time = time.time()
            try:
                # Try to bind to port
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.bind(('127.0.0.1', port))
                sock.close()

                results.append(ValidationResult(
                    category="ports",
                    test_name=f"Port {port}",
                    status="passed",
                    message=f"{service} port available",
                    details={"port": port, "service": service},
                    duration=time.time() - start_time
                ))
                self.log(f"✓ Port {port}: Available ({service})", "SUCCESS")
            except OSError as e:
                if "Address already in use" in str(e):
                    results.append(ValidationResult(
                        category="ports",
                        test_name=f"Port {port}",
                        status="warning",
                        message=f"{service} port in use",
                        details={"port": port, "service": service, "error": str(e)},
                        duration=time.time() - start_time
                    ))
                    self.log(f"⚠ Port {port}: In use ({service})", "WARNING")
                else:
                    results.append(ValidationResult(
                        category="ports",
                        test_name=f"Port {port}",
                        status="failed",
                        message=f"Port check failed: {str(e)}",
                        details={"port": port, "service": service, "error": str(e)},
                        duration=time.time() - start_time
                    ))
                    self.log(f"✗ Port {port}: Error - {str(e)}", "ERROR")

        return results

    async def validate_python_version(self) -> List[ValidationResult]:
        """Validate Python version"""
        self.log("Checking Python version...", "INFO")
        results = []
        start_time = time.time()

        version = sys.version_info
        version_str = f"{version.major}.{version.minor}.{version.micro}"

        if version.major >= 3 and version.minor >= 8:
            results.append(ValidationResult(
                category="system",
                test_name="Python version",
                status="passed",
                message=f"Python {version_str} (compatible)",
                details={"version": version_str, "required": "3.8+"},
                duration=time.time() - start_time
            ))
            self.log(f"✓ Python {version_str}", "SUCCESS")
        else:
            results.append(ValidationResult(
                category="system",
                test_name="Python version",
                status="failed",
                message=f"Python {version_str} (requires 3.8+)",
                details={"version": version_str, "required": "3.8+"},
                duration=time.time() - start_time
            ))
            self.log(f"✗ Python {version_str}: Requires 3.8+", "ERROR")

        return results

    async def validate_configs(self) -> List[ValidationResult]:
        """Validate configuration files"""
        self.log("Validating configuration files...", "INFO")
        results = []

        config_files = [
            ("config/services.yaml", "Service configuration", False),
            ("config/intelligence.yaml", "Intelligence configuration", True),
            ("config/vulnerabilities.yaml", "Vulnerability simulations", True),
        ]

        for config_path, description, optional in config_files:
            start_time = time.time()
            full_path = self.project_root / config_path

            if full_path.exists():
                try:
                    import yaml
                    with open(full_path, 'r') as f:
                        config = yaml.safe_load(f)

                    results.append(ValidationResult(
                        category="config",
                        test_name=f"Config {config_path}",
                        status="passed",
                        message=f"{description} valid",
                        details={"path": str(full_path), "keys": len(config) if config else 0},
                        duration=time.time() - start_time
                    ))
                    self.log(f"✓ {config_path}", "SUCCESS")
                except Exception as e:
                    results.append(ValidationResult(
                        category="config",
                        test_name=f"Config {config_path}",
                        status="failed",
                        message=f"Invalid YAML: {str(e)}",
                        details={"path": str(full_path), "error": str(e)},
                        duration=time.time() - start_time
                    ))
                    self.log(f"✗ {config_path}: Invalid - {str(e)}", "ERROR")
            elif not optional:
                results.append(ValidationResult(
                    category="config",
                    test_name=f"Config {config_path}",
                    status="failed",
                    message=f"{description} missing",
                    details={"path": str(full_path)},
                    duration=time.time() - start_time
                ))
                self.log(f"✗ {config_path}: Missing", "ERROR")
            else:
                results.append(ValidationResult(
                    category="config",
                    test_name=f"Config {config_path}",
                    status="warning",
                    message=f"{description} missing (optional)",
                    details={"path": str(full_path), "optional": True},
                    duration=time.time() - start_time
                ))
                self.log(f"⊘ {config_path}: Not found (optional)", "WARNING")

        return results

    async def run_all_validations(self) -> List[ValidationResult]:
        """Run all validation tests"""
        all_results = []

        print("\n" + "="*80)
        print("          LureNet Integration Validation")
        print("="*80 + "\n")

        # Run all validation tests
        all_results.extend(await self.validate_python_version())
        all_results.extend(await self.validate_imports())
        all_results.extend(await self.validate_project_structure())
        all_results.extend(await self.validate_database())
        all_results.extend(await self.validate_configs())
        all_results.extend(await self.validate_ports())

        self.results = all_results
        return all_results

    def print_summary(self):
        """Print validation summary"""
        print("\n" + "="*80)
        print("                    VALIDATION SUMMARY")
        print("="*80 + "\n")

        # Count by status
        passed = sum(1 for r in self.results if r.status == "passed")
        failed = sum(1 for r in self.results if r.status == "failed")
        warnings = sum(1 for r in self.results if r.status == "warning")
        skipped = sum(1 for r in self.results if r.status == "skipped")

        total = len(self.results)
        success_rate = (passed / total * 100) if total > 0 else 0

        print(f"  ✅ Passed:    {passed}")
        print(f"  ❌ Failed:    {failed}")
        print(f"  ⚠️  Warnings:  {warnings}")
        print(f"  ⊘  Skipped:   {skipped}")
        print(f"  📊 Total:     {total}")
        print(f"  📈 Success:   {success_rate:.1f}%\n")

        # Results by category
        print("Results by Category:")
        categories = {}
        for result in self.results:
            if result.category not in categories:
                categories[result.category] = {"passed": 0, "failed": 0, "warning": 0}
            categories[result.category][result.status] += 1

        for category, counts in sorted(categories.items()):
            total_cat = sum(counts.values())
            passed_cat = counts["passed"]
            print(f"  • {category.title()}: {passed_cat}/{total_cat} passed")

        print("\n" + "="*80)

        # Show failed tests
        failed_tests = [r for r in self.results if r.status == "failed"]
        if failed_tests:
            print("\n❌ Failed Tests:")
            print("-" * 80)
            for test in failed_tests:
                print(f"\n  {test.test_name}")
                print(f"  Error: {test.message}")

        # Exit code
        if failed:
            print("\n⚠️  Validation completed with failures!")
            print("Please address the issues above before deploying.\n")
            return 1
        else:
            print("\n✅ All validations passed successfully!\n")
            return 0

    def save_report(self, output_path: str = "validation_report.json"):
        """Save validation report to JSON"""
        report = {
            "timestamp": time.time(),
            "summary": {
                "total": len(self.results),
                "passed": sum(1 for r in self.results if r.status == "passed"),
                "failed": sum(1 for r in self.results if r.status == "failed"),
                "warnings": sum(1 for r in self.results if r.status == "warning"),
            },
            "results": [
                {
                    "category": r.category,
                    "test_name": r.test_name,
                    "status": r.status,
                    "message": r.message,
                    "details": r.details,
                    "duration": r.duration
                }
                for r in self.results
            ]
        }

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n📄 Report saved to: {output_path}")


async def main():
    parser = argparse.ArgumentParser(
        description='LureNet Integration Validation Tool'
    )
    parser.add_argument('--quick', action='store_true', help='Quick validation only')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--report', help='Save JSON report to file')

    args = parser.parse_args()

    validator = IntegrationValidator(verbose=args.verbose or not args.quick)
    await validator.run_all_validations()
    exit_code = validator.print_summary()

    if args.report:
        validator.save_report(args.report)

    sys.exit(exit_code)


if __name__ == "__main__":
    asyncio.run(main())
