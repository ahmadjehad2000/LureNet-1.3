#!/usr/bin/env python3
"""
LureNet System Test Suite
Comprehensive testing of all components
"""

import sys
import os
from pathlib import Path
import traceback

# Colors for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def print_test(message):
    print(f"{BLUE}[TEST]{RESET} {message}")

def print_pass(message):
    print(f"{GREEN}[PASS]{RESET} {message}")

def print_fail(message):
    print(f"{RED}[FAIL]{RESET} {message}")

def print_warn(message):
    print(f"{YELLOW}[WARN]{RESET} {message}")

def print_section(title):
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}{title.center(60)}{RESET}")
    print(f"{BLUE}{'='*60}{RESET}\n")

# Add to path
sys.path.insert(0, str(Path(__file__).parent / "Protocols" / "http_protocol"))

test_results = {
    'passed': 0,
    'failed': 0,
    'warnings': 0
}

# Test 1: Core Imports
print_section("Testing Core Imports")

tests = [
    ("Storage", "from intelligence.storage import get_storage, ThreatEvent"),
    ("Dashboard", "from intelligence.dashboard import get_dashboard"),
    ("Exporter", "from intelligence.exporter import get_exporter"),
    ("Logger", "from utils.logger import setup_logger"),
]

for name, import_stmt in tests:
    print_test(f"Importing {name}...")
    try:
        exec(import_stmt)
        print_pass(f"{name} imported successfully")
        test_results['passed'] += 1
    except Exception as e:
        print_fail(f"{name} import failed: {e}")
        test_results['failed'] += 1

# Test 2: Storage Initialization
print_section("Testing Storage System")

print_test("Initializing storage...")
try:
    from intelligence.storage import get_storage
    storage = get_storage()
    print_pass("Storage initialized successfully")
    test_results['passed'] += 1

    # Test database file
    db_path = Path("data/threat_intelligence.db")
    if db_path.exists():
        print_pass(f"Database file exists: {db_path}")
        test_results['passed'] += 1
    else:
        print_warn(f"Database file not found at: {db_path}")
        test_results['warnings'] += 1

except Exception as e:
    print_fail(f"Storage initialization failed: {e}")
    test_results['failed'] += 1

# Test 3: Dashboard
print_section("Testing Dashboard")

print_test("Initializing dashboard...")
try:
    from intelligence.dashboard import get_dashboard
    dashboard = get_dashboard()
    app = dashboard.get_app()
    print_pass("Dashboard initialized successfully")
    print_pass(f"Dashboard app type: {type(app).__name__}")
    test_results['passed'] += 2
except Exception as e:
    print_fail(f"Dashboard initialization failed: {e}")
    test_results['failed'] += 1

# Test 4: Service Manager
print_section("Testing Service Manager")

print_test("Importing service manager...")
try:
    import service_manager
    print_pass("Service manager imported successfully")
    test_results['passed'] += 1

    # Check config
    config_path = Path("config/services.yaml")
    if config_path.exists():
        print_pass(f"Configuration file exists: {config_path}")
        test_results['passed'] += 1
    else:
        print_warn(f"Configuration will be created on first run")
        test_results['warnings'] += 1

except Exception as e:
    print_fail(f"Service manager import failed: {e}")
    test_results['failed'] += 1

# Test 5: Protocol Files
print_section("Testing Protocol Services")

protocols = [
    ("DNS", "Protocols/dns_protocol/main.py"),
    ("SMB", "Protocols/smb_protocol/main.py"),
    ("SSH", "Protocols/ssh_protocol/main.py"),
    ("FTP", "Protocols/ftp_protocol/main.py"),
    ("SMTP", "Protocols/smtp_protocol/main.py"),
    ("AD/LDAP", "Protocols/ad_protocol/main.py"),
    ("HTTP", "Protocols/http_protocol/main.py"),
]

for name, path in protocols:
    print_test(f"Checking {name} protocol...")
    protocol_path = Path(path)
    if protocol_path.exists():
        print_pass(f"{name} protocol file exists")
        test_results['passed'] += 1

        # Try to compile it
        try:
            with open(protocol_path, 'r', encoding='utf-8') as f:
                compile(f.read(), path, 'exec')
            print_pass(f"{name} protocol compiles successfully")
            test_results['passed'] += 1
        except Exception as e:
            print_fail(f"{name} protocol has syntax errors: {e}")
            test_results['failed'] += 1
    else:
        print_fail(f"{name} protocol file not found: {path}")
        test_results['failed'] += 1

# Test 6: Critical Files
print_section("Testing Critical Files")

critical_files = [
    ("README.md", "README.md"),
    ("Requirements", "requirements.txt"),
    ("Gitignore", ".gitignore"),
    ("Bug Fix Summary", "BUG_FIX_SUMMARY.md"),
    ("Import Check", "check_imports.py"),
]

for name, path in critical_files:
    filepath = Path(path)
    if filepath.exists():
        print_pass(f"{name} exists: {path}")
        test_results['passed'] += 1
    else:
        print_warn(f"{name} not found: {path}")
        test_results['warnings'] += 1

# Test 7: Dependencies Check
print_section("Checking Dependencies")

required_deps = [
    'fastapi',
    'uvicorn',
    'click',
    'yaml',
    'asyncio',
    'pathlib',
    'sqlite3',
]

for dep in required_deps:
    print_test(f"Checking {dep}...")
    try:
        if dep == 'yaml':
            __import__('yaml')
        else:
            __import__(dep)
        print_pass(f"{dep} is available")
        test_results['passed'] += 1
    except ImportError:
        print_warn(f"{dep} not installed (install with: pip install {dep})")
        test_results['warnings'] += 1

# Test 8: Directory Structure
print_section("Checking Directory Structure")

required_dirs = [
    "Protocols",
    "Protocols/http_protocol",
    "Protocols/dns_protocol",
    "Protocols/smb_protocol",
    "Protocols/ssh_protocol",
    "Protocols/ftp_protocol",
    "Protocols/smtp_protocol",
    "Protocols/ad_protocol",
    "deploy",
    "deploy/production",
]

for dir_path in required_dirs:
    if Path(dir_path).is_dir():
        print_pass(f"Directory exists: {dir_path}")
        test_results['passed'] += 1
    else:
        print_fail(f"Directory missing: {dir_path}")
        test_results['failed'] += 1

# Test 9: Windows Compatibility
print_section("Testing Windows Compatibility")

print_test("Checking platform detection...")
import platform
system = platform.system()
print_pass(f"Running on: {system}")
test_results['passed'] += 1

if system == "Windows":
    print_test("Checking Windows-specific code...")
    try:
        import ctypes
        # Test admin check (should not crash)
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            print_pass(f"Windows admin check works (Admin: {bool(is_admin)})")
            test_results['passed'] += 1
        except:
            print_warn("Windows admin check failed (not critical)")
            test_results['warnings'] += 1
    except Exception as e:
        print_warn(f"Windows compatibility check failed: {e}")
        test_results['warnings'] += 1
else:
    print_pass("Unix/Linux platform detected")
    test_results['passed'] += 1

# Final Summary
print_section("Test Summary")

total = test_results['passed'] + test_results['failed'] + test_results['warnings']
print(f"Total Tests: {total}")
print(f"{GREEN}Passed: {test_results['passed']}{RESET}")
print(f"{RED}Failed: {test_results['failed']}{RESET}")
print(f"{YELLOW}Warnings: {test_results['warnings']}{RESET}")

pass_rate = (test_results['passed'] / total * 100) if total > 0 else 0
print(f"\n{BLUE}Pass Rate: {pass_rate:.1f}%{RESET}")

if test_results['failed'] == 0:
    print(f"\n{GREEN}✓ All critical tests passed!{RESET}")
    print(f"{GREEN}✓ System is ready to use{RESET}")
    sys.exit(0)
else:
    print(f"\n{RED}✗ Some tests failed{RESET}")
    print(f"{YELLOW}Review the output above for details{RESET}")
    sys.exit(1)
