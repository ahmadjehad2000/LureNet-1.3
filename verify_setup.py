#!/usr/bin/env python3
"""
LureNet Setup Verification Script

Verifies that all components are properly configured and templates are accessible.
"""

import os
import sys
from pathlib import Path

def check_templates():
    """Verify all required templates exist"""
    print("🔍 Checking templates...")
    template_dir = Path(__file__).parent / "lurenet" / "web" / "templates"
    
    required_templates = [
        'base.html',
        'login.html',
        'dashboard.html',
        'threats.html',
        'services.html',
        'analytics.html',
        'intelligence.html',
        'yara_scan.html',
        'ip_lookup.html'
    ]
    
    missing = []
    for template in required_templates:
        template_path = template_dir / template
        if template_path.exists():
            print(f"  ✓ {template}")
        else:
            print(f"  ✗ {template} - MISSING")
            missing.append(template)
    
    if missing:
        print(f"\n❌ Missing templates: {', '.join(missing)}")
        return False
    print("✅ All templates found!\n")
    return True

def check_static_files():
    """Verify CSS and static files exist"""
    print("🔍 Checking static files...")
    static_dir = Path(__file__).parent / "lurenet" / "web" / "static"
    css_file = static_dir / "css" / "main.css"
    
    if css_file.exists():
        file_size = css_file.stat().st_size
        print(f"  ✓ main.css ({file_size:,} bytes)")
        print("✅ Static files found!\n")
        return True
    else:
        print("  ✗ main.css - MISSING")
        print("❌ Static files not found!\n")
        return False

def check_routes():
    """Verify Flask app routes are configured"""
    print("🔍 Checking Flask app configuration...")
    app_file = Path(__file__).parent / "lurenet" / "web" / "app.py"
    
    if not app_file.exists():
        print("  ✗ app.py - MISSING")
        print("❌ Flask app not found!\n")
        return False
    
    content = app_file.read_text()
    
    required_routes = [
        "'/login'",
        "'/'",  # Dashboard at root
        "'/intelligence'",
        "'/yara_scan'",
        "'/ip_lookup'",
        "'/api/intel/hash'",
        "'/api/yara/scan'",
        "'/api/ip/lookup'"
    ]
    
    missing = []
    for route in required_routes:
        if route in content:
            print(f"  ✓ Route {route}")
        else:
            print(f"  ✗ Route {route} - MISSING")
            missing.append(route)
    
    if missing:
        print(f"\n❌ Missing routes: {', '.join(missing)}")
        return False
    print("✅ All routes configured!\n")
    return True

def check_analysis_module():
    """Verify analysis module exists"""
    print("🔍 Checking analysis module...")
    analysis_dir = Path(__file__).parent / "lurenet" / "analysis"
    
    required_files = [
        '__init__.py',
        'threat_intel.py',
        'yara_scanner.py',
        'ip_reputation.py'
    ]
    
    missing = []
    for file in required_files:
        file_path = analysis_dir / file
        if file_path.exists():
            print(f"  ✓ {file}")
        else:
            print(f"  ✗ {file} - MISSING")
            missing.append(file)
    
    if missing:
        print(f"\n❌ Missing analysis files: {', '.join(missing)}")
        return False
    print("✅ Analysis module complete!\n")
    return True

def main():
    """Run all verification checks"""
    print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║       🎯 LureNet Setup Verification                       ║
║                                                           ║
║       Verifying all components are properly configured    ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    checks = [
        ("Templates", check_templates),
        ("Static Files", check_static_files),
        ("Flask Routes", check_routes),
        ("Analysis Module", check_analysis_module)
    ]
    
    results = []
    for name, check_func in checks:
        try:
            results.append(check_func())
        except Exception as e:
            print(f"❌ Error checking {name}: {e}\n")
            results.append(False)
    
    print("=" * 60)
    if all(results):
        print("✅ All checks passed! LureNet is properly configured.")
        print("\nYou can now start LureNet with:")
        print("  python app.py")
        print("\nDashboard will be available at:")
        print("  http://localhost:5000")
        print("\nDefault credentials:")
        print("  Username: admin")
        print("  Password: LureNet2024!")
        return 0
    else:
        print("❌ Some checks failed. Please review the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
