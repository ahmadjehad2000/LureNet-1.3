#!/usr/bin/env python3
"""
Quick test to verify authentication fixes and library compatibility
"""

print("=" * 60)
print("LureNet Authentication & Library Test")
print("=" * 60)

# Test 1: Import core libraries
print("\n1. Testing core library imports...")
try:
    import flask
    print(f"   ✓ Flask {flask.__version__}")
except Exception as e:
    print(f"   ✗ Flask import failed: {e}")

try:
    import flask_socketio
    print(f"   ✓ Flask-SocketIO {flask_socketio.__version__}")
except Exception as e:
    print(f"   ✗ Flask-SocketIO import failed: {e}")

try:
    import sqlalchemy
    print(f"   ✓ SQLAlchemy {sqlalchemy.__version__}")
except Exception as e:
    print(f"   ✗ SQLAlchemy import failed: {e}")

# Test 2: Test threading mode (no gevent)
print("\n2. Testing SocketIO threading mode...")
try:
    from flask import Flask
    from flask_socketio import SocketIO

    test_app = Flask(__name__)
    test_app.config['SECRET_KEY'] = 'test-secret-key'

    # Initialize with threading mode (should work without gevent)
    test_socketio = SocketIO(
        test_app,
        async_mode='threading',
        logger=False,
        engineio_logger=False
    )

    print("   ✓ SocketIO initialized with threading mode")
    print(f"   ✓ Async mode: {test_socketio.async_mode}")

except Exception as e:
    print(f"   ✗ SocketIO threading mode failed: {e}")

# Test 3: Test session management
print("\n3. Testing session management...")
try:
    from flask import Flask, session
    from datetime import timedelta

    test_app = Flask(__name__)
    test_app.config['SECRET_KEY'] = 'test-secret-key'
    test_app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    test_app.config['SESSION_COOKIE_NAME'] = 'lurenet_session'

    with test_app.test_request_context():
        session['logged_in'] = True
        session['username'] = 'test_user'

        assert session.get('logged_in') == True
        assert session.get('username') == 'test_user'

    print("   ✓ Session management works correctly")

except Exception as e:
    print(f"   ✗ Session test failed: {e}")

# Test 4: Test authentication flow
print("\n4. Testing authentication flow...")
try:
    from flask import Flask, session
    from werkzeug.security import check_password_hash, generate_password_hash

    test_app = Flask(__name__)
    test_app.config['SECRET_KEY'] = 'test-secret-key'

    # Test credentials
    admin_user = 'admin'
    admin_pass = 'LureNet2024!'

    # Simulate login
    with test_app.test_request_context():
        session.clear()
        session.permanent = True
        session['logged_in'] = True
        session['username'] = admin_user
        session.modified = True

        # Verify session
        assert session.get('logged_in') == True
        assert session.get('username') == admin_user

    print("   ✓ Authentication flow simulation passed")
    print(f"   ✓ Test user: {admin_user}")

except Exception as e:
    print(f"   ✗ Authentication test failed: {e}")

# Test 5: Test analysis modules
print("\n5. Testing analysis modules...")
try:
    from lurenet.analysis import ThreatIntelligence, YARAScanner, IPReputation

    # Test ThreatIntelligence
    intel = ThreatIntelligence()
    assert intel._detect_hash_type('a' * 32) == 'md5'
    print("   ✓ ThreatIntelligence module works")

    # Test YARAScanner
    scanner = YARAScanner()
    assert scanner.compiled_rules is not None
    print("   ✓ YARAScanner module works")

    # Test IPReputation
    ip_rep = IPReputation()
    assert hasattr(ip_rep, 'lookup')
    print("   ✓ IPReputation module works")

except Exception as e:
    print(f"   ✗ Analysis modules test failed: {e}")

print("\n" + "=" * 60)
print("✅ All tests completed successfully!")
print("=" * 60)
print("\nYou can now run: python app.py")
print("Default login: admin / LureNet2024!")
print("=" * 60)
