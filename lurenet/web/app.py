"""
Flask Application

Modern web dashboard for threat visualization and analysis.
"""

from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_socketio import SocketIO, emit
from functools import wraps
from datetime import datetime, timedelta
import secrets


def create_app(engine):
    """
    Create and configure Flask application

    Args:
        engine: Honeypot engine instance

    Returns:
        Configured Flask app
    """
    app = Flask(__name__)

    # Configuration - Use Flask's built-in cookie sessions
    # Generate a stable secret key (same key each time for session persistence)
    secret_key = engine.config.get('dashboard.secret_key')
    if not secret_key:
        # Use a consistent secret key based on config
        secret_key = secrets.token_hex(32)
        app.logger.warning("Using auto-generated SECRET_KEY - set dashboard.secret_key in config for persistence")

    app.config['SECRET_KEY'] = secret_key

    # Session configuration
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_NAME'] = 'lurenet_session'
    app.config['SESSION_REFRESH_EACH_REQUEST'] = True
    app.config['JSON_AS_ASCII'] = False  # Support UTF-8 in JSON responses

    # Disable session modification tracking for better compatibility
    app.config['SESSION_COOKIE_DOMAIN'] = None
    app.config['APPLICATION_ROOT'] = '/'

    # Initialize SocketIO with threading mode (more reliable than gevent)
    # Threading mode is the recommended option as of 2025
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        async_mode='threading',
        logger=True,
        engineio_logger=False,
        ping_timeout=60,
        ping_interval=25
    )

    # Store engine reference
    app.engine = engine

    # Ensure UTF-8 encoding for all responses
    @app.after_request
    def add_header(response):
        """Add UTF-8 encoding header to all responses"""
        if 'Content-Type' in response.headers:
            if 'text/html' in response.headers['Content-Type']:
                response.headers['Content-Type'] = 'text/html; charset=utf-8'
        return response

    # Authentication decorator
    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('logged_in'):
                app.logger.warning(f"Unauthorized access attempt to {request.path}")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function

    # Routes
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Login page"""
        # If already logged in, redirect to dashboard
        if session.get('logged_in') == True:
            app.logger.info(f"User {session.get('username')} already logged in, redirecting to dashboard")
            return redirect(url_for('dashboard'))

        error = None
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()

            # Get credentials from config
            admin_user = engine.config.get('dashboard.admin_username', 'admin')
            admin_pass = engine.config.get('dashboard.admin_password', 'LureNet2024!')

            # Log login attempt (without sensitive info in production)
            app.logger.info(f"Login attempt for username: '{username}'")

            # Validate credentials
            if username and password and username == admin_user and password == admin_pass:
                # Clear any existing session data
                session.clear()

                # Set session as permanent (uses PERMANENT_SESSION_LIFETIME)
                session.permanent = True

                # Set authentication flags
                session['logged_in'] = True
                session['username'] = username
                session['login_time'] = datetime.utcnow().isoformat()

                # Force session to be saved
                session.modified = True

                app.logger.info(f"✓ Successful login for user: {username}")

                # Redirect to dashboard
                response = redirect(url_for('dashboard'))
                return response
            else:
                error = 'Invalid username or password. Please try again.'
                app.logger.warning(f"✗ Failed login attempt for username: '{username}'")

        return render_template('login.html', error=error)

    @app.route('/logout')
    def logout():
        """Logout"""
        session.clear()
        return redirect(url_for('login'))

    @app.route('/')
    @login_required
    def dashboard():
        """Main dashboard"""
        return render_template('dashboard.html', username=session.get('username'))

    @app.route('/threats')
    @login_required
    def threats():
        """Threats page"""
        return render_template('threats.html', username=session.get('username'))

    @app.route('/services')
    @login_required
    def services():
        """Services monitoring page"""
        return render_template('services.html', username=session.get('username'))

    @app.route('/analytics')
    @login_required
    def analytics():
        """Analytics page"""
        return render_template('analytics.html', username=session.get('username'))

    @app.route('/intelligence')
    @login_required
    def intelligence():
        """Threat Intelligence page"""
        return render_template('intelligence.html', username=session.get('username'))

    @app.route('/yara_scan')
    @login_required
    def yara_scan():
        """YARA Scanner page"""
        return render_template('yara_scan.html', username=session.get('username'))

    @app.route('/ip_lookup')
    @login_required
    def ip_lookup():
        """IP Lookup page"""
        return render_template('ip_lookup.html', username=session.get('username'))

    # API Routes
    @app.route('/api/statistics')
    @login_required
    def api_statistics():
        """Get threat statistics"""
        try:
            stats = engine.get_statistics()
            return jsonify(stats)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/events')
    @login_required
    def api_events():
        """Get recent events"""
        try:
            limit = request.args.get('limit', 100, type=int)
            events = engine.get_recent_events(limit)
            return jsonify({'events': events})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/services/status')
    @login_required
    def api_service_status():
        """Get service status"""
        try:
            status = engine.get_handler_status()
            return jsonify({'services': status, 'running': engine.is_running()})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # Analysis API Routes
    @app.route('/api/intel/hash', methods=['POST'])
    @login_required
    def api_analyze_hash():
        """Analyze hash via threat intelligence"""
        try:
            from lurenet.analysis import ThreatIntelligence

            data = request.get_json()
            file_hash = data.get('hash', '').strip()

            if not file_hash:
                return jsonify({'error': 'Hash required'}), 400

            intel = ThreatIntelligence()
            result = intel.analyze_hash(file_hash)
            return jsonify(result)
        except Exception as e:
            app.logger.error(f"Hash analysis error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/intel/url', methods=['POST'])
    @login_required
    def api_analyze_url():
        """Analyze URL via threat intelligence"""
        try:
            from lurenet.analysis import ThreatIntelligence

            data = request.get_json()
            url = data.get('url', '').strip()

            if not url:
                return jsonify({'error': 'URL required'}), 400

            intel = ThreatIntelligence()
            result = intel.analyze_url(url)
            return jsonify(result)
        except Exception as e:
            app.logger.error(f"URL analysis error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/yara/scan', methods=['POST'])
    @login_required
    def api_yara_scan():
        """Scan data with YARA rules"""
        try:
            from lurenet.analysis import YARAScanner

            data = request.get_json()
            scan_data = data.get('data', '').strip()

            if not scan_data:
                return jsonify({'error': 'Data required'}), 400

            scanner = YARAScanner()
            result = scanner.scan_string(scan_data, identifier=data.get('name', 'input'))
            return jsonify(result)
        except Exception as e:
            app.logger.error(f"YARA scan error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/yara/info', methods=['GET'])
    @login_required
    def api_yara_info():
        """Get YARA rule information"""
        try:
            from lurenet.analysis import YARAScanner

            scanner = YARAScanner()
            info = scanner.get_rule_info()
            return jsonify(info)
        except Exception as e:
            app.logger.error(f"YARA info error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/ip/lookup', methods=['POST'])
    @login_required
    def api_ip_lookup():
        """Lookup IP address"""
        try:
            from lurenet.analysis import IPReputation

            data = request.get_json()
            ip_address = data.get('ip', '').strip()

            if not ip_address:
                return jsonify({'error': 'IP address required'}), 400

            ip_rep = IPReputation()
            result = ip_rep.lookup(ip_address)
            return jsonify(result)
        except Exception as e:
            app.logger.error(f"IP lookup error: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/attacker/ips', methods=['GET'])
    @login_required
    def api_attacker_ips():
        """Get list of attacking IPs from database"""
        try:
            # Get unique attacker IPs from recent events
            events = engine.get_recent_events(1000)
            ips = list(set([e.get('source_ip') for e in events if e.get('source_ip')]))
            return jsonify({'ips': ips[:100]})  # Limit to 100 most recent
        except Exception as e:
            app.logger.error(f"Attacker IPs error: {e}")
            return jsonify({'error': str(e)}), 500

    # WebSocket events
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        if 'logged_in' not in session:
            return False
        emit('connected', {'message': 'Connected to LureNet'})

    @socketio.on('request_stats')
    def handle_stats_request():
        """Handle statistics request"""
        try:
            stats = engine.get_statistics()
            emit('stats_update', stats)
        except Exception as e:
            emit('error', {'message': str(e)})

    # Store socketio reference
    app.socketio = socketio

    return app, socketio
