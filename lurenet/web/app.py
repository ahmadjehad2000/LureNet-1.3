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
    app.config['SECRET_KEY'] = engine.config.get(
        'dashboard.secret_key',
        secrets.token_hex(32)
    )
    # Session configuration
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_REFRESH_EACH_REQUEST'] = True
    app.config['JSON_AS_ASCII'] = False  # Support UTF-8 in JSON responses

    # Initialize SocketIO with gevent
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')

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
        if session.get('logged_in'):
            app.logger.info(f"User {session.get('username')} already logged in, redirecting to dashboard")
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')

            # Get credentials from config
            admin_user = engine.config.get('dashboard.admin_username', 'admin')
            admin_pass = engine.config.get('dashboard.admin_password', 'LureNet2024!')

            # Debug logging
            app.logger.info(f"Login attempt - Username: '{username}', Expected: '{admin_user}'")
            app.logger.debug(f"Password length: {len(password)}, Expected length: {len(admin_pass)}")

            if username == admin_user and password == admin_pass:
                # Clear session and set new data
                session.clear()
                session.permanent = True
                session['logged_in'] = True
                session['username'] = username

                app.logger.info(f"✓ Successful login for user: {username}, Session ID: {session.sid if hasattr(session, 'sid') else 'N/A'}")
                app.logger.info(f"Session data after login: {dict(session)}")

                return redirect(url_for('dashboard'))
            else:
                app.logger.warning(f"✗ Failed login attempt - Username: '{username}'")
                if username != admin_user:
                    app.logger.warning(f"  Username mismatch: got '{username}', expected '{admin_user}'")
                if password != admin_pass:
                    app.logger.warning(f"  Password mismatch")
                return render_template('login.html', error='Invalid username or password')

        return render_template('login.html')

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
