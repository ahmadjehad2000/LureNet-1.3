"""
HTTP Honeypot

Professional HTTP honeypot for detecting web-based attacks.
"""

import re
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from typing import Dict, Any, List
from lurenet.protocols.base import BaseProtocolHandler


class HTTPHoneypotHandler(BaseHTTPRequestHandler):
    """HTTP request handler for honeypot"""

    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

    def _analyze_request(self) -> Dict[str, Any]:
        """Analyze HTTP request for threats"""
        indicators = []
        payload = None

        # Get request components
        path = self.path
        method = self.command
        headers = dict(self.headers)

        # Read POST data if present
        if method in ['POST', 'PUT']:
            try:
                content_length = int(headers.get('Content-Length', 0))
                if content_length > 0:
                    payload = self.rfile.read(content_length).decode('utf-8', errors='ignore')
            except:
                pass

        # Analyze for attack patterns
        combined_data = f"{path} {payload or ''}"

        # SQL Injection patterns
        sql_patterns = [
            r"(?:')|(?:--)|(?:#)|(/\*(?:.|[\n\r])*?\*/)",
            r"(?:UNION\s+SELECT)|(?:SELECT.*FROM)",
            r"(?:DROP\s+TABLE)|(?:INSERT\s+INTO)",
            r"(?:1=1)|(?:' OR '1'='1)",
        ]
        for pattern in sql_patterns:
            if re.search(pattern, combined_data, re.IGNORECASE):
                indicators.append('sql_injection')
                break

        # XSS patterns
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe",
        ]
        for pattern in xss_patterns:
            if re.search(pattern, combined_data, re.IGNORECASE):
                indicators.append('xss')
                break

        # Path Traversal
        if re.search(r"\.\.(/|\\)", path):
            indicators.append('path_traversal')

        # Command Injection
        cmd_patterns = [
            r"[;&|`$]",
            r"(?:cat|ls|wget|curl)\s+",
            r"(?:>/dev/null)",
        ]
        for pattern in cmd_patterns:
            if re.search(pattern, combined_data):
                indicators.append('command_injection')
                break

        # File Upload attempts
        if 'multipart/form-data' in headers.get('Content-Type', ''):
            indicators.append('file_upload')

        # Malware/exploit tools detection
        user_agent = headers.get('User-Agent', '').lower()
        malicious_agents = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'metasploit',
            'burp', 'w3af', 'acunetix', 'nessus', 'openvas'
        ]
        for agent in malicious_agents:
            if agent in user_agent:
                indicators.append('scanning_tool')
                break

        # Sensitive paths
        sensitive_paths = [
            '/admin', '/phpmyadmin', '/wp-admin', '/.env',
            '/config', '/backup', '/.git', '/mysql'
        ]
        for sens_path in sensitive_paths:
            if sens_path in path.lower():
                indicators.append('sensitive_path_access')
                break

        return {
            'method': method,
            'path': path,
            'user_agent': headers.get('User-Agent', ''),
            'headers': headers,
            'payload': payload,
            'indicators': list(set(indicators)),  # Remove duplicates
        }

    def _send_response(self, status: int = 200, content: str = None):
        """Send HTTP response"""
        try:
            if content is None:
                content = self._generate_fake_page()

            self.send_response(status)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Server', self.server.honeypot.config.get('banner', 'Apache/2.4.52'))
            self.send_header('Content-Length', len(content))
            self.end_headers()
            self.wfile.write(content.encode())
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            # Client disconnected before response could be sent
            # This is normal in honeypots - attackers often disconnect early
            pass
        except Exception:
            # Silently ignore other errors to avoid cluttering logs
            pass

    def _generate_fake_page(self) -> str:
        """Generate fake web page"""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .login-box { max-width: 400px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; }
        input { width: 100%; padding: 10px; margin: 10px 0; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Login</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>"""

    def _log_request(self, analysis: Dict[str, Any]):
        """Log request to honeypot engine"""
        client_ip, client_port = self.client_address

        # Calculate threat score
        threat_score = self.server.honeypot.calculate_threat_score(
            analysis['indicators']
        )

        severity = self.server.honeypot.get_severity(threat_score)

        # Determine attack type
        attack_type = 'port_scan' if not analysis['indicators'] else analysis['indicators'][0]

        # Create event
        event_data = {
            'source_ip': client_ip,
            'source_port': client_port,
            'attack_type': attack_type,
            'severity': severity,
            'threat_score': threat_score,
            'method': analysis['method'],
            'path': analysis['path'],
            'user_agent': analysis['user_agent'],
            'headers': analysis['headers'],
            'payload': analysis['payload'],
            'detected_tools': analysis['indicators'],
            'indicators': analysis['indicators'],
        }

        # Log to engine
        self.server.honeypot.log_event(event_data)

    def do_GET(self):
        """Handle GET request"""
        analysis = self._analyze_request()
        self._log_request(analysis)
        self._send_response()

    def do_POST(self):
        """Handle POST request"""
        analysis = self._analyze_request()
        self._log_request(analysis)
        self._send_response()

    def do_HEAD(self):
        """Handle HEAD request"""
        analysis = self._analyze_request()
        self._log_request(analysis)
        self._send_response()

    def do_PUT(self):
        """Handle PUT request"""
        analysis = self._analyze_request()
        self._log_request(analysis)
        self._send_response()

    def do_DELETE(self):
        """Handle DELETE request"""
        analysis = self._analyze_request()
        self._log_request(analysis)
        self._send_response()

    def do_OPTIONS(self):
        """Handle OPTIONS request"""
        analysis = self._analyze_request()
        self._log_request(analysis)
        self._send_response()


class CustomHTTPServer(HTTPServer):
    """Custom HTTP server with honeypot reference"""

    def __init__(self, server_address, RequestHandlerClass, honeypot):
        super().__init__(server_address, RequestHandlerClass)
        self.honeypot = honeypot


class HTTPHoneypot(BaseProtocolHandler):
    """HTTP honeypot implementation"""

    def __init__(self, config: Dict[str, Any], engine):
        super().__init__('http', config, engine)
        self.server = None

    def start(self):
        """Start HTTP honeypot server"""
        host = self.config.get('host', '0.0.0.0')
        port = self.config.get('port', 8080)

        try:
            self.server = CustomHTTPServer(
                (host, port),
                HTTPHoneypotHandler,
                self
            )

            self.running = True
            self.logger.info(f"HTTP honeypot listening on {host}:{port}")

            # Start server
            self.server.serve_forever()

        except Exception as e:
            self.logger.error(f"Failed to start HTTP honeypot: {e}")
            self.running = False

    def stop(self):
        """Stop HTTP honeypot server"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.running = False
            self.logger.info("HTTP honeypot stopped")
