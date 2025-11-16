"""
SSH Honeypot

Captures SSH brute force attempts and command execution.
"""

import socket
import threading
import time
from typing import Dict, Any
from lurenet.protocols.base import BaseProtocolHandler


class SSHHoneypot(BaseProtocolHandler):
    """SSH honeypot implementation"""

    def __init__(self, config: Dict[str, Any], engine):
        super().__init__('ssh', config, engine)
        self.server_socket = None
        self.fake_users = config.get('fake_users', ['root', 'admin', 'user', 'ubuntu'])
        self.max_attempts = config.get('max_attempts', 3)
        self.banner = config.get('banner', 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5')

    def start(self):
        """Start SSH honeypot server"""
        host = self.config.get('host', '0.0.0.0')
        port = self.config.get('port', 2222)

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((host, port))
            self.server_socket.listen(5)

            self.running = True
            self.logger.info(f"SSH honeypot listening on {host}:{port}")

            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error accepting connection: {e}")

        except Exception as e:
            self.logger.error(f"Failed to start SSH honeypot: {e}")
            self.running = False

    def _handle_client(self, client_socket: socket.socket, client_address: tuple):
        """Handle SSH client connection"""
        client_ip, client_port = client_address
        self.logger.info(f"SSH connection from {client_ip}:{client_port}")

        try:
            # Send SSH banner
            client_socket.send(f"{self.banner}\r\n".encode())

            # Track login attempts
            attempts = 0
            username = None
            password = None

            # Simple SSH simulation - read data
            data = b""
            client_socket.settimeout(5)

            while attempts < self.max_attempts and self.running:
                try:
                    chunk = client_socket.recv(1024)
                    if not chunk:
                        break

                    data += chunk

                    # Try to extract credentials (simplified)
                    data_str = data.decode('utf-8', errors='ignore')

                    # Look for common patterns
                    if 'user' in data_str.lower() or 'login' in data_str.lower():
                        username = self._extract_credential(data_str)

                    if 'pass' in data_str.lower():
                        password = self._extract_credential(data_str)

                    # Simulate authentication failure
                    attempts += 1
                    client_socket.send(b"Permission denied, please try again.\r\n")

                    # Log attempt
                    if username or password:
                        self._log_login_attempt(
                            client_ip,
                            client_port,
                            username,
                            password,
                            attempts
                        )

                except socket.timeout:
                    break
                except Exception as e:
                    self.logger.debug(f"Error reading from client: {e}")
                    break

            # Final rejection
            client_socket.send(b"Too many authentication failures.\r\n")

        except Exception as e:
            self.logger.debug(f"Error handling SSH client: {e}")

        finally:
            client_socket.close()

    def _extract_credential(self, data: str) -> str:
        """Extract credential from data (simplified)"""
        # Look for common delimiters
        for delim in ['\x00', '\n', '\r', ' ', ':']:
            if delim in data:
                parts = data.split(delim)
                for part in parts:
                    part = part.strip()
                    if len(part) > 2 and len(part) < 50 and part.isalnum():
                        return part
        return "unknown"

    def _log_login_attempt(self, ip: str, port: int, username: str, password: str, attempt: int):
        """Log SSH login attempt"""
        indicators = ['ssh_brute_force']

        # Check if targeting known users
        if username in self.fake_users:
            indicators.append('default_credentials')

        # Calculate threat score
        threat_score = self.calculate_threat_score(indicators)
        severity = self.get_severity(threat_score)

        # Create event
        event_data = {
            'source_ip': ip,
            'source_port': port,
            'attack_type': 'ssh_brute_force',
            'severity': severity,
            'threat_score': threat_score,
            'method': 'SSH',
            'path': f"user:{username}",
            'user_agent': f"SSH Client - Attempt {attempt}",
            'headers': {'username': username, 'password': password or 'N/A'},
            'payload': f"Username: {username}, Password: {password or 'N/A'}",
            'detected_tools': indicators,
            'indicators': indicators,
        }

        self.log_event(event_data)

    def stop(self):
        """Stop SSH honeypot server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.logger.info("SSH honeypot stopped")
