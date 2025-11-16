"""
LDAP Honeypot

Captures LDAP/Active Directory enumeration and attacks.
"""

import socket
import threading
from typing import Dict, Any
from lurenet.protocols.base import BaseProtocolHandler


class LDAPHoneypot(BaseProtocolHandler):
    """LDAP honeypot implementation"""

    def __init__(self, config: Dict[str, Any], engine):
        super().__init__('ldap', config, engine)
        self.server_socket = None
        self.domain = config.get('domain', 'dc=lurenet,dc=local')
        self.fake_users = config.get('fake_users', ['Administrator', 'Guest', 'krbtgt'])

    def start(self):
        """Start LDAP honeypot server"""
        host = self.config.get('host', '0.0.0.0')
        port = self.config.get('port', 3389)

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((host, port))
            self.server_socket.listen(5)

            self.running = True
            self.logger.info(f"LDAP honeypot listening on {host}:{port}")

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
            self.logger.error(f"Failed to start LDAP honeypot: {e}")
            self.running = False

    def _handle_client(self, client_socket: socket.socket, client_address: tuple):
        """Handle LDAP client connection"""
        client_ip, client_port = client_address
        self.logger.info(f"LDAP connection from {client_ip}:{client_port}")

        try:
            client_socket.settimeout(10)
            data = b""

            while len(data) < 4096 and self.running:
                try:
                    chunk = client_socket.recv(1024)
                    if not chunk:
                        break
                    data += chunk

                    # Detect LDAP operations
                    operation = self._detect_ldap_operation(data)
                    if operation:
                        self._log_operation(client_ip, client_port, operation, data)

                        # Send fake LDAP response
                        response = self._create_ldap_response(data, operation)
                        client_socket.send(response)

                except socket.timeout:
                    break
                except Exception as e:
                    self.logger.debug(f"Error reading LDAP data: {e}")
                    break

        except Exception as e:
            self.logger.debug(f"Error handling LDAP client: {e}")

        finally:
            client_socket.close()

    def _detect_ldap_operation(self, data: bytes) -> str:
        """Detect LDAP operation type"""
        try:
            # Simplified LDAP operation detection based on ASN.1 tags
            if b'\x60' in data:  # BindRequest
                return 'bind'
            elif b'\x63' in data:  # SearchRequest
                return 'search'
            elif b'\x64' in data:  # ModifyRequest
                return 'modify'
            elif b'\x66' in data:  # AddRequest
                return 'add'
            elif b'\x67' in data:  # DelRequest
                return 'delete'
            elif b'\x50' in data:  # UnbindRequest
                return 'unbind'
            return 'unknown'
        except:
            return 'unknown'

    def _create_ldap_response(self, request: bytes, operation: str) -> bytes:
        """Create fake LDAP response"""
        # Simplified LDAP response
        if operation == 'bind':
            # Bind response with invalid credentials
            response = b'\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x31\x04\x00\x04\x00'
            return response
        elif operation == 'search':
            # Empty search result
            response = b'\x30\x0c\x02\x01\x02\x65\x07\x04\x00\x04\x00\x04\x00'
            return response
        else:
            # Generic success
            response = b'\x30\x0c\x02\x01\x01\x0a\x01\x00\x04\x00\x04\x00'
            return response

    def _log_operation(self, ip: str, port: int, operation: str, data: bytes):
        """Log LDAP operation"""
        indicators = [f'ldap_{operation}']

        # Detect enumeration
        if operation == 'search':
            indicators.append('ad_enumeration')

        # Detect authentication attempts
        if operation == 'bind':
            indicators.append('ldap_auth_attempt')

            # Check for common usernames
            for user in self.fake_users:
                if user.lower().encode() in data.lower():
                    indicators.append('default_credentials')
                    break

        # Detect privilege escalation attempts
        priv_patterns = [b'admin', b'domain admins', b'enterprise admins', b'schema admins']
        if any(pattern in data.lower() for pattern in priv_patterns):
            indicators.append('privilege_escalation')

        # Detect Kerberos-related queries
        if b'kerberos' in data.lower() or b'krbtgt' in data.lower():
            indicators.append('kerberoasting')

        # Detect LDAP injection attempts
        if b'*' in data or b'|' in data or b'&' in data:
            indicators.append('ldap_injection')

        threat_score = self.calculate_threat_score(indicators)
        severity = self.get_severity(threat_score)

        event_data = {
            'source_ip': ip,
            'source_port': port,
            'attack_type': f'ldap_{operation}',
            'severity': severity,
            'threat_score': threat_score,
            'method': 'LDAP',
            'path': self.domain,
            'user_agent': 'LDAP Client',
            'headers': {
                'operation': operation,
                'data_length': len(data),
                'domain': self.domain
            },
            'payload': data[:200].hex(),  # First 200 bytes as hex
            'detected_tools': indicators,
            'indicators': indicators,
        }

        self.log_event(event_data)

    def stop(self):
        """Stop LDAP honeypot server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.logger.info("LDAP honeypot stopped")
