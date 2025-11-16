"""
SMB Honeypot

Captures SMB/Windows file sharing attacks.
"""

import socket
import threading
from typing import Dict, Any
from lurenet.protocols.base import BaseProtocolHandler


class SMBHoneypot(BaseProtocolHandler):
    """SMB honeypot implementation"""

    def __init__(self, config: Dict[str, Any], engine):
        super().__init__('smb', config, engine)
        self.server_socket = None
        self.fake_shares = config.get('fake_shares', ['Users', 'Public', 'Admin$', 'C$'])

    def start(self):
        """Start SMB honeypot server"""
        host = self.config.get('host', '0.0.0.0')
        port = self.config.get('port', 4445)

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((host, port))
            self.server_socket.listen(5)

            self.running = True
            self.logger.info(f"SMB honeypot listening on {host}:{port}")

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
            self.logger.error(f"Failed to start SMB honeypot: {e}")
            self.running = False

    def _handle_client(self, client_socket: socket.socket, client_address: tuple):
        """Handle SMB client connection"""
        client_ip, client_port = client_address
        self.logger.info(f"SMB connection from {client_ip}:{client_port}")

        try:
            client_socket.settimeout(10)
            data = b""

            # Read initial negotiation
            while len(data) < 4096 and self.running:
                try:
                    chunk = client_socket.recv(1024)
                    if not chunk:
                        break
                    data += chunk

                    # Simple SMB detection
                    if b'\xffSMB' in data or b'\xfeSMB' in data:
                        self._log_connection(client_ip, client_port, data)

                        # Send fake SMB response (simplified)
                        response = self._create_smb_response(data)
                        client_socket.send(response)

                except socket.timeout:
                    break
                except Exception as e:
                    self.logger.debug(f"Error reading SMB data: {e}")
                    break

        except Exception as e:
            self.logger.debug(f"Error handling SMB client: {e}")

        finally:
            client_socket.close()

    def _create_smb_response(self, request: bytes) -> bytes:
        """Create fake SMB response"""
        # Simplified SMB response - just acknowledge
        if b'\xfeSMB' in request:  # SMB2/3
            response = b'\xfe\x53\x4d\x42'  # SMB2 header
            response += b'\x40\x00'  # Structure size
            response += b'\x00\x00'  # Credit charge
            response += b'\x00\x00\x00\x00'  # Status
            response += b'\x00\x00'  # Command
            response += b'\x00\x00'  # Credits
            response += b'\x00\x00\x00\x00'  # Flags
            response += b'\x00\x00\x00\x00'  # Next command
            response += b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Message ID
            response += b'\x00' * 16  # Rest of header
            return response
        else:  # SMB1
            response = b'\xff\x53\x4d\x42'  # SMB1 header
            response += b'\x72'  # Negotiate Protocol Response
            response += b'\x00' * 31  # Rest of response
            return response

    def _log_connection(self, ip: str, port: int, data: bytes):
        """Log SMB connection attempt"""
        indicators = ['smb_connection']

        # Detect SMB version
        if b'\xfeSMB' in data:
            smb_version = 'SMB2/3'
            indicators.append('smb2_smb3')
        else:
            smb_version = 'SMB1'
            indicators.append('smb1')

        # Check for known exploits
        exploit_signatures = [
            (b'MS17-010', 'eternalblue'),
            (b'\x00\x00\x00\x2f', 'doublepulsar'),
            (b'PSEXEC', 'psexec'),
        ]

        for signature, name in exploit_signatures:
            if signature in data:
                indicators.append(name)

        # Check for authentication attempts
        if b'NTLMSSP' in data:
            indicators.append('ntlm_auth')

        threat_score = self.calculate_threat_score(indicators)
        severity = self.get_severity(threat_score)

        event_data = {
            'source_ip': ip,
            'source_port': port,
            'attack_type': 'smb_exploit' if any(x in indicators for x in ['eternalblue', 'doublepulsar']) else 'smb_scan',
            'severity': severity,
            'threat_score': threat_score,
            'method': 'SMB',
            'path': smb_version,
            'user_agent': 'SMB Client',
            'headers': {
                'smb_version': smb_version,
                'data_length': len(data)
            },
            'payload': data[:200].hex(),  # First 200 bytes as hex
            'detected_tools': indicators,
            'indicators': indicators,
        }

        self.log_event(event_data)

    def stop(self):
        """Stop SMB honeypot server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.logger.info("SMB honeypot stopped")
