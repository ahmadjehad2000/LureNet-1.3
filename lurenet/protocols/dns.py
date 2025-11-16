"""
DNS Honeypot

Captures DNS queries and detects DNS tunneling attempts.
"""

import socket
import struct
import threading
from typing import Dict, Any
from lurenet.protocols.base import BaseProtocolHandler


class DNSHoneypot(BaseProtocolHandler):
    """DNS honeypot implementation"""

    def __init__(self, config: Dict[str, Any], engine):
        super().__init__('dns', config, engine)
        self.server_socket = None
        self.fake_domains = config.get('fake_domains', ['lurenet.local', 'admin.lurenet.local'])

    def start(self):
        """Start DNS honeypot server"""
        host = self.config.get('host', '0.0.0.0')
        port = self.config.get('port', 5353)

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((host, port))

            self.running = True
            self.logger.info(f"DNS honeypot listening on {host}:{port}")

            while self.running:
                try:
                    data, client_address = self.server_socket.recvfrom(512)
                    threading.Thread(
                        target=self._handle_query,
                        args=(data, client_address),
                        daemon=True
                    ).start()
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error receiving DNS query: {e}")

        except Exception as e:
            self.logger.error(f"Failed to start DNS honeypot: {e}")
            self.running = False

    def _handle_query(self, data: bytes, client_address: tuple):
        """Handle DNS query"""
        client_ip, client_port = client_address

        try:
            # Parse DNS query (simplified)
            domain = self._parse_dns_query(data)

            if domain:
                self.logger.info(f"DNS query from {client_ip}: {domain}")
                self._log_query(client_ip, client_port, domain, data)

                # Send fake response
                response = self._create_dns_response(data, domain)
                self.server_socket.sendto(response, client_address)

        except Exception as e:
            self.logger.debug(f"Error handling DNS query: {e}")

    def _parse_dns_query(self, data: bytes) -> str:
        """Parse domain name from DNS query (simplified)"""
        try:
            # Skip DNS header (12 bytes)
            i = 12
            domain_parts = []

            while i < len(data):
                length = data[i]
                if length == 0:
                    break

                i += 1
                domain_parts.append(data[i:i+length].decode('utf-8', errors='ignore'))
                i += length

            return '.'.join(domain_parts) if domain_parts else 'unknown'

        except:
            return 'unknown'

    def _create_dns_response(self, query_data: bytes, domain: str) -> bytes:
        """Create fake DNS response"""
        try:
            # Copy query
            response = bytearray(query_data)

            # Set response flag
            response[2] = 0x81
            response[3] = 0x80

            # Add answer section (simplified - just return 127.0.0.1)
            response += bytes([0xc0, 0x0c])  # Name pointer
            response += bytes([0x00, 0x01])  # Type A
            response += bytes([0x00, 0x01])  # Class IN
            response += bytes([0x00, 0x00, 0x00, 0x3c])  # TTL (60 seconds)
            response += bytes([0x00, 0x04])  # Data length
            response += bytes([127, 0, 0, 1])  # IP address

            return bytes(response)

        except:
            return query_data

    def _log_query(self, ip: str, port: int, domain: str, raw_data: bytes):
        """Log DNS query"""
        indicators = ['dns_query']

        # Detect DNS tunneling attempts
        if len(domain) > 50:
            indicators.append('dns_tunneling')

        # Check for suspicious patterns
        if domain.count('.') > 5:
            indicators.append('suspicious_domain')

        # Check for Base64-like subdomains
        parts = domain.split('.')
        for part in parts:
            if len(part) > 20 and all(c.isalnum() or c in ['-', '_'] for c in part):
                indicators.append('encoded_subdomain')
                break

        # Check for command and control patterns
        c2_patterns = ['dga', 'beacon', 'callback', 'cmd', 'exec']
        if any(pattern in domain.lower() for pattern in c2_patterns):
            indicators.append('c2_communication')

        threat_score = self.calculate_threat_score(indicators)
        severity = self.get_severity(threat_score)

        event_data = {
            'source_ip': ip,
            'source_port': port,
            'attack_type': 'dns_tunneling' if 'dns_tunneling' in indicators else 'dns_query',
            'severity': severity,
            'threat_score': threat_score,
            'method': 'DNS',
            'path': domain,
            'user_agent': 'DNS Client',
            'headers': {
                'domain': domain,
                'query_length': len(raw_data),
                'subdomain_count': domain.count('.')
            },
            'payload': f"DNS Query: {domain}",
            'detected_tools': indicators,
            'indicators': indicators,
        }

        self.log_event(event_data)

    def stop(self):
        """Stop DNS honeypot server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.logger.info("DNS honeypot stopped")
