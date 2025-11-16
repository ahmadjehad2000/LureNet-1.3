"""
SMTP Honeypot

Captures spam attempts and email-based attacks.
"""

import socket
import threading
from typing import Dict, Any
from lurenet.protocols.base import BaseProtocolHandler


class SMTPHoneypot(BaseProtocolHandler):
    """SMTP honeypot implementation"""

    def __init__(self, config: Dict[str, Any], engine):
        super().__init__('smtp', config, engine)
        self.server_socket = None
        self.banner = config.get('banner', '220 mail.lurenet.local ESMTP Postfix')
        self.accept_all = config.get('accept_all', True)

    def start(self):
        """Start SMTP honeypot server"""
        host = self.config.get('host', '0.0.0.0')
        port = self.config.get('port', 2525)

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((host, port))
            self.server_socket.listen(5)

            self.running = True
            self.logger.info(f"SMTP honeypot listening on {host}:{port}")

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
            self.logger.error(f"Failed to start SMTP honeypot: {e}")
            self.running = False

    def _handle_client(self, client_socket: socket.socket, client_address: tuple):
        """Handle SMTP client connection"""
        client_ip, client_port = client_address
        self.logger.info(f"SMTP connection from {client_ip}:{client_port}")

        try:
            # Send greeting
            self._send_response(client_socket, self.banner)

            mail_from = None
            rcpt_to = []
            data_content = ""
            in_data_mode = False

            client_socket.settimeout(30)

            while self.running:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break

                    command = data.decode('utf-8', errors='ignore').strip()
                    cmd_upper = command.upper()

                    if in_data_mode:
                        # Collecting email data
                        if command == '.':
                            in_data_mode = False
                            self._log_email(client_ip, client_port, mail_from, rcpt_to, data_content)
                            self._send_response(client_socket, '250 Message accepted for delivery')
                            data_content = ""
                        else:
                            data_content += command + "\n"
                        continue

                    # Handle SMTP commands
                    if cmd_upper.startswith('HELO') or cmd_upper.startswith('EHLO'):
                        self._send_response(client_socket, f'250 mail.lurenet.local')

                    elif cmd_upper.startswith('MAIL FROM'):
                        mail_from = command.split(':', 1)[1].strip() if ':' in command else 'unknown'
                        self._send_response(client_socket, '250 OK')

                    elif cmd_upper.startswith('RCPT TO'):
                        rcpt = command.split(':', 1)[1].strip() if ':' in command else 'unknown'
                        rcpt_to.append(rcpt)
                        self._send_response(client_socket, '250 OK')

                    elif cmd_upper.startswith('DATA'):
                        in_data_mode = True
                        self._send_response(client_socket, '354 End data with <CR><LF>.<CR><LF>')

                    elif cmd_upper.startswith('QUIT'):
                        self._send_response(client_socket, '221 Bye')
                        break

                    elif cmd_upper.startswith('RSET'):
                        mail_from = None
                        rcpt_to = []
                        data_content = ""
                        self._send_response(client_socket, '250 OK')

                    elif cmd_upper.startswith('NOOP'):
                        self._send_response(client_socket, '250 OK')

                    else:
                        self._send_response(client_socket, '502 Command not implemented')

                except socket.timeout:
                    break
                except Exception as e:
                    self.logger.debug(f"Error processing SMTP command: {e}")
                    break

        except Exception as e:
            self.logger.debug(f"Error handling SMTP client: {e}")

        finally:
            client_socket.close()

    def _send_response(self, client_socket: socket.socket, message: str):
        """Send SMTP response"""
        try:
            client_socket.send(f"{message}\r\n".encode())
        except:
            pass

    def _log_email(self, ip: str, port: int, mail_from: str, rcpt_to: list, content: str):
        """Log SMTP email attempt"""
        indicators = ['smtp_email']

        # Check for spam indicators
        spam_keywords = ['viagra', 'cialis', 'lottery', 'winner', 'urgent', 'click here']
        content_lower = content.lower()

        if any(keyword in content_lower for keyword in spam_keywords):
            indicators.append('spam')

        # Check for phishing
        phishing_keywords = ['verify your account', 'confirm identity', 'update payment', 'suspended account']
        if any(keyword in content_lower for keyword in phishing_keywords):
            indicators.append('phishing')

        # Check for mass mailing
        if len(rcpt_to) > 10:
            indicators.append('mass_mailing')

        threat_score = self.calculate_threat_score(indicators)
        severity = self.get_severity(threat_score)

        event_data = {
            'source_ip': ip,
            'source_port': port,
            'attack_type': 'smtp_spam' if 'spam' in indicators else 'smtp_email',
            'severity': severity,
            'threat_score': threat_score,
            'method': 'SMTP',
            'path': f"from:{mail_from} to:{','.join(rcpt_to[:3])}",
            'user_agent': 'SMTP Client',
            'headers': {
                'mail_from': mail_from,
                'rcpt_to': rcpt_to,
                'recipient_count': len(rcpt_to)
            },
            'payload': content[:500],  # First 500 chars
            'detected_tools': indicators,
            'indicators': indicators,
        }

        self.log_event(event_data)

    def stop(self):
        """Stop SMTP honeypot server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.logger.info("SMTP honeypot stopped")
