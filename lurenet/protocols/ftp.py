"""
FTP Honeypot

Captures FTP login attempts and file operations.
"""

import socket
import threading
from typing import Dict, Any
from lurenet.protocols.base import BaseProtocolHandler


class FTPHoneypot(BaseProtocolHandler):
    """FTP honeypot implementation"""

    def __init__(self, config: Dict[str, Any], engine):
        super().__init__('ftp', config, engine)
        self.server_socket = None
        self.banner = config.get('banner', '220 ProFTPD Server (LureNet FTP)')
        self.fake_files = config.get('fake_files', ['readme.txt', 'config.xml', 'backup.tar.gz'])
        self.anonymous_login = config.get('anonymous_login', True)

    def start(self):
        """Start FTP honeypot server"""
        host = self.config.get('host', '0.0.0.0')
        port = self.config.get('port', 2121)

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((host, port))
            self.server_socket.listen(5)

            self.running = True
            self.logger.info(f"FTP honeypot listening on {host}:{port}")

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
            self.logger.error(f"Failed to start FTP honeypot: {e}")
            self.running = False

    def _handle_client(self, client_socket: socket.socket, client_address: tuple):
        """Handle FTP client connection"""
        client_ip, client_port = client_address
        self.logger.info(f"FTP connection from {client_ip}:{client_port}")

        try:
            # Send welcome banner
            self._send_response(client_socket, self.banner)

            username = None
            password = None
            authenticated = False
            commands = []

            client_socket.settimeout(30)

            while self.running:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break

                    command = data.decode('utf-8', errors='ignore').strip()
                    commands.append(command)

                    cmd_upper = command.upper()

                    # Handle FTP commands
                    if cmd_upper.startswith('USER'):
                        username = command.split(' ', 1)[1] if len(command.split(' ')) > 1 else 'anonymous'
                        self._send_response(client_socket, '331 Password required')

                    elif cmd_upper.startswith('PASS'):
                        password = command.split(' ', 1)[1] if len(command.split(' ')) > 1 else ''

                        # Log login attempt
                        self._log_login_attempt(client_ip, client_port, username, password)

                        if self.anonymous_login and username == 'anonymous':
                            authenticated = True
                            self._send_response(client_socket, '230 Login successful')
                        else:
                            self._send_response(client_socket, '530 Login incorrect')
                            break

                    elif cmd_upper.startswith('SYST'):
                        self._send_response(client_socket, '215 UNIX Type: L8')

                    elif cmd_upper.startswith('PWD'):
                        self._send_response(client_socket, '257 "/" is current directory')

                    elif cmd_upper.startswith('LIST'):
                        # Send fake file list
                        self._send_response(client_socket, '150 Opening data connection')
                        file_list = '\r\n'.join([f'-rw-r--r-- 1 ftp ftp 1024 Jan 01 12:00 {f}'
                                                 for f in self.fake_files])
                        self._send_response(client_socket, file_list)
                        self._send_response(client_socket, '226 Transfer complete')

                    elif cmd_upper.startswith('RETR'):
                        filename = command.split(' ', 1)[1] if len(command.split(' ')) > 1 else 'unknown'
                        self._log_file_operation(client_ip, client_port, 'RETR', filename, username)
                        self._send_response(client_socket, '550 File not available')

                    elif cmd_upper.startswith('STOR'):
                        filename = command.split(' ', 1)[1] if len(command.split(' ')) > 1 else 'unknown'
                        self._log_file_operation(client_ip, client_port, 'STOR', filename, username)
                        self._send_response(client_socket, '550 Permission denied')

                    elif cmd_upper.startswith('QUIT'):
                        self._send_response(client_socket, '221 Goodbye')
                        break

                    else:
                        self._send_response(client_socket, '502 Command not implemented')

                except socket.timeout:
                    break
                except Exception as e:
                    self.logger.debug(f"Error processing FTP command: {e}")
                    break

        except Exception as e:
            self.logger.debug(f"Error handling FTP client: {e}")

        finally:
            client_socket.close()

    def _send_response(self, client_socket: socket.socket, message: str):
        """Send FTP response"""
        try:
            client_socket.send(f"{message}\r\n".encode())
        except:
            pass

    def _log_login_attempt(self, ip: str, port: int, username: str, password: str):
        """Log FTP login attempt"""
        indicators = ['ftp_login_attempt']

        if username == 'anonymous':
            indicators.append('anonymous_ftp')

        threat_score = self.calculate_threat_score(indicators)
        severity = self.get_severity(threat_score)

        event_data = {
            'source_ip': ip,
            'source_port': port,
            'attack_type': 'ftp_brute_force',
            'severity': severity,
            'threat_score': threat_score,
            'method': 'FTP',
            'path': f"user:{username}",
            'user_agent': 'FTP Client',
            'headers': {'username': username, 'password': password},
            'payload': f"FTP Login: {username}:{password}",
            'detected_tools': indicators,
            'indicators': indicators,
        }

        self.log_event(event_data)

    def _log_file_operation(self, ip: str, port: int, operation: str, filename: str, username: str):
        """Log FTP file operation"""
        indicators = ['ftp_file_operation']

        if operation == 'RETR':
            indicators.append('data_exfiltration')
        elif operation == 'STOR':
            indicators.append('file_upload')

        threat_score = self.calculate_threat_score(indicators)
        severity = self.get_severity(threat_score)

        event_data = {
            'source_ip': ip,
            'source_port': port,
            'attack_type': f'ftp_{operation.lower()}',
            'severity': severity,
            'threat_score': threat_score,
            'method': operation,
            'path': filename,
            'user_agent': 'FTP Client',
            'headers': {'operation': operation, 'filename': filename, 'user': username},
            'payload': f"FTP {operation}: {filename}",
            'detected_tools': indicators,
            'indicators': indicators,
        }

        self.log_event(event_data)

    def stop(self):
        """Stop FTP honeypot server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.logger.info("FTP honeypot stopped")
