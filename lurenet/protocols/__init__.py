"""
Protocol Handlers

Modular honeypot protocol implementations.
"""

from lurenet.protocols.base import BaseProtocolHandler
from lurenet.protocols.http import HTTPHoneypot
from lurenet.protocols.ssh import SSHHoneypot
from lurenet.protocols.ftp import FTPHoneypot
from lurenet.protocols.smtp import SMTPHoneypot
from lurenet.protocols.dns import DNSHoneypot
from lurenet.protocols.smb import SMBHoneypot
from lurenet.protocols.ldap import LDAPHoneypot

__all__ = [
    "BaseProtocolHandler",
    "HTTPHoneypot",
    "SSHHoneypot",
    "FTPHoneypot",
    "SMTPHoneypot",
    "DNSHoneypot",
    "SMBHoneypot",
    "LDAPHoneypot",
]
