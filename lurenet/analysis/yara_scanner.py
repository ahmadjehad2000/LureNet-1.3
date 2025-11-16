"""
YARA Scanner Module

Scan files and payloads with YARA rules for malware detection.
Includes built-in rules for common malware families and attack patterns.
"""

import yara
import os
import tempfile
from typing import Dict, List, Any, Optional
from pathlib import Path
from lurenet.core.logger import get_logger


class YARAScanner:
    """YARA-based malware scanner with built-in rules"""

    # Built-in YARA rules for common attack patterns
    BUILTIN_RULES = """
    rule Suspicious_Base64 {
        meta:
            description = "Detects suspicious base64 encoded strings"
            severity = "medium"
        strings:
            $b64_1 = /[A-Za-z0-9+\/]{50,}={0,2}/ nocase
            $decode_cmd = "base64" nocase
            $decode_py = "b64decode" nocase
        condition:
            $b64_1 and ($decode_cmd or $decode_py)
    }

    rule Powershell_Obfuscation {
        meta:
            description = "Detects obfuscated PowerShell commands"
            severity = "high"
        strings:
            $ps1 = "powershell" nocase
            $ps2 = "pwsh" nocase
            $enc = "-enc" nocase
            $hidden = "-w hidden" nocase
            $bypass = "-exec bypass" nocase
            $downloadstring = "downloadstring" nocase
        condition:
            ($ps1 or $ps2) and 2 of ($enc, $hidden, $bypass, $downloadstring)
    }

    rule Reverse_Shell_Patterns {
        meta:
            description = "Detects reverse shell command patterns"
            severity = "critical"
        strings:
            $bash_reverse = "bash -i >& /dev/tcp/"
            $nc_reverse = "nc -e /bin/"
            $python_reverse = "socket.socket" nocase
            $python_shell = "subprocess.call" nocase
            $perl_reverse = "socket(S,PF_INET,SOCK_STREAM"
        condition:
            any of them
    }

    rule SQL_Injection_Payload {
        meta:
            description = "Detects SQL injection payloads"
            severity = "high"
        strings:
            $sqli_1 = "' OR '1'='1"
            $sqli_2 = "' OR 1=1--"
            $sqli_3 = "UNION SELECT" nocase
            $sqli_4 = "'; DROP TABLE" nocase
            $sqli_5 = "'; EXEC " nocase
            $sqli_6 = "1' AND '1'='1"
        condition:
            any of them
    }

    rule XSS_Payload {
        meta:
            description = "Detects XSS attack payloads"
            severity = "medium"
        strings:
            $xss_1 = "<script>" nocase
            $xss_2 = "javascript:" nocase
            $xss_3 = "onerror=" nocase
            $xss_4 = "onload=" nocase
            $xss_5 = "eval(" nocase
            $xss_6 = "<img src=x onerror=" nocase
        condition:
            2 of them
    }

    rule Webshell_Indicators {
        meta:
            description = "Detects webshell indicators"
            severity = "critical"
        strings:
            $php_eval = "eval($_" nocase
            $php_system = "system($_" nocase
            $php_exec = "exec($_" nocase
            $php_passthru = "passthru($_" nocase
            $php_shell_exec = "shell_exec($_" nocase
            $jsp_runtime = "Runtime.getRuntime().exec" nocase
            $asp_shell = "WScript.Shell" nocase
        condition:
            any of them
    }

    rule Ransomware_Indicators {
        meta:
            description = "Detects ransomware-like behavior patterns"
            severity = "critical"
        strings:
            $encrypt_ext_1 = ".encrypted"
            $encrypt_ext_2 = ".locked"
            $encrypt_ext_3 = ".crypto"
            $ransom_note_1 = "YOUR FILES HAVE BEEN ENCRYPTED"
            $ransom_note_2 = "DECRYPT YOUR FILES"
            $ransom_note_3 = "PAY BITCOIN"
            $crypto_lib = "CryptEncrypt"
            $file_enum = "FindFirstFile"
        condition:
            (any of ($encrypt_ext_*) and any of ($ransom_note_*)) or
            ($crypto_lib and $file_enum)
    }

    rule Cryptocurrency_Miner {
        meta:
            description = "Detects cryptocurrency miner indicators"
            severity = "high"
        strings:
            $miner_1 = "stratum+tcp://" nocase
            $miner_2 = "xmrig" nocase
            $miner_3 = "claymore" nocase
            $miner_4 = "ethminer" nocase
            $mining_pool_1 = "nanopool" nocase
            $mining_pool_2 = "minergate" nocase
            $mining_algo = "cryptonight" nocase
        condition:
            any of them
    }

    rule CVE_Exploit_Attempts {
        meta:
            description = "Detects common CVE exploit attempts"
            severity = "critical"
        strings:
            $log4j = "${jndi:ldap://" nocase
            $log4j_alt = "${jndi:rmi://" nocase
            $eternal_blue = "\\\\ADMIN$" nocase
            $shellshock = "() { :; };" nocase
            $heartbleed = "18030000000002"
        condition:
            any of them
    }

    rule Suspicious_Network_Activity {
        meta:
            description = "Detects suspicious network activity patterns"
            severity = "medium"
        strings:
            $beacon_1 = /http:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}/
            $exfil_1 = "Content-Disposition: attachment"
            $exfil_2 = "multipart/form-data"
            $tunnel_1 = "SSH-2.0-" nocase
            $proxy_1 = "CONNECT " nocase
        condition:
            any of them
    }

    rule Credential_Harvesting {
        meta:
            description = "Detects credential harvesting attempts"
            severity = "high"
        strings:
            $mimikatz = "sekurlsa::logonpasswords" nocase
            $lazagne = "LaZagne" nocase
            $password_dump = "password" nocase wide ascii
            $credential_1 = "username=" nocase
            $credential_2 = "password=" nocase
        condition:
            $mimikatz or $lazagne or
            ($password_dump and ($credential_1 and $credential_2))
    }
    """

    def __init__(self, custom_rules_dir: Optional[str] = None):
        """
        Initialize YARA scanner

        Args:
            custom_rules_dir: Optional directory containing custom YARA rules
        """
        self.logger = get_logger("lurenet.yara_scanner")
        self.custom_rules_dir = custom_rules_dir
        self.compiled_rules = None
        self._compile_rules()

    def _compile_rules(self):
        """Compile YARA rules"""
        try:
            # Compile built-in rules
            self.compiled_rules = yara.compile(source=self.BUILTIN_RULES)
            self.logger.info("YARA rules compiled successfully")

            # If custom rules directory exists, compile those too
            if self.custom_rules_dir and os.path.exists(self.custom_rules_dir):
                custom_files = {}
                for filename in os.listdir(self.custom_rules_dir):
                    if filename.endswith('.yar') or filename.endswith('.yara'):
                        filepath = os.path.join(self.custom_rules_dir, filename)
                        namespace = os.path.splitext(filename)[0]
                        custom_files[namespace] = filepath

                if custom_files:
                    self.custom_compiled_rules = yara.compile(filepaths=custom_files)
                    self.logger.info(f"Compiled {len(custom_files)} custom YARA rules")

        except Exception as e:
            self.logger.error(f"Failed to compile YARA rules: {e}")
            raise

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a file with YARA rules

        Args:
            file_path: Path to file to scan

        Returns:
            Scan results dictionary
        """
        self.logger.info(f"Scanning file: {file_path}")

        results = {
            'file': file_path,
            'matches': [],
            'matched_rules': 0,
            'severity': 'clean',
            'threat_score': 0
        }

        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")

            # Scan with built-in rules
            matches = self.compiled_rules.match(file_path)

            for match in matches:
                rule_info = {
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': []
                }

                # Add matched strings
                for string_match in match.strings:
                    rule_info['strings'].append({
                        'identifier': string_match.identifier,
                        'instances': len(string_match.instances)
                    })

                results['matches'].append(rule_info)

            # Scan with custom rules if available
            if hasattr(self, 'custom_compiled_rules'):
                custom_matches = self.custom_compiled_rules.match(file_path)
                for match in custom_matches:
                    rule_info = {
                        'rule': match.rule,
                        'namespace': match.namespace,
                        'tags': match.tags,
                        'meta': match.meta,
                        'strings': []
                    }
                    results['matches'].append(rule_info)

            # Calculate results
            results['matched_rules'] = len(results['matches'])
            results['severity'] = self._calculate_severity(results['matches'])
            results['threat_score'] = self._calculate_threat_score(results['matches'])

        except Exception as e:
            self.logger.error(f"Error scanning file: {e}")
            results['error'] = str(e)

        return results

    def scan_data(self, data: bytes, identifier: str = "data") -> Dict[str, Any]:
        """
        Scan raw data with YARA rules

        Args:
            data: Raw bytes to scan
            identifier: Identifier for the data

        Returns:
            Scan results dictionary
        """
        self.logger.info(f"Scanning data: {identifier}")

        results = {
            'identifier': identifier,
            'size': len(data),
            'matches': [],
            'matched_rules': 0,
            'severity': 'clean',
            'threat_score': 0
        }

        try:
            # Scan with built-in rules
            matches = self.compiled_rules.match(data=data)

            for match in matches:
                rule_info = {
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': []
                }

                # Add matched strings
                for string_match in match.strings:
                    rule_info['strings'].append({
                        'identifier': string_match.identifier,
                        'instances': len(string_match.instances)
                    })

                results['matches'].append(rule_info)

            # Scan with custom rules if available
            if hasattr(self, 'custom_compiled_rules'):
                custom_matches = self.custom_compiled_rules.match(data=data)
                for match in custom_matches:
                    rule_info = {
                        'rule': match.rule,
                        'namespace': match.namespace,
                        'tags': match.tags,
                        'meta': match.meta,
                        'strings': []
                    }
                    results['matches'].append(rule_info)

            # Calculate results
            results['matched_rules'] = len(results['matches'])
            results['severity'] = self._calculate_severity(results['matches'])
            results['threat_score'] = self._calculate_threat_score(results['matches'])

        except Exception as e:
            self.logger.error(f"Error scanning data: {e}")
            results['error'] = str(e)

        return results

    def scan_string(self, text: str, identifier: str = "string") -> Dict[str, Any]:
        """
        Scan a text string with YARA rules

        Args:
            text: Text string to scan
            identifier: Identifier for the string

        Returns:
            Scan results dictionary
        """
        return self.scan_data(text.encode('utf-8', errors='ignore'), identifier)

    def _calculate_severity(self, matches: List[Dict]) -> str:
        """Calculate overall severity from matches"""
        if not matches:
            return 'clean'

        severities = []
        for match in matches:
            meta = match.get('meta', {})
            severity = meta.get('severity', 'low')
            severities.append(severity)

        if 'critical' in severities:
            return 'critical'
        elif 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        else:
            return 'low'

    def _calculate_threat_score(self, matches: List[Dict]) -> int:
        """Calculate threat score (0-100) from matches"""
        if not matches:
            return 0

        severity_scores = {
            'critical': 100,
            'high': 75,
            'medium': 50,
            'low': 25
        }

        total_score = 0
        for match in matches:
            meta = match.get('meta', {})
            severity = meta.get('severity', 'low')
            total_score += severity_scores.get(severity, 25)

        # Average the scores but cap at 100
        avg_score = total_score // len(matches)
        return min(100, avg_score)

    def get_rule_info(self) -> Dict[str, Any]:
        """Get information about loaded YARA rules"""
        info = {
            'builtin_rules': 11,  # Number of built-in rules
            'custom_rules': 0,
            'total_rules': 11,
            'rule_categories': [
                'Web Attacks (SQL Injection, XSS, Webshells)',
                'Malware (Ransomware, Miners, Exploits)',
                'Network Attacks (Reverse Shells, Tunneling)',
                'Credential Theft (Mimikatz, Password Dumps)',
                'Obfuscation (PowerShell, Base64)'
            ]
        }

        if hasattr(self, 'custom_compiled_rules'):
            # Count custom rules (would need to parse rule files)
            info['custom_rules'] = len(os.listdir(self.custom_rules_dir)) if self.custom_rules_dir else 0
            info['total_rules'] = info['builtin_rules'] + info['custom_rules']

        return info
