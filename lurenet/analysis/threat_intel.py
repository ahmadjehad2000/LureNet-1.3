"""
Threat Intelligence Module

Hash and URL analysis using multiple free threat intelligence sources.
No API keys required for basic functionality.
"""

import hashlib
import requests
import json
from typing import Dict, Any, Optional
from lurenet.core.logger import get_logger


class ThreatIntelligence:
    """Threat intelligence analysis using free open-source APIs"""

    def __init__(self):
        self.logger = get_logger("lurenet.threat_intel")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'LureNet-ThreatIntel/2.0'
        })

    def analyze_hash(self, file_hash: str, hash_type: str = 'auto') -> Dict[str, Any]:
        """
        Analyze file hash using multiple threat intelligence sources

        Args:
            file_hash: File hash (MD5, SHA1, or SHA256)
            hash_type: Hash type ('md5', 'sha1', 'sha256', or 'auto')

        Returns:
            Analysis results dictionary
        """
        if hash_type == 'auto':
            hash_type = self._detect_hash_type(file_hash)

        self.logger.info(f"Analyzing {hash_type.upper()} hash: {file_hash}")

        results = {
            'hash': file_hash,
            'hash_type': hash_type,
            'sources': {},
            'verdict': 'unknown',
            'threat_score': 0,
            'detections': 0,
            'total_scans': 0
        }

        # Check multiple free sources
        try:
            # MalwareBazaar (abuse.ch) - Free, no API key required
            malware_bazaar = self._check_malwarebazaar(file_hash, hash_type)
            if malware_bazaar:
                results['sources']['malwarebazaar'] = malware_bazaar

            # ThreatFox (abuse.ch) - Free, no API key required
            threatfox = self._check_threatfox(file_hash)
            if threatfox:
                results['sources']['threatfox'] = threatfox

            # URLhaus (abuse.ch) - Free, no API key required
            urlhaus = self._check_urlhaus_hash(file_hash)
            if urlhaus:
                results['sources']['urlhaus'] = urlhaus

            # Calculate overall verdict
            results['verdict'] = self._calculate_verdict(results['sources'])
            results['threat_score'] = self._calculate_threat_score(results['sources'])

        except Exception as e:
            self.logger.error(f"Error analyzing hash: {e}")
            results['error'] = str(e)

        return results

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL using threat intelligence sources

        Args:
            url: URL to analyze

        Returns:
            Analysis results dictionary
        """
        self.logger.info(f"Analyzing URL: {url}")

        results = {
            'url': url,
            'sources': {},
            'verdict': 'unknown',
            'threat_score': 0,
            'categories': []
        }

        try:
            # URLhaus (abuse.ch) - Free, no API key required
            urlhaus = self._check_urlhaus_url(url)
            if urlhaus:
                results['sources']['urlhaus'] = urlhaus

            # PhishTank - Free, no API key for lookups
            phishtank = self._check_phishtank(url)
            if phishtank:
                results['sources']['phishtank'] = phishtank

            # Calculate verdict
            results['verdict'] = self._calculate_verdict(results['sources'])
            results['threat_score'] = self._calculate_threat_score(results['sources'])

        except Exception as e:
            self.logger.error(f"Error analyzing URL: {e}")
            results['error'] = str(e)

        return results

    def _detect_hash_type(self, hash_value: str) -> str:
        """Detect hash type based on length"""
        hash_len = len(hash_value)
        if hash_len == 32:
            return 'md5'
        elif hash_len == 40:
            return 'sha1'
        elif hash_len == 64:
            return 'sha256'
        else:
            return 'unknown'

    def _check_malwarebazaar(self, file_hash: str, hash_type: str) -> Optional[Dict]:
        """Check MalwareBazaar database"""
        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            data = {
                'query': 'get_info',
                'hash': file_hash
            }

            response = self.session.post(url, data=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok':
                    data = result.get('data', [])
                    if data:
                        sample = data[0]
                        return {
                            'found': True,
                            'malware': sample.get('signature'),
                            'file_type': sample.get('file_type'),
                            'file_name': sample.get('file_name'),
                            'first_seen': sample.get('first_seen'),
                            'tags': sample.get('tags', []),
                            'verdict': 'malicious'
                        }
                return {'found': False, 'verdict': 'clean'}
        except Exception as e:
            self.logger.warning(f"MalwareBazaar check failed: {e}")
            return None

    def _check_threatfox(self, ioc: str) -> Optional[Dict]:
        """Check ThreatFox database"""
        try:
            url = "https://threatfox-api.abuse.ch/api/v1/"
            data = {
                'query': 'search_ioc',
                'search_term': ioc
            }

            response = self.session.post(url, json=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok':
                    data = result.get('data', [])
                    if data:
                        ioc_data = data[0]
                        return {
                            'found': True,
                            'threat_type': ioc_data.get('threat_type'),
                            'malware': ioc_data.get('malware'),
                            'confidence': ioc_data.get('confidence_level'),
                            'first_seen': ioc_data.get('first_seen'),
                            'tags': ioc_data.get('tags', []),
                            'verdict': 'malicious'
                        }
                return {'found': False, 'verdict': 'clean'}
        except Exception as e:
            self.logger.warning(f"ThreatFox check failed: {e}")
            return None

    def _check_urlhaus_hash(self, file_hash: str) -> Optional[Dict]:
        """Check URLhaus for hash"""
        try:
            url = "https://urlhaus-api.abuse.ch/v1/payload/"
            data = {'sha256_hash': file_hash}

            response = self.session.post(url, data=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok':
                    return {
                        'found': True,
                        'file_type': result.get('file_type'),
                        'file_size': result.get('file_size'),
                        'signature': result.get('signature'),
                        'first_seen': result.get('firstseen'),
                        'url_count': result.get('url_count'),
                        'verdict': 'malicious'
                    }
                return {'found': False, 'verdict': 'clean'}
        except Exception as e:
            self.logger.warning(f"URLhaus hash check failed: {e}")
            return None

    def _check_urlhaus_url(self, url: str) -> Optional[Dict]:
        """Check URLhaus for URL"""
        try:
            api_url = "https://urlhaus-api.abuse.ch/v1/url/"
            data = {'url': url}

            response = self.session.post(api_url, data=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok':
                    return {
                        'found': True,
                        'url_status': result.get('url_status'),
                        'threat': result.get('threat'),
                        'tags': result.get('tags', []),
                        'date_added': result.get('date_added'),
                        'verdict': 'malicious' if result.get('url_status') == 'online' else 'suspicious'
                    }
                return {'found': False, 'verdict': 'clean'}
        except Exception as e:
            self.logger.warning(f"URLhaus URL check failed: {e}")
            return None

    def _check_phishtank(self, url: str) -> Optional[Dict]:
        """Check PhishTank for phishing URLs"""
        try:
            # PhishTank requires URL to be checked via their database
            # For now, we'll use a simple lookup approach
            # In production, you'd want to use their API with proper credentials
            return {
                'found': False,
                'verdict': 'unknown',
                'note': 'PhishTank integration requires API key for full functionality'
            }
        except Exception as e:
            self.logger.warning(f"PhishTank check failed: {e}")
            return None

    def _calculate_verdict(self, sources: Dict) -> str:
        """Calculate overall verdict from sources"""
        verdicts = []
        for source_name, source_data in sources.items():
            if source_data and isinstance(source_data, dict):
                verdict = source_data.get('verdict', 'unknown')
                if verdict != 'unknown':
                    verdicts.append(verdict)

        if 'malicious' in verdicts:
            return 'malicious'
        elif 'suspicious' in verdicts:
            return 'suspicious'
        elif 'clean' in verdicts:
            return 'clean'
        else:
            return 'unknown'

    def _calculate_threat_score(self, sources: Dict) -> int:
        """Calculate threat score (0-100) from sources"""
        score = 0
        found_count = 0

        for source_name, source_data in sources.items():
            if source_data and isinstance(source_data, dict):
                if source_data.get('found'):
                    found_count += 1
                    verdict = source_data.get('verdict', 'unknown')
                    if verdict == 'malicious':
                        score += 100
                    elif verdict == 'suspicious':
                        score += 50

        if found_count > 0:
            return min(100, score // found_count)
        return 0

    def hash_file(self, file_path: str) -> Dict[str, str]:
        """
        Calculate hashes for a file

        Args:
            file_path: Path to file

        Returns:
            Dictionary with MD5, SHA1, and SHA256 hashes
        """
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)

            return {
                'md5': md5.hexdigest(),
                'sha1': sha1.hexdigest(),
                'sha256': sha256.hexdigest()
            }
        except Exception as e:
            self.logger.error(f"Error hashing file: {e}")
            raise
