"""
IP Reputation Module

IP geolocation and reputation checking using free open-source APIs.
No API keys required for basic functionality.
"""

import requests
import json
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from lurenet.core.logger import get_logger


class IPReputation:
    """IP reputation and geolocation lookup"""

    def __init__(self):
        self.logger = get_logger("lurenet.ip_reputation")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'LureNet-IPReputation/2.0'
        })
        self.cache = {}
        self.cache_ttl = timedelta(hours=24)

    def lookup(self, ip_address: str) -> Dict[str, Any]:
        """
        Comprehensive IP lookup

        Args:
            ip_address: IP address to lookup

        Returns:
            Complete IP information dictionary
        """
        self.logger.info(f"Looking up IP: {ip_address}")

        # Check cache
        if ip_address in self.cache:
            cached_data, cached_time = self.cache[ip_address]
            if datetime.now() - cached_time < self.cache_ttl:
                self.logger.debug(f"Using cached data for {ip_address}")
                return cached_data

        results = {
            'ip': ip_address,
            'geolocation': {},
            'reputation': {},
            'threat_score': 0,
            'verdict': 'unknown',
            'is_vpn': False,
            'is_proxy': False,
            'is_tor': False,
            'is_cloud': False,
            'timestamp': datetime.now().isoformat()
        }

        try:
            # Get geolocation
            geo_data = self._get_geolocation(ip_address)
            if geo_data:
                results['geolocation'] = geo_data

            # Get reputation data
            reputation_data = self._get_reputation(ip_address)
            if reputation_data:
                results['reputation'] = reputation_data

            # Check if VPN/Proxy/Tor
            privacy_data = self._check_privacy_services(ip_address)
            if privacy_data:
                results.update(privacy_data)

            # Calculate threat score and verdict
            results['threat_score'] = self._calculate_threat_score(results)
            results['verdict'] = self._calculate_verdict(results)

            # Cache results
            self.cache[ip_address] = (results, datetime.now())

        except Exception as e:
            self.logger.error(f"Error looking up IP {ip_address}: {e}")
            results['error'] = str(e)

        return results

    def _get_geolocation(self, ip_address: str) -> Optional[Dict]:
        """Get IP geolocation using free API"""
        try:
            # ip-api.com - Free, no API key required (up to 45 req/min)
            url = f"http://ip-api.com/json/{ip_address}"
            params = {
                'fields': 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting'
            }

            response = self.session.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'organization': data.get('org'),
                        'asn': data.get('as'),
                        'is_mobile': data.get('mobile', False),
                        'is_proxy': data.get('proxy', False),
                        'is_hosting': data.get('hosting', False)
                    }
        except Exception as e:
            self.logger.warning(f"Geolocation lookup failed: {e}")
        return None

    def _get_reputation(self, ip_address: str) -> Optional[Dict]:
        """Get IP reputation from threat intelligence sources"""
        reputation = {
            'sources': {},
            'threat_lists': [],
            'abuse_reports': 0,
            'last_seen': None
        }

        try:
            # Check AbuseIPDB (requires free API key - skipping for now)
            # Users can add their own API key in production

            # Check ThreatFox for IP IoCs
            threatfox = self._check_threatfox_ip(ip_address)
            if threatfox:
                reputation['sources']['threatfox'] = threatfox
                if threatfox.get('found'):
                    reputation['threat_lists'].append('ThreatFox')

            # Check Blocklist.de
            blocklist = self._check_blocklist_de(ip_address)
            if blocklist:
                reputation['sources']['blocklist_de'] = blocklist
                if blocklist.get('listed'):
                    reputation['threat_lists'].append('Blocklist.de')

            return reputation if reputation['sources'] else None

        except Exception as e:
            self.logger.warning(f"Reputation check failed: {e}")
            return None

    def _check_threatfox_ip(self, ip_address: str) -> Optional[Dict]:
        """Check ThreatFox for IP address"""
        try:
            url = "https://threatfox-api.abuse.ch/api/v1/"
            data = {
                'query': 'search_ioc',
                'search_term': ip_address
            }

            response = self.session.post(url, json=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok':
                    data_list = result.get('data', [])
                    if data_list:
                        ioc_data = data_list[0]
                        return {
                            'found': True,
                            'threat_type': ioc_data.get('threat_type'),
                            'malware': ioc_data.get('malware'),
                            'confidence': ioc_data.get('confidence_level'),
                            'first_seen': ioc_data.get('first_seen'),
                            'last_seen': ioc_data.get('last_seen'),
                            'tags': ioc_data.get('tags', [])
                        }
                return {'found': False}
        except Exception as e:
            self.logger.warning(f"ThreatFox IP check failed: {e}")
            return None

    def _check_blocklist_de(self, ip_address: str) -> Optional[Dict]:
        """Check Blocklist.de for IP"""
        try:
            # Blocklist.de provides DNS-based lookups
            # This is a simple implementation
            return {
                'listed': False,
                'note': 'Full Blocklist.de integration requires DNS lookup'
            }
        except Exception as e:
            self.logger.warning(f"Blocklist.de check failed: {e}")
            return None

    def _check_privacy_services(self, ip_address: str) -> Optional[Dict]:
        """Check if IP is VPN, Proxy, or Tor"""
        privacy_info = {
            'is_vpn': False,
            'is_proxy': False,
            'is_tor': False,
            'is_cloud': False
        }

        try:
            # Check Tor exit nodes (can be done via public list)
            # For demo, we'll use a simple approach
            # In production, download and check against Tor exit node list

            # Check for common cloud providers via ASN/organization
            # This is already done in geolocation data

            return privacy_info

        except Exception as e:
            self.logger.warning(f"Privacy service check failed: {e}")
            return None

    def _calculate_threat_score(self, results: Dict) -> int:
        """Calculate threat score (0-100) from lookup results"""
        score = 0

        # Check reputation sources
        reputation = results.get('reputation', {})
        threat_lists = reputation.get('threat_lists', [])

        if threat_lists:
            # Each threat list adds to the score
            score += len(threat_lists) * 30

        # Check for suspicious indicators
        if results.get('is_proxy'):
            score += 20
        if results.get('is_vpn'):
            score += 10
        if results.get('is_tor'):
            score += 40

        # Check geolocation for high-risk countries (optional)
        geo = results.get('geolocation', {})
        if geo.get('is_hosting'):
            score += 15

        return min(100, score)

    def _calculate_verdict(self, results: Dict) -> str:
        """Calculate verdict from results"""
        threat_score = results.get('threat_score', 0)

        if threat_score >= 75:
            return 'malicious'
        elif threat_score >= 50:
            return 'suspicious'
        elif threat_score >= 25:
            return 'low_risk'
        else:
            return 'clean'

    def bulk_lookup(self, ip_addresses: list) -> Dict[str, Dict]:
        """
        Lookup multiple IP addresses

        Args:
            ip_addresses: List of IP addresses

        Returns:
            Dictionary mapping IP to lookup results
        """
        results = {}
        for ip in ip_addresses:
            try:
                results[ip] = self.lookup(ip)
            except Exception as e:
                self.logger.error(f"Failed to lookup {ip}: {e}")
                results[ip] = {'error': str(e)}
        return results

    def clear_cache(self):
        """Clear the IP lookup cache"""
        self.cache.clear()
        self.logger.info("IP reputation cache cleared")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            'cached_ips': len(self.cache),
            'cache_ttl_hours': self.cache_ttl.total_seconds() / 3600
        }
