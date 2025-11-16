"""
Base Protocol Handler

Abstract base class for all protocol implementations.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
from lurenet.core.logger import get_logger


class BaseProtocolHandler(ABC):
    """Abstract base for protocol handlers"""

    def __init__(self, name: str, config: Dict[str, Any], engine):
        """
        Initialize handler

        Args:
            name: Protocol name
            config: Configuration dictionary
            engine: Reference to honeypot engine
        """
        self.name = name
        self.config = config
        self.engine = engine
        self.logger = get_logger(f"lurenet.{name}")
        self.running = False

    @abstractmethod
    def start(self):
        """Start the protocol handler"""
        pass

    @abstractmethod
    def stop(self):
        """Stop the protocol handler"""
        pass

    def log_event(self, event_data: Dict[str, Any]):
        """
        Log a threat event

        Args:
            event_data: Event data dictionary
        """
        # Add protocol information
        event_data['protocol'] = self.name
        event_data['service'] = self.name

        # Forward to engine
        self.engine.log_event(event_data)

    def calculate_threat_score(self, indicators: list) -> float:
        """
        Calculate threat score based on indicators

        Args:
            indicators: List of detected indicators

        Returns:
            Threat score (0-10)
        """
        if not indicators:
            return 0.0

        # Base score
        score = len(indicators) * 2.0

        # Severity multipliers
        severity_map = {
            'sql_injection': 3.0,
            'xss': 2.5,
            'rce': 4.0,
            'path_traversal': 2.0,
            'malware': 5.0,
            'exploit_attempt': 3.5,
        }

        for indicator in indicators:
            score += severity_map.get(indicator, 1.0)

        # Cap at 10
        return min(score, 10.0)

    def get_severity(self, threat_score: float) -> str:
        """
        Get severity level from threat score

        Args:
            threat_score: Threat score (0-10)

        Returns:
            Severity level
        """
        if threat_score >= 8.0:
            return 'critical'
        elif threat_score >= 6.0:
            return 'high'
        elif threat_score >= 4.0:
            return 'medium'
        else:
            return 'low'
