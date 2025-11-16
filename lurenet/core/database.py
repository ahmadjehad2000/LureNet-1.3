"""
Database Layer

Professional SQLAlchemy-based database for threat intelligence.
"""

import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from pathlib import Path

Base = declarative_base()


class ThreatEvent(Base):
    """Threat event model"""
    __tablename__ = 'threat_events'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(45), index=True)  # IPv6 support
    source_port = Column(Integer)
    protocol = Column(String(20), index=True)
    service = Column(String(50))
    attack_type = Column(String(100))
    severity = Column(String(20), index=True)
    threat_score = Column(Float, default=0.0)

    # Request details
    method = Column(String(20))
    path = Column(Text)
    user_agent = Column(Text)
    headers = Column(Text)  # JSON
    payload = Column(Text)

    # GeoIP
    country = Column(String(2))
    city = Column(String(100))
    latitude = Column(Float)
    longitude = Column(Float)

    # Analysis
    detected_tools = Column(Text)  # JSON array
    indicators = Column(Text)  # JSON array
    is_blocked = Column(Boolean, default=False)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'source_port': self.source_port,
            'protocol': self.protocol,
            'service': self.service,
            'attack_type': self.attack_type,
            'severity': self.severity,
            'threat_score': self.threat_score,
            'method': self.method,
            'path': self.path,
            'user_agent': self.user_agent,
            'country': self.country,
            'city': self.city,
            'detected_tools': json.loads(self.detected_tools) if self.detected_tools else [],
            'indicators': json.loads(self.indicators) if self.indicators else [],
            'is_blocked': self.is_blocked,
        }


class AttackerProfile(Base):
    """Attacker profile aggregation"""
    __tablename__ = 'attacker_profiles'

    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), unique=True, index=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    total_events = Column(Integer, default=1)
    max_threat_score = Column(Float, default=0.0)
    attack_types = Column(Text)  # JSON array
    protocols = Column(Text)  # JSON array
    country = Column(String(2))
    is_blocked = Column(Boolean, default=False)
    notes = Column(Text)


class SessionData(Base):
    """Session correlation data"""
    __tablename__ = 'sessions'

    id = Column(Integer, primary_key=True)
    session_id = Column(String(64), unique=True, index=True)
    source_ip = Column(String(45))
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    event_count = Column(Integer, default=0)
    services_accessed = Column(Text)  # JSON array


class Database:
    """Professional database management"""

    def __init__(self, db_path: str = "data/lurenet.db"):
        """
        Initialize database

        Args:
            db_path: Path to SQLite database
        """
        # Create directory if needed
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        # Create engine
        self.engine = create_engine(
            f'sqlite:///{db_path}',
            echo=False,
            pool_pre_ping=True
        )

        # Create session factory
        session_factory = sessionmaker(bind=self.engine)
        self.Session = scoped_session(session_factory)

        # Create tables
        Base.metadata.create_all(self.engine)

    def get_session(self):
        """Get database session"""
        return self.Session()

    def add_event(self, event_data: Dict[str, Any]) -> int:
        """
        Add threat event

        Args:
            event_data: Event data dictionary

        Returns:
            Event ID
        """
        session = self.get_session()
        try:
            event = ThreatEvent(
                source_ip=event_data.get('source_ip'),
                source_port=event_data.get('source_port'),
                protocol=event_data.get('protocol'),
                service=event_data.get('service'),
                attack_type=event_data.get('attack_type'),
                severity=event_data.get('severity', 'low'),
                threat_score=event_data.get('threat_score', 0.0),
                method=event_data.get('method'),
                path=event_data.get('path'),
                user_agent=event_data.get('user_agent'),
                headers=json.dumps(event_data.get('headers', {})),
                payload=event_data.get('payload'),
                country=event_data.get('country'),
                city=event_data.get('city'),
                detected_tools=json.dumps(event_data.get('detected_tools', [])),
                indicators=json.dumps(event_data.get('indicators', [])),
            )

            session.add(event)
            session.commit()

            # Update attacker profile
            self._update_attacker_profile(session, event_data.get('source_ip'), event_data)

            return event.id

        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def _update_attacker_profile(self, session, ip: str, event_data: Dict):
        """Update or create attacker profile"""
        profile = session.query(AttackerProfile).filter_by(ip_address=ip).first()

        if profile:
            profile.last_seen = datetime.utcnow()
            profile.total_events += 1
            profile.max_threat_score = max(
                profile.max_threat_score,
                event_data.get('threat_score', 0.0)
            )
        else:
            profile = AttackerProfile(
                ip_address=ip,
                total_events=1,
                max_threat_score=event_data.get('threat_score', 0.0),
                country=event_data.get('country'),
            )
            session.add(profile)

        session.commit()

    def get_recent_events(self, limit: int = 100,
                         protocol: Optional[str] = None) -> List[Dict]:
        """
        Get recent threat events

        Args:
            limit: Maximum events to return
            protocol: Filter by protocol

        Returns:
            List of event dictionaries
        """
        session = self.get_session()
        try:
            query = session.query(ThreatEvent).order_by(
                ThreatEvent.timestamp.desc()
            )

            if protocol:
                query = query.filter(ThreatEvent.protocol == protocol)

            events = query.limit(limit).all()
            return [event.to_dict() for event in events]

        finally:
            session.close()

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get threat statistics

        Returns:
            Statistics dictionary
        """
        session = self.get_session()
        try:
            total_events = session.query(ThreatEvent).count()
            unique_ips = session.query(ThreatEvent.source_ip).distinct().count()

            # Get severity distribution
            from sqlalchemy import func
            severity_dist = dict(
                session.query(
                    ThreatEvent.severity,
                    func.count(ThreatEvent.id)
                ).group_by(ThreatEvent.severity).all()
            )

            # Get protocol distribution
            protocol_dist = dict(
                session.query(
                    ThreatEvent.protocol,
                    func.count(ThreatEvent.id)
                ).group_by(ThreatEvent.protocol).all()
            )

            # Get top attackers
            top_attackers = session.query(
                AttackerProfile
            ).order_by(
                AttackerProfile.total_events.desc()
            ).limit(10).all()

            return {
                'total_events': total_events,
                'unique_ips': unique_ips,
                'severity_distribution': severity_dist,
                'protocol_distribution': protocol_dist,
                'top_attackers': [
                    {
                        'ip': a.ip_address,
                        'events': a.total_events,
                        'threat_score': a.max_threat_score,
                        'country': a.country,
                    }
                    for a in top_attackers
                ],
            }

        finally:
            session.close()

    def cleanup_old_events(self, days: int = 90):
        """
        Clean up events older than specified days

        Args:
            days: Number of days to retain
        """
        session = self.get_session()
        try:
            from datetime import timedelta
            cutoff = datetime.utcnow() - timedelta(days=days)

            deleted = session.query(ThreatEvent).filter(
                ThreatEvent.timestamp < cutoff
            ).delete()

            session.commit()
            return deleted

        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def close(self):
        """Close database connections"""
        self.Session.remove()
        self.engine.dispose()
