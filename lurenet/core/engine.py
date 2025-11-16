"""
Honeypot Engine

Core orchestration engine for managing protocol handlers and threat intelligence.
"""

import signal
import sys
import threading
from typing import Dict, List, Any
from lurenet.core.config import Config
from lurenet.core.logger import get_logger
from lurenet.core.database import Database


class HoneypotEngine:
    """Main honeypot orchestration engine"""

    def __init__(self, config_path: str = None):
        """
        Initialize honeypot engine

        Args:
            config_path: Path to configuration file
        """
        # Load configuration
        self.config = Config()
        if config_path:
            self.config.load(config_path)

        # Setup logging
        self.logger = get_logger("lurenet.engine")
        self.logger.info(f"Initializing LureNet v{self.config.version}")

        # Initialize database
        db_path = self.config.get("database.path", "data/lurenet.db")
        self.db = Database(db_path)

        # Protocol handlers
        self.handlers = {}
        self.handler_threads = {}

        # Running state
        self.running = False

        # Setup signal handlers (SIGTERM not available on Windows)
        signal.signal(signal.SIGINT, self._signal_handler)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info("Received shutdown signal")
        self.stop()
        sys.exit(0)

    def register_handler(self, name: str, handler):
        """
        Register a protocol handler

        Args:
            name: Handler name (e.g., 'http', 'ssh')
            handler: Handler instance
        """
        self.handlers[name] = handler
        self.logger.info(f"Registered handler: {name}")

    def start(self):
        """Start all enabled honeypot services"""
        self.logger.info("Starting LureNet honeypot engine")
        self.running = True

        # Get enabled services
        enabled_services = self.config.get_enabled_services()
        self.logger.info(f"Enabled services: {', '.join(enabled_services)}")

        # Start each enabled service
        for service_name in enabled_services:
            if service_name in self.handlers:
                self._start_handler(service_name)
            else:
                self.logger.warning(f"No handler registered for: {service_name}")

        self.logger.info(f"LureNet started with {len(self.handler_threads)} services")

    def _start_handler(self, name: str):
        """Start a specific handler in a thread"""
        handler = self.handlers[name]

        try:
            thread = threading.Thread(
                target=handler.start,
                name=f"Handler-{name}",
                daemon=True
            )
            thread.start()
            self.handler_threads[name] = thread
            self.logger.info(f"Started {name} handler")

        except Exception as e:
            self.logger.error(f"Failed to start {name} handler: {e}")

    def stop(self):
        """Stop all running services"""
        self.logger.info("Stopping LureNet honeypot engine")
        self.running = False

        # Stop all handlers
        for name, handler in self.handlers.items():
            try:
                handler.stop()
                self.logger.info(f"Stopped {name} handler")
            except Exception as e:
                self.logger.error(f"Error stopping {name}: {e}")

        # Close database
        self.db.close()

        self.logger.info("LureNet stopped")

    def log_event(self, event_data: Dict[str, Any]) -> int:
        """
        Log a threat event

        Args:
            event_data: Event data dictionary

        Returns:
            Event ID
        """
        try:
            event_id = self.db.add_event(event_data)
            self.logger.debug(f"Logged event {event_id} from {event_data.get('source_ip')}")
            return event_id

        except Exception as e:
            self.logger.error(f"Failed to log event: {e}")
            return -1

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get threat statistics

        Returns:
            Statistics dictionary
        """
        return self.db.get_statistics()

    def get_recent_events(self, limit: int = 100) -> List[Dict]:
        """
        Get recent events

        Args:
            limit: Maximum events to return

        Returns:
            List of event dictionaries
        """
        return self.db.get_recent_events(limit)

    def is_running(self) -> bool:
        """Check if engine is running"""
        return self.running

    def get_handler_status(self) -> Dict[str, bool]:
        """
        Get status of all handlers

        Returns:
            Dictionary of handler name -> running status
        """
        status = {}
        for name, thread in self.handler_threads.items():
            status[name] = thread.is_alive()
        return status
