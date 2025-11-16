"""
LureNet Health Monitoring and Auto-Recovery System
Monitors all services, system resources, database health, and provides auto-recovery.
Includes alert system with email and webhook notifications.
"""

import asyncio
import time
import psutil
import json
import logging
import sqlite3
import smtplib
import requests
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess
import socket
from collections import deque


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('health_monitor')


class ServiceStatus(str, Enum):
    """Service health status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    DOWN = "down"
    RECOVERING = "recovering"


class AlertSeverity(str, Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class HealthCheckResult:
    """Health check result"""
    service_name: str
    status: ServiceStatus
    response_time: float
    message: str
    timestamp: float
    details: Dict[str, Any]


@dataclass
class ResourceMetrics:
    """System resource metrics"""
    cpu_percent: float
    memory_percent: float
    memory_available_gb: float
    disk_percent: float
    disk_free_gb: float
    network_bytes_sent: int
    network_bytes_recv: int
    active_connections: int
    timestamp: float


@dataclass
class Alert:
    """Alert notification"""
    severity: AlertSeverity
    service: str
    message: str
    timestamp: float
    details: Dict[str, Any]


class ServiceHealthChecker:
    """Health checker for individual services"""

    def __init__(self, name: str, check_func: Callable, interval: int = 30):
        """
        Initialize service health checker

        Args:
            name: Service name
            check_func: Async function that returns HealthCheckResult
            interval: Check interval in seconds
        """
        self.name = name
        self.check_func = check_func
        self.interval = interval
        self.last_check: Optional[HealthCheckResult] = None
        self.check_history: deque = deque(maxlen=100)
        self.consecutive_failures = 0
        self.last_alert_time = 0
        self.is_running = False

    async def run_check(self) -> HealthCheckResult:
        """Run health check"""
        start_time = time.time()

        try:
            result = await self.check_func()
            result.response_time = time.time() - start_time
            result.timestamp = time.time()

            self.last_check = result
            self.check_history.append(result)

            if result.status == ServiceStatus.HEALTHY:
                self.consecutive_failures = 0
            else:
                self.consecutive_failures += 1

            return result

        except Exception as e:
            logger.error(f"Health check failed for {self.name}: {e}")
            result = HealthCheckResult(
                service_name=self.name,
                status=ServiceStatus.DOWN,
                response_time=time.time() - start_time,
                message=f"Health check error: {str(e)}",
                timestamp=time.time(),
                details={'error': str(e)}
            )
            self.consecutive_failures += 1
            self.last_check = result
            self.check_history.append(result)
            return result

    def get_uptime_percentage(self, hours: int = 24) -> float:
        """Calculate uptime percentage for last N hours"""
        if not self.check_history:
            return 0.0

        cutoff_time = time.time() - (hours * 3600)
        recent_checks = [c for c in self.check_history if c.timestamp > cutoff_time]

        if not recent_checks:
            return 0.0

        healthy_checks = sum(1 for c in recent_checks if c.status == ServiceStatus.HEALTHY)
        return (healthy_checks / len(recent_checks)) * 100


class ResourceMonitor:
    """Monitor system resources"""

    def __init__(self):
        self.metrics_history: deque = deque(maxlen=1440)  # 24 hours at 1-minute intervals
        self.network_io_last = psutil.net_io_counters()
        self.last_check_time = time.time()

    async def collect_metrics(self) -> ResourceMetrics:
        """Collect current resource metrics"""
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)

            # Memory
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_available_gb = memory.available / (1024 ** 3)

            # Disk
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            disk_free_gb = disk.free / (1024 ** 3)

            # Network
            network_io = psutil.net_io_counters()
            network_bytes_sent = network_io.bytes_sent
            network_bytes_recv = network_io.bytes_recv

            # Connections
            active_connections = len(psutil.net_connections())

            metrics = ResourceMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                memory_available_gb=memory_available_gb,
                disk_percent=disk_percent,
                disk_free_gb=disk_free_gb,
                network_bytes_sent=network_bytes_sent,
                network_bytes_recv=network_bytes_recv,
                active_connections=active_connections,
                timestamp=time.time()
            )

            self.metrics_history.append(metrics)
            self.last_check_time = time.time()

            return metrics

        except Exception as e:
            logger.error(f"Error collecting resource metrics: {e}")
            raise

    def get_metrics_summary(self, hours: int = 1) -> Dict[str, Any]:
        """Get metrics summary for last N hours"""
        cutoff_time = time.time() - (hours * 3600)
        recent_metrics = [m for m in self.metrics_history if m.timestamp > cutoff_time]

        if not recent_metrics:
            return {}

        return {
            'avg_cpu_percent': sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics),
            'max_cpu_percent': max(m.cpu_percent for m in recent_metrics),
            'avg_memory_percent': sum(m.memory_percent for m in recent_metrics) / len(recent_metrics),
            'max_memory_percent': max(m.memory_percent for m in recent_metrics),
            'min_disk_free_gb': min(m.disk_free_gb for m in recent_metrics),
            'avg_connections': sum(m.active_connections for m in recent_metrics) / len(recent_metrics),
            'samples': len(recent_metrics)
        }


class DatabaseHealthChecker:
    """Check database health"""

    def __init__(self, db_path: str):
        self.db_path = db_path

    async def check_health(self) -> HealthCheckResult:
        """Check database health"""
        start_time = time.time()

        try:
            # Check file exists
            if not Path(self.db_path).exists():
                return HealthCheckResult(
                    service_name="database",
                    status=ServiceStatus.DOWN,
                    response_time=time.time() - start_time,
                    message="Database file not found",
                    timestamp=time.time(),
                    details={'db_path': self.db_path}
                )

            # Try to connect and query
            conn = sqlite3.connect(self.db_path, timeout=5)
            cursor = conn.cursor()

            # Check database integrity
            cursor.execute("PRAGMA integrity_check")
            integrity = cursor.fetchone()[0]

            # Get table count
            cursor.execute("SELECT count(*) FROM sqlite_master WHERE type='table'")
            table_count = cursor.fetchone()[0]

            # Get database size
            db_size_mb = Path(self.db_path).stat().st_size / (1024 ** 2)

            # Test write
            cursor.execute("CREATE TABLE IF NOT EXISTS health_check (ts REAL)")
            cursor.execute("INSERT INTO health_check VALUES (?)", (time.time(),))
            cursor.execute("DELETE FROM health_check WHERE ts < ?", (time.time() - 3600,))
            conn.commit()

            conn.close()

            status = ServiceStatus.HEALTHY if integrity == "ok" else ServiceStatus.DEGRADED

            return HealthCheckResult(
                service_name="database",
                status=status,
                response_time=time.time() - start_time,
                message=f"Database healthy: {integrity}",
                timestamp=time.time(),
                details={
                    'integrity': integrity,
                    'table_count': table_count,
                    'size_mb': round(db_size_mb, 2),
                    'db_path': self.db_path
                }
            )

        except Exception as e:
            return HealthCheckResult(
                service_name="database",
                status=ServiceStatus.UNHEALTHY,
                response_time=time.time() - start_time,
                message=f"Database error: {str(e)}",
                timestamp=time.time(),
                details={'error': str(e), 'db_path': self.db_path}
            )


class LogFileMonitor:
    """Monitor log files for errors and patterns"""

    def __init__(self, log_paths: List[str]):
        self.log_paths = log_paths
        self.error_patterns = ['ERROR', 'CRITICAL', 'FATAL', 'Exception', 'Traceback']
        self.warning_patterns = ['WARNING', 'WARN']

    async def check_logs(self, since_minutes: int = 5) -> Dict[str, Any]:
        """Check logs for errors in last N minutes"""
        results = {
            'errors': 0,
            'warnings': 0,
            'critical_messages': [],
            'files_checked': 0
        }

        cutoff_time = time.time() - (since_minutes * 60)

        for log_path in self.log_paths:
            try:
                if not Path(log_path).exists():
                    continue

                results['files_checked'] += 1

                # Check if file was modified recently
                if Path(log_path).stat().st_mtime < cutoff_time:
                    continue

                # Read recent lines
                with open(log_path, 'r') as f:
                    lines = f.readlines()[-1000:]  # Last 1000 lines

                for line in lines:
                    if any(pattern in line for pattern in self.error_patterns):
                        results['errors'] += 1
                        if results['errors'] <= 10:  # Keep first 10 critical messages
                            results['critical_messages'].append(line.strip())

                    elif any(pattern in line for pattern in self.warning_patterns):
                        results['warnings'] += 1

            except Exception as e:
                logger.error(f"Error reading log file {log_path}: {e}")

        return results


class AlertManager:
    """Manage and send alerts"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.alert_history: deque = deque(maxlen=1000)
        self.last_alert_times: Dict[str, float] = {}
        self.alert_cooldown = 300  # 5 minutes between same alerts

    async def send_alert(self, alert: Alert) -> None:
        """Send alert through configured channels"""
        # Check cooldown
        alert_key = f"{alert.service}:{alert.severity}"
        if alert_key in self.last_alert_times:
            if time.time() - self.last_alert_times[alert_key] < self.alert_cooldown:
                return

        self.last_alert_times[alert_key] = time.time()
        self.alert_history.append(alert)

        logger.info(f"Sending alert: {alert.severity} - {alert.service} - {alert.message}")

        # Send email
        if self.config.get('email_enabled'):
            await self._send_email_alert(alert)

        # Send webhook
        if self.config.get('webhook_enabled'):
            await self._send_webhook_alert(alert)

    async def _send_email_alert(self, alert: Alert) -> None:
        """Send email alert"""
        try:
            email_config = self.config.get('email', {})

            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[LureNet {alert.severity.upper()}] {alert.service}"
            msg['From'] = email_config.get('from_address')
            msg['To'] = ', '.join(email_config.get('to_addresses', []))

            # Create email body
            text = f"""
LureNet Health Alert

Severity: {alert.severity.upper()}
Service: {alert.service}
Message: {alert.message}
Time: {datetime.fromtimestamp(alert.timestamp).isoformat()}

Details:
{json.dumps(alert.details, indent=2)}
"""

            html = f"""
<html>
<body>
    <h2 style="color: {'#dc2626' if alert.severity in ['error', 'critical'] else '#f59e0b'};">
        LureNet Health Alert
    </h2>
    <table>
        <tr><td><strong>Severity:</strong></td><td>{alert.severity.upper()}</td></tr>
        <tr><td><strong>Service:</strong></td><td>{alert.service}</td></tr>
        <tr><td><strong>Message:</strong></td><td>{alert.message}</td></tr>
        <tr><td><strong>Time:</strong></td><td>{datetime.fromtimestamp(alert.timestamp).isoformat()}</td></tr>
    </table>
    <h3>Details:</h3>
    <pre>{json.dumps(alert.details, indent=2)}</pre>
</body>
</html>
"""

            msg.attach(MIMEText(text, 'plain'))
            msg.attach(MIMEText(html, 'html'))

            # Send email
            with smtplib.SMTP(email_config.get('smtp_host'), email_config.get('smtp_port', 587)) as server:
                if email_config.get('smtp_use_tls', True):
                    server.starttls()
                if email_config.get('smtp_username'):
                    server.login(email_config.get('smtp_username'), email_config.get('smtp_password'))
                server.send_message(msg)

            logger.info(f"Email alert sent successfully")

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")

    async def _send_webhook_alert(self, alert: Alert) -> None:
        """Send webhook alert"""
        try:
            webhook_config = self.config.get('webhook', {})
            url = webhook_config.get('url')

            if not url:
                return

            payload = {
                'severity': alert.severity,
                'service': alert.service,
                'message': alert.message,
                'timestamp': alert.timestamp,
                'details': alert.details
            }

            # Add custom fields
            if webhook_config.get('custom_fields'):
                payload.update(webhook_config['custom_fields'])

            response = requests.post(
                url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )

            if response.status_code >= 200 and response.status_code < 300:
                logger.info(f"Webhook alert sent successfully")
            else:
                logger.error(f"Webhook alert failed: {response.status_code}")

        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")


class ServiceRecovery:
    """Auto-recovery for services"""

    def __init__(self):
        self.recovery_attempts: Dict[str, int] = {}
        self.max_recovery_attempts = 3
        self.recovery_cooldown = 300  # 5 minutes

    async def attempt_recovery(self, service_name: str, recovery_func: Callable) -> bool:
        """Attempt to recover a service"""
        try:
            # Check recovery attempts
            if service_name in self.recovery_attempts:
                if self.recovery_attempts[service_name] >= self.max_recovery_attempts:
                    logger.warning(f"Max recovery attempts reached for {service_name}")
                    return False

            logger.info(f"Attempting recovery for {service_name}")
            self.recovery_attempts[service_name] = self.recovery_attempts.get(service_name, 0) + 1

            # Call recovery function
            success = await recovery_func()

            if success:
                logger.info(f"Recovery successful for {service_name}")
                self.recovery_attempts[service_name] = 0
                return True
            else:
                logger.error(f"Recovery failed for {service_name}")
                return False

        except Exception as e:
            logger.error(f"Recovery error for {service_name}: {e}")
            return False


class HealthMonitor:
    """Main health monitoring system"""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize health monitor

        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)
        self.service_checkers: Dict[str, ServiceHealthChecker] = {}
        self.resource_monitor = ResourceMonitor()
        self.alert_manager = AlertManager(self.config.get('alerts', {}))
        self.recovery = ServiceRecovery()
        self.is_running = False

        # Setup database health checker
        db_path = self.config.get('database', {}).get('path', '/tmp/lurenet_intelligence.db')
        self.db_checker = DatabaseHealthChecker(db_path)

        # Setup log monitor
        log_paths = self.config.get('log_paths', [])
        self.log_monitor = LogFileMonitor(log_paths)

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file"""
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                return json.load(f)

        # Default configuration
        return {
            'services': {
                'http': {'port': 8080, 'enabled': True},
                'ssh': {'port': 2222, 'enabled': True},
                'ftp': {'port': 2121, 'enabled': True},
                'smtp': {'port': 2525, 'enabled': True},
                'dns': {'port': 5353, 'enabled': True},
                'smb': {'port': 4445, 'enabled': True},
                'ldap': {'port': 3389, 'enabled': True}
            },
            'database': {
                'path': '/tmp/lurenet_intelligence.db'
            },
            'resource_thresholds': {
                'cpu_percent': 90,
                'memory_percent': 90,
                'disk_percent': 90,
                'disk_free_gb_min': 1
            },
            'alerts': {
                'email_enabled': False,
                'webhook_enabled': False,
                'email': {
                    'smtp_host': 'smtp.gmail.com',
                    'smtp_port': 587,
                    'smtp_use_tls': True,
                    'from_address': 'lurenet@example.com',
                    'to_addresses': []
                },
                'webhook': {
                    'url': None
                }
            },
            'log_paths': [
                '/var/log/lurenet/http.log',
                '/var/log/lurenet/ssh.log',
                '/var/log/lurenet/ftp.log'
            ]
        }

    def register_service_checker(
        self,
        name: str,
        check_func: Callable,
        recovery_func: Optional[Callable] = None,
        interval: int = 30
    ) -> None:
        """Register a service health checker"""
        checker = ServiceHealthChecker(name, check_func, interval)
        self.service_checkers[name] = checker
        logger.info(f"Registered health checker for {name}")

    async def check_service_port(self, name: str, port: int) -> HealthCheckResult:
        """Check if a service port is listening"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()

            if result == 0:
                return HealthCheckResult(
                    service_name=name,
                    status=ServiceStatus.HEALTHY,
                    response_time=0,
                    message=f"Port {port} is listening",
                    timestamp=time.time(),
                    details={'port': port}
                )
            else:
                return HealthCheckResult(
                    service_name=name,
                    status=ServiceStatus.DOWN,
                    response_time=0,
                    message=f"Port {port} is not responding",
                    timestamp=time.time(),
                    details={'port': port}
                )

        except Exception as e:
            return HealthCheckResult(
                service_name=name,
                status=ServiceStatus.DOWN,
                response_time=0,
                message=f"Port check failed: {str(e)}",
                timestamp=time.time(),
                details={'port': port, 'error': str(e)}
            )

    async def start(self) -> None:
        """Start health monitoring"""
        self.is_running = True
        logger.info("Starting health monitoring system")

        # Register default service checkers
        for service_name, service_config in self.config['services'].items():
            if service_config.get('enabled'):
                port = service_config.get('port')
                self.register_service_checker(
                    service_name,
                    lambda n=service_name, p=port: self.check_service_port(n, p),
                    interval=30
                )

        # Start monitoring tasks
        tasks = [
            self._monitor_services(),
            self._monitor_resources(),
            self._monitor_database(),
            self._monitor_logs()
        ]

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _monitor_services(self) -> None:
        """Monitor all registered services"""
        while self.is_running:
            try:
                for checker in self.service_checkers.values():
                    result = await checker.run_check()

                    # Check if alert needed
                    if result.status in [ServiceStatus.DOWN, ServiceStatus.UNHEALTHY]:
                        if checker.consecutive_failures >= 3:
                            await self.alert_manager.send_alert(Alert(
                                severity=AlertSeverity.CRITICAL if result.status == ServiceStatus.DOWN else AlertSeverity.ERROR,
                                service=result.service_name,
                                message=result.message,
                                timestamp=time.time(),
                                details=result.details
                            ))

                            # Attempt recovery
                            # await self.recovery.attempt_recovery(result.service_name, recovery_func)

                await asyncio.sleep(30)

            except Exception as e:
                logger.error(f"Service monitoring error: {e}")
                await asyncio.sleep(30)

    async def _monitor_resources(self) -> None:
        """Monitor system resources"""
        while self.is_running:
            try:
                metrics = await self.resource_monitor.collect_metrics()
                thresholds = self.config.get('resource_thresholds', {})

                # Check thresholds
                if metrics.cpu_percent > thresholds.get('cpu_percent', 90):
                    await self.alert_manager.send_alert(Alert(
                        severity=AlertSeverity.WARNING,
                        service='system',
                        message=f"High CPU usage: {metrics.cpu_percent:.1f}%",
                        timestamp=time.time(),
                        details=asdict(metrics)
                    ))

                if metrics.memory_percent > thresholds.get('memory_percent', 90):
                    await self.alert_manager.send_alert(Alert(
                        severity=AlertSeverity.WARNING,
                        service='system',
                        message=f"High memory usage: {metrics.memory_percent:.1f}%",
                        timestamp=time.time(),
                        details=asdict(metrics)
                    ))

                if metrics.disk_percent > thresholds.get('disk_percent', 90):
                    await self.alert_manager.send_alert(Alert(
                        severity=AlertSeverity.CRITICAL,
                        service='system',
                        message=f"High disk usage: {metrics.disk_percent:.1f}%",
                        timestamp=time.time(),
                        details=asdict(metrics)
                    ))

                await asyncio.sleep(60)  # Check every minute

            except Exception as e:
                logger.error(f"Resource monitoring error: {e}")
                await asyncio.sleep(60)

    async def _monitor_database(self) -> None:
        """Monitor database health"""
        while self.is_running:
            try:
                result = await self.db_checker.check_health()

                if result.status in [ServiceStatus.DOWN, ServiceStatus.UNHEALTHY]:
                    await self.alert_manager.send_alert(Alert(
                        severity=AlertSeverity.CRITICAL,
                        service='database',
                        message=result.message,
                        timestamp=time.time(),
                        details=result.details
                    ))

                await asyncio.sleep(60)

            except Exception as e:
                logger.error(f"Database monitoring error: {e}")
                await asyncio.sleep(60)

    async def _monitor_logs(self) -> None:
        """Monitor log files"""
        while self.is_running:
            try:
                log_results = await self.log_monitor.check_logs(since_minutes=5)

                if log_results['errors'] > 10:
                    await self.alert_manager.send_alert(Alert(
                        severity=AlertSeverity.WARNING,
                        service='logs',
                        message=f"High error rate: {log_results['errors']} errors in last 5 minutes",
                        timestamp=time.time(),
                        details=log_results
                    ))

                await asyncio.sleep(300)  # Check every 5 minutes

            except Exception as e:
                logger.error(f"Log monitoring error: {e}")
                await asyncio.sleep(300)

    async def stop(self) -> None:
        """Stop health monitoring"""
        self.is_running = False
        logger.info("Stopping health monitoring system")

    async def get_status(self) -> Dict[str, Any]:
        """Get current health status"""
        status = {
            'timestamp': time.time(),
            'services': {},
            'resources': {},
            'database': {},
            'alerts': {
                'recent_count': len(self.alert_manager.alert_history),
                'recent_alerts': [asdict(a) for a in list(self.alert_manager.alert_history)[-10:]]
            }
        }

        # Service statuses
        for name, checker in self.service_checkers.items():
            if checker.last_check:
                status['services'][name] = {
                    'status': checker.last_check.status,
                    'message': checker.last_check.message,
                    'response_time': checker.last_check.response_time,
                    'uptime_24h': checker.get_uptime_percentage(24),
                    'consecutive_failures': checker.consecutive_failures
                }

        # Resource metrics
        if self.resource_monitor.metrics_history:
            latest = self.resource_monitor.metrics_history[-1]
            status['resources'] = asdict(latest)
            status['resources']['summary'] = self.resource_monitor.get_metrics_summary(1)

        # Database health
        db_result = await self.db_checker.check_health()
        status['database'] = asdict(db_result)

        return status


# CLI interface
async def main():
    """Main entry point"""
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='LureNet Health Monitor')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--status', action='store_true', help='Show current status')
    args = parser.parse_args()

    monitor = HealthMonitor(config_path=args.config)

    if args.status:
        # Show status once
        status = await monitor.get_status()
        print(json.dumps(status, indent=2))
    else:
        # Run continuous monitoring
        try:
            await monitor.start()
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
            await monitor.stop()


if __name__ == "__main__":
    asyncio.run(main())
