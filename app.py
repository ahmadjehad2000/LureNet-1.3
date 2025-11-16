#!/usr/bin/env python3
"""
LureNet Enterprise v2.0
Professional Honeypot & Threat Intelligence Platform

A unified, enterprise-grade deception platform for capturing and analyzing
cyber threats in real-time. Perfect for malware researchers, security analysts,
and organizations studying attacker behavior.

Usage:
    python app.py                    # Start with default config
    python app.py --config myconfig.yaml    # Use custom config
    python app.py --no-dashboard     # Run without web interface
"""

import click
import sys
from lurenet.core.engine import HoneypotEngine
from lurenet.core.logger import get_logger
from lurenet.protocols import (
    HTTPHoneypot,
    SSHHoneypot,
    FTPHoneypot,
    SMTPHoneypot,
    DNSHoneypot,
    SMBHoneypot,
    LDAPHoneypot
)
from lurenet.web.app import create_app


@click.command()
@click.option('--config', default='config.yaml', help='Path to configuration file')
@click.option('--no-dashboard', is_flag=True, help='Disable web dashboard')
@click.option('--debug', is_flag=True, help='Enable debug mode')
def main(config, no_dashboard, debug):
    """
    LureNet Enterprise - Professional Honeypot Platform

    Start the honeypot engine with all configured services.
    """
    logger = get_logger("lurenet.main")

    # Banner
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║       🎯 LureNet Enterprise v2.0                          ║
    ║                                                           ║
    ║       Professional Honeypot & Threat Intelligence         ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)

    try:
        # Initialize engine
        logger.info("Initializing honeypot engine...")
        engine = HoneypotEngine(config)

        # Register all protocol handlers
        protocol_classes = {
            'http': HTTPHoneypot,
            'ssh': SSHHoneypot,
            'ftp': FTPHoneypot,
            'smtp': SMTPHoneypot,
            'dns': DNSHoneypot,
            'smb': SMBHoneypot,
            'ldap': LDAPHoneypot
        }

        for protocol_name, protocol_class in protocol_classes.items():
            if engine.config.is_service_enabled(protocol_name):
                protocol_config = engine.config.get_service_config(protocol_name)
                protocol_instance = protocol_class(protocol_config, engine)
                engine.register_handler(protocol_name, protocol_instance)
                logger.info(f"{protocol_name.upper()} honeypot registered")

        # Start honeypot services
        logger.info("Starting honeypot services...")
        engine.start()

        # Start web dashboard
        if not no_dashboard:
            logger.info("Starting web dashboard...")
            app, socketio = create_app(engine)

            dashboard_host = engine.config.get('dashboard.host', '0.0.0.0')
            dashboard_port = engine.config.get('dashboard.port', 5000)

            print(f"\n✓ LureNet is running!")
            print(f"\n📊 Dashboard: http://{dashboard_host if dashboard_host != '0.0.0.0' else 'localhost'}:{dashboard_port}")
            print(f"🔐 Login: admin / LureNet2024!")

            # Show all running services
            print(f"\n🎯 Active Honeypots:")
            for service_name in engine.config.get_enabled_services():
                service_config = engine.config.get_service_config(service_name)
                port = service_config.get('port', 'N/A')
                print(f"   • {service_name.upper()}: port {port}")

            print(f"\nPress Ctrl+C to stop\n")

            # Run Flask with SocketIO
            socketio.run(
                app,
                host=dashboard_host,
                port=dashboard_port,
                debug=debug,
                use_reloader=False  # Avoid double startup
            )
        else:
            # Run without dashboard
            print(f"\n✓ LureNet honeypot is running (dashboard disabled)")

            # Show all running services
            print(f"\n🎯 Active Honeypots:")
            for service_name in engine.config.get_enabled_services():
                service_config = engine.config.get_service_config(service_name)
                port = service_config.get('port', 'N/A')
                print(f"   • {service_name.upper()}: port {port}")

            print(f"\nPress Ctrl+C to stop\n")

            # Keep running
            import time
            while engine.is_running():
                time.sleep(1)

    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
        engine.stop()
        print("\n\n✓ LureNet stopped gracefully")
        sys.exit(0)

    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
