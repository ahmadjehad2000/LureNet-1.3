"""
Configuration Management System

Professional configuration loader with validation and defaults.
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional


class Config:
    """Centralized configuration management"""

    _instance = None
    _config = None

    def __new__(cls):
        """Singleton pattern for global config access"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize configuration"""
        if self._config is None:
            self.load()

    def load(self, config_path: Optional[str] = None):
        """
        Load configuration from YAML file

        Args:
            config_path: Path to config file (default: config.yaml)
        """
        if config_path is None:
            config_path = self._find_config_file()

        try:
            with open(config_path, 'r') as f:
                self._config = yaml.safe_load(f)

            # Validate configuration
            self._validate()

            # Create required directories
            self._create_directories()

        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML configuration: {e}")

    def _find_config_file(self) -> str:
        """Find configuration file in common locations"""
        search_paths = [
            "config.yaml",
            "lurenet/config.yaml",
            "/etc/lurenet/config.yaml",
            str(Path.home() / ".lurenet" / "config.yaml"),
        ]

        for path in search_paths:
            if os.path.exists(path):
                return path

        # Return default if not found
        return "config.yaml"

    def _validate(self):
        """Validate configuration structure"""
        required_sections = ["global", "database", "services"]

        for section in required_sections:
            if section not in self._config:
                raise ValueError(f"Missing required configuration section: {section}")

    def _create_directories(self):
        """Create required directories"""
        data_dir = self.get("global.data_dir", "data")
        log_dir = os.path.dirname(self.get("logging.file", "data/logs/lurenet.log"))

        for directory in [data_dir, log_dir]:
            Path(directory).mkdir(parents=True, exist_ok=True)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation

        Args:
            key: Configuration key (e.g., 'services.http.port')
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self._config

        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any):
        """
        Set configuration value using dot notation

        Args:
            key: Configuration key
            value: Value to set
        """
        keys = key.split('.')
        config = self._config

        for k in keys[:-1]:
            config = config.setdefault(k, {})

        config[keys[-1]] = value

    def get_service_config(self, service: str) -> Dict[str, Any]:
        """
        Get configuration for specific service

        Args:
            service: Service name (e.g., 'http', 'ssh')

        Returns:
            Service configuration dictionary
        """
        return self.get(f"services.{service}", {})

    def is_service_enabled(self, service: str) -> bool:
        """
        Check if service is enabled

        Args:
            service: Service name

        Returns:
            True if enabled, False otherwise
        """
        return self.get(f"services.{service}.enabled", False)

    def get_enabled_services(self) -> list:
        """
        Get list of enabled services

        Returns:
            List of enabled service names
        """
        services = self.get("services", {})
        return [name for name, config in services.items()
                if config.get("enabled", False)]

    @property
    def debug(self) -> bool:
        """Check if debug mode is enabled"""
        return self.get("global.debug", False)

    @property
    def version(self) -> str:
        """Get application version"""
        return self.get("global.version", "2.0.0")

    def __repr__(self) -> str:
        """String representation"""
        enabled_services = self.get_enabled_services()
        return f"<Config version={self.version} services={enabled_services}>"


# Global config instance
config = Config()
