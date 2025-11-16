"""
Logging System

Professional logging with file rotation and colored console output.
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support"""

    COLORS = {
        'DEBUG': Fore.CYAN if COLORS_AVAILABLE else '',
        'INFO': Fore.GREEN if COLORS_AVAILABLE else '',
        'WARNING': Fore.YELLOW if COLORS_AVAILABLE else '',
        'ERROR': Fore.RED if COLORS_AVAILABLE else '',
        'CRITICAL': Fore.RED + Style.BRIGHT if COLORS_AVAILABLE else '',
    }

    def format(self, record):
        """Format log record with colors"""
        if COLORS_AVAILABLE and record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)


class Logger:
    """Professional logging system"""

    _loggers = {}

    @classmethod
    def get_logger(cls, name: str = "lurenet",
                   log_file: Optional[str] = None,
                   level: str = "INFO") -> logging.Logger:
        """
        Get or create logger instance

        Args:
            name: Logger name
            log_file: Log file path
            level: Logging level

        Returns:
            Configured logger instance
        """
        if name in cls._loggers:
            return cls._loggers[name]

        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, level.upper()))
        logger.propagate = False

        # Clear existing handlers
        logger.handlers.clear()

        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_formatter = ColoredFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

        # File handler with rotation
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=100 * 1024 * 1024,  # 100MB
                backupCount=5
            )
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)

        cls._loggers[name] = logger
        return logger

    @classmethod
    def setup_from_config(cls, config):
        """
        Setup logging from configuration

        Args:
            config: Config instance
        """
        log_file = config.get("logging.file", "data/logs/lurenet.log")
        level = config.get("logging.level", "INFO")

        return cls.get_logger("lurenet", log_file, level)


# Convenience function
def get_logger(name: str = "lurenet") -> logging.Logger:
    """Get logger instance"""
    return Logger.get_logger(name)
