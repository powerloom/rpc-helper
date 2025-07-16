import sys
from pathlib import Path

from loguru import logger

from rpc_helper.utils.models.settings_model import LoggingConfig


def create_level_filter(level):
    """
    Create a filter function for a specific log level.
    """
    return lambda record: record['level'].name == level


def configure_logger(config: LoggingConfig = LoggingConfig()):
    """
    Configure and return a logger instance based on the provided configuration.
    
    Args:
        config (LoggingConfig): The logging configuration to use.
                              If not provided, uses default settings.
    
    Returns:
        Logger: Configured logger instance
    """
    # Force remove all handlers
    new_logger = logger.bind()
    if config.module_name:
        new_logger = new_logger.bind(module=config.module_name)
    else:
        new_logger = new_logger.bind(module="RpcHelper")
        
    new_logger.configure(handlers=[])
    new_logger.remove()

    # Configure file logging if enabled
    if config.log_dir is not None and config.file_levels is not None:
        # Ensure log directory exists with proper permissions
        log_dir = Path(config.log_dir)
        try:
            log_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
        except PermissionError:
            # Fallback to user's home directory
            log_dir = Path.home() / ".rpc_helper/logs/rpc_helper"
            log_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
            print(f"Warning: Could not create log directory at {config.log_dir}. Using {log_dir} instead.")
        
        # Add file handlers for enabled levels
        for level, enabled in config.file_levels.items():
            if enabled:
                log_file = log_dir / f"{level.lower()}.log"
                new_logger.add(
                    str(log_file),
                    level=level,
                    format=config.format,
                    filter=create_level_filter(level),
                    rotation=config.rotation,
                    compression=config.compression,
                    retention=config.retention,
                )

    # Configure console logging
    for level, output in config.console_levels.items():
        stream = sys.stdout if output.lower() == "stdout" else sys.stderr
        new_logger.add(
            stream,
            level=level,
            format=config.format,
            filter=create_level_filter(level),
        )

    return new_logger


def get_logger(config: LoggingConfig = LoggingConfig()):
    """
    Get a configured logger instance.
    
    Args:
        config (LoggingConfig): The logging configuration to use.
                              If not provided, uses default settings.
    
    Returns:
        Logger: Configured logger instance
    """
    return configure_logger(config)


# Default logger instance with default configuration
default_logger = get_logger()
