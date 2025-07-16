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
    # Create a new logger instance with module binding
    if config.module_name:
        new_logger = logger.bind(module=config.module_name)
    else:
        new_logger = logger.bind(module="RpcHelper")

    # Remove all handlers from this logger instance
    new_logger.configure(handlers=[])

    # Configure file logging if enabled
    if config.log_dir is not None and config.file_levels is not None:
        # Convert to absolute path if not already
        log_dir = Path(config.log_dir)
        if not log_dir.is_absolute():
            log_dir = Path.cwd() / log_dir
            
        try:
            log_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
        except PermissionError:
            # Fallback to user's home directory with absolute path
            log_dir = Path.home() / ".rpc_helper/logs/rpc_helper"
            log_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
            print(f"Warning: Could not create log directory at {config.log_dir}. Using {log_dir} instead.")
        
        # Common log format for files, matching shared logger style
        file_format = "{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {module}:{function}:{line} - {message}"
        
        # Add file handlers for enabled levels
        for level, enabled in config.file_levels.items():
            if enabled:
                log_file = log_dir / f"{level.lower()}.log"
                new_logger.add(
                    str(log_file.absolute()),  # Use absolute path
                    level=level,
                    format=file_format,
                    filter=create_level_filter(level),
                    rotation="100 MB",
                    retention="7 days",
                    compression="zip",
                    backtrace=True,
                    diagnose=True
                )

    # Configure console logging with colors, matching shared logger style
    console_format = "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{module}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    
    # Split console output between stdout and stderr like shared logger
    stdout_levels = []
    stderr_levels = []
    
    for level, output in config.console_levels.items():
        if logger.level(level).no < logger.level("WARNING").no:
            stdout_levels.append(level)
        else:
            stderr_levels.append(level)
    
    # Add stdout handler for INFO and below
    if stdout_levels:
        new_logger.add(
            sys.stdout,
            format=console_format,
            filter=lambda record: record["level"].name in stdout_levels,
            colorize=True
        )
    
    # Add stderr handler for WARNING and above
    if stderr_levels:
        new_logger.add(
            sys.stderr,
            format=console_format,
            filter=lambda record: record["level"].name in stderr_levels,
            colorize=True
        )

    return new_logger


def get_logger(config: LoggingConfig = None):
    """
    Get a configured logger instance.
    
    Args:
        config (LoggingConfig, optional): The logging configuration to use.
                                        If not provided, uses default RpcHelper settings.
    
    Returns:
        Logger: Configured logger instance
    """
    if not config:
        config = LoggingConfig(module_name="RpcHelper")
    return configure_logger(config)


# Default logger instance with RpcHelper-specific configuration
default_logger = get_logger()
