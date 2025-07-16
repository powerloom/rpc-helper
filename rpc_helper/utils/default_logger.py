import sys
from pathlib import Path

from loguru import logger

from rpc_helper.utils.models.settings_model import LoggingConfig


# Global state to track if RPC Helper logging has been configured
_rpc_helper_configured = False
_rpc_helper_handler_ids = []


def _rpc_helper_filter(record):
    """Filter that only allows RPC Helper logs through."""
    return record.get("extra", {}).get("rpc_helper") == True


def _setup_rpc_helper_logging(config: LoggingConfig):
    """
    Configure RPC Helper logging handlers on the global loguru logger.
    This should only be called once per application.
    """
    global _rpc_helper_handler_ids
    
    # Setup file logging if enabled
    if config.enable_file_logging and config.log_dir is not None and config.file_levels is not None:
        # Convert to absolute path if not already
        log_dir = Path(config.log_dir)
        if not log_dir.is_absolute():
            log_dir = Path.cwd() / log_dir
            
        try:
            log_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
        except PermissionError:
            # Fallback to user's home directory
            log_dir = Path.home() / ".rpc_helper/logs/rpc_helper"
            log_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
            print(f"Warning: Could not create log directory at {config.log_dir}. Using {log_dir} instead.")
        
        # File format
        file_format = "{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {module}:{function}:{line} - {message}"
        
        # Add file handlers for each enabled level
        for level, enabled in config.file_levels.items():
            if enabled:
                log_file = log_dir / f"{level.lower()}.log"
                
                def level_filter(record, target_level=level):
                    return (_rpc_helper_filter(record) and 
                           record["level"].name == target_level)
                
                handler_id = logger.add(
                    str(log_file.absolute()),
                    level=level,
                    format=file_format,
                    filter=level_filter,
                    rotation="100 MB",
                    retention="7 days",
                    compression="zip",
                    backtrace=True,
                    diagnose=True
                )
                _rpc_helper_handler_ids.append(handler_id)
    
    # Setup console logging if enabled
    if config.enable_console_logging:
        console_format = "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{module}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
        
        # Split levels between stdout and stderr
        stdout_levels = []
        stderr_levels = []
        
        for level, output in config.console_levels.items():
            if logger.level(level).no < logger.level("WARNING").no:
                stdout_levels.append(level)
            else:
                stderr_levels.append(level)
        
        # Add stdout handler for INFO and below
        if stdout_levels:
            def stdout_filter(record):
                return (_rpc_helper_filter(record) and 
                       record["level"].name in stdout_levels)
            
            handler_id = logger.add(
                sys.stdout,
                format=console_format,
                filter=stdout_filter,
                colorize=True
            )
            _rpc_helper_handler_ids.append(handler_id)
        
        # Add stderr handler for WARNING and above
        if stderr_levels:
            def stderr_filter(record):
                return (_rpc_helper_filter(record) and 
                       record["level"].name in stderr_levels)
            
            handler_id = logger.add(
                sys.stderr,
                format=console_format,
                filter=stderr_filter,
                colorize=True
            )
            _rpc_helper_handler_ids.append(handler_id)


def configure_logger(config: LoggingConfig = LoggingConfig()):
    """
    Configure RPC Helper logging globally (one-time setup).
    
    Args:
        config (LoggingConfig): The logging configuration to use.
    
    Returns:
        Logger: A bound logger instance for RPC Helper.
    """
    global _rpc_helper_configured
    
    if not _rpc_helper_configured:
        _setup_rpc_helper_logging(config)
        _rpc_helper_configured = True
    
    # Return a bound logger instance with RPC Helper marker
    module_name = config.module_name or "RpcHelper"
    return logger.bind(rpc_helper=True, module=module_name)


def get_logger(config: LoggingConfig = None):
    """
    Get a configured RPC Helper logger instance.
    
    If this is the first call, it will configure the global logging.
    Subsequent calls will return bound logger instances without reconfiguring.
    
    Args:
        config (LoggingConfig, optional): The logging configuration to use.
                                        Only used on first call.
    
    Returns:
        Logger: A bound logger instance for RPC Helper.
    """
    if not config:
        config = LoggingConfig(module_name="RpcHelper")
    
    return configure_logger(config)


def cleanup_rpc_helper_logging():
    """
    Remove all RPC Helper logging handlers.
    Useful for testing or when you need to reconfigure.
    """
    global _rpc_helper_configured, _rpc_helper_handler_ids
    
    for handler_id in _rpc_helper_handler_ids:
        try:
            logger.remove(handler_id)
        except ValueError:
            pass
    
    _rpc_helper_handler_ids.clear()
    _rpc_helper_configured = False


# Default logger instance - configured on first import
default_logger = get_logger()
