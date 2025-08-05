import sys
from pathlib import Path

from loguru import logger

from rpc_helper.utils.models.settings_model import LoggingConfig


# Create a library-specific logger instance
_rpc_logger = logger.bind(library="rpc_helper")


def get_logger(module_name: str = "RpcHelper"):
    """
    Get a logger instance with module binding.
    
    This uses the library-scoped logger with module name binding.
    No automatic configuration is performed.
    
    Args:
        module_name (str): Module name to bind to the logger.
    
    Returns:
        Logger: A bound logger instance scoped to this library.
    """
    return _rpc_logger.bind(module=module_name)


def configure_rpc_logging(config: LoggingConfig):
    """
    Configure the library-scoped logger for RPC Helper.
    
    This function must be called explicitly if you want to configure
    file logging or modify console logging behavior. It only affects
    this library's logging and won't interfere with the host application's
    logging configuration.
    
    Args:
        config (LoggingConfig): The logging configuration to apply.
    """
    # Setup file logging if enabled
    if config.log_dir is not None:
        # Convert to absolute path if not already
        log_dir = Path(config.log_dir)
        if not log_dir.is_absolute():
            log_dir = Path.cwd() / log_dir
            
        log_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
        
        # Add file handlers for each enabled level
        for level, enabled in config.file_levels.items():
            if enabled:
                log_file = log_dir / f"{level.lower()}.log"
                
                def level_filter(record, target_level=level):
                    return record["level"].name == target_level
                
                _rpc_logger.add(
                    str(log_file.absolute()),
                    level=level,
                    format=config.format,
                    filter=level_filter,
                    rotation=config.rotation,
                    retention=config.retention,
                    compression=config.compression,
                    backtrace=True,
                    diagnose=True
                )
    
    # Setup additional console logging if enabled and different from defaults
    if config.enable_console_logging and hasattr(config, 'console_levels'):
        # Only add handlers that are different from loguru's defaults
        for level, output_stream in config.console_levels.items():
            output = sys.stdout if output_stream == "stdout" else sys.stderr
            
            def level_filter(record, target_level=level):
                return record["level"].name == target_level
            
            _rpc_logger.add(
                output,
                level=level,
                format=config.format,
                filter=level_filter,
                colorize=True
            )


def disable_rpc_file_logging():
    """
    Convenience function to disable file logging by removing file handlers.
    
    This removes file handlers from the library-scoped logger only,
    keeping only console output for this library.
    """
    # Remove all file handlers from the library-scoped logger
    handlers_to_remove = []
    for handler_id, handler in _rpc_logger._core.handlers.items():
        sink = handler._sink
        # Only identify actual file handlers by checking for _file attribute
        # which is specific to Loguru's FileSink class
        if hasattr(sink, '_file'):
            handlers_to_remove.append(handler_id)
    
    for handler_id in handlers_to_remove:
        try:
            _rpc_logger.remove(handler_id)
        except ValueError:
            pass  # Handler already removed


def enable_debug_logging():
    """
    Convenience function to enable debug and trace logging to console
    for the library-scoped logger only.
    """
    _rpc_logger.add(
        sys.stdout,
        level="TRACE",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {extra[module]} | {message}",
        filter=lambda record: record["level"].name in ["DEBUG", "TRACE"],
        colorize=True
    )


# Default logger instance - uses library-scoped logger with module binding
default_logger = get_logger("RpcHelper")
