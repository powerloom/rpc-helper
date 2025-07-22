import sys
from pathlib import Path

from loguru import logger

from rpc_helper.utils.models.settings_model import LoggingConfig


def get_logger(module_name: str = "RpcHelper"):
    """
    Get a logger instance with module binding.
    
    This uses the default loguru logger with just module name binding.
    No automatic configuration is performed.
    
    Args:
        module_name (str): Module name to bind to the logger.
    
    Returns:
        Logger: A bound logger instance.
    """
    return logger.bind(module=module_name)


def configure_rpc_logging(config: LoggingConfig):
    """
    Configure the global loguru logger for RPC Helper.
    
    This function must be called explicitly if you want to configure
    file logging or modify console logging behavior.
    
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
                
                logger.add(
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
            
            logger.add(
                output,
                level=level,
                format=config.format,
                filter=level_filter,
                colorize=True
            )


def disable_rpc_file_logging():
    """
    Convenience function to disable file logging by removing file handlers.
    
    This removes all handlers that write to files, keeping only console output.
    """
    # Remove all file handlers (handlers that don't write to stdout/stderr)
    handlers_to_remove = []
    for handler_id, handler in logger._core.handlers.items():
        sink = handler._sink
        if hasattr(sink, '_file') or (hasattr(sink, 'write') and sink not in [sys.stdout, sys.stderr]):
            handlers_to_remove.append(handler_id)
    
    for handler_id in handlers_to_remove:
        try:
            logger.remove(handler_id)
        except ValueError:
            pass  # Handler already removed


def enable_debug_logging():
    """
    Convenience function to enable debug and trace logging to console.
    """
    logger.add(
        sys.stdout,
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {module} | {message}",
        filter=lambda record: record["level"].name in ["DEBUG", "TRACE"],
        colorize=True
    )


# Default logger instance - uses loguru defaults with module binding
default_logger = get_logger("RpcHelper")
