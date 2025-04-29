import sys
from functools import lru_cache

from loguru import logger

# Format string for log messages
FORMAT = '{time:MMMM D, YYYY > HH:mm:ss!UTC} | {level} | Message: {message} | {extra}'


def create_level_filter(level):
    """
    Create a filter function for a specific log level.
    """
    return lambda record: record['level'].name == level


@lru_cache(maxsize=None)
def get_logger():
    """
    Configure and return the logger instance.
    This function is cached, so it will only configure the logger once.
    """
    # Force remove all handlers
    new_logger = logger.bind()
    new_logger.configure(handlers=[])
    new_logger.remove()
    # Configure file logging
    log_levels = [
        ('trace', 'TRACE'),
        ('debug', 'DEBUG'),
        ('info', 'INFO'),
        ('success', 'SUCCESS'),
        ('warning', 'WARNING'),
        ('error', 'ERROR'),
        ('critical', 'CRITICAL'),
    ]

    for file_name, level in log_levels:
        logger.add(
            f'logs/{file_name}.log',
            level=level,
            format=FORMAT,
            filter=create_level_filter(level),
            rotation='6 hours',
            compression='tar.xz',
            retention='2 days',
        )

    logger.add(sys.stdout, level='INFO', format=FORMAT, filter=create_level_filter('INFO'))
    logger.add(sys.stdout, level='SUCCESS', format=FORMAT, filter=create_level_filter('SUCCESS'))

    logger.add(sys.stderr, level='WARNING', format=FORMAT, filter=create_level_filter('WARNING'))
    logger.add(sys.stderr, level='ERROR', format=FORMAT, filter=create_level_filter('ERROR'))
    logger.add(sys.stderr, level='CRITICAL', format=FORMAT, filter=create_level_filter('CRITICAL'))

    return new_logger


# Usage
default_logger = get_logger()
