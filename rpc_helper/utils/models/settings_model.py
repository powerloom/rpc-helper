from pydantic import BaseModel
from typing import Dict, List, Optional
from pathlib import Path


class LoggingConfig(BaseModel):
    """Logging configuration model."""
    log_dir: Optional[Path] = Path("logs/rpc_helper")  # None disables file logging
    console_levels: Dict[str, str] = {
        # Debug levels disabled by default
        "INFO": "stdout",
        "SUCCESS": "stdout",
        "WARNING": "stderr",
        "ERROR": "stderr",
        "CRITICAL": "stderr"
    }
    file_levels: Optional[Dict[str, bool]] = {
        # Debug levels disabled by default
        "INFO": True,
        "SUCCESS": True,
        "WARNING": True,
        "ERROR": True,
        "CRITICAL": True
    }
    module_name: Optional[str] = None  # Added for module-specific context
    rotation: str = "6 hours"
    retention: str = "2 days"
    compression: str = "tar.xz"
    format: str = "{time:MMMM D, YYYY > HH:mm:ss!UTC} | {level} | {module} | Message: {message} | {extra}"  # Added module to format


class RPCNodeConfig(BaseModel):
    """RPC node configuration model."""
    url: str


class ConnectionLimits(BaseModel):
    """Connection limits configuration model."""
    max_connections: int = 100
    max_keepalive_connections: int = 50
    keepalive_expiry: int = 300


class RPCConfigBase(BaseModel):
    """Base RPC configuration model."""
    full_nodes: List[RPCNodeConfig]
    archive_nodes: Optional[List[RPCNodeConfig]] = []
    force_archive_blocks: Optional[int] = 0
    retry: int
    request_time_out: int
    connection_limits: ConnectionLimits


class RPCConfigFull(RPCConfigBase):
    """Full RPC configuration model."""
    polling_interval: int
    semaphore_value: int = 20