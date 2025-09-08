from typing import List, Optional

from pydantic import BaseModel


class RPCNodeConfig(BaseModel):
    """RPC node configuration model."""

    url: str


class ConnectionLimits(BaseModel):
    """Connection limits configuration model."""

    max_connections: int = 100
    max_keepalive_connections: int = 50
    keepalive_expiry: int = 300


class RateLimitConfig(BaseModel):
    """Rate Limiter Config"""
    rate_limiter_url: Optional[str] = "http://rate-limiter:8000/check"
    enabled: Optional[bool] = True


class RPCConfigBase(BaseModel):
    """Base RPC configuration model."""

    full_nodes: List[RPCNodeConfig]
    archive_nodes: Optional[List[RPCNodeConfig]] = []
    force_archive_blocks: Optional[int] = 0
    retry: int
    request_time_out: int
    connection_limits: ConnectionLimits
    rate_limit_config: Optional[RateLimitConfig] = RateLimitConfig()


class RPCConfigFull(RPCConfigBase):
    """Full RPC configuration model."""

    polling_interval: int
    semaphore_value: int = 20
