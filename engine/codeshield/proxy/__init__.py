"""Authenticated loopback-only LLM proxy."""

from codeshield.proxy.app import create_proxy_app
from codeshield.proxy.config import (
    ProxyConfig,
    ProxyConfigError,
    load_proxy_config,
)

__all__ = [
    "ProxyConfig",
    "ProxyConfigError",
    "create_proxy_app",
    "load_proxy_config",
]
