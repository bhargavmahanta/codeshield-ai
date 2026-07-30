"""Outbound network boundary checks for the local proxy."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urlsplit

from codeshield.proxy.config import ProxyConfig


class ProxyNetworkError(ValueError):
    """Safe upstream network validation error."""


AddressResolver = Callable[[str, int], list[str]]


def system_resolver(host: str, port: int) -> list[str]:
    try:
        return sorted(
            {
                str(item[4][0])
                for item in socket.getaddrinfo(
                    host,
                    port,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                )
            }
        )
    except OSError as exc:
        raise ProxyNetworkError("upstream address resolution failed") from exc


def validate_upstream_addresses(
    config: ProxyConfig,
    resolver: AddressResolver = system_resolver,
) -> None:
    parsed = urlsplit(config.upstream_base_url)
    host = parsed.hostname
    if host is None:
        raise ProxyNetworkError("upstream host is invalid")
    port = parsed.port or 443
    try:
        literal = ipaddress.ip_address(host)
        addresses = [str(literal)]
    except ValueError:
        addresses = resolver(host, port)
    if not addresses:
        raise ProxyNetworkError("upstream address resolution returned no addresses")
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ProxyNetworkError("upstream address resolution was invalid") from exc
        if not address.is_global:
            raise ProxyNetworkError("upstream address is not globally routable")
