#!/usr/bin/env python3

from __future__ import annotations

import asyncio
import socket

from typing import TYPE_CHECKING

import dns

from dns.asyncresolver import Resolver
from dns.resolver import Cache
from dns._asyncio_backend import _maybe_wait_for, StreamSocket, Backend
from python_socks.async_.asyncio import Proxy


if TYPE_CHECKING:
    from .capture import PlaywrightCaptureLogAdapter
    from logging import Logger


class Socks5Backend(Backend):

    def __init__(self, socks5_proxy_url: str):
        super().__init__()
        self.proxy = Proxy.from_url(socks5_proxy_url)

    def name(self) -> str:
        return "asyncio socks5"

    async def make_socket(  # type: ignore[no-untyped-def]
        self,
        af,
        socktype,
        proto=0,
        source=None,
        destination=None,
        timeout=None,
        ssl_context=None,
        server_hostname=None,
    ):
        if socktype == socket.SOCK_STREAM:
            if destination is None:
                # This shouldn't happen, but we check to make code analysis software
                # happier.
                raise ValueError("destination required for stream sockets")
            sock = await self.proxy.connect(dest_host=destination[0], dest_port=destination[1])
            (r, w) = await _maybe_wait_for(  # type: ignore[no-untyped-call]
                asyncio.open_connection(
                    None,
                    None,
                    sock=sock,
                    ssl=ssl_context,
                    family=af,
                    proto=proto,
                    local_addr=source,
                    server_hostname=server_hostname,
                ),
                timeout,
            )
            return StreamSocket(af, r, w)  # type: ignore[no-untyped-call]
        raise NotImplementedError(
            "unsupported socket " + f"type {socktype}"
        )  # pragma: no cover


class Socks5Resolver:

    def __init__(self, logger: Logger | PlaywrightCaptureLogAdapter, socks5_proxy: str, dns_resolver: str | list[str] | None=None):
        self.logger = logger
        # configure set to false means we don't want to load resolv.conf
        self.resolver = Resolver(configure=False)
        self.resolver.cache = Cache(900)
        self.resolver.timeout = 2
        self.resolver.lifetime = 4

        if not dns_resolver:
            # Fallback to 1.1.1.1
            dns_resolver = ['1.1.1.1']
        elif isinstance(dns_resolver, str):
            dns_resolver = [dns_resolver]
        self.resolver.nameservers = dns_resolver

        self.backend = Socks5Backend(socks5_proxy_url=socks5_proxy)

    def get_cache(self, domain: str, rdatatype: dns.rdatatype.RdataType=dns.rdatatype.A) -> dns.resolver.Answer | None:
        # Get domain from cache
        return self.resolver.cache.get((dns.name.from_text(domain), rdatatype, dns.rdataclass.IN))

    async def resolve(self, domain: str, semaphore: asyncio.Semaphore, rdatatype: dns.rdatatype.RdataType=dns.rdatatype.A) -> dns.resolver.Answer | None:
        # Resolve the A record only for the domain, might want to do AAAA instead.
        async with semaphore:
            max_retries = 3
            while max_retries > 0:
                try:
                    response = await self.resolver.resolve(domain, rdatatype,
                                                           tcp=True, backend=self.backend)
                    return response
                except dns.resolver.LifetimeTimeout:
                    # Retry a few times on timeout, it happens.
                    max_retries -= 1
                    if max_retries > 0:
                        self.logger.debug(f"[Socks5] Timeout resolving {domain}, retrying.")
                        await asyncio.sleep(1)
                    else:
                        self.logger.info(f"[Socks5] Timeout resolving {domain}.")
                except Exception as e:
                    self.logger.info(f"[Socks5] Error resolving {domain}: {e}")
                    break
            return None
