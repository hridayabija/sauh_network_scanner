"""Resolve once, reject private destinations and connect to the checked addresses."""

import asyncio
import ipaddress
import socket

from aiohttp.abc import AbstractResolver


async def resolve_public(host, port):
    loop = asyncio.get_running_loop()
    addresses = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    result = []
    for family, _, _, _, address in addresses:
        ip = ipaddress.ip_address(address[0])
        if not ip.is_global:
            raise OSError("non-public destination")
        if (family, str(ip)) not in result:
            result.append((family, str(ip)))
    if not result:
        raise OSError("no public destination addresses")
    return sorted(result, key=lambda item: item[0] != socket.AF_INET)


class PublicResolver(AbstractResolver):
    async def resolve(self, host, port=0, family=socket.AF_INET):
        addresses = await resolve_public(host, port)
        return [
            {
                "hostname": host,
                "host": address,
                "port": port,
                "family": address_family,
                "proto": socket.IPPROTO_TCP,
                "flags": socket.AI_NUMERICHOST,
            }
            for address_family, address in addresses
            if family in (socket.AF_UNSPEC, address_family)
        ]

    async def close(self):
        pass
