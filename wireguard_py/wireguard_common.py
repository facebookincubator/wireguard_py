# pyre-unsafe
"""
Copyright (c) Meta Platforms, Inc. and affiliates.

This software may be used and distributed according to the terms of the
MIT License.
"""

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Union

IPAddress = Union[IPv4Address, IPv6Address]
IPNetwork = Union[IPv4Network, IPv6Network]


@dataclass
class Endpoint:
    ip: IPAddress
    port: int

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"


@dataclass
class Peer:
    pubkey: str
    endpoint: Endpoint | None = None
    allowed_ips: list[IPNetwork] = field(default_factory=list)
    last_handshake_time: int | None = None
    rx_bytes: int | None = None
    tx_bytes: int | None = None

    def __str__(self) -> str:
        return self.pubkey
