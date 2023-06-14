"""
Copyright (c) Meta Platforms, Inc. and affiliates.

This software may be used and distributed according to the terms of the
MIT License.
"""

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import List, Optional, Union

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
    endpoint: Optional[Endpoint] = None
    allowed_ips: List[IPNetwork] = field(default_factory=list)

    def __str__(self) -> str:
        return self.pubkey
