#!/usr/bin/env python

# pyre-unsafe

"""
Copyright (c) Meta Platforms, Inc. and affiliates.

This software may be used and distributed according to the terms of the
MIT License.
"""

import ipaddress
import sys
from typing import List, Optional

import click

import wireguard_py as wg

from wireguard_py.wireguard_common import Endpoint


"""
This is a dummy CLI intended to test the functionality of the wireguard cython
module (a.k.a. wireguard_py), located in this code path, as well as to serve as
an example for the use of this module.  It is not intended in any way to act as
a replacement for the official wireguard cli, distributed as part of the
wireguard_tools package.
"""


@click.group()
@click.version_option(wg.__version__)
def cli():
    """
    An example cli to test wireguard_py functionality
    """
    pass


@cli.command()
def gen_priv_key():
    """
    Generates a new private key and writes it to stdout
    """
    print(wg.gen_priv_key().decode())


@cli.command()
def get_pub_key():
    """
    Reads a private key from stdin and writes a public key to stdout
    """
    privkey = sys.stdin.read().encode()
    print(wg.get_pub_key(privkey).decode())


@cli.command()
@click.argument("device_name")
@click.option("--listen-port", type=int, help="Optional port to listen on")
@click.option("--private-key", help="Optional private key to use")
def set_device(
    device_name: str, private_key: Optional[str], listen_port: Optional[int]
) -> None:
    """
    Change the current device configuration
    """
    if not any([private_key, listen_port]):
        raise click.UsageError("At least one option is required")

    wg.set_device(
        device_name=device_name.encode(),
        priv_key=private_key.encode() if private_key is not None else None,
        port=listen_port,
    )


@cli.command()
@click.argument("device_name")
@click.argument("public-key")
@click.option(
    "--endpoint", "endpoint_str", help="<ip>:<port> of optional remote endpoint"
)
@click.option(
    "--allowed-ip",
    "allowed_ip_strs",
    multiple=True,
    help="<ip>/<prefixlen> to allow through peer",
)
@click.option(
    "--replace-allowed-ips",
    is_flag=True,
    default=False,
    help="Replace existing allowed IPs",
)
def set_peer(
    device_name: str,
    public_key: str,
    endpoint_str: Optional[str],
    allowed_ip_strs: List[str],
    replace_allowed_ips: bool,
) -> None:
    """
    Add/change a peer, identified by its public key, on a wireguard device
    """

    endpoint: Optional[str] = None
    if endpoint_str:
        try:
            ip, port = endpoint_str.rsplit(":", 1)
            # pyre-fixme[9]: endpoint has type `Optional[str]`; used as `Endpoint`.
            endpoint = Endpoint(ip=ipaddress.ip_address(ip), port=int(port))
        except KeyError:
            raise click.UsageError("Endpoint must be in <ip>:<port> format")

    allowed_ips = [ipaddress.ip_network(addr) for addr in allowed_ip_strs]

    wg.set_peer(
        device_name=device_name.encode(),
        pub_key=public_key.encode(),
        endpoint=endpoint,
        # pyre-fixme[6]: For 4th argument expected `Optional[Set[Union[IPv4Network,
        #  IPv6Network]]]` but got `List[Union[IPv4Network, IPv6Network]]`.
        allowed_ips=allowed_ips,
        replace_allowed_ips=replace_allowed_ips,
    )


@cli.command()
@click.argument("device_name")
@click.argument("public-key")
def delete_peer(
    device_name: str,
    public_key: str,
) -> None:
    """
    Deleting a peer, as identified by its public key
    """
    wg.delete_peer(
        device_name=device_name.encode(),
        pub_key=public_key.encode(),
    )


@cli.command()
def list_devices() -> None:
    """
    List all wireguard devices on this host
    """
    # pyre-fixme[6]: For 1st argument expected `Iterable[LiteralString]` but got `None`.
    print("\n".join(wg.list_devices()))


@cli.command()
@click.argument("device_name")
def list_peers(device_name) -> None:
    """
    List all peers for a given wireguard device
    """
    for peer in wg.list_peers(device_name.encode()):
        print(f"peer: {peer.pubkey}")
        if peer.endpoint is not None:
            print(f"  endpoint: {peer.endpoint}")
        if peer.allowed_ips:
            print(f"  allowed ips: {', '.join(str(ip) for ip in peer.allowed_ips)}")
        else:
            print("  allowed ips: (none)")
        if peer.last_handshake_time is not None:
            print(f"  last handshake time: {peer.last_handshake_time}")
        if peer.rx_bytes is not None:
            print(f"  rx bytes: {peer.rx_bytes}")
        if peer.tx_bytes is not None:
            print(f"  tx bytes: {peer.tx_bytes}")
        print("")


if __name__ == "__main__":
    cli()
