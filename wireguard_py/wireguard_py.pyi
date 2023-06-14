"""
Copyright (c) Meta Platforms, Inc. and affiliates.

This software may be used and distributed according to the terms of the
MIT License.
"""

from typing import Optional, Set

from wireguard_py.wireguard_common import Endpoint, IPNetwork, Peer

def gen_priv_key() -> bytes: ...
def get_pub_key(priv_key: bytes) -> bytes: ...
def set_device(
    device_name: bytes, priv_key: Optional[bytes] = None, port: Optional[int] = None
) -> None: ...
def set_peer(
    device_name: bytes,
    pub_key: bytes,
    endpoint: Optional[Endpoint],
    allowed_ips: Optional[Set[IPNetwork]],
    replace_allowed_ips: bool,
) -> None: ...
def delete_peer(device_name: bytes, pub_key: bytes) -> None: ...
def list_devices() -> None: ...
def list_peers(device_name: bytes) -> List[Peer]: ...
