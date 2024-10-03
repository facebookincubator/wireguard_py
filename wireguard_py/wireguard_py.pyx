# cython: language_level=3

"""
Copyright (c) Meta Platforms, Inc. and affiliates.

This software may be used and distributed according to the terms of the
MIT License.
"""

from wireguard_py.wireguard_py cimport (
    AF_INET,
    AF_INET6,
    INET6_ADDRSTRLEN,
    INET_ADDRSTRLEN,
    WGDEVICE_HAS_LISTEN_PORT,
    WGDEVICE_HAS_PRIVATE_KEY,
    WGPEER_HAS_PUBLIC_KEY,
    WGPEER_REMOVE_ME,
    WGPEER_REPLACE_ALLOWEDIPS,
    htons,
    in_addr,
    inet_ntop,
    inet_pton,
    ntohs,
    wg_allowedip,
    wg_device,
    wg_free_device,
    wg_generate_private_key,
    wg_generate_public_key,
    wg_get_device,
    wg_key,
    wg_key_b64_string,
    wg_key_from_base64,
    wg_key_to_base64,
    wg_list_device_names,
    wg_peer,
    wg_set_device,
)

from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network, ip_address, ip_network
from libc.stdlib cimport free, calloc
from typing import List, Optional, Set

from wireguard_py.wireguard_common import Endpoint, IPAddress, IPNetwork, Peer

def gen_priv_key() -> bytes:
    """
    Generate a wireguard private key; returned as encoded base64
    """

    cdef wg_key priv_key_int
    cdef wg_key_b64_string priv_key

    wg_generate_private_key(priv_key_int)
    wg_key_to_base64(priv_key, priv_key_int)

    return priv_key

def get_pub_key(priv_key: bytes) -> bytes:
    """
    Accept an encoded base64 wireguard private key and return a public key
    encoded as base64
    """

    cdef wg_key priv_key_int
    cdef wg_key pub_key_int
    cdef wg_key_b64_string pub_key

    wg_key_from_base64(priv_key_int, priv_key)
    wg_generate_public_key(pub_key_int, priv_key_int)
    wg_key_to_base64(pub_key, pub_key_int)

    return pub_key

def set_device(
    device_name: bytes, priv_key: Optional[bytes] = None, port: Optional[int] = None
) -> None:
    """
    Configure an existing wireguard interface.  Listening port is optional; if
    omitted we will assume that this host is operating as a client and not as a
    server.  Note that this can be used on both an unconfigured wireguard-type
    interface as well as an interface that has been already configured, in
    which case the existing config is overwritten.
    """

    cdef wg_device* device = NULL
    cdef wg_key priv_key_int

    ret = wg_get_device(&device, device_name)
    if ret:
        wg_free_device(device)
        raise RuntimeError(f"Unable to get device {device_name.decode()}: {ret}")

    if priv_key is not None:
        wg_key_from_base64(priv_key_int, priv_key)
        device.private_key = priv_key_int
        device.flags |= WGDEVICE_HAS_PRIVATE_KEY

    if port is not None:
        device.listen_port = port
        device.flags |= WGDEVICE_HAS_LISTEN_PORT

    ret = wg_set_device(device)
    if ret:
        wg_free_device(device)
        raise RuntimeError(f"Error setting config on {device_name.decode()}: {ret}")

    wg_free_device(device)

def set_peer(
    device_name: bytes,
    pub_key: bytes,
    endpoint: Optional[Endpoint],
    allowed_ips: Optional[Set[IPNetwork]] = None,
    replace_allowed_ips: bool = False,
)-> None:
    """
    Add/configure a peer on a given wireguard interface.  If an endpoint is
    specified, our wireguard instance will attempt to connect to it to
    establish a peering session, otherwise we will need to wait for the other
    peer to connect to us, whichassumes we have set up our wireguard interface
    to listen on a port.

    NB: The IP of the endpoint will automatically be included in the allowed IPs
    list; any others passed in the allowed_ips argument will be append to it.
    """

    cdef wg_device* device = NULL
    cdef wg_peer* peer = <wg_peer*>calloc(1, sizeof(wg_peer))
    cdef wg_allowedip* allowed_ip
    cdef wg_key pub_key_int

    peer.first_allowedip = NULL
    peer.last_allowedip = NULL
    peer.next_peer = NULL

    ret = wg_get_device(&device, device_name)
    if ret:
        wg_free_device(device)
        free(peer)
        raise RuntimeError(f"Unable to get device {device_name.decode()}: {ret}")

    wg_key_from_base64(pub_key_int, pub_key)
    peer.public_key = pub_key_int
    peer.flags |= WGPEER_HAS_PUBLIC_KEY

    if replace_allowed_ips:
        peer.flags |= WGPEER_REPLACE_ALLOWEDIPS

    if endpoint is not None:
        ip_str = str(endpoint.ip).encode()
        if isinstance(endpoint.ip, IPv4Address):
            peer.endpoint.addr4.sin_family = AF_INET
            peer.endpoint.addr4.sin_port = htons(endpoint.port)
            inet_pton(AF_INET, ip_str, &peer.endpoint.addr4.sin_addr)
        else:
            peer.endpoint.addr6.sin6_family = AF_INET6
            peer.endpoint.addr6.sin6_port = htons(endpoint.port)
            inet_pton(AF_INET6, ip_str, &peer.endpoint.addr6.sin6_addr)

    if allowed_ips is not None:
        for net in allowed_ips:
            addr = str(net.network_address).encode()
            allowed_ip = <wg_allowedip*>calloc(1, sizeof(wg_allowedip))
            allowed_ip.next_allowedip = NULL
            if isinstance(net, IPv4Network):
                allowed_ip.family = AF_INET
                inet_pton(AF_INET, addr, &allowed_ip.ip4)
            else:
                allowed_ip.family = AF_INET6
                inet_pton(AF_INET6, addr, &allowed_ip.ip6)

            allowed_ip.cidr = net.prefixlen

            if peer.first_allowedip is NULL:
                peer.first_allowedip = allowed_ip
                peer.last_allowedip = allowed_ip
            else:
                peer.last_allowedip.next_allowedip = allowed_ip
                peer.last_allowedip = allowed_ip

    if device.last_peer is NULL:
        device.first_peer = peer
        device.last_peer = peer
    else:
        device.last_peer.next_peer = peer
        device.last_peer = peer

    ret = wg_set_device(device)
    if ret:
        wg_free_device(device)
        raise RuntimeError(f"Error setting peer on {device_name.decode()}: {ret}")

    wg_free_device(device)

def delete_peer(
    device_name: bytes,
    pub_key: bytes,
)-> None:
    """
    Delete a peer from a wireguard device
    """

    cdef wg_device* device = NULL
    cdef wg_peer* peer = <wg_peer*>calloc(1, sizeof(wg_peer))
    cdef wg_key pub_key_int

    peer.first_allowedip = NULL
    peer.last_allowedip = NULL
    peer.next_peer = NULL

    ret = wg_get_device(&device, device_name)
    if ret:
        wg_free_device(device)
        free(peer)
        raise RuntimeError(f"Unable to get device {device_name.decode()}: {ret}")

    wg_key_from_base64(pub_key_int, pub_key)
    peer.public_key = pub_key_int
    peer.flags = WGPEER_REMOVE_ME

    if device.last_peer is NULL:
        device.first_peer = peer
        device.last_peer = peer
    else:
        device.last_peer.next_peer = peer
        device.last_peer = peer

    ret = wg_set_device(device)
    if ret:
        wg_free_device(device)
        raise RuntimeError(f"Error deleting peer on {device_name.decode()}: {ret}")

    wg_free_device(device)

def list_devices() -> List[str]:
    """
    Return a list of string representing wireguard device names
    """

    cdef char* devices
    devices = wg_list_device_names()
    devices_a = bytearray()
    i = 0
    while True:
        v = devices[i]
        if not v and not devices[i+1]:
            break
        devices_a.append(v)
        i += 1

    free(devices)
    return [b.decode() for b in devices_a.split(b"\x00")]

def list_peers(device_name: bytes) -> List[Peer]:
    """
    Given a wg device, return a list of all peers as a python dataclass
    """

    cdef wg_device* device = NULL
    cdef wg_peer* peer
    cdef wg_allowedip* allowedip
    cdef wg_key_b64_string pub_key
    cdef char ip[INET6_ADDRSTRLEN]
    cdef bytes buf
    cdef int port

    ret = wg_get_device(&device, device_name)
    if ret:
        wg_free_device(device)
        raise RuntimeError(f"Unable to get device {device_name.decode()}: {ret}")

    peers = []
    if device.last_peer is not NULL:
        peer = device.first_peer
        while True:
            
            wg_key_to_base64(pub_key, peer.public_key)
            buf = pub_key
            peer_py = Peer(pubkey = buf.decode())

            if peer.endpoint.addr.sa_family == AF_INET:
                inet_ntop(
                    AF_INET, &peer.endpoint.addr4.sin_addr, ip, INET_ADDRSTRLEN
                )
                port = ntohs(peer.endpoint.addr4.sin_port)
                buf = ip
                peer_py.endpoint = Endpoint(ip=ip_address(buf.decode()), port=port)
            elif peer.endpoint.addr.sa_family == AF_INET6:
                inet_ntop(
                    AF_INET6, &peer.endpoint.addr6.sin6_addr, ip, INET6_ADDRSTRLEN
                )
                port = ntohs(peer.endpoint.addr6.sin6_port)
                buf = ip
                peer_py.endpoint = Endpoint(ip=ip_address(buf.decode()), port=port)

            if peer.last_allowedip is not NULL:
                allowedip = peer.first_allowedip

                while True:
                    if allowedip.family == AF_INET:
                        inet_ntop(AF_INET, &allowedip.ip4, ip, INET_ADDRSTRLEN)
                    else:
                        inet_ntop(AF_INET6, &allowedip.ip6, ip, INET6_ADDRSTRLEN)

                    buf = ip
                    peer_py.allowed_ips.append(
                        ip_network(f"{buf.decode()}/{allowedip.cidr}")
                    )

                    if allowedip == peer.last_allowedip:
                        break

                    allowedip = allowedip.next_allowedip
            
            # Add last_handshake_time, rx_bytes, and tx_bytes
            peer_py.last_handshake_time = peer.last_handshake_time.tv_sec
            peer_py.rx_bytes = peer.rx_bytes
            peer_py.tx_bytes = peer.tx_bytes

            peers.append(peer_py)

            if peer == device.last_peer:
                break

            peer = peer.next_peer

    wg_free_device(device)
    return peers
