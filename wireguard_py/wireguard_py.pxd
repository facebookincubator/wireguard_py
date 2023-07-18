# cython: language_level=3

"""
Copyright (c) Meta Platforms, Inc. and affiliates.

This software may be used and distributed according to the terms of the
MIT License.
"""

cdef extern from "net/if.h":
    cdef const int IFNAMSIZ

cdef extern from "sys/socket.h":
    int AF_INET, AF_INET6
    int inet_pton(int af, char *src, void *dst)
    char *inet_ntop (int af, void *src, char *dst, int size)

    cdef struct sockaddr:
        int sa_family
        char sa_data[250]

cdef extern from "arpa/inet.h":
    cdef enum:
        INET_ADDRSTRLEN
        INET6_ADDRSTRLEN

    int htons(int)
    int ntohs(int)

cdef extern from "netinet/in.h":
    cdef struct in_addr:
        int s_addr

    cdef struct in6_addr:
        int s6_addr[16]
        int s6_addr16[8]
        int s6_addr32[4]

    cdef struct sockaddr_in:
        int sin_family
        int sin_port
        in_addr sin_addr

    cdef struct sockaddr_in6:
        int sin6_family
        int sin6_port
        int sin6_flowinfo
        in6_addr sin6_addr
        int sin6_scope_id


cdef extern from "wireguard_py/wireguard_tools/wireguard.h":
    ctypedef unsigned char[32] wg_key
    ctypedef char[45] wg_key_b64_string

    cdef struct timespec64:
        int tv_sec
        int tv_nsec

    cdef struct wg_allowedip:
        int family
        in_addr ip4
        in6_addr ip6
        int cidr
        wg_allowedip *next_allowedip
        
    enum wg_peer_flags:
        WGPEER_REMOVE_ME
        WGPEER_REPLACE_ALLOWEDIPS
        WGPEER_HAS_PUBLIC_KEY
        WGPEER_HAS_PRESHARED_KEY
        WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL

    union wg_endpoint:
        sockaddr addr
        sockaddr_in addr4
        sockaddr_in6 addr6

    cdef struct wg_peer:
        int flags
        wg_key public_key
        wg_endpoint endpoint
        wg_allowedip *first_allowedip
        wg_allowedip *last_allowedip
        wg_peer *next_peer

    enum wg_device_flags:
        WGDEVICE_REPLACE_PEERS
        WGDEVICE_HAS_PRIVATE_KEY
        WGDEVICE_HAS_PUBLIC_KEY
        WGDEVICE_HAS_LISTEN_PORT
        WGDEVICE_HAS_FWMARK

    cdef struct wg_device:
        char name[IFNAMSIZ]
        int flags
        wg_key public_key
        wg_key private_key
        int listen_port
        wg_peer *first_peer
        wg_peer *last_peer


    int wg_set_device(wg_device *dev)
    int wg_get_device(wg_device **dev, const char *device_name)
    int wg_add_device(const char *device_name)
    char *wg_list_device_names()
    void wg_key_to_base64(wg_key_b64_string base64, const wg_key key)
    int wg_key_from_base64(wg_key key, const wg_key_b64_string base64)
    void wg_generate_private_key(wg_key private_key)
    void wg_generate_public_key(wg_key public_key, const wg_key private_key)
    void wg_free_device(wg_device *dev)
