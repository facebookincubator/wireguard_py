# flake8: noqa
"""
Copyright (c) Meta Platforms, Inc. and affiliates.

This software may be used and distributed according to the terms of the
MIT License.
"""
__version__ = "trunk"

from .wireguard_py import (
    delete_peer,
    gen_priv_key,
    get_pub_key,
    list_devices,
    list_peers,
    set_device,
    set_peer,
)
