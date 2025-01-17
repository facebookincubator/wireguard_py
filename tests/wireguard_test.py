# pyre-unsafe
"""
Copyright (c) Meta Platforms, Inc. and affiliates.

This software may be used and distributed according to the terms of the
MIT License.
"""

import base64
import unittest

import wireguard_py as wg


class WireguardTest(unittest.TestCase):
    def test_gen_priv_key(self) -> None:
        key1 = wg.gen_priv_key()
        assert len(key1) == 44
        key1_bin = base64.b64decode(key1)
        assert len(key1_bin) == 32

        key2 = wg.gen_priv_key()
        assert key1 != key2

    def test_get_pub_key(self) -> None:
        known_priv_key = b"IICoxfMPrzOJnD7XfFIslcrxR/ztm1Sr8vo1V/os/kQ="
        known_pub_key = b"34cqsYrb2IeWYz2Gi2ElcBzC55k5sBLClNG8twOkEho="
        pub_key1 = wg.get_pub_key(known_priv_key)
        assert pub_key1 == known_pub_key

        random_priv_key = wg.gen_priv_key()
        pub_key2 = wg.get_pub_key(random_priv_key)
        assert pub_key2 != known_pub_key
