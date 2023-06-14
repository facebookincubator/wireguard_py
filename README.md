# wireguard_py - A cython library allowing direct access to Wireguard kernel functions from Python

[![GitHub link](https://img.shields.io/badge/GitHub-facebookincubator%2Fwireguard_py-blue.svg)](https://github.com/facebookincubator/wireguard_py)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)
[![PyPI](https://img.shields.io/pypi/v/wireguard_py)](https://pypi.org/project/wireguard_py/)
[![Downloads](https://pepy.tech/badge/wireguard_py/week)](https://pepy.tech/project/wireguard_py/week)

For most use cases, the Wireguard CLI is all one needs to set up a working Wireguard tunnel.  However, for more complex scenarios (e.g. the creation and maintenance of a
Wireguard mesh involving many thousands of peers), using a high-level language to manage all of the peer configuration and monitoring make life much easier.  The `wireguard_py`
cython module exists to make this possible in Python without the additional overhead and fragility of having to shell out to the wireguard CLI, as well as providing type hints.

## Installing

Installation is performed via pip:

```
pip install wireguard-py
```

## Using wireguard_py

An quick example of setting up a wireguard connection and peering:


```python
import ipaddress
import pyroute2
import wireguard_py
from wireguard_py.wireguard_common import Endpoint

# Create the wireguard interface
ipr = pyroute2.IPRoute()
ipr.link("add", ifname="wg0", kind="wireguard")
wg_ifc = ipr.link_lookup(ifname="wg0")[0]
ipr.addr("add", index=wg_ifc, address="172.16.0.1", prefixlen=24)
ipr.link("set", index=wg_ifc, state="up")

# Configure wireguard interface
priv_key = wireguard_py.gen_priv_key()
wireguard_py.set_device(
    device_name=b"wg0",
    priv_key=priv_key,
    port=51820,
)

# Create a peer
wireguard_py.set_peer(
    device_name=b"wg0",
    pub_key=b"lM77O8LlU4PNI0ZPWsTPYS3SGubG2/YT26uh9o9LKzM=",
    endpoint=Endpoint(ip=ipaddress.ip_address("172.16.0.2"), port=51820),
    allowed_ips={
        ipaddress.ip_network("172.16.0.2/32"),
        ipaddress.ip_network("10.0.0.0/8"),
    },
    replace_allowed_ips=True,
)

# List peers
peers = wireguard_py.list_peers(b"wg0")
print(peers)
```

## License

wireguard_py is licensed under the MIT License.
