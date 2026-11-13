"""
P2P Network Discovery Package
Provides multi-tier discovery mechanisms:
1. STUN Client (RFC 5389 NAT traversal & public IP resolution)
2. LAN UDP Beacon (Local Wi-Fi zero-configuration auto-discovery)
3. Bootstrap Tracker Client & Server (Public Internet rendezvous)
"""

from .stun_client import (
    get_lan_ip,
    get_public_ip_and_port,
    resolve_network_addresses,
    query_stun_server,
)
from .lan_beacon import LanBeacon
from .bootstrap_server import BootstrapServer, start_bootstrap_server
from .tracker_client import TrackerClient

__all__ = [
    "LanBeacon",
    "BootstrapServer",
    "start_bootstrap_server",
    "TrackerClient",
    "get_lan_ip",
    "get_public_ip_and_port",
    "resolve_network_addresses",
    "query_stun_server",
]
