"""
Unit and Integration Tests for WAN Bootstrap Tracker Server & Tracker Client (Feature F30)
and P2PNode Discovery Lifecycle Integration.
"""

import time
import json
import socket
import asyncio
import threading
import urllib.request
import urllib.error
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from src.discovery.bootstrap_server import (
    PeerRegistry,
    BootstrapServer,
    start_bootstrap_server,
)
from src.discovery.tracker_client import TrackerClient
from src.core.p2p_node import P2PNode


def get_free_tcp_port() -> int:
    """Find a free TCP port on localhost for isolated testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class MockReputation:
    def __init__(self, blacklisted_ids=None):
        self.blacklisted_ids = set(blacklisted_ids or [])

    def is_blacklisted(self, peer_id: str) -> bool:
        return peer_id in self.blacklisted_ids


class MockNode:
    def __init__(self, peer_id="client_node_id_1234567890abcdef", port=8001, node_name="Alice", advertised_host="192.168.1.100"):
        self.peer_id = peer_id
        self.port = port
        self.host = "0.0.0.0"
        self.node_name = node_name
        self.advertised_host = advertised_host
        self.reputation = MockReputation()
        self.peers = {}
        self.connections_made = []

    async def connect_to_peer(self, host: str, port: int, timeout: float = 5.0, force: bool = False):
        self.connections_made.append((host, port))
        return True, "Connected"


# =============================================================================
# 1. PeerRegistry Tests
# =============================================================================

def test_peer_registry_register_and_get_active():
    registry = PeerRegistry(default_ttl=10.0)
    record = registry.register(
        peer_id="peer_1",
        username="Alice",
        ip="192.168.1.50",
        port=8001,
        lan_ip="192.168.1.50",
        wan_ip="203.0.113.1",
        wan_port=50001
    )

    assert record["peer_id"] == "peer_1"
    assert record["username"] == "Alice"
    assert record["ip"] == "192.168.1.50"
    assert record["port"] == 8001
    assert record["lan_ip"] == "192.168.1.50"
    assert record["wan_ip"] == "203.0.113.1"
    assert record["wan_port"] == 50001
    assert registry.count() == 1

    peers = registry.get_active_peers()
    assert len(peers) == 1
    assert peers[0]["peer_id"] == "peer_1"


def test_peer_registry_ttl_expiration_and_pruning():
    registry = PeerRegistry(default_ttl=1.0)
    registry.register(peer_id="peer_short", username="ShortLived", ip="10.0.0.1", port=9000, ttl=0.1)
    registry.register(peer_id="peer_long", username="LongLived", ip="10.0.0.2", port=9001, ttl=10.0)

    assert registry.count() == 2
    time.sleep(0.2)  # Wait for peer_short to expire

    active = registry.get_active_peers()
    assert len(active) == 1
    assert active[0]["peer_id"] == "peer_long"
    assert registry.count() == 1

    pruned = registry.prune_expired()
    assert pruned == 0  # get_active_peers already pruned it


def test_peer_registry_exclude_peer_id():
    registry = PeerRegistry(default_ttl=10.0)
    registry.register(peer_id="peer_me", username="Me", ip="10.0.0.1", port=8001)
    registry.register(peer_id="peer_other", username="Other", ip="10.0.0.2", port=8002)

    peers = registry.get_active_peers(exclude_peer_id="peer_me")
    assert len(peers) == 1
    assert peers[0]["peer_id"] == "peer_other"


def test_peer_registry_heartbeat():
    registry = PeerRegistry(default_ttl=1.0)
    record = registry.register(peer_id="peer_hb", username="HB", ip="10.0.0.1", port=8001, ttl=0.5)
    first_exp = record["expires_at"]

    time.sleep(0.1)
    updated = registry.heartbeat("peer_hb", ttl=5.0)
    assert updated is not None
    assert updated["expires_at"] > first_exp

    # Heartbeat for non-existent peer
    assert registry.heartbeat("non_existent_peer") is None


def test_peer_registry_unregister():
    registry = PeerRegistry(default_ttl=10.0)
    registry.register(peer_id="peer_del", username="Del", ip="10.0.0.1", port=8001)
    assert registry.count() == 1

    assert registry.unregister("peer_del") is True
    assert registry.count() == 0
    assert registry.unregister("peer_del") is False


def test_peer_registry_clear():
    registry = PeerRegistry(default_ttl=10.0)
    registry.register(peer_id="p1", username="P1", ip="1.1.1.1", port=8000)
    registry.register(peer_id="p2", username="P2", ip="2.2.2.2", port=8000)
    assert registry.count() == 2
    registry.clear()
    assert registry.count() == 0


# =============================================================================
# 2. BootstrapServer REST Endpoints Tests
# =============================================================================

@pytest.fixture
def bootstrap_server():
    port = get_free_tcp_port()
    server = start_bootstrap_server(host="127.0.0.1", port=port, ttl=10.0)
    time.sleep(0.05)
    yield server
    server.stop()


def _http_post(url: str, data: dict, timeout=3.0):
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def _http_get(url: str, timeout=3.0):
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def test_server_health_and_root(bootstrap_server):
    base_url = f"http://127.0.0.1:{bootstrap_server.port}"

    status, data = _http_get(f"{base_url}/health")
    assert status == 200
    assert data["status"] == "ok"
    assert data["service"] == "BootstrapServer"
    assert data["active_peers"] == 0

    status_root, data_root = _http_get(f"{base_url}/")
    assert status_root == 200
    assert data_root["status"] == "ok"


def test_server_register_success(bootstrap_server):
    base_url = f"http://127.0.0.1:{bootstrap_server.port}"
    payload = {
        "peer_id": "test_peer_123",
        "username": "TestNode",
        "ip": "192.168.1.75",
        "port": 8080,
        "lan_ip": "192.168.1.75",
        "wan_ip": "198.51.100.5",
        "wan_port": 58080
    }

    status, data = _http_post(f"{base_url}/register", payload)
    assert status == 200
    assert data["status"] == "ok"
    assert data["message"] == "Registered"
    assert data["registered_ip"] == "192.168.1.75"
    assert "expires_at" in data

    # Verify listing via GET /peers
    status_peers, data_peers = _http_get(f"{base_url}/peers")
    assert status_peers == 200
    assert len(data_peers["peers"]) == 1
    assert data_peers["peers"][0]["peer_id"] == "test_peer_123"


def test_server_register_wildcard_ip_fallback(bootstrap_server):
    base_url = f"http://127.0.0.1:{bootstrap_server.port}"
    payload = {
        "peer_id": "wildcard_peer",
        "username": "WildcardNode",
        "ip": "0.0.0.0",  # Wildcard IP
        "port": 8090
    }

    status, data = _http_post(f"{base_url}/register", payload)
    assert status == 200
    # Must fallback to socket client IP (127.0.0.1)
    assert data["registered_ip"] == "127.0.0.1"


def test_server_register_invalid_payloads(bootstrap_server):
    base_url = f"http://127.0.0.1:{bootstrap_server.port}"

    # Missing peer_id
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        _http_post(f"{base_url}/register", {"port": 8000})
    assert exc_info.value.code == 400

    # Invalid port
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        _http_post(f"{base_url}/register", {"peer_id": "p1", "port": "invalid"})
    assert exc_info.value.code == 400

    # Out of range port
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        _http_post(f"{base_url}/register", {"peer_id": "p1", "port": 70000})
    assert exc_info.value.code == 400


def test_server_heartbeat_and_unregister(bootstrap_server):
    base_url = f"http://127.0.0.1:{bootstrap_server.port}"
    peer_id = "hb_peer_999"

    # Register peer
    _http_post(f"{base_url}/register", {"peer_id": peer_id, "port": 8001})

    # Send heartbeat
    status_hb, data_hb = _http_post(f"{base_url}/heartbeat", {"peer_id": peer_id})
    assert status_hb == 200
    assert data_hb["status"] == "ok"
    assert "expires_at" in data_hb

    # Unregister peer
    status_unreg, data_unreg = _http_post(f"{base_url}/unregister", {"peer_id": peer_id})
    assert status_unreg == 200
    assert data_unreg["status"] == "ok"

    # Subsequent heartbeat returns 404
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        _http_post(f"{base_url}/heartbeat", {"peer_id": peer_id})
    assert exc_info.value.code == 404


def test_server_peers_exclusion(bootstrap_server):
    base_url = f"http://127.0.0.1:{bootstrap_server.port}"
    _http_post(f"{base_url}/register", {"peer_id": "peer_a", "port": 8001})
    _http_post(f"{base_url}/register", {"peer_id": "peer_b", "port": 8002})

    status, data = _http_get(f"{base_url}/peers?exclude=peer_a")
    assert status == 200
    peers = data["peers"]
    assert len(peers) == 1
    assert peers[0]["peer_id"] == "peer_b"


def test_server_unknown_endpoint_404(bootstrap_server):
    base_url = f"http://127.0.0.1:{bootstrap_server.port}"
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        _http_get(f"{base_url}/nonexistent")
    assert exc_info.value.code == 404


def test_server_payload_size_limit_rejection(bootstrap_server):
    base_url = f"http://127.0.0.1:{bootstrap_server.port}"
    huge_data = {"peer_id": "p1", "port": 8000, "junk": "x" * 70000}  # > 64KB
    with pytest.raises((urllib.error.HTTPError, ConnectionAbortedError, ConnectionResetError)) as exc_info:
        _http_post(f"{base_url}/register", huge_data)
    if isinstance(exc_info.value, urllib.error.HTTPError):
        assert exc_info.value.code == 400


# =============================================================================
# 3. TrackerClient Tests
# =============================================================================

def test_tracker_client_init():
    node = MockNode()
    client = TrackerClient(node, tracker_url="http://localhost:9000/", interval=15.0)
    assert client.tracker_url == "http://localhost:9000"
    assert client.interval == 15.0
    assert not client.running
    assert not client.is_registered


def test_tracker_client_network_coordinates_stun_fallback():
    node = MockNode(advertised_host="192.168.1.150")
    client = TrackerClient(node)

    # 1. When STUN succeeds with public IP
    with patch("src.discovery.stun_client.get_public_ip_and_port", return_value=("93.184.216.34", 54321)):
        coords = client._resolve_network_coordinates()
        assert coords["wan_ip"] == "93.184.216.34"
        assert coords["wan_port"] == 54321
        assert coords["chosen_ip"] == "93.184.216.34"
        assert coords["is_public"] is True

    # 2. When STUN fails or returns private IP (e.g. 192.168.x.x)
    with patch("src.discovery.stun_client.get_public_ip_and_port", return_value=(None, None)):
        coords = client._resolve_network_coordinates()
        assert coords["wan_ip"] is None
        # Fallback hierarchy: advertised_host is chosen
        assert coords["chosen_ip"] == "192.168.1.150"
        assert coords["is_public"] is False


@pytest.mark.asyncio
async def test_tracker_client_register_and_heartbeat(bootstrap_server):
    node = MockNode(peer_id="tracker_node_abc", port=7777, node_name="TrackerNode")
    client = TrackerClient(
        node=node,
        tracker_url=f"http://127.0.0.1:{bootstrap_server.port}",
        interval=10.0,
        loop=asyncio.get_running_loop()
    )

    success = await client.register()
    assert success is True
    assert client.is_registered is True

    # Verify registration in server
    assert bootstrap_server.registry.count() == 1

    # Heartbeat
    hb_success = await client.heartbeat()
    assert hb_success is True

    # Unregister
    unreg_success = await client.unregister()
    assert unreg_success is True
    assert client.is_registered is False
    assert bootstrap_server.registry.count() == 0


@pytest.mark.asyncio
async def test_tracker_client_heartbeat_auto_reregister_on_expiration(bootstrap_server):
    node = MockNode(peer_id="auto_rereg_node", port=7778)
    client = TrackerClient(
        node=node,
        tracker_url=f"http://127.0.0.1:{bootstrap_server.port}",
        loop=asyncio.get_running_loop()
    )

    await client.register()
    # Expire record on server manually
    bootstrap_server.registry.clear()

    # Heartbeat returns 404, prompting automatic re-registration
    hb_res = await client.heartbeat()
    assert hb_res is True
    assert bootstrap_server.registry.count() == 1


@pytest.mark.asyncio
async def test_tracker_client_poll_peers_triggers_connection(bootstrap_server):
    # Register peer on tracker
    bootstrap_server.registry.register(
        peer_id="remote_node_1",
        username="RemoteOne",
        ip="10.0.0.5",
        port=8005
    )

    node = MockNode(peer_id="local_client_id", port=8001)
    client = TrackerClient(
        node=node,
        tracker_url=f"http://127.0.0.1:{bootstrap_server.port}",
        loop=asyncio.get_running_loop()
    )

    peers = await client.poll_peers()
    assert len(peers) == 1
    assert peers[0]["peer_id"] == "remote_node_1"

    await asyncio.sleep(0.05)
    assert len(node.connections_made) == 1
    assert node.connections_made[0] == ("10.0.0.5", 8005)


@pytest.mark.asyncio
async def test_tracker_client_poll_peers_filters_self_and_blacklisted(bootstrap_server):
    node = MockNode(peer_id="local_peer_filter_test", port=8001)
    node.reputation = MockReputation(blacklisted_ids=["bad_peer_xyz"])

    # Register self, blacklisted peer, and already-connected peer
    bootstrap_server.registry.register(peer_id="local_peer_filter_test", username="Self", ip="127.0.0.1", port=8001)
    bootstrap_server.registry.register(peer_id="bad_peer_xyz", username="Bad", ip="10.0.0.6", port=8006)
    bootstrap_server.registry.register(peer_id="already_connected", username="Connected", ip="10.0.0.7", port=8007)
    node.peers[("10.0.0.7", 8007)] = ("already_connected", "Connected")

    client = TrackerClient(
        node=node,
        tracker_url=f"http://127.0.0.1:{bootstrap_server.port}",
        loop=asyncio.get_running_loop()
    )

    await client.poll_peers()
    await asyncio.sleep(0.05)
    assert len(node.connections_made) == 0


@pytest.mark.asyncio
async def test_tracker_client_nat_hairpinning(bootstrap_server):
    """When remote peer shares the same WAN IP as us, prefer remote peer's LAN IP."""
    bootstrap_server.registry.register(
        peer_id="remote_nat_peer",
        username="SameNATNode",
        ip="203.0.113.1",
        port=8001,
        lan_ip="192.168.1.120",
        wan_ip="203.0.113.1"
    )

    node = MockNode(peer_id="my_nat_node", port=8002)
    client = TrackerClient(
        node=node,
        tracker_url=f"http://127.0.0.1:{bootstrap_server.port}",
        loop=asyncio.get_running_loop()
    )
    # Simulate that we resolved the same public WAN IP
    client.wan_ip = "203.0.113.1"

    await client.poll_peers()
    await asyncio.sleep(0.05)

    assert len(node.connections_made) == 1
    # Must connect to LAN IP 192.168.1.120 instead of WAN IP
    assert node.connections_made[0] == ("192.168.1.120", 8001)


@pytest.mark.asyncio
async def test_tracker_client_start_and_stop_lifecycle(bootstrap_server):
    node = MockNode()
    client = TrackerClient(
        node=node,
        tracker_url=f"http://127.0.0.1:{bootstrap_server.port}",
        interval=0.5,
        loop=asyncio.get_running_loop()
    )

    client.start()
    assert client.running is True
    assert client._task is not None

    await asyncio.sleep(0.1)
    assert client.is_registered is True
    assert bootstrap_server.registry.count() == 1

    client.stop()
    assert client.running is False
    assert client._task is None
    # Client should have unregistered
    assert bootstrap_server.registry.count() == 0


# =============================================================================
# 4. P2PNode Discovery Lifecycle Integration Tests
# =============================================================================

def test_p2p_node_discovery_disabled_by_default(tmp_path):
    db_file = str(tmp_path / "rep_test.db")
    storage_path = str(tmp_path / "storage")

    node = P2PNode(
        host="127.0.0.1",
        port=get_free_tcp_port(),
        db_path=db_file,
        storage_dir=storage_path,
        node_name="IsolatedNode"
    )

    assert node.enable_discovery is False
    assert node.lan_beacon is None
    assert node.tracker_client is None
    assert node.beacon_port == 50050
    assert node.tracker_url is None

    # Idempotent stop
    node.stop()
    node.stop()


@pytest.mark.asyncio
async def test_p2p_node_discovery_enabled_lifecycle(tmp_path):
    db_file = str(tmp_path / "rep_disco.db")
    storage_path = str(tmp_path / "storage_disco")
    tcp_port = get_free_tcp_port()
    beacon_port = get_free_tcp_port()  # Use free port for UDP beacon

    node = P2PNode(
        host="127.0.0.1",
        port=tcp_port,
        db_path=db_file,
        storage_dir=storage_path,
        node_name="DiscoveryNode",
        enable_discovery=True,
        tracker_url="http://127.0.0.1:9999",
        beacon_port=beacon_port
    )

    assert node.enable_discovery is True
    assert node.tracker_url == "http://127.0.0.1:9999"
    assert node.beacon_port == beacon_port

    # Verify stop() works cleanly before and after start
    node.stop()
    await node.stop_async()
